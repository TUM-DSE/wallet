use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::process_manager::process_paging::ProcessPageFlags;
use crate::address::PhysAddr;
use crate::address::VirtAddr;
use crate::process_runtime::ReturnTarget;
use crate::process_runtime::RETURN_TO_PROCESS;
use crate::sev::{rmp_adjust, RMPFlags};
use crate::process_manager::process_memory::allocate_page;
use crate::types::PageSize;
use crate::map_paddr;
use crate::paddr_as_slice;
use crate::vaddr_as_slice;
use crate::memory::paging::PerCPUPageMappingGuard;

use super::super::PALContext;

/// Where the shared staging window lands in the trustlet: same PML4
/// slot as the comm page (9 - see redirect/filter.py for the slot
/// map), 2 MiB above it so the comm page's PMD entry is not shared
/// with the window's and there is room for the largest window.
pub const GPU_WINDOW_VADDR: u64 = 0x48000200000;

pub trait ProcessRuntimeGpu {
    fn pal_svsm_gpu_channel(&mut self) -> ReturnTarget;
}

impl ProcessRuntimeGpu for PALContext {
    /// Provision the trustlet's GPU comm page and hand it to the
    /// donated-core GPU poller.
    ///
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFF2)
    /// * rbx: trustlet virtual address to map the page at (page aligned)
    ///
    /// Return:
    /// * rcx: 0 on success, -1 if no donated core is polling,
    ///        -2 on bad arguments
    /// * rdx: the VMPL this process' VMSA executes at (authoritative -
    ///        set by the monitor at trustlet creation; lets callers
    ///        verify they really run as a VMPL1 trustlet)
    ///
    /// The page is monitor-allocated (never trustlet/guest heap: the
    /// poller needs a physically stable page), zeroed, mapped
    /// VMPL1-accessible at the requested VA and registered in the
    /// poller's engine slot exactly like a guest client's page - the
    /// wire protocol (stop id 500 included) is unchanged. The page is
    /// leaked when the session ends: one 4 KiB page per trustlet
    /// session, acceptable for now.
    fn pal_svsm_gpu_channel(&mut self) -> ReturnTarget {
        self.vmsa.rdx = self.vmsa.vmpl as u64;
        let addr = self.vmsa.rbx;
        if addr % 4096 != 0 {
            self.vmsa.rcx = u64::from_ne_bytes((-2i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }
        /* Prefer a donated core with no engine on it, so each trustlet
           gets its own engine slot - and therefore its own service
           process and CUDA context. With only one core donated this is
           the same core every time, and re-registering over a dead
           client's slot is still how crash recovery works, so the
           single-engine behaviour is unchanged. */
        let core = match crate::exclusive::free_donated_core()
            .or_else(crate::exclusive::replacement_donated_core) {
            Some(c) => c,
            None => {
                log::warn!("gpu_channel: no donated core is polling (run tools/donate first)");
                self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
                return RETURN_TO_PROCESS;
            }
        };
        if !crate::gpu::direct::engine_registered(core) {
            log::info!("gpu_channel: assigning engine slot {} (free)", core);
        } else {
            log::warn!("gpu_channel: no free donated core, replacing the engine \
                        on core {} - donate one core per concurrent engine", core);
        }

        let page = allocate_page();
        let (mapping, page_mapped) = paddr_as_slice!(page);
        rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        for i in 0..512 {
            page_mapped[i] = 0u64;
        }

        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);
        let flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE
            | ProcessPageFlags::USER_ACCESSIBLE | ProcessPageFlags::ACCESSED
            | ProcessPageFlags::NO_EXECUTE;
        page_table_ref.map_4k_page(VirtAddr::from(addr), page, flags);

        /* Remember the slot so death (exit/fault) can free it - a dead
           session's registration otherwise squats on the donated core
           until another session replaces it. */
        self.process.gpu_core = core as i64;
        log::warn!("gpu_channel: comm page {:#x?} mapped at {:#x}, polled by core {}",
                   page, addr, core);
        if !crate::gpu::direct::service_registered(core) {
            /* Every relayed call will answer 802 and llama falls back
               to CPU inference SILENTLY (observed: init 6 s instead of
               13 s, tokens/s ~10x off) - make the poisoned session
               unmissable in the log. Happens after a dropped
               registration (relay timeout / slow session_reset): the
               service never re-registers, restart it. */
            log::error!("gpu_channel: NO SERVICE registered for engine {} - \
                         this session will run WITHOUT the GPU (CPU \
                         fallback); restart the engine's service", core);
        }

        /* Approach B: if the service registered a staging window for
           this engine, grant the trustlet VMPL1|RW on its pages and map
           them at GPU_WINDOW_VADDR. The window is pinned SERVICE memory
           (guest-owned; VMPL2 keeps its access - by design, the service
           must read what the client stages), so large memcpy payloads
           can travel through it with one descriptor per windowful
           instead of one comm-page round trip per 4056 bytes. r9 tells
           the client how many bytes are mapped; 0 = no window, client
           stays on the chunked path. */
        let (wlist, wpages) = crate::gpu::direct::window_for(core);
        let mut window_bytes: u64 = 0;
        if wlist != PhysAddr::null() && wpages > 0 {
            let (_list_mapping, list) = paddr_as_slice!(wlist);
            let mut mapped: usize = 0;
            for i in 0..wpages {
                let phys = PhysAddr::from(list[i]);
                if phys == PhysAddr::null() {
                    break;
                }
                let guard = match PerCPUPageMappingGuard::create_4k(phys) {
                    Ok(g) => g,
                    Err(_) => break,
                };
                if rmp_adjust(guard.virt_addr(),
                              RMPFlags::VMPL1 | RMPFlags::READ | RMPFlags::WRITE,
                              PageSize::Regular).is_err() {
                    break;
                }
                page_table_ref.map_4k_page(
                    VirtAddr::from(GPU_WINDOW_VADDR + (i as u64) * 4096),
                    phys, flags);
                mapped += 1;
            }
            if mapped == wpages {
                window_bytes = (wpages as u64) * 4096;
                log::warn!("gpu_channel: staging window mapped at {:#x} ({} KiB)",
                           GPU_WINDOW_VADDR, wpages * 4);
            } else {
                /* Partial mappings are not exposed: the client would
                   fault at the first unmapped page mid-copy. */
                log::warn!("gpu_channel: window mapping failed at page {}/{} - \
                            window not exposed", mapped, wpages);
            }
        }
        self.vmsa.r9 = window_bytes;

        /* Shared heap: map whatever the service has registered so far
           at GPU_HEAP_VADDR (later growth is mapped by poll_engine
           when it relays a HEAP_GROW). rbx reports the mapped bytes -
           0 means no heap, client allocates from plain memory and
           large copies stay on the window path. */
        self.vmsa.rbx = crate::gpu::direct::map_heap_for_trustlet(
            core, PhysAddr::from(self.vmsa.cr3));
        if self.vmsa.rbx != 0 {
            log::warn!("gpu_channel: shared heap mapped at {:#x} ({} KiB)",
                       crate::gpu::direct::GPU_HEAP_VADDR, self.vmsa.rbx >> 10);
        }

        /* Publish the comm page LAST - after IS_TRUSTLET/HEAP_MAPPED
           (map_heap_for_trustlet) and the page table are in place.
           The old order registered first, so the poller could start
           relaying (and take the HEAP_GROW trustlet branch) against
           incomplete slot metadata. The trustlet only touches the
           page after this call returns, so nothing is delayed. The
           bulk memcpy path translates client source addresses itself
           rather than having the payload copied through the comm
           page - hence the page table travels with the registration. */
        crate::gpu::direct::register_engine_page(
            core, page, PhysAddr::from(self.vmsa.cr3));

        /* Phase-0 instrumentation: state of the monitor-managed PML4
           slots after everything gpu_channel just mapped. */
        page_table_ref.log_pml4_slots("gpu_channel");

        self.vmsa.rcx = 0;
        /* Which engine slot this trustlet got: the service that serves
           it must register with SERVICE_ENGINE set to the same core. */
        self.vmsa.r8 = core as u64;
        RETURN_TO_PROCESS
    }
}
