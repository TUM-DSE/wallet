use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::process_manager::process_paging::ProcessPageFlags;
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
        let core = match crate::exclusive::donated_core() {
            Some(c) => c,
            None => {
                log::warn!("gpu_channel: no donated core is polling (run tools/donate first)");
                self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
                return RETURN_TO_PROCESS;
            }
        };

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

        crate::gpu::direct::register_engine_page(core, page);
        log::warn!("gpu_channel: comm page {:#x?} mapped at {:#x}, polled by core {}",
                   page, addr, core);

        self.vmsa.rcx = 0;
        RETURN_TO_PROCESS
    }
}
