
use crate::{memory::paging::PerCPUPageMappingGuard, MonitorError, RequestParams};
use core::sync::atomic::{AtomicU8, AtomicU32};
use core::sync::atomic::Ordering;
use crate::address::Address;
use crate::address::PhysAddr;
use crate::address::VirtAddr;
use crate::process_manager::process_memory::allocate_page;
use crate::paddr_as_slice;
use crate::map_paddr;
use crate::vaddr_as_slice;
use crate::process_manager::process_paging::ProcessPageTableRef;
extern "Rust" {
    fn wallet_get_apic_id() -> u32;
}

fn get_apic_id() -> u32 {
    unsafe { wallet_get_apic_id() }
}

/// Usable payload bytes: one 4 KiB page minus the 8-byte lock/id header.
/// data[4091] would make the struct 4100 bytes and the tail of `data`
/// would fall outside the single mapped page (GP fault on CPU 8).
pub const COMM_DATA_SIZE: usize = 4088;

#[repr(C)]
#[derive(Debug)]
pub struct CommunicationPage {
    pub lock: AtomicU8,
    pub id: AtomicU32,//u32,
    pub data: [u8; COMM_DATA_SIZE],
}

const _: () = assert!(core::mem::size_of::<CommunicationPage>() == 4096);

static mut ENGINE_PAGES: [PhysAddr; 64] = [PhysAddr::null(); 64];

/// Monitor-allocated comm page of a DEAD trustlet session on this
/// core, awaiting reclamation (F4). Freeing it inside free_engine_slot
/// would race the donated-core poller, which only notices the nulled
/// ENGINE_PAGES entry on its next iteration - so the free is deferred
/// to the next engine registration on the core, by which point the
/// poller has long gone idle. Guest-client pages are never stashed
/// here: those are guest memory, not the monitor's to free.
static mut RETIRED_ENGINE_PAGE: [PhysAddr; 64] = [PhysAddr::null(); 64];

static mut ENGINE_PAGE_TABLE: [PhysAddr; 64] = [PhysAddr::null(); 64];

/// Fallback service page: one service process serving whichever engine
/// is polling. Used when a service registers without naming an engine,
/// which is what the pre-per-engine service binary does.
static mut SERVICE_PAGE: PhysAddr = PhysAddr::null();

/// Per-engine service pages, indexed like ENGINE_PAGES (by polling
/// core). One service PROCESS per engine is what actually isolates
/// engines from each other: separate contexts inside one process do
/// not (measured - see PLAN.md Stage D-0), and a shared process also
/// shares its fixed-size module/kernel tables across sessions.
static mut SERVICE_PAGES: [PhysAddr; 64] = [PhysAddr::null(); 64];

/// Which service page relays for `core`: its own if one registered,
/// otherwise the shared fallback.
fn service_page_for(core: usize) -> PhysAddr {
    let own = unsafe { SERVICE_PAGES[core] };
    if own != PhysAddr::null() {
        return own;
    }
    unsafe { SERVICE_PAGE }
}

pub fn register_service(params: &mut RequestParams) -> Result<(), MonitorError> {
    // Args:
    //  rcx: service comm page phys address
    //  r8:  engine this service serves (its polling core); values >= 64
    //       mean "serve any engine", the legacy single-service mode.
    let comm_page = params.rcx;
    let engine = params.r8 as usize;
    log::warn!("GPU service registration: {:#x?} engine {}", comm_page, engine);
    /* Same deferred-panic argument as register_engine: forward_call
       maps this page from the donated core. */
    if PhysAddr::from(comm_page).is_null() || !PhysAddr::from(comm_page).is_page_aligned() {
        log::warn!("GPU service registration rejected: comm page {:#x?}",
                   PhysAddr::from(comm_page));
        return crate::process_manager::reject(
            params, crate::process_manager::STATUS_BAD_ARGS);
    }
    unsafe {
        if engine < 64 {
            SERVICE_PAGES[engine] = PhysAddr::from(comm_page);
        } else {
            SERVICE_PAGE = PhysAddr::from(comm_page);
        }
    };
    /* Return a defined status. Without this rcx still holds the comm
       page address on the way out, and libwallet - which takes the
       ioctl result as an int and treats negative as failure - reports
       "gpu_service_setup_call failed" whenever that address happens to
       have bit 31 set. Registration then succeeds or fails depending on
       where the page landed in physical memory. */
    params.rcx = 0;
    Ok(())
}

/// Shared staging window (approach B, see PLAN.md): a few hundred KiB
/// of ordinary SERVICE memory, pinned by vmpl.ko and registered here as
/// a physical page list. The monitor maps the same pages into the
/// trustlet (VMPL1|RW) when the trustlet requests its GPU channel, so
/// large memcpy payloads travel client -> window -> cudaMemcpy with no
/// monitor copying and one comm-page round trip per windowful instead
/// of per 4056 bytes. Guest-side clients map the very same pages via
/// vmpl.ko's mmap handler instead - no monitor involvement at all.
///
/// The window is guest memory and stays fully VMPL2-accessible: it
/// carries data the service was going to see anyway (everything the
/// relay forwards to the GPU is already plaintext to the guest), so
/// sharing it costs no confidentiality the relay ever provided.
pub const GPU_WINDOW_MAX_PAGES: usize = 512; // list must fit one page

/// Per-engine window page lists (monitor-owned copies), indexed like
/// SERVICE_PAGES, plus the legacy any-engine fallback slot.
static mut WINDOW_LISTS: [PhysAddr; 64] = [PhysAddr::null(); 64];
static mut WINDOW_NPAGES: [u64; 64] = [0; 64];
static mut WINDOW_LIST_ANY: PhysAddr = PhysAddr::null();
static mut WINDOW_NPAGES_ANY: u64 = 0;

/// Which window serves `core`: its own if one registered, otherwise
/// the shared fallback. Returns the monitor-owned list page and the
/// number of valid entries (0 = no window).
pub fn window_for(core: usize) -> (PhysAddr, usize) {
    unsafe {
        if core < 64 && WINDOW_LISTS[core] != PhysAddr::null()
            && WINDOW_NPAGES[core] != 0 {
            return (WINDOW_LISTS[core], WINDOW_NPAGES[core] as usize);
        }
        (WINDOW_LIST_ANY, WINDOW_NPAGES_ANY as usize)
    }
}

pub fn register_window(params: &mut RequestParams) -> Result<(), MonitorError> {
    // Args:
    //  rcx: phys address of a page holding the window's physical page
    //       list (u64 per page, vmpl.ko-pinned service memory)
    //  rdx: number of pages in the list
    //  r8:  engine this window belongs to (>= 64 = any, like services)
    // Returns (rcx): 0 ok, -1 bad arguments.
    let list_phys = PhysAddr::from(params.rcx);
    let npages = params.rdx as usize;
    let engine = params.r8 as usize;
    if list_phys == PhysAddr::null() || !list_phys.is_page_aligned()
        || npages == 0 || npages > GPU_WINDOW_MAX_PAGES {
        log::warn!("GPU window registration rejected: list {:#x?}, {} pages",
                   list_phys, npages);
        return crate::process_manager::reject(params, crate::process_manager::STATUS_BAD_ARGS);
    }
    /* Copy the list into a monitor-owned page: the trustlet mapping
       happens later (gpu_channel), and it must see the registration-
       time list, not whatever the guest wrote in between. The page is
       reused across re-registrations (fresh service per session), so
       it is one page per engine slot for the monitor's lifetime. */
    let slot = unsafe {
        if engine < 64 { WINDOW_LISTS[engine] } else { WINDOW_LIST_ANY }
    };
    let copy = if slot == PhysAddr::null() { allocate_page() } else { slot };
    {
        let (_guest_mapping, guest_list) = paddr_as_slice!(list_phys);
        let (_copy_mapping, copy_list) = paddr_as_slice!(copy);
        for i in 0..npages {
            copy_list[i] = guest_list[i];
        }
    }
    unsafe {
        if engine < 64 {
            WINDOW_LISTS[engine] = copy;
            WINDOW_NPAGES[engine] = npages as u64;
        } else {
            WINDOW_LIST_ANY = copy;
            WINDOW_NPAGES_ANY = npages as u64;
        }
    }
    log::warn!("GPU window registration: {} pages ({} KiB), engine {}",
               npages, npages * 4, engine);
    params.rcx = 0;
    Ok(())
}

/// Shared heap (the window generalized, see PLAN.md): pinned SERVICE
/// memory that the client ALLOCATES from (cudaMallocHost interception),
/// so descriptors can name payload by heap offset and nobody copies
/// per byte. Offsets are the shared address space - raw host VAs never
/// cross the relay, which is what keeps "addresses" consistent between
/// an engine and its service. Registered in append-only bites of at
/// most one list page (512 pages = 2 MiB); chunks are offset-contiguous
/// but need not be VA-contiguous anywhere.
///
/// Growth is client-triggered: a HEAP_GROW descriptor is relayed to the
/// service, which allocates and registers another chunk; poll_engine
/// then maps the delta into the requesting trustlet before completing
/// the call (the trustlet is spinning on the comm page at that moment,
/// so its page table only gains entries while nothing faults - and
/// added mappings need no TLB shootdown).
pub const GPU_HEAP_MAX_PAGES: usize = 262144; // 1 GiB per engine
pub const GPU_HEAP_VADDR: u64 = 0x48100000000;

/// Per-engine heap page directories: one monitor page of pointers to
/// monitor pages of physical addresses (512 * 512 pages = 1 GiB max),
/// plus the any-engine fallback slot, mirroring windows/services.
static mut HEAP_DIRS: [PhysAddr; 64] = [PhysAddr::null(); 64];
static mut HEAP_NPAGES: [u64; 64] = [0; 64];
static mut HEAP_DIR_ANY: PhysAddr = PhysAddr::null();
static mut HEAP_NPAGES_ANY: u64 = 0;

/// How many heap pages are mapped into the trustlet on `core` (grows
/// at gpu_channel time and after HEAP_GROW relays).
static mut HEAP_MAPPED: [u64; 64] = [0; 64];

/// Whether the engine slot on `core` is a monitor-provisioned trustlet
/// channel (gpu_channel) rather than a guest client (register_engine).
/// Only trustlet channels get heap pages mapped by the monitor - a
/// guest client maps the heap itself through vmpl.ko, and writing a
/// guest process page table from here would corrupt the guest kernel's
/// bookkeeping.
static mut ENGINE_IS_TRUSTLET: [bool; 64] = [false; 64];

/* Set by free_engine_slot when a LIVE session is torn down (serve
   trustlet deleted, client SIGKILLed): the session's stop (500) was
   never sent, so the service still holds its modules. The DONATED
   poller forwards the stop from its own loop - it may take the service
   tens of seconds to reset (cuModuleUnload x123 after a llama
   session), and the donated core is the only place that can block that
   long without the VMPL0-residency IPI hazard. Handled BEFORE any
   relaying, so the next session cannot race the reset. */
static mut PENDING_SERVICE_STOP: [bool; 64] = [false; 64];
/* The service page the dead session was relayed to, captured when the
   stop is armed. The poller often exits poll_engine (registration
   already nulled) before it can notice the flag, so the stop is
   delivered at the NEXT session's entry - by which time a NEW service
   may have registered on this slot. Delivering the stale stop to that
   fresh service killed it (exit-on-stop) or forced a pointless reset:
   deliver only while the registration still IS the dead session's
   service. */
static mut PENDING_STOP_PAGE: [PhysAddr; 64] = [PhysAddr::null(); 64];

fn heap_for(core: usize) -> (PhysAddr, usize) {
    unsafe {
        if core < 64 && HEAP_DIRS[core] != PhysAddr::null() && HEAP_NPAGES[core] != 0 {
            return (HEAP_DIRS[core], HEAP_NPAGES[core] as usize);
        }
        (HEAP_DIR_ANY, HEAP_NPAGES_ANY as usize)
    }
}

/// Physical address of heap page `idx` from directory `dir`.
fn heap_page(dir: PhysAddr, idx: usize) -> PhysAddr {
    let (_dm, dir_page) = paddr_as_slice!(dir);
    let list = PhysAddr::from(dir_page[idx / 512]);
    if list == PhysAddr::null() {
        return PhysAddr::null();
    }
    let (_lm, list_page) = paddr_as_slice!(list);
    PhysAddr::from(list_page[idx % 512])
}

pub fn register_heap(params: &mut RequestParams) -> Result<(), MonitorError> {
    // Args:
    //  rcx: phys address of a page holding this bite's physical page
    //       list (u64 per page, vmpl.ko-pinned service memory)
    //  rdx: number of pages in the list (<= 512)
    //  r8:  engine (>= 64 = any)
    //  r9:  heap page offset this bite starts at; must equal the pages
    //       registered so far (append-only, no holes)
    // Returns (rcx): 0 ok, -1 bad arguments.
    let list_phys = PhysAddr::from(params.rcx);
    let npages = params.rdx as usize;
    let engine = params.r8 as usize;
    let offset = params.r9 as usize;
    use crate::process_manager::reject;
    /* `offset + npages` overflowed BEFORE this test could reject it
       (overflow-checks are on in the shipping dev profile) - checked
       add first. The list page is also mapped below, so an unaligned
       address would panic inside the SVSM's create_4k assert. */
    if list_phys == PhysAddr::null() || !list_phys.is_page_aligned()
        || npages == 0 || npages > 512
        || offset.checked_add(npages).map_or(true, |e| e > GPU_HEAP_MAX_PAGES) {
        log::warn!("GPU heap registration rejected: list {:#x?}, {} pages at {}",
                   list_phys, npages, offset);
        return reject(params, crate::process_manager::STATUS_BAD_ARGS);
    }
    /* Offset 0 resets the slot: a fresh service process registers a
       fresh heap (vmpl.ko already dropped the old pins). Directory
       pages are kept and overwritten. Any trustlet still holding the
       old mapping belongs to a session whose service is gone - dead
       either way. The mapped counters go back to zero so gpu_channel
       and the grow hook re-map from the start. */
    if offset == 0 {
        unsafe {
            if engine < 64 {
                HEAP_NPAGES[engine] = 0;
                HEAP_MAPPED[engine] = 0;
            } else {
                HEAP_NPAGES_ANY = 0;
                for i in 0..64 { HEAP_MAPPED[i] = 0; }
            }
        }
    }
    let current = unsafe {
        if engine < 64 { HEAP_NPAGES[engine] } else { HEAP_NPAGES_ANY }
    } as usize;
    if offset != current {
        log::warn!("GPU heap registration rejected: offset {} != current {} \
                    (append-only)", offset, current);
        return reject(params, crate::process_manager::STATUS_BAD_STATE);
    }
    let dir = unsafe {
        if engine < 64 { HEAP_DIRS[engine] } else { HEAP_DIR_ANY }
    };
    let dir = if dir == PhysAddr::null() {
        let d = allocate_page();
        let (_m, dp) = paddr_as_slice!(d);
        for i in 0..512 { dp[i] = 0; }
        unsafe {
            if engine < 64 { HEAP_DIRS[engine] = d; } else { HEAP_DIR_ANY = d; }
        }
        d
    } else { dir };

    /* Copy this bite's entries into monitor-owned list pages (same
       TOCTOU argument as the window: later trustlet mappings must see
       registration-time contents). */
    let (_gm, guest_list) = paddr_as_slice!(list_phys);
    for i in 0..npages {
        let idx = offset + i;
        let (_dm, dir_page) = paddr_as_slice!(dir);
        if PhysAddr::from(dir_page[idx / 512]) == PhysAddr::null() {
            let l = allocate_page();
            let (_m, lp) = paddr_as_slice!(l);
            for j in 0..512 { lp[j] = 0; }
            dir_page[idx / 512] = u64::from(l);
        }
        let list = PhysAddr::from(dir_page[idx / 512]);
        let (_lm, list_page) = paddr_as_slice!(list);
        list_page[idx % 512] = guest_list[i];
    }
    unsafe {
        if engine < 64 { HEAP_NPAGES[engine] = (offset + npages) as u64; }
        else { HEAP_NPAGES_ANY = (offset + npages) as u64; }
    }
    log::warn!("GPU heap registration: +{} pages at {} ({} KiB total), engine {}",
               npages, offset, (offset + npages) * 4, engine);
    params.rcx = 0;
    Ok(())
}

/// Map heap pages [from, to) into the trustlet page table `cr3` at
/// GPU_HEAP_VADDR, VMPL1|RW. Returns pages actually mapped.
pub fn map_heap_range(cr3: PhysAddr, dir: PhysAddr, from: usize, to: usize) -> usize {
    let mut page_table_ref = ProcessPageTableRef::default();
    page_table_ref.set_external_table(u64::from(cr3));
    let flags = crate::process_manager::process_paging::ProcessPageFlags::PRESENT
        | crate::process_manager::process_paging::ProcessPageFlags::WRITABLE
        | crate::process_manager::process_paging::ProcessPageFlags::USER_ACCESSIBLE
        | crate::process_manager::process_paging::ProcessPageFlags::ACCESSED
        | crate::process_manager::process_paging::ProcessPageFlags::NO_EXECUTE;
    let mut mapped = 0;
    for idx in from..to {
        let phys = heap_page(dir, idx);
        if phys == PhysAddr::null() {
            break;
        }
        let guard = match PerCPUPageMappingGuard::create_4k(phys) {
            Ok(g) => g,
            Err(_) => break,
        };
        if crate::sev::rmp_adjust(guard.virt_addr(),
                crate::sev::RMPFlags::VMPL1
                    | crate::sev::RMPFlags::READ | crate::sev::RMPFlags::WRITE,
                crate::types::PageSize::Regular).is_err() {
            break;
        }
        page_table_ref.map_4k_page(
            VirtAddr::from(GPU_HEAP_VADDR + (idx as u64) * 4096), phys, flags);
        mapped += 1;
    }
    mapped
}

/// Called from gpu_channel: map the whole registered heap for `core`'s
/// fresh trustlet and record the trustlet-ness of the slot. Returns
/// mapped bytes (0 = no heap).
pub fn map_heap_for_trustlet(core: usize, cr3: PhysAddr) -> u64 {
    unsafe { ENGINE_IS_TRUSTLET[core] = true; }
    let (dir, npages) = heap_for(core);
    if dir == PhysAddr::null() || npages == 0 {
        unsafe { HEAP_MAPPED[core] = 0; }
        return 0;
    }
    let mapped = map_heap_range(cr3, dir, 0, npages);
    unsafe { HEAP_MAPPED[core] = mapped as u64; }
    if mapped != npages {
        log::warn!("gpu heap: mapped {}/{} pages for core {} - heap not exposed",
                   mapped, npages, core);
        unsafe { HEAP_MAPPED[core] = 0; }
        return 0;
    }
    (mapped as u64) * 4096
}

pub fn register_engine(params: &mut RequestParams) -> Result<(), MonitorError> {
    // Args:
    //  rcx: shared page phys address
    //  rdx: page table phys address
    //  r8:  target polling core (explicit - the donated core is offline
    //       in the guest, so nothing can pin there to register via the
    //       caller's apic id; values >= 64 fall back to caller-apic
    //       indexing for the legacy parked path)
    // Returns (rcx): 1 if a donated poller is live on that core (the
    // client must not park a thread), 0 otherwise.
    let page_table = params.rdx;
    let comm_page = params.rcx;
    let core = params.r8 as usize;
    let id = if core < 64 { core } else { get_apic_id() as usize };

    /* comm page 0 = UNREGISTER, issued by vmpl.ko when a client that
       registered an engine closes its device fd - which covers every
       way a client dies, SIGKILL included, not just a clean stop (500).
       Without it a dead client's slot stayed registered until some
       later client happened to overwrite it: the poller kept polling a
       dead page, and `make donate` afterwards adopted it.
       rdx carries the client's own comm page so the slot is freed ONLY
       if it still holds that page - a client that died after the NEXT
       client registered on this core must not tear down the newcomer's
       session (the same shape as the stop-path race fixed today). */
    if comm_page == 0 {
        params.rcx = 0;
        if core >= 64 {
            return crate::process_manager::reject(
                params, crate::process_manager::STATUS_BAD_ID);
        }
        let owned = PhysAddr::from(page_table);
        if owned.is_null() || unsafe { ENGINE_PAGES[id] } != owned {
            log::info!("engine release core {}: slot no longer {:#x?}, ignored",
                       id, owned);
            return Ok(());
        }
        free_engine_slot(id);
        return Ok(());
    }

    log::warn!("Registraton: {:#x?} {:#x?} core {}", page_table, comm_page, id);

    /* Neither page was validated, and the panic lands LATER on the
       donated core (poll_engine maps the comm page), long after this
       call returned - the worst kind to debug. Reject here instead. */
    let comm = PhysAddr::from(comm_page);
    if comm.is_null() || !comm.is_page_aligned()
        || !PhysAddr::from(page_table).is_page_aligned() {
        log::warn!("GPU engine registration rejected: comm {:#x?}, page table {:#x?}",
                   comm, PhysAddr::from(page_table));
        return crate::process_manager::reject(
            params, crate::process_manager::STATUS_BAD_ARGS);
    }

    reclaim_retired_engine_page(id);
    unsafe {
        ENGINE_PAGE_TABLE[id] = PhysAddr::from(page_table);
        ENGINE_PAGES[id] = PhysAddr::from(comm_page);
        /* Guest client: the monitor must never write this page table
           (the guest kernel owns it); heap mapping is the client's own
           mmap business. */
        ENGINE_IS_TRUSTLET[id] = false;
    };

    let donated = unsafe { crate::exclusive::CONTROL[id] } != PhysAddr::null();
    params.rcx = donated as u64;

    Ok(())
}

/// Release `core`'s engine slot: the poller sees the null page on its
/// next iteration and goes idle, and free_donated_core can hand the
/// core to the next session. Called when the owning trustlet dies -
/// before this, dead sessions squatted on their cores and concurrent
/// new sessions were forced into the replacement fallback.
pub fn free_engine_slot(core: usize) {
    if core >= 64 {
        return;
    }
    let had_session = unsafe { ENGINE_PAGES[core] != PhysAddr::null() };
    unsafe {
        /* Trustlet sessions use a monitor-allocated comm page - stash
           it for deferred reclamation (see RETIRED_ENGINE_PAGE). A
           still-stashed page from an earlier session stays leaked
           rather than freed here: same poller race. */
        if ENGINE_IS_TRUSTLET[core] && RETIRED_ENGINE_PAGE[core] == PhysAddr::null() {
            RETIRED_ENGINE_PAGE[core] = ENGINE_PAGES[core];
        }
        ENGINE_PAGES[core] = PhysAddr::null();
        HEAP_MAPPED[core] = 0;
    }
    /* Wire the stop the session never sent: a serve-mode trustlet (and
       a SIGKILLed client) dies without the 500, so a persistent
       service kept the session's modules and the NEXT session died on
       "module table full". A cleanly stopped session reached here with
       the registration already nulled by poll_engine's 500 path, so
       had_session distinguishes the two - no double stop. Forwarding
       happens on the DONATED poller (see PENDING_SERVICE_STOP), never
       here: this runs in a guest ioctl's vCPU, and waiting out a
       multi-second service reset at VMPL0 is the parked-CPU IPI
       hazard. */
    if had_session {
        unsafe {
            PENDING_SERVICE_STOP[core] = true;
            PENDING_STOP_PAGE[core] = service_page_for(core);
        }
    }
    log::warn!("engine slot {} freed (owner died)", core);
}

/// Free the previous trustlet session's comm page on `core`, if one is
/// pending. Called from both registration paths: by now the poller has
/// observed the nulled slot, so no one dereferences the old page.
fn reclaim_retired_engine_page(core: usize) {
    if core >= 64 {
        return;
    }
    let retired = unsafe { RETIRED_ENGINE_PAGE[core] };
    if retired != PhysAddr::null() {
        unsafe { RETIRED_ENGINE_PAGE[core] = PhysAddr::null(); }
        crate::process_manager::process_paging::revoke_and_free(retired);
        log::info!("gpu: reclaimed retired comm page {:?} on core {}", retired, core);
    }
}

/// True when a client comm page is registered for `core`. Used by the
/// donated-core command loop to decide when to enter `poll_engine`.
pub fn engine_registered(core: usize) -> bool {
    core < 64 && unsafe { ENGINE_PAGES[core] } != PhysAddr::null()
}

/// True when a service (per-engine or legacy) would answer relays for
/// `core`. A session created without one runs its CUDA calls into the
/// 802 arm and llama silently falls back to CPU inference - poisonous
/// for benchmarks, so gpu_channel warns loudly on this.
pub fn service_registered(core: usize) -> bool {
    service_page_for(core) != PhysAddr::null()
}

/// True when `core`'s service still owes a deferred session reset (a
/// dead session's stop is pending). The next session on this core
/// queues behind that reset - which the CC driver can stretch to
/// minutes on large sessions - so the slot picker prefers cores
/// without this debt.
pub fn engine_slot_owes_stop(core: usize) -> bool {
    core < 64 && unsafe { PENDING_SERVICE_STOP[core] }
}

/// Register a monitor-provisioned comm page (trustlet GPU channel) in
/// `core`'s engine slot — same slot and polling as a guest client's
/// page registered via register_engine.
pub fn register_engine_page(core: usize, page: PhysAddr, page_table: PhysAddr) {
    reclaim_retired_engine_page(core);
    unsafe {
        ENGINE_PAGES[core] = page;
        /* The bulk path translates client source addresses itself, so it
           needs the client's page table. The guest-client path records
           this in register_engine; trustlets come through here. */
        ENGINE_PAGE_TABLE[core] = page_table;
    }
}

/// Poll the engine page registered for `core` and relay calls to the
/// service. Returns when the client stops (id 500) or its registration
/// disappears — return value LOOP_CLEAR — or, when `ctr` is given
/// (donated-core mode), when a LOOP_* command arrives on the control
/// page; the consumed command is returned for the caller to handle.
/// With a `deadline` (absolute TSC; bounded parked mode only), returns
/// LOOP_YIELD once it passes — checked only at the top of the loop, so
/// never mid-relay; a call that lands right at expiry just waits one
/// guest round trip for re-entry.
///
/// The registration is re-read every iteration: a new client's
/// register_engine replaces a dead client's page, so a crashed client
/// cannot wedge the poller — the next registration just remaps. The
/// service mapping likewise follows SERVICE_PAGE re-registrations.
///
/// Locals (mappings, idle_beats, last_id) are caches over per-core
/// statics and rebuild cheaply on every entry; note the 4e9-beat
/// "alive, waiting" heartbeat therefore never fires in a bounded
/// session (~1 ms slices) — a diagnostic loss only.
pub fn poll_engine(core: usize,
                   ctr: Option<&crate::exclusive::ControlStruct>,
                   deadline: Option<u64>) -> u64 {
    use crate::exclusive::LOOP_CLEAR;

    let mut engine_phys = PhysAddr::null();
    let mut engine_mapping: Option<PerCPUPageMappingGuard> = None;
    let mut service_phys = PhysAddr::null();
    let mut service_mapping: Option<PerCPUPageMappingGuard> = None;
    let mut idle_beats: u64 = 0;
    let mut last_id: u32 = 0;

    loop {
        if let Some(ctr) = ctr {
            let cmd = ctr.next.swap(LOOP_CLEAR, Ordering::Relaxed);
            if cmd != LOOP_CLEAR {
                return cmd;
            }
        }

        /* Checked every iteration, not on a spin-counter cadence: busy
           iterations each contain a full 1-30 us relay, so any counted
           cadence would overshoot the budget under load. One rdtsc
           (~25 cycles) is noise against either loop body. */
        if let Some(d) = deadline {
            if crate::utils::tsc::rdtsc() > d {
                return crate::exclusive::LOOP_YIELD;
            }
        }

        /* A dead session's deferred stop is forwarded before ANY other
           relaying (and only in donated mode - ctr - where blocking is
           this core's job): the service may spend tens of seconds in
           its reset, and the next session's calls must queue behind
           it, not race it into forward_call's timeout. */
        if ctr.is_some() && unsafe { PENDING_SERVICE_STOP[core] } {
            let sp = service_page_for(core);
            let target = unsafe { PENDING_STOP_PAGE[core] };
            if sp != PhysAddr::null() && sp != target {
                /* The registration changed since the stop was armed: a
                   fresh service replaced the dead session's one. The
                   stop is for a service that no longer serves this
                   slot - delivering it here killed the NEW service
                   (exit-on-stop) or forced a pointless full reset. */
                log::info!("deferred stop: service on core {} re-registered \
                            ({:#x?} -> {:#x?}) - stale stop dropped",
                           core, target, sp);
            } else if sp != PhysAddr::null() {
                log::info!("deferred stop -> service page {:#x?} (core {})",
                           sp, core);
                if let Ok(m) = PerCPUPageMappingGuard::create_4k(sp) {
                    let svc: &mut CommunicationPage =
                        unsafe { &mut *m.virt_addr().as_mut_ptr::<CommunicationPage>() };
                    /* ONE attempt, long bound - never a retry loop.
                       The stop ack means "session reset done" (see
                       service.c: acking first raced the next session's
                       fatbin into the relay bound), and a reset can
                       run 30+ s degraded. Re-sending 500 on a timeout
                       re-triggers a FULL reset each time: the old
                       10x30 s retry loop chained ~10 resets into a
                       ~300 s relay wedge, after which the next
                       session's first call timed out too, dropped the
                       registration, and llama fell back to CPU
                       inference - the whole "slot-recycle darkness"
                       family. A timeout here now usually just means
                       the service already exited (exit-on-stop). */
                    if forward_call_bounded(svc, 500, DEFERRED_STOP_TIMEOUT_SECS) {
                        log::info!("deferred stop acked by service (core {})", core);
                    } else {
                        /* Exited (exit-on-stop) or resetting slower
                           than the bound (observed 245.7 s with the
                           default MEMLOCK limit - run services with
                           LimitMEMLOCK=infinity / ulimit -l unlimited
                           like the e2e unit). Drop the registration
                           NOW: the next session's calls then fail
                           fast and loud (802) instead of stalling
                           another full bound each and silently
                           falling back to CPU inference. */
                        log::warn!("deferred stop: no ack (core {}) - dropping \
                                    the service registration", core);
                        drop_service(core);
                    }
                }
            }
            unsafe {
                PENDING_SERVICE_STOP[core] = false;
                PENDING_STOP_PAGE[core] = PhysAddr::null();
            }
            continue;
        }

        let current = unsafe { ENGINE_PAGES[core] };
        if current == PhysAddr::null() {
            return LOOP_CLEAR;
        }
        if current != engine_phys {
            engine_mapping = Some(PerCPUPageMappingGuard::create_4k(current).unwrap());
            engine_phys = current;
        }
        let args_ptr: *mut CommunicationPage =
            engine_mapping.as_ref().unwrap().virt_addr().as_mut_ptr::<CommunicationPage>();
        let args = unsafe { &mut *args_ptr };

        let valid_call = args.lock.load(Ordering::Acquire);
        if valid_call == 0 {
            // Session-poll heartbeat: distinguishes "waiting for the
            // next call on this page" from being stuck relaying one
            // (silent-hang diagnosis; ~seconds per beat).
            idle_beats = idle_beats.wrapping_add(1u64);
            if idle_beats % 4_000_000_000u64 == 0 {
                log::warn!("poll_engine[{}]: alive, waiting on {:#x?} (last id {})",
                           core, engine_phys, last_id);
            }
            // Watchdog detection: an idle relay plus an over-budget
            // invoke is the silent-spin signature (rate-limited
            // inside; one rdtsc per idle spin, same cost argument as
            // the deadline check above).
            crate::process_runtime::log_overbudget_invokes(core, last_id as i64);
            continue;
        }
        let call_id = args.id.load(Ordering::Relaxed);
        last_id = call_id;

        // Map lazily and remap when the service re-registers (each
        // forwarded session starts a fresh service process).
        let sp = service_page_for(core);
        if sp != service_phys {
            service_mapping = if sp == PhysAddr::null() {
                None
            } else {
                log::info!("poll_engine[{}]: relaying to service page {:#x?}",
                           core, sp);
                Some(PerCPUPageMappingGuard::create_4k(sp).unwrap())
            };
            service_phys = sp;
        }
        let service: Option<&mut CommunicationPage> = service_mapping.as_ref().map(|m| {
            let ptr: *mut CommunicationPage = m.virt_addr().as_mut_ptr::<CommunicationPage>();
            unsafe { &mut *ptr }
        });

        if call_id == 500 {
            if let Some(service) = service {
                // Session is ending either way; a timeout here is not
                // worth special handling beyond the log.
                let _ = forward_call(service, call_id);
            }
            /* Drop the registration BEFORE releasing the client, not
               after: the store below lets the client return from its
               stop and exit, and the NEXT client can register on this
               core immediately - nulling afterwards wiped THAT
               registration, leaving the poller idle forever while the
               new client spun on a page nobody polled. Reproduced by
               running test/transport twice back to back: the second
               run reported "no poller answered the first probe". */
            unsafe { ENGINE_PAGES[core] = PhysAddr::null(); }
            args.lock.store(0, Ordering::Release);
            return LOOP_CLEAR;
        }

        if call_id as u64 == BULK_MEMCPY {
            // Handled entirely inside the monitor: one client round trip
            // regardless of size, N monitor-to-service exchanges.
            let err = bulk_memcpy(core, args, service);
            args.data[0..4].copy_from_slice(&err.to_le_bytes());
            args.lock.store(0, Ordering::Release);
            if err == RELAY_TIMEOUT_ERR {
                // Same treatment as the single-call path: without this
                // the next ordinary call pays another full timeout.
                drop_service(core);
                service_phys = PhysAddr::null();
                service_mapping = None;
            }
            continue;
        }

        if let Some((req_len, resp_len)) = forward_spec(call_id, &args.data) {
            match service {
                Some(service) => {
                    service.data[..req_len].copy_from_slice(&args.data[..req_len]);
                    if !forward_call_bounded(service, call_id, slow_call_bound(call_id)) {
                        /* Fail this call back to the client and drop
                           the dead service, rather than spinning here
                           forever with the CPU (and, on the legacy
                           path, the guest) held hostage. */
                        args.data[0..4].copy_from_slice(&RELAY_TIMEOUT_ERR.to_le_bytes());
                        args.lock.store(0, Ordering::Release);
                        drop_service(core);
                        service_phys = PhysAddr::null();
                        service_mapping = None;
                        continue;
                    }
                    args.data[..resp_len].copy_from_slice(&service.data[..resp_len]);
                    /* The service just registered more heap chunk(s):
                       map the delta into this core's trustlet before
                       the client sees the new size. The trustlet is
                       spinning on this comm page right now, so its
                       page table only GAINS entries - safe without a
                       TLB shootdown (x86 does not cache not-present).
                       Guest clients map the heap themselves. */
                    if call_id as u64 == HEAP_GROW
                        && unsafe { ENGINE_IS_TRUSTLET[core] } {
                        let (dir, npages) = heap_for(core);
                        let done = unsafe { HEAP_MAPPED[core] } as usize;
                        if dir != PhysAddr::null() && npages > done {
                            let cr3 = unsafe { ENGINE_PAGE_TABLE[core] };
                            let mapped = map_heap_range(cr3, dir, done, npages);
                            unsafe { HEAP_MAPPED[core] = (done + mapped) as u64; }
                            if done + mapped != npages {
                                /* Partial: report the size that IS
                                   mapped so the client never touches
                                   unmapped heap. */
                                let usable = ((done + mapped) * 4096) as u64;
                                args.data[0..8].copy_from_slice(&usable.to_le_bytes());
                                log::warn!("heap grow: mapped {}/{} for core {}",
                                           done + mapped, npages, core);
                            }
                        }
                    }
                }
                None => {
                    // No service registered: fail the call with
                    // cudaErrorSystemNotReady (802) instead of pretending
                    // it succeeded.
                    args.data[..resp_len].fill(0);
                    args.data[0..4].copy_from_slice(&802i32.to_le_bytes());
                }
            }
        }

        args.lock.store(0, Ordering::Release);
    }
}

/// GpuRun statuses returned in rcx (mirrored by GPU_RUN_* in libwallet
/// memory.h): 0 = session over, exit; 1 = yield budget expired, the
/// guest kernel loop services pending IPIs and re-enters.
const GPU_RUN_SESSION_OVER: u64 = 0;
const GPU_RUN_YIELD: u64 = 1;
/// Garbage-rdx guard (an old vmpl.ko that predates the budget field
/// sends stack garbage): budgets above 10 s are clamped, not honored.
const MAX_YIELD_BUDGET_US: u64 = 10_000_000;

/// Parked-thread path (GpuRun): the client thread pinned to the polling
/// core enters here. With yield budget 0 (rdx) this is the unbounded
/// "parked" mode, kept for A/B: the call only returns on the client's
/// stop message. With a budget it is the "bounded" mode: the call also
/// returns GPU_RUN_YIELD every ~budget us so the vCPU can ack IPIs in
/// the guest kernel's re-entry loop (vmpl.c) - which is what removes
/// the parked-online-CPU TLB-shootdown hazard.
pub fn run(params: &mut RequestParams) -> Result<(), MonitorError> {
    use crate::utils::tsc::{rdtsc, ticks_for_micros};

    let id = get_apic_id() as usize;

    /* Input registers - read before rcx doubles as the status output:
       rcx = 0 on first entry / 1 on re-entry (set by the kernel loop),
       rdx = yield budget in us (0 = never yield). */
    let first_entry = params.rcx == 0;
    let budget_us = params.rdx.min(MAX_YIELD_BUDGET_US);

    let engine_page = unsafe {ENGINE_PAGES[id]};

    if first_entry {
        log::warn!("Monitor polling on {:#x?} on thread {} (yield budget {} us)",
                   engine_page, id, budget_us);
    }
    /* Defined status, like register_service: this handler used to leave
       rcx untouched, and the guest wrapper never initialised it, so
       gpu_run returned uninitialised stack to userspace. */
    params.rcx = GPU_RUN_SESSION_OVER;
    if engine_page == PhysAddr::null() {
        /* On a re-entry a vanished registration is the normal end of a
           session (stop consumed on an earlier entry), not an error. */
        if first_entry {
            log::warn!("No engine found");
        }
        return Ok(())
    }

    let deadline = if budget_us == 0 {
        None
    } else {
        /* saturating_add, not forward_call's wrapping_add: a saturated
           huge budget must clamp to "never", not invert into "always
           expired". */
        Some(rdtsc().saturating_add(ticks_for_micros(budget_us)))
    };
    /* Namespace trap: LOOP_EXIT == 1 == GPU_RUN_YIELD. Map explicitly,
       never hand poll_engine's raw return to the guest. */
    if poll_engine(id, None, deadline) == crate::exclusive::LOOP_YIELD {
        params.rcx = GPU_RUN_YIELD;
    }
    Ok(())

}

/// cudaMemcpy payload travels inline after a 32-byte request header.
/// Bulk memcpy id, outside the cudart enumeration like the cuBLAS
/// range. One of these replaces ceil(count/4056) per-chunk calls.
pub const BULK_MEMCPY: u64 = 700;
/// Windowed memcpy (approach B): the payload travels through a staging
/// window the service donated and the monitor mapped into the client at
/// registration time. The comm page only carries a 28-byte descriptor
/// per windowful; the monitor copies nothing.
pub const WINDOW_MEMCPY: u64 = 701;
/// Shared-heap ids: grow request (relayed to the service, which
/// allocates and registers another chunk; the monitor then maps the
/// delta into the requesting trustlet) and heap memcpy (payload named
/// by heap offset, nobody copies).
pub const HEAP_GROW: u64 = 702;
pub const HEAP_MEMCPY: u64 = 703;
const MEMCPY_ID: u32 = 121;
const PAGE_SIZE: usize = 4096;
const MEMCPY_HDR: usize = 32;
const MEMCPY_MAX_PAYLOAD: usize = COMM_DATA_SIZE - MEMCPY_HDR;

const MEMCPY_HOST_TO_DEVICE: i32 = 1;
const MEMCPY_DEVICE_TO_HOST: i32 = 2;

/// Registration control messages (fatbin transfer + kernel lookup),
/// relayed as full pages: startup-only, not performance sensitive.
const CTRL_FIRST: u64 = 501; // FATBIN_INIT
const CTRL_LAST: u64 = 504; // REGISTER_FUNC

/// cuBLAS forwarding (1.4b): ids 600+ are reserved outside the cudart
/// enumeration; layouts shared with redirect/filter.py and
/// service/service.c.
const CUBLAS_CREATE: u64 = 600;
const CUBLAS_DESTROY: u64 = 601;
const CUBLAS_SET_STREAM: u64 = 602;
const CUBLAS_SET_MATH_MODE: u64 = 603;
const CUBLAS_GEMM_STRIDED_BATCHED_EX: u64 = 604;
const CUBLAS_GEMM_BATCHED_EX: u64 = 605;
const CUBLAS_GEMM_EX: u64 = 606;

/// cudaLaunchKernel: kernel params packed after a 56-byte header at the
/// driver-provided offsets; args_len is a u32 at request offset 48.
const LAUNCH_HDR: usize = 56;
const LAUNCH_MAX_ARGS: usize = COMM_DATA_SIZE - LAUNCH_HDR;

/// (request bytes, response bytes) exchanged through the data area for
/// each CUDA call the service implements; None means ack-and-drop.
/// Layouts are shared with redirect/filter.py and service/service.c.
fn forward_spec(call_id: u32, data: &[u8; COMM_DATA_SIZE]) -> Option<(usize, usize)> {
    use super::api::CudaApiCall as C;
    let id = call_id as u64;
    if id == C::CUDA_API_CALL_cudaGetDeviceCount.0 {
        // response: int32 err, int32 count
        Some((0, 8))
    } else if id == C::CUDA_API_CALL_cudaMalloc.0 {
        // request: u64 size; response: int32 err, pad, u64 device ptr
        Some((8, 16))
    } else if id == C::CUDA_API_CALL_cudaFree.0 {
        // request: u64 device ptr; response: int32 err
        Some((8, 4))
    } else if id == C::CUDA_API_CALL_cudaDeviceSynchronize.0 {
        // response: int32 err
        Some((0, 4))
    } else if id == C::CUDA_API_CALL_cudaLaunchKernel.0 {
        // request: u64 func, grid/block dims, u64 shared, u64 stream,
        // u32 args_len, then params packed at driver-provided offsets;
        // response: int32 err
        let args_len =
            u32::from_le_bytes(data[48..52].try_into().unwrap()) as usize;
        Some((LAUNCH_HDR + args_len.min(LAUNCH_MAX_ARGS), 4))
    } else if id == 505 {
        // fatbin via the shared heap: u64 heap offset + u64 size in;
        // i32 err + u32 module id back. The bytes never touch the
        // relay - the service loads the module from its own memory.
        Some((16, 8))
    } else if id == 501 {
        // fatbin init: u64 total size in; i32 err back
        Some((8, 4))
    } else if id == 502 {
        // fatbin chunk: u32 len @0 + payload @8 in; i32 err back. The
        // old full-page response echoed ~171 MB of dead bytes over a
        // llama registration (42k chunks x 4088).
        let chunk = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        Some(((8 + chunk).min(COMM_DATA_SIZE), 4))
    } else if id == 503 {
        // fatbin end: no request payload; i32 err + u32 module id back
        Some((4, 8))
    } else if id >= CTRL_FIRST && id <= CTRL_LAST {
        // kernel registration (504): variable name in, param table out
        Some((COMM_DATA_SIZE, COMM_DATA_SIZE))
    } else if id == C::CUDA_API_CALL_cudaGetDeviceProperties_v2.0 {
        // req: i32 device; resp: i32 err @0, cudaDeviceProp @8 —
        // relay the whole page rather than tracking the prop size
        Some((4, COMM_DATA_SIZE))
    } else if id == C::CUDA_API_CALL_cudaMemGetInfo.0 {
        // resp: i32 err @0, u64 free @8, u64 total @16
        Some((0, 24))
    } else if id == C::CUDA_API_CALL_cudaMemset.0 {
        // req: u64 ptr, u64 count, i32 value (Async variant reuses
        // this id client-side); resp: i32 err
        Some((20, 4))
    } else if id == C::CUDA_API_CALL_cudaFuncSetAttribute.0 {
        // req: u64 hostFun, i32 attr, i32 value; resp: i32 err
        Some((16, 4))
    } else if id == C::CUDA_API_CALL_cudaOccupancyMaxActiveBlocksPerMultiprocessorWithFlags.0 {
        // req: u64 hostFun, i32 blockSize, u64 smem @16, u32 flags @24;
        // resp: i32 err, i32 numBlocks
        Some((28, 8))
    } else if id == C::CUDA_API_CALL_cudaStreamCreateWithFlags.0 {
        // req: u32 flags; resp: i32 err @0, u64 handle @8
        Some((4, 16))
    } else if id == C::CUDA_API_CALL_cudaStreamDestroy.0
        || id == C::CUDA_API_CALL_cudaStreamSynchronize.0 {
        // req: u64 handle; resp: i32 err
        Some((8, 4))
    } else if id == C::CUDA_API_CALL_cudaStreamBeginCapture.0 {
        // req: u64 stream, u32 mode; resp: i32 err
        Some((12, 4))
    } else if id == C::CUDA_API_CALL_cudaStreamEndCapture.0
        || id == C::CUDA_API_CALL_cudaGraphInstantiate.0 {
        // req: u64 (stream / graph); resp: i32 err @0, u64 handle @8.
        // Graphs and execs are opaque u64 tokens, same convention as
        // streams and cuBLAS handles: the value is the service's own
        // pointer, meaningless to the client except as a token.
        Some((8, 16))
    } else if id == C::CUDA_API_CALL_cudaGraphExecUpdate.0 {
        // req: u64 exec, u64 graph; resp: i32 err @0, u32 result @4
        Some((16, 8))
    } else if id == C::CUDA_API_CALL_cudaGraphLaunch.0 {
        // req: u64 exec, u64 stream; resp: i32 err. The hot one: this
        // single relay replaces a whole token's kernel launches.
        Some((16, 4))
    } else if id == C::CUDA_API_CALL_cudaGraphDestroy.0
        || id == C::CUDA_API_CALL_cudaGraphExecDestroy.0 {
        // req: u64 handle; resp: i32 err
        Some((8, 4))
    } else if id == CUBLAS_CREATE {
        // resp: i32 status @0, u64 handle token @8
        Some((0, 16))
    } else if id == CUBLAS_DESTROY {
        // req: u64 handle; resp: i32 status
        Some((8, 4))
    } else if id == CUBLAS_SET_STREAM {
        // req: u64 handle, u64 stream token; resp: i32 status
        Some((16, 4))
    } else if id == CUBLAS_SET_MATH_MODE {
        // req: u64 handle, i32 mode; resp: i32 status
        Some((12, 4))
    } else if id == CUBLAS_GEMM_STRIDED_BATCHED_EX {
        // req: 144-byte fixed header (scalars + device pointers +
        // inline 16-byte alpha/beta slots); resp: i32 status
        Some((144, 4))
    } else if id == CUBLAS_GEMM_BATCHED_EX || id == CUBLAS_GEMM_EX {
        // 605: like 604 minus the strides - the batched variant's
        // Aarray/Barray/Carray are device pointers ggml built
        // on-device, plain values here. 606: the non-batched sibling,
        // same wire shape. req: 120-byte header (scalars + 3 pointers
        // + inline 16-byte alpha/beta at 88/104); resp: i32 status
        Some((120, 4))
    } else if id == HEAP_GROW {
        // req: u64 min bytes needed; resp: u64 new total heap bytes
        // (0 = grow failed). The service does the allocation and the
        // register_gpu_heap ioctl inside this call.
        Some((8, 8))
    } else if id == HEAP_MEMCPY {
        // req: u64 device ptr, u64 count, u64 heap offset, i32 kind,
        // i32 is_async @28, u64 stream token @32; resp: i32 err. Like
        // WINDOW_MEMCPY, but the payload already lives in the shared
        // heap - not even the client copies - and async copies stay
        // ordered on (or captured into) the client's stream.
        Some((40, 4))
    } else if id == WINDOW_MEMCPY {
        // req: u64 device ptr, u64 count, u64 window offset, i32 kind;
        // resp: i32 err. The payload travels through the shared staging
        // window (mapped into client and service alike), NOT the comm
        // page - this descriptor is all the monitor relays.
        Some((28, 4))
    } else if id == C::CUDA_API_CALL_cudaMemcpy.0 {
        // header: u64 dst, u64 src, u64 count, int32 kind; the payload
        // direction depends on kind. Clamped to the page capacity — the
        // client warns about the truncation (bulk transfers TBD).
        let count = u64::from_le_bytes(data[16..24].try_into().unwrap()) as usize;
        let kind = i32::from_le_bytes(data[24..28].try_into().unwrap());
        let payload = count.min(MEMCPY_MAX_PAYLOAD);
        let req = MEMCPY_HDR + if kind == MEMCPY_HOST_TO_DEVICE { payload } else { 0 };
        let resp = if kind == MEMCPY_DEVICE_TO_HOST { MEMCPY_HDR + payload } else { 4 };
        Some((req, resp))
    } else {
        None
    }
}

/// Hand a call to the service comm page and wait for its completion.
/// The request payload must already be in the service data area.
/// Bulk memcpy: one client round trip for a transfer of any size.
///
/// The client sends {dst, src_vaddr, count, kind} and does NOT copy the
/// payload anywhere. The monitor walks the client's own page table,
/// maps each source page, and feeds the service in page-sized pieces
/// without ever returning to the client. That is the point: a 1.3 GB
/// model upload was 325,710 client round trips at 4056 bytes each, and
/// the client round trip is the expensive one - it costs a VMPL switch
/// and a spin on both sides. The monitor-to-service exchanges remain,
/// but they are VMPL0 to VMPL2 with no trustlet involved.
///
/// Returns the CUDA error to hand back to the client.
fn bulk_memcpy(core: usize, args: &CommunicationPage,
               service: Option<&mut CommunicationPage>) -> i32 {
    const CUDA_ERROR_INVALID_VALUE: i32 = 1;
    const CUDA_ERROR_SYSTEM_NOT_READY: i32 = 802;

    let dst = u64::from_le_bytes(args.data[0..8].try_into().unwrap());
    let src = u64::from_le_bytes(args.data[8..16].try_into().unwrap());
    let count = u64::from_le_bytes(args.data[16..24].try_into().unwrap());
    let kind = i32::from_le_bytes(args.data[24..28].try_into().unwrap());

    let service = match service {
        Some(s) => s,
        None => return CUDA_ERROR_SYSTEM_NOT_READY,
    };

    let table = unsafe { ENGINE_PAGE_TABLE[core] };
    if table == PhysAddr::null() {
        log::warn!("bulk_memcpy: no page table registered for engine {}", core);
        return CUDA_ERROR_INVALID_VALUE;
    }
    if kind != MEMCPY_HOST_TO_DEVICE && kind != MEMCPY_DEVICE_TO_HOST {
        return CUDA_ERROR_INVALID_VALUE;
    }

    let mut page_table_ref = ProcessPageTableRef::default();
    page_table_ref.set_external_table(u64::from(table));

    /* Which side is the client's host buffer depends on direction: the
       source for H2D, the destination for D2H. Walking `src` in both
       directions means walking a DEVICE pointer for D2H, which is not
       in the client's page table - it fails with invalid-value while
       H2D quietly works. */
    let (host_base, dev_base) = if kind == MEMCPY_HOST_TO_DEVICE {
        (src, dst)
    } else {
        (dst, src)
    };

    let mut done: u64 = 0;
    let mut err: i32 = 0;
    while done < count {
        // Message size is the payload cap, NOT "to the end of this
        // page". Clamping to both meant a page-aligned buffer produced
        // an alternating 4056 + 40 pattern - two messages per page,
        // double the round trips, each paying its own page-table walk.
        // A message may therefore span two source pages, which is
        // handled by copying it in per-page pieces.
        let chunk = core::cmp::min(count - done, MEMCPY_MAX_PAYLOAD as u64) as usize;

        let dev_addr = dev_base + done;
        let host_addr = host_base + done;
        if kind == MEMCPY_HOST_TO_DEVICE {
            service.data[0..8].copy_from_slice(&dev_addr.to_le_bytes());
            service.data[8..16].copy_from_slice(&host_addr.to_le_bytes());
        } else {
            service.data[0..8].copy_from_slice(&host_addr.to_le_bytes());
            service.data[8..16].copy_from_slice(&dev_addr.to_le_bytes());
        }
        service.data[16..24].copy_from_slice(&(chunk as u64).to_le_bytes());
        service.data[24..28].copy_from_slice(&kind.to_le_bytes());

        // Gather (H2D) or scatter (D2H) across however many source
        // pages this message touches - at most two.
        let mut filled: usize = 0;
        while filled < chunk {
            let va = host_addr + filled as u64;
            let page_off = (va & 0xFFF) as usize;
            let take = core::cmp::min(PAGE_SIZE - page_off, chunk - filled);

            let phys = page_table_ref.get_page_4k_hugeaware(VirtAddr::from(va));
            if phys == PhysAddr::null() {
                log::warn!("bulk_memcpy: client vaddr {:#x} not mapped", va);
                return CUDA_ERROR_INVALID_VALUE;
            }
            let mapping = match PerCPUPageMappingGuard::create_4k(phys) {
                Ok(m) => m,
                Err(_) => return CUDA_ERROR_INVALID_VALUE,
            };
            let client_page = unsafe {
                core::slice::from_raw_parts_mut(
                    mapping.virt_addr().as_mut_ptr::<u8>(), PAGE_SIZE)
            };

            if kind == MEMCPY_HOST_TO_DEVICE {
                service.data[MEMCPY_HDR + filled..MEMCPY_HDR + filled + take]
                    .copy_from_slice(&client_page[page_off..page_off + take]);
            }
            // D2H fills the client pages after the service replies, so
            // remember nothing here; the second pass below re-walks.
            filled += take;
        }

        if !forward_call(service, MEMCPY_ID) {
            err = RELAY_TIMEOUT_ERR;
            break;
        }

        let e = i32::from_le_bytes(service.data[0..4].try_into().unwrap());
        if e != 0 {
            err = e;
            break;
        }

        if kind == MEMCPY_DEVICE_TO_HOST {
            let mut written: usize = 0;
            while written < chunk {
                let va = host_addr + written as u64;
                let page_off = (va & 0xFFF) as usize;
                let take = core::cmp::min(PAGE_SIZE - page_off, chunk - written);
                let phys = page_table_ref.get_page_4k_hugeaware(VirtAddr::from(va));
                if phys == PhysAddr::null() {
                    return CUDA_ERROR_INVALID_VALUE;
                }
                let mapping = match PerCPUPageMappingGuard::create_4k(phys) {
                    Ok(m) => m,
                    Err(_) => return CUDA_ERROR_INVALID_VALUE,
                };
                let client_page = unsafe {
                    core::slice::from_raw_parts_mut(
                        mapping.virt_addr().as_mut_ptr::<u8>(), PAGE_SIZE)
                };
                client_page[page_off..page_off + take].copy_from_slice(
                    &service.data[MEMCPY_HDR + written..MEMCPY_HDR + written + take]);
                written += take;
            }
        }

        done += chunk as u64;
    }
    err
}

/// Error handed to the client when the service does not answer within
/// FORWARD_TIMEOUT_SECS. Distinct from any CUDA error so it is
/// recognisable in a client log.
pub const RELAY_TIMEOUT_ERR: i32 = 802;
const FORWARD_TIMEOUT_SECS: u64 = 30;
/// Bound for the deferred session stop: must outlast one full
/// session_reset (2 s healthy, 30+ s with a degraded MEMLOCK limit),
/// because the ack only comes after the reset. See the deferred-stop
/// branch in poll_engine for why this is one attempt, never retried.
const DEFERRED_STOP_TIMEOUT_SECS: u64 = 120;

/// Longer bound for calls the CC-mode driver is KNOWN to stall on for
/// tens of seconds (the os_alloc_mem family, stream/module setup):
/// observed cudaStreamCreateWithFlags (38) blowing the 30 s bound
/// mid-init, killing an otherwise healthy session (802 -> llama
/// abort). The default stays 30 s so a dead service is still detected
/// fast on the hot path (memcpy/launch/sync).
const SLOW_CALL_TIMEOUT_SECS: u64 = 120;

fn slow_call_bound(call_id: u32) -> u64 {
    match call_id {
        // stream create/destroy, malloc/free family (device + host)
        37 | 38 | 47 | 93 | 94 | 97 | 98 | 101 => SLOW_CALL_TIMEOUT_SECS,
        // fatbin transfer + kernel registration (module load JITs) and
        // cuBLAS handle creation - all one-per-session setup calls
        501..=505 | 600 => SLOW_CALL_TIMEOUT_SECS,
        _ => FORWARD_TIMEOUT_SECS,
    }
}

/// Relay one call to the service. Returns false if the service did not
/// answer in time.
///
/// This spin used to be unbounded, so a wedged or killed service
/// stranded the polling CPU with no recovery but a VM reboot - and on
/// the legacy path that CPU belongs to the guest, so the whole guest
/// went with it. A bounded outer poll loop cannot help: the wait
/// happens INSIDE one iteration.
#[must_use]
fn forward_call(service: &mut CommunicationPage, call_id: u32) -> bool {
    forward_call_bounded(service, call_id, FORWARD_TIMEOUT_SECS)
}

#[must_use]
fn forward_call_bounded(service: &mut CommunicationPage, call_id: u32,
                        timeout_secs: u64) -> bool {
    use crate::utils::tsc::{rdtsc, ticks_for_secs};
    service.id.store(call_id, Ordering::Relaxed);
    service.lock.store(1, Ordering::Release);
    let deadline = rdtsc().wrapping_add(ticks_for_secs(timeout_secs));
    let mut spins: u64 = 0;
    while service.lock.load(Ordering::Acquire) != 0 {
        spins = spins.wrapping_add(1);
        /* Check the clock rarely: rdtsc is cheap but this is the
           hottest loop in the relay. */
        if spins % 4096 == 0 && rdtsc() > deadline {
            log::error!("forward_call: service did not answer id {} within {} s - \
                         failing the call and dropping the service registration",
                        call_id, timeout_secs);
            return false;
        }
    }
    true
}

/// Drop the service registration after a timeout so the poller goes
/// idle instead of re-timing-out on every subsequent call. A fresh
/// service process re-registers (register_service) and relaying
/// resumes.
fn drop_service(core: usize) {
    /* Mirror service_for()'s selection: a per-engine registration wins,
       otherwise the shared fallback was in use. Only clear the one that
       was actually being relayed to - clearing the fallback because one
       engine's private service died would cut off every other engine. */
    unsafe {
        if core < 64 && SERVICE_PAGES[core] != PhysAddr::null() {
            SERVICE_PAGES[core] = PhysAddr::null();
        } else {
            SERVICE_PAGE = PhysAddr::null();
        }
    }
}
