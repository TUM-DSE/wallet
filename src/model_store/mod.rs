pub mod store;
pub mod model;
pub mod lora;
pub mod engine;
pub mod stream;

pub use store::*;

use igvm_defs::PAGE_SIZE_4K;
use crate::attestation::monitor::measure;
use crate::process_manager::allocation::AllocationRange;
use crate::RequestParams;
use crate::MonitorError;

use crate::{paddr_as_slice, vaddr_as_slice, map_paddr};
use crate::memory::paging::PerCPUPageMappingGuard;
use crate::process_manager::outb::capture;

pub static MODEL_STORE: Store<StoreEntry> = Store::<StoreEntry>::new();
pub static LORA_STORE: Store<StoreEntry> = Store::<StoreEntry>::new();
pub static ENGINE_STORE: Store<StoreEntry> = Store::<StoreEntry>::new();

fn convert(num: i64) -> u64 {
    u64::from_ne_bytes(num.to_ne_bytes())
}

/* Guest-supplied store ids and PGD slots index straight into a Vec
   and a [u64;512]; unchecked, either is a monitor panic (which kills
   the VM, not just the caller). Each op keeps its OWN failure signal
   rather than the negative STATUS_* classes: the guest decodes
   get/get_undo as `rcx_out > 0`, so a negative value there would read
   as a huge successful size. See lib/guest/wallet/src/store.c. */
fn store_id_ok(store_id: u64, store: &Store<StoreEntry>) -> bool {
    if (store_id as usize) < store.len() {
        return true;
    }
    log::warn!("store: id {} out of range", store_id);
    false
}

fn pgd_idx_ok(idx: u64) -> bool {
    if idx < 512 {
        return true;
    }
    log::warn!("store: guest PGD slot {} out of range", idx);
    false
}

fn load_init(params: &mut RequestParams) -> AllocationRange {
    capture(200);
    let size = params.rcx;
    let guest_pgd = params.rdx;

    log::debug!("load_init: Size: {:x?}, Guest PGD: {:x?}", size, guest_pgd);

    if size == 0 {
        log::warn!("Zero sized allocation requested!");
        return AllocationRange(0,0);
    }

    /* size is entirely guest-chosen and drives a per-page allocation
       loop; without this the bump allocator walked past its region and
       pvalidate panicked. Leave one page of slack for the mapping
       structures the allocation itself needs. */
    let pages = size.div_ceil(PAGE_SIZE_4K);
    let available = crate::process_manager::process_memory::pages_available();
    if pages + 1 >= available {
        log::warn!("load_init: {} pages requested, {} available", pages, available);
        return AllocationRange(0,0);
    }

    let mut range = AllocationRange(0,0);
    let (_map, page_table) = paddr_as_slice!(guest_pgd.into());

    log::debug!("Allocating page for guest");
    /* Streaming load: pay only the INITIAL chunk here - the donated
       worker (or the eager fallback in stream::update) grows the
       window behind the guest's download. The pages_available check
       above still covers the FULL size, so exhaustion fails early as
       before. The guest PGD entry below is the subtree ROOT and never
       changes as the range grows in place. */
    let initial = core::cmp::min(pages, stream::INITIAL_PAGES);
    range.allocate_for_guest(initial);
    log::debug!("Allocation successful");

    capture(201);
    range.guest_write_access();
    //log::debug!("CYC 3: {}", rdtsc());
    capture(202);
    page_table[1] = range.0;
    stream::begin(&range, size);

    /* Slot 6 was needed only for guest_write_access()'s VA pass above;
       the guest writes the model bytes through its OWN PGD slot 1, and
       load_fin re-mounts via e.data.mount(). Leaving it mounted was
       the guaranteed leak feeding the stale-slot adoption corruption
       (PLAN.md F2/F3). */
    range.unmount();

    return range;
}

fn load_fin(params: &mut RequestParams, store: &Store<StoreEntry>) -> bool{
    capture(203);
    let guest_pgd = params.rdx;
    let store_id = params.rcx;

    log::debug!("load_fin: StoreID: {:x?}, Guest PGD: {:x?}", store_id, guest_pgd);

    if !store_id_ok(store_id, store) {
        params.rcx = 1;
        return false;
    }
    let (_map, page_table) = paddr_as_slice!(guest_pgd.into());
    let e = store.get(store_id.try_into().unwrap());
    if e.state {
        log::warn!("Attempting to finilize empty store entry");
        params.rcx = 1;
        return false;
    }
    /* The entry recorded load_init's INITIAL page count; the stream
       worker (or eager fallback) has grown the range since. fin can
       only run after a COMPLETE download, and the download cannot
       outrun the allocation watermark, so the grown count covers the
       whole model - the revoke walk and the legacy-measure fallback
       below depend on that invariant. */
    if stream::is_active() {
        e.data.1 = core::cmp::max(e.data.1, stream::final_pages());
    }
    e.data.mount();

    capture(204);

    e.data.guest_remove_write_access();

    capture(205);

    // Reset guest page table
    page_table[1] = 0;

    let region = unsafe {
        core::slice::from_raw_parts(0x30000000000u64 as *const u8,  e.real_size as usize)
    };

    log::debug!("[Measure] Region address {:p} and len { }", region, region.len());

    /* Streamed digest when the worker finished; otherwise the legacy
       synchronous hash (no worker claimed, worker timed out, or a
       non-hacl build). stream::finish() logs the hash_ms/alloc_ms/
       wall_ms split either way - the benchmark lanes scrape it. */
    e.measurement = stream::finish()
        .unwrap_or_else(|| measure(0x30000000000u64, e.real_size));

    capture(206);
    e.data.unmount();

    log::debug!("Resulting store entry: \n{:#x?}\n", e);

    params.rcx = 0;
    return true;
}

pub fn delete(params: &mut RequestParams, store: &Store<StoreEntry>) -> Result<(), MonitorError> {
    let store_id = params.rcx;

    log::debug!("Removing: {store_id} from store");

    if !store_id_ok(store_id, store) {
        params.rcx = 1;
        return Ok(())
    }
    let e = store.get(store_id.try_into().unwrap());
    if e.state{
        log::warn!("Attempting to delete empty store entry");
        params.rcx = 1;
        return Ok(())
    }
    e.data.delete();
    e.set_empty();
    e.real_size = 0;
    e.measurement = [0; 64];

    log::debug!("Removed entry from store");

    return Ok(())
}

pub fn get(params: &mut RequestParams, store: &Store<StoreEntry>) -> Result<(), MonitorError>{
    let store_id = params.rcx;
    let guest_pgd = params.rdx;
    let guest_pgd_idx: usize = params.r8.try_into().unwrap();

    log::debug!("Mapping: {store_id} from store");

    if !store_id_ok(store_id, store) || !pgd_idx_ok(params.r8) {
        params.rcx = 0;
        return Ok(())
    }
    let e = store.get(store_id.try_into().unwrap());
    if e.state{
        log::warn!("Attempting to map empty store entry");
        params.rcx = 0;
        return Ok(())
    }
    let (_map, page_table) = paddr_as_slice!(guest_pgd.into());
    page_table[guest_pgd_idx] = e.data.0;

    params.rcx = e.real_size;

    Ok(())
}

pub fn get_undo(params: &mut RequestParams, store: &Store<StoreEntry>) -> Result<(), MonitorError>{
    let store_id = params.rcx;
    let guest_pgd = params.rdx;
    let guest_pgd_idx: usize = params.r8.try_into().unwrap();

    log::debug!("Removing mapping: {store_id} from store");

    if !store_id_ok(store_id, store) || !pgd_idx_ok(params.r8) {
        params.rcx = 0;
        return Ok(())
    }
    let e = store.get(store_id.try_into().unwrap());
    if e.state{
        log::warn!("Attempting to remove mapping to empty store entry");
        params.rcx = 0;
        return Ok(())
    }
    let (_map, page_table) = paddr_as_slice!(guest_pgd.into());
    /* Copy-paste bug until 2026-08-25: this wrote e.data.0 (the same
       entry `get` installs), so "undo" RE-mapped the store instead of
       unmapping it. Clear the slot. */
    page_table[guest_pgd_idx] = 0;
    params.rcx = e.real_size;

    Ok(())
}
