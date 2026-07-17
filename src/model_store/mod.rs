pub mod store;
pub mod model;
pub mod lora;
pub mod engine;

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

fn load_init(params: &mut RequestParams) -> AllocationRange {
    capture(200);
    let size = params.rcx;
    let guest_pgd = params.rdx;

    log::debug!("load_init: Size: {:x?}, Guest PGD: {:x?}", size, guest_pgd);

    if size == 0 {
        log::warn!("Zero sized allocation requested!");
        return AllocationRange(0,0);
    }

    let mut range = AllocationRange(0,0);
    let (_map, page_table) = paddr_as_slice!(guest_pgd.into());

    log::debug!("Allocating page for guest");
//    range.allocate_for_guest(((size + PAGE_SIZE_4K) & !PAGE_SIZE_4K) / PAGE_SIZE_4K);
    range.allocate_for_guest(size.div_ceil(PAGE_SIZE_4K));
    log::debug!("Allocation successful");

    capture(201);
    range.guest_write_access();
    //log::debug!("CYC 3: {}", rdtsc());
    capture(202);
    page_table[1] = range.0;

    return range;
}

fn load_fin(params: &mut RequestParams, store: &Store<StoreEntry>) -> bool{
    capture(203);
    let guest_pgd = params.rdx;
    let store_id = params.rcx;

    log::debug!("load_fin: StoreID: {:x?}, Guest PGD: {:x?}", store_id, guest_pgd);

    let (_map, page_table) = paddr_as_slice!(guest_pgd.into());
    let e = store.get(store_id.try_into().unwrap());
    if e.state {
        log::warn!("Attempting to finilize empty store entry");
        params.rcx = 1;
        return false;
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

    e.measurement =
        measure(0x30000000000u64, e.real_size);

    capture(206);
    e.data.unmount();

    log::debug!("Resulting store entry: \n{:#x?}\n", e);

    params.rcx = 0;
    return true;
}

pub fn delete(params: &mut RequestParams, store: &Store<StoreEntry>) -> Result<(), MonitorError> {
    let store_id = params.rcx;

    log::debug!("Removing: {store_id} from store");

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

    let e = store.get(store_id.try_into().unwrap());
    if e.state{
        log::warn!("Attempting to remove mapping to empty store entry");
        params.rcx = 0;
        return Ok(())
    }
    let (_map, page_table) = paddr_as_slice!(guest_pgd.into());
    page_table[guest_pgd_idx] = e.data.0;
    params.rcx = e.real_size;

    Ok(())
}
