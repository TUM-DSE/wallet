use igvm_defs::PAGE_SIZE_4K;

use crate::process_manager::allocation::AllocationRange;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::RequestParams;
use crate::SvsmReqError;

use super::store::Store;
use super::store::StoreTrait;
use crate::{paddr_as_table, paddr_as_slice, paddr_as_u64_slice, vaddr_as_u64_slice, vaddr_as_slice, map_paddr, strip_paddr};
use crate::memory::paging::PerCPUPageMappingGuard;
use crate::my_crypto_wrapper::my_SHA512;
use crate::interop::memory::rdtsc;
use crate::process_manager::outb::capture;

#[derive(Debug)]
pub struct modelInfo {
    pub measurement: [u8; 64],
    pub data: AllocationRange,
    pub real_size: u64,
    pub state: bool,
}

impl StoreTrait for modelInfo {
    fn empty() -> Self {
        Self {
            state: true,
            data: AllocationRange(0,0),
            real_size: 0,
            measurement: [0; 64],
        }
    }
    fn is_empty(&self) -> bool {
        return self.state;
    }
    fn set_empty(&mut self) {
        self.state = true;
    }

    fn cmp(&self, index: [u8; 64]) -> bool {
        self.measurement == index
    }
}

pub static MODEL_STORE: Store<modelInfo> = Store::<modelInfo>::new();
pub static LORA_STORE: Store<modelInfo> = Store::<modelInfo>::new();
pub static ENGINE_STORE: Store<modelInfo> = Store::<modelInfo>::new();

fn convert(num: i64) -> u64 {
    u64::from_ne_bytes(num.to_ne_bytes())
}

fn load_init(params: &mut RequestParams) -> AllocationRange {
    //log::debug!("CYC 1: {}", rdtsc());
    capture(200);
    let size = params.rcx;
    let guest_pgt = params.rdx;
    let mut range = AllocationRange(0,0);
    let (_map, page_table) = paddr_as_slice!(guest_pgt.into());

    range.allocate_for_guest(((size + PAGE_SIZE_4K) & !PAGE_SIZE_4K) / PAGE_SIZE_4K);
    //log::debug!("CYC 2: {}", rdtsc());
    capture(201);
    range.guest_write_access();
    //log::debug!("CYC 3: {}", rdtsc());
    capture(202);
    page_table[1] = range.0;

    return range;
}

fn load_fin(params: &mut RequestParams, store: &Store<modelInfo>) {
    //log::debug!("CYC 4: {}", rdtsc());
    capture(203);
    let guest_pgt = params.rdx;
    let store_id = params.rcx;
    let (_map, page_table) = paddr_as_slice!(guest_pgt.into());
    let e = store.get(store_id.try_into().unwrap());

    e.data.mount();
    //log::debug!("CYC 5: {}", rdtsc());
    capture(204);
    e.data.guest_remove_write_access();
    //log::debug!("CYC 6: {}", rdtsc());
    capture(205);
    page_table[1] = 0;
    let region = unsafe {
        core::slice::from_raw_parts(0x30000000000u64 as *const u8,  e.real_size as usize)
    };
    log::debug!("[Measure] Region address {:p} and len { }", region, region.len());

    let mut hash: [u8; 64] = [0; 64];
    unsafe {
        my_SHA512(
            region.as_ptr() as *mut u8,
            region.len().try_into().unwrap(),
            e.measurement.as_mut_ptr(),
        );
    }
    //log::debug!("CYC 7: {}", rdtsc());
    capture(206);
    e.data.unmount();
    log::debug!("{:x?}", e);
    params.rcx = 0;
}

pub fn delete(params: &mut RequestParams, store: &Store<modelInfo>) -> Result<(), SvsmReqError> {
    let store_id = params.rcx;

    log::debug!("Removing entry from store");
    let e = store.get(store_id.try_into().unwrap());
    e.data.delete();
    e.state = false;
    e.data.0 = 0;
    e.data.1 = 0;
    e.real_size = 0;
    log::debug!("Removed entry from store");
    return Ok(())
}

pub fn model_load_init(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let range = load_init(params);

    let m = modelInfo {
        measurement: [0; 64],
        data: range,
        real_size: params.rcx,
        state: false,
    };
    let num = MODEL_STORE.insert(m);
    params.rcx = convert(num);
    Ok(())
}

pub fn model_load_data(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    load_fin(params, &MODEL_STORE);
    Ok(())
}

pub fn model_delete(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    delete(params, &MODEL_STORE)
}

pub fn lora_load_init(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let range = load_init(params);

    let l = modelInfo {
        measurement: [0; 64],
        data: range,
        real_size: params.rcx,
        state: false,
    };
    params.rcx = convert(LORA_STORE.insert(l));
    Ok(())
}

pub fn lora_load_data(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    load_fin(params, &LORA_STORE);
    Ok(())
}

pub fn lora_delete(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    delete(params, &LORA_STORE)
}

pub fn engine_load_init(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let range = load_init(params);

    let e = modelInfo {
        measurement: [0; 64],
        data: range,
        real_size: params.rcx,
        state: false,
    };
    params.rcx = convert(ENGINE_STORE.insert(e));
    Ok(())
}

pub fn engine_load_data(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    load_fin(params, &ENGINE_STORE);
    Ok(())
}

pub fn engine_delete(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    delete(params, &ENGINE_STORE)
}
