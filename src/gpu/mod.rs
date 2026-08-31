#[allow(unused_imports)]
use crate::{address::PhysAddr, memory::paging::PerCPUPageMappingGuard, process_manager::{outb::capture, process_paging::ProcessPageTableRef}, MonitorError, RequestParams};

pub mod api;
pub mod direct;


pub fn handle_api_call(params: &mut RequestParams) -> Result<(), MonitorError> {
    /* Per-ioctl-era data plane (call-optimization demo): map the
       caller's request page, copy the payload into monitor memory
       (to_vec, like the original per-ioctl handler did) and copy it
       back out - the marshalling every CUDA call paid before the
       comm-page relay existed. black_box pins both copies against
       release-build elision. create_4k asserts page alignment, so
       map the page base and index by the sub-page offset. A bad or
       missing address is acked without work: this path only exists
       to price the transit, never to fail a run. The copies are
       STRICTLY opt-in: only the demo id (998, what cu.so's
       CU_LEGACY_IOCTL transit sends) takes them - every other GpuApi
       caller, including the id-999 pure-transit calibration probe,
       keeps the historical no-op ack unchanged. */
    if params.rcx != 998 {
        return Ok(());
    }
    let addr = params.r8;
    let size = core::cmp::min(params.rdx as usize, 4096);
    if addr == 0 || size == 0 {
        return Ok(());
    }
    let off = (addr & 0xfff) as usize;
    let n = core::cmp::min(size, 4096 - off);
    let mapping = match PerCPUPageMappingGuard::create_4k(
        PhysAddr::from(addr & !0xfffu64)) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    let base = unsafe { mapping.virt_addr().as_mut_ptr::<u8>().add(off) };
    let guest = unsafe { core::slice::from_raw_parts_mut(base, n) };
    let staged = core::hint::black_box(guest.to_vec());
    guest.copy_from_slice(core::hint::black_box(&staged[..n]));
    core::hint::black_box(guest.as_ptr());
    Ok(())
}

#[allow(unused)]
fn match_id_to_func(args: *mut u8, size: u64, id: u64){
    //TODO: Check allocation/Limit size
    if api::CudaApiCall::CUDA_API_CALL_cudaMallocManaged.0 >= id &&
        api::CudaApiCall::CUDA_API_CALL_cudaMallocArray.0 <= id {

    }

}
