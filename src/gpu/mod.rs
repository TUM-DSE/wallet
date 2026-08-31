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
    /* Stub dispatch - the shape of the per-ioctl handler's decode
       step: read the cuda call id the client prepended, pick the
       call family the way match_id_to_func would have, and fold the
       argument words a real unmarshaller would walk. black_box plus
       the ack write below keep every step live in release builds. */
    let call_id = if n >= 4 {
        u32::from_le_bytes([staged[0], staged[1], staged[2], staged[3]])
    } else {
        0
    };
    let fold_words: usize = match call_id {
        501..=505 => 4, // fatbin/registration family: header words
        600..=699 => 8, // cuBLAS family: full descriptor
        _ => 8,         // runtime API argument pack
    };
    let mut acc: u64 = call_id as u64;
    if n > 4 {
        for chunk in staged[4..].chunks_exact(8).take(fold_words) {
            let mut w = [0u8; 8];
            w.copy_from_slice(chunk);
            acc = acc.wrapping_add(u64::from_le_bytes(w));
        }
    }
    let acc = core::hint::black_box(acc);
    guest.copy_from_slice(core::hint::black_box(&staged[..n]));
    if n >= 12 {
        /* response stub: status word + decode ack, the era response
           header shape (client reads it into scratch, never the
           comm page, so nothing real sees these bytes) */
        guest[0..4].copy_from_slice(&0u32.to_le_bytes());
        guest[4..12].copy_from_slice(&acc.to_le_bytes());
    }
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
