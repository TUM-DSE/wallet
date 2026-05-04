#[allow(unused_imports)]
use crate::{address::PhysAddr, memory::paging::PerCPUPageMappingGuard, process_manager::{outb::capture, process_paging::ProcessPageTableRef}, MonitorError, RequestParams};

mod api;
pub mod direct;


pub fn handle_api_call(_params: &mut RequestParams) -> Result<(), MonitorError> {
    return Ok(());
    /*
    //capture(10);
    let api_id = params.rcx;
    let api_arg_size: u64 = params.rdx;
    let api_arg_addr = params.r8;
    //capture(11);
    //return Ok(());
    //let guest_page = params.r9;

    let arg_mapping = PerCPUPageMappingGuard::create_4k(PhysAddr::from(api_arg_addr)).unwrap();

    //let args = unsafe {
    //    core::slice::from_raw_parts(arg_mapping.virt_addr().as_mut_ptr::<u8>(), api_arg_size.try_into().unwrap())
    //};
    let args: *mut u8 = arg_mapping.virt_addr().as_mut_ptr::<u8>();

    match_id_to_func(args, api_arg_size, api_id);

    let slice = unsafe { core::slice::from_raw_parts(args, api_arg_size.try_into().unwrap()) } ;
    let vec = slice.to_vec();

    let src_ptr = vec.as_ptr();
    unsafe {core::ptr::copy(src_ptr, args, api_arg_size.try_into().unwrap());};
    //capture(11);
    Ok(())*/
}

#[allow(unused)]
fn match_id_to_func(args: *mut u8, size: u64, id: u64){
    //TODO: Check allocation/Limit size
    if api::CudaApiCall::CUDA_API_CALL_cudaMallocManaged.0 >= id &&
        api::CudaApiCall::CUDA_API_CALL_cudaMallocArray.0 <= id {

    }

}
