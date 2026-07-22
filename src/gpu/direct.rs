
use crate::{memory::paging::PerCPUPageMappingGuard, MonitorError, RequestParams};
use core::sync::atomic::{AtomicU8, AtomicU32};
use core::sync::atomic::Ordering;
use crate::address::PhysAddr;
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

static mut ENGINE_PAGE_TABLE: [PhysAddr; 64] = [PhysAddr::null(); 64];

static mut SERVICE_PAGE: PhysAddr = PhysAddr::null();

pub fn register_service(params: &mut RequestParams) -> Result<(), MonitorError> {
    let comm_page = params.rcx;
    log::warn!("GPU service registration: {:#x?}", comm_page);
    unsafe {
        SERVICE_PAGE = PhysAddr::from(comm_page);
    };
    Ok(())
}

pub fn register_engine(params: &mut RequestParams) -> Result<(), MonitorError> {
    //let engine_page =
    // Args:
    //  shared page phys address
    //  page table pyhs address
    //let a: CommunicationPage = CommunicationPage {lock: 0.into(), data: 0};
    let page_table = params.rdx;
    let comm_page = params.rcx;
    log::warn!("Registraton: {:#x?} {:#x?}", page_table, comm_page);

    let id = get_apic_id() as usize;
    unsafe {
        ENGINE_PAGE_TABLE[id] = PhysAddr::from(page_table);
        ENGINE_PAGES[id] = PhysAddr::from(comm_page);
    };

    Ok(())
}

pub fn run(_params: &mut RequestParams) -> Result<(), MonitorError> {

    let id = get_apic_id() as usize;

    let engine_page = unsafe {ENGINE_PAGES[id]};

    log::warn!("Monitor polling on {:#x?} on thread {}", engine_page, id);
    if engine_page == PhysAddr::null() {
        log::warn!("No engine found");
        let mut counter: u64 = 0;
        loop{ counter = counter.wrapping_add(1); log::warn!("Failed {}", counter); if counter == 10000 { break;} }
        return Ok(())
        //return Err(MonitorError::invalid_params());
    }

    let arg_mapping = PerCPUPageMappingGuard::create_4k(PhysAddr::from(engine_page)).unwrap();

    let args_ptr: *mut CommunicationPage = arg_mapping.virt_addr().as_mut_ptr::<CommunicationPage>();

    let args = unsafe {&mut *args_ptr};

    // The service page is mapped lazily on first use so the service may
    // register after the client has already parked this CPU in the loop.
    let mut service_mapping: Option<PerCPUPageMappingGuard> = None;

    loop {
        let valid_call = args.lock.load(Ordering::Acquire);
        if valid_call != 0 {
            let call_id = args.id.load(Ordering::Relaxed);

            if service_mapping.is_none() {
                let service_page = unsafe { SERVICE_PAGE };
                if service_page != PhysAddr::null() {
                    service_mapping = Some(PerCPUPageMappingGuard::create_4k(service_page).unwrap());
                }
            }
            let service: Option<&mut CommunicationPage> = service_mapping.as_ref().map(|m| {
                let ptr: *mut CommunicationPage = m.virt_addr().as_mut_ptr::<CommunicationPage>();
                unsafe { &mut *ptr }
            });

            if call_id == 500 {
                if let Some(service) = service {
                    forward_call(service, call_id);
                }
                args.lock.store(0, Ordering::Release);
                break;
            }

            if let Some((req_len, resp_len)) = forward_spec(call_id, &args.data) {
                match service {
                    Some(service) => {
                        service.data[..req_len].copy_from_slice(&args.data[..req_len]);
                        forward_call(service, call_id);
                        args.data[..resp_len].copy_from_slice(&service.data[..resp_len]);
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
    Ok(())

}

/// cudaMemcpy payload travels inline after a 32-byte request header.
const MEMCPY_HDR: usize = 32;
const MEMCPY_MAX_PAYLOAD: usize = COMM_DATA_SIZE - MEMCPY_HDR;

const MEMCPY_HOST_TO_DEVICE: i32 = 1;
const MEMCPY_DEVICE_TO_HOST: i32 = 2;

/// Registration control messages (fatbin transfer + kernel lookup),
/// relayed as full pages: startup-only, not performance sensitive.
const CTRL_FIRST: u64 = 501; // FATBIN_INIT
const CTRL_LAST: u64 = 504; // REGISTER_FUNC

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
    } else if id >= CTRL_FIRST && id <= CTRL_LAST {
        // registration control messages: full data-area relay both ways
        Some((COMM_DATA_SIZE, COMM_DATA_SIZE))
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
fn forward_call(service: &mut CommunicationPage, call_id: u32) {
    service.id.store(call_id, Ordering::Relaxed);
    service.lock.store(1, Ordering::Release);
    while service.lock.load(Ordering::Acquire) != 0 {}
}
