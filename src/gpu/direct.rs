
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
    unsafe {
        if engine < 64 {
            SERVICE_PAGES[engine] = PhysAddr::from(comm_page);
        } else {
            SERVICE_PAGE = PhysAddr::from(comm_page);
        }
    };
    Ok(())
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
    log::warn!("Registraton: {:#x?} {:#x?} core {}", page_table, comm_page, id);

    unsafe {
        ENGINE_PAGE_TABLE[id] = PhysAddr::from(page_table);
        ENGINE_PAGES[id] = PhysAddr::from(comm_page);
    };

    let donated = unsafe { crate::exclusive::CONTROL[id] } != PhysAddr::null();
    params.rcx = donated as u64;

    Ok(())
}

/// True when a client comm page is registered for `core`. Used by the
/// donated-core command loop to decide when to enter `poll_engine`.
pub fn engine_registered(core: usize) -> bool {
    core < 64 && unsafe { ENGINE_PAGES[core] } != PhysAddr::null()
}

/// Register a monitor-provisioned comm page (trustlet GPU channel) in
/// `core`'s engine slot — same slot and polling as a guest client's
/// page registered via register_engine.
pub fn register_engine_page(core: usize, page: PhysAddr) {
    unsafe { ENGINE_PAGES[core] = page; }
}

/// Poll the engine page registered for `core` and relay calls to the
/// service. Returns when the client stops (id 500) or its registration
/// disappears — return value LOOP_CLEAR — or, when `ctr` is given
/// (donated-core mode), when a LOOP_* command arrives on the control
/// page; the consumed command is returned for the caller to handle.
///
/// The registration is re-read every iteration: a new client's
/// register_engine replaces a dead client's page, so a crashed client
/// cannot wedge the poller — the next registration just remaps. The
/// service mapping likewise follows SERVICE_PAGE re-registrations.
pub fn poll_engine(core: usize, ctr: Option<&crate::exclusive::ControlStruct>) -> u64 {
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
                forward_call(service, call_id);
            }
            args.lock.store(0, Ordering::Release);
            // Session over: drop the registration so the poller goes
            // idle until the next client registers.
            unsafe { ENGINE_PAGES[core] = PhysAddr::null(); }
            return LOOP_CLEAR;
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

/// Legacy parked-thread path (GpuRun): the client thread pinned to the
/// polling core enters here and the call only returns on the client's
/// stop message. Kept for A/B comparison with donated-core polling.
pub fn run(_params: &mut RequestParams) -> Result<(), MonitorError> {

    let id = get_apic_id() as usize;

    let engine_page = unsafe {ENGINE_PAGES[id]};

    log::warn!("Monitor polling on {:#x?} on thread {}", engine_page, id);
    if engine_page == PhysAddr::null() {
        log::warn!("No engine found");
        return Ok(())
    }

    poll_engine(id, None);
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

/// cuBLAS forwarding (1.4b): ids 600+ are reserved outside the cudart
/// enumeration; layouts shared with redirect/filter.py and
/// service/service.c.
const CUBLAS_CREATE: u64 = 600;
const CUBLAS_DESTROY: u64 = 601;
const CUBLAS_SET_STREAM: u64 = 602;
const CUBLAS_SET_MATH_MODE: u64 = 603;
const CUBLAS_GEMM_STRIDED_BATCHED_EX: u64 = 604;

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
    let mut spins: u64 = 0;
    while service.lock.load(Ordering::Acquire) != 0 {
        spins = spins.wrapping_add(1);
        if spins % 4_000_000_000u64 == 0 {
            log::warn!("forward_call: still waiting on service for id {} ({}B spins)",
                       call_id, spins / 1_000_000_000);
        }
    }
}
