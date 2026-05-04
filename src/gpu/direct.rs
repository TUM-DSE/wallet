
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

#[repr(C)]
#[derive(Debug)]
pub struct CommunicationPage {
    pub lock: AtomicU8,
    pub data: [u8;4091],
    pub id: AtomicU32,//u32,
}

static mut ENGINE_PAGES: [PhysAddr; 64] = [PhysAddr::null(); 64];

static mut ENGINE_PAGE_TABLE: [PhysAddr; 64] = [PhysAddr::null(); 64];

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

    let mut counter: u64 = 0;
    loop {
        let valid_call = args.lock.load(Ordering::Relaxed);
        //log::warn!("Sizeof:  {}", core::mem::size_of::<CommunicationPage>());
        //log::warn!("{}", counter);
        counter = counter.wrapping_add(1);
        if valid_call != 0 {
            let call_id = args.id.load(Ordering::Relaxed);
            if call_id == 500 {
                log::warn!("Stop polling");
                args.lock.store(0, Ordering::Relaxed);
                break;
            }
            log::warn!("Call received, {}", call_id);
            //log::warn!("{:?}", args);
            args.lock.store(0, Ordering::Relaxed);
        }
        if counter == 1000 {
            //counter = 0;
            //break;
        }
    }
    Ok(())

}
