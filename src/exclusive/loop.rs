use core::sync::atomic::Ordering;
use crate::exclusive::scheduling::sleep;
use crate::{MonitorError, RequestParams};
use crate::process_manager::process_memory::{allocate_page, free_page};
use crate::memory::paging::PerCPUPageMappingGuard;
use crate::exclusive::{get_apic_id, ControlStruct, COM_PAGES, CONTROL, LOOP_CLEAR, LOOP_EXIT, LOOP_SLEEP, LOOP_WAKEUP, VMSA_FEAT, VMSA_PHYS};
use crate::address::PhysAddr;
use crate::types::PageSize;
use crate::sev::{rmp_adjust, RMPFlags};

extern "Rust" {
    fn wallet_get_vmsa() -> PhysAddr;
    fn wallet_get_features() -> u64;
    fn wallet_enter_guest();
}

fn enter_guest(){
    unsafe {wallet_enter_guest();};
}

pub fn run_register(_params: &mut RequestParams) -> Result<(), MonitorError> {
    Ok(())
}


pub fn run_exclusive(_params: &mut RequestParams) -> Result<(), MonitorError> {
    let id = get_apic_id() as usize;


    let ctr_page = allocate_page();
    let ctr_mapping = PerCPUPageMappingGuard::create_4k(ctr_page).unwrap();
    let ctr_ptr: *mut ControlStruct = ctr_mapping.virt_addr().as_mut_ptr::<ControlStruct>();
    let ctr = unsafe {&mut *ctr_ptr};
    ctr.next.store(LOOP_CLEAR, Ordering::Relaxed);
    ctr.hlt.store(0, Ordering::Relaxed);

    unsafe {
        CONTROL[id] = ctr_page;
    };


    let comm_page_phy = allocate_page();
    let mapping = PerCPUPageMappingGuard::create_4k(comm_page_phy).unwrap();

    let _ = rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL2 | RMPFlags::RWX, PageSize::Regular);

    //Register control struct
    unsafe {
        COM_PAGES[id] = comm_page_phy;
    }

    unsafe {
        VMSA_PHYS[id] = wallet_get_vmsa();
        VMSA_FEAT[id] = wallet_get_features();
        //log::warn!("What");
        //VMSA_FEAT[id] = wallet_get_features();
        //log::warn!("What2");
    };
    //use core::arch::asm;
    log::warn!("Reserving CPU for Monitor: {}", id);
    //unsafe { asm!("hlt"); };
    enter_guest();
    log::warn!("\n\nAfter return: {}\n\n", get_apic_id());

    //let comm_ptr: *mut u64 = mapping.virt_addr().as_mut_ptr::<u64>();
    //let comm: &mut u64 = unsafe {&mut *comm_ptr};


    loop {
        let cmd = ctr.next.swap(LOOP_CLEAR, Ordering::Relaxed);
        if cmd != LOOP_CLEAR {
            if cmd == LOOP_EXIT {
                break;
            }
            if cmd == LOOP_SLEEP {
                loop {
                    sleep(ctr);
                    let cmd = ctr.next.swap(LOOP_CLEAR, Ordering::Relaxed);
                    if cmd == LOOP_WAKEUP {
                        break;
                    }
                }
            }
            continue;
        }
    }

    unsafe {
        CONTROL[id] = PhysAddr::null();
        VMSA_PHYS[id] = PhysAddr::null();
        VMSA_FEAT[id] = 0;
    };
    free_page(ctr_page);
    Ok(())
}
