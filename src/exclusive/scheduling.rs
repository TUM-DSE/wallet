use core::sync::atomic::Ordering;
use core::arch::asm;
use crate::exclusive::{ControlStruct, VMSA_FEAT, VMSA_PHYS, CONTROL};
use crate::address::{Address, PhysAddr};
use crate::memory::paging::PerCPUPageMappingGuard;
use crate::{MonitorError, RequestParams};

use super::{set_next, LOOP_CLEAR, LOOP_EXIT, LOOP_SLEEP, LOOP_WAKEUP};

extern "Rust" {
    fn wallet_run_donated_vcpu(vmsa_pa: PhysAddr, features: u64, cpu: u32);
}

pub fn sleep(ctr: &mut ControlStruct) {
    ctr.hlt.store(1, Ordering::Relaxed);
    unsafe { asm!("hlt"); };
    ctr.hlt.store(0, Ordering::Relaxed);
}

pub fn wakeup(id: usize) -> u64 {
    let (vmsa_pa, features) = unsafe {
        (VMSA_PHYS[id], VMSA_FEAT[id])
    };
    if vmsa_pa.is_null() {
        log::warn!("Not running in exclusive mode");
        return 1;
    }

    let ctr_page: PhysAddr = unsafe {
        CONTROL[id]
    };
    if ctr_page.is_null() {
        log::warn!("Control area missing");
        return 1;
    }
    let ctr_mapping = PerCPUPageMappingGuard::create_4k(ctr_page).unwrap();
    let ctr_ptr: *mut ControlStruct = ctr_mapping.virt_addr().as_mut_ptr::<ControlStruct>();
    let ctr = unsafe {&mut *ctr_ptr};
    if ctr.hlt.load(Ordering::Relaxed) == 0 {
        log::warn!("Monitor thread is not asleep");
        return 1;
    }

    set_next(&mut ctr.next, LOOP_CLEAR, LOOP_WAKEUP);

    unsafe {wallet_run_donated_vcpu(vmsa_pa, features, id as u32);};
    return 0;
}

pub fn run_sleep(params: &mut RequestParams) -> Result<(), MonitorError> {
    let id: usize = params.rcx.try_into().unwrap();
    let ctr_page: PhysAddr = unsafe {
        CONTROL[id]
    };
    if ctr_page.is_null() {
        log::warn!("Control area missing");
        return Err(MonitorError::invalid_params());
    }
    let ctr_mapping = PerCPUPageMappingGuard::create_4k(ctr_page).unwrap();
    let ctr_ptr: *mut ControlStruct = ctr_mapping.virt_addr().as_mut_ptr::<ControlStruct>();
    let ctr = unsafe {&mut *ctr_ptr};
    if ctr.hlt.load(Ordering::Relaxed) == 1 {
        log::warn!("Monitor thread is already asleep");
        return Err(MonitorError::invalid_params());
    }

    set_next(&mut ctr.next, LOOP_CLEAR, LOOP_SLEEP);

    Ok(())
}

pub fn run_wakeup(params: &mut RequestParams) -> Result<(), MonitorError> {
    let id: usize = params.rcx.try_into().unwrap();
    if wakeup(id) == 0 {
        return Ok(());
    };
    return Err(MonitorError::invalid_params());
}

pub fn run_exit(params: &mut RequestParams) -> Result<(), MonitorError> {
    let id: usize = params.rcx.try_into().unwrap();

    let vmsa_pa = unsafe {
        VMSA_PHYS[id]
    };
    if vmsa_pa.is_null() {
        log::warn!("Not running in exclusive mode");
        return Err(MonitorError::invalid_params());
    }

    let ctr_page: PhysAddr = unsafe {
        CONTROL[id]
    };
    if ctr_page.is_null() {
        log::warn!("Control area missing");
        return Err(MonitorError::invalid_params());
    }
    let ctr_mapping = PerCPUPageMappingGuard::create_4k(ctr_page).unwrap();
    let ctr_ptr: *mut ControlStruct = ctr_mapping.virt_addr().as_mut_ptr::<ControlStruct>();
    let ctr = unsafe {&mut *ctr_ptr};

    set_next(&mut ctr.next, LOOP_CLEAR, LOOP_EXIT);

    if ctr.hlt.load(Ordering::Relaxed) == 0 {
    } else {
        wakeup(id);
    }
    Ok(())
}
