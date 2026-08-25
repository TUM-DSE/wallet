use crate::process_runtime::ReturnValues;
use crate::process_runtime::TrustedProcess;
use crate::memory::paging::PerCPUPageMappingGuard;
use cpuarch::vmsa::VMSA;
use crate::interop::ap::register_guest_vmsa;
use crate::interop::ap::switch_to_vmpl;

use super::PALContext;
use super::runtime::ProcessRuntime;
use super::runtime::TRUSTLET_VMPL;

pub fn early_invoke(zygote: &'static mut TrustedProcess) {
        //let zygote = PROCESS_STORE.get(ProcessID(id.try_into().unwrap()));

    let vmsa_paddr = zygote.context.vmsa;
    let vmsa_mapping = PerCPUPageMappingGuard::create_4k(zygote.context.vmsa).unwrap();
    log::debug!("VMSA Mapping: {:x?}", vmsa_mapping.vaddr);
    let vmsa: &mut VMSA = unsafe { vmsa_mapping.virt_addr().as_mut_ptr::<VMSA>().as_mut().unwrap() };
    let string_buf: [u8;256] = [0;256];
    let string_pos: usize = 0;
    let sev_features = zygote.context.sev_features;
    log::debug!("Setting up features");
    //let apic_id = this_cpu().get_apic_id();

    let mut rc = PALContext{
        process: zygote,
        vmsa,
        string_buf,
        string_pos,
        // Only required for Trustlet
        result_addr: 0,
        result_size: 0,
        guest_page_table: 0,
        invocation_arg_guest_vaddr: 0,
        invocation_arg_size: 0,
        nested_call: false,
        return_values: ReturnValues{
            rcx: core::ptr::null_mut(),
            rdx: core::ptr::null_mut(),
            r8:  core::ptr::null_mut(),
            r9:  core::ptr::null_mut()},
    };

    //_ = register_guest_vmsa(vmsa_paddr, TRUSTLET_VMPL, sev_features);
    log::info!("Successfully called PALContext");
    /* F5 instrumentation: which page is being registered, so it can
       be matched against the RECYCLED log above. */
    log::warn!("[vmsa] registering {:#x} (vmpl {})", u64::from(vmsa_paddr), TRUSTLET_VMPL);
    let ok = register_guest_vmsa(vmsa_paddr, TRUSTLET_VMPL, sev_features);
    log::info!("register_guest_vmsa(vmpl={}, sev_features={:x}) -> {}",
               TRUSTLET_VMPL, sev_features, ok);
    if !ok {
        panic!("register_guest_vmsa failed");
    }

    loop {
        _ = switch_to_vmpl(TRUSTLET_VMPL);
        let rip = rc.vmsa.rip;
        let rax = rc.vmsa.rax;
        let exit = rc.vmsa.guest_exit_code;
        //log::info!("trustlet exit: rip={:x} rax={:x} exit={:x?}", rip, rax, exit);
        if !rc.handle_process_request(){
            break;
        }
    }

}
