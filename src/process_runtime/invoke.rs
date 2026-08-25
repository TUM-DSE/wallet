use crate::process_manager::outb::breakdown_outb;
use crate::interop::ap::switch_to_vmpl;
use crate::interop::ap::register_guest_vmsa;
use crate::process_manager::process_paging::ProcessPageFlags;
use crate::process_runtime::ReturnValues;
use crate::types::PageSize;
use crate::sev::RMPFlags;
use crate::sev::rmp_adjust;
use crate::process_manager::process_memory::allocate_page;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::address::VirtAddr;
use crate::memory::paging::PerCPUPageMappingGuard;
use crate::MonitorError;
use cpuarch::vmsa::VMSA;
use igvm_defs::PAGE_SIZE_4K;
use crate::vaddr_as_u64_slice;
use crate::map_paddr;
use crate::paddr_as_slice;
use crate::RequestParams;
use crate::vaddr_as_slice;
use crate::process_manager::PROCESS_STORE;
use crate::process_manager::process::ProcessID;
use num_enum::TryFromPrimitive;

use super::PALContext;
use super::runtime::ProcessRuntime;
use super::runtime::TRUSTLET_VMPL;

/// Invocation type of invokeTrustlet
#[derive(Debug,Clone,Copy,Eq,PartialEq,TryFromPrimitive)]
#[repr(u64)]
enum TrustletInvocationType {
    NORMAL=0,
    FILEATTR=1,
    OPEN=2,
    READ=3,
    MMAP=4,
    INFERREGISTER = 5,
    INFERPROMPT = 6,
}

pub fn invoke_trustlet(params: &mut RequestParams) -> Result<(), MonitorError> {

    log::debug!("Invoking Trustlet");

    let id = params.rcx;

    /* Refuse to resume anything that cannot be resumed - out-of-range
       or unoccupied ids (the id comes from the guest; get() would
       panic the monitor), and processes marked dead by the exit and
       exception paths. Resuming an exited/faulted VMSA #GPs on garbage
       state, and before the return values were defined on those paths
       the guest would read a leftover value as a guest-request code
       and retry the dead trustlet forever, wedging the VM (observed
       2026-08-25, PLAN.md). */
    if id as usize >= PROCESS_STORE.len() {
        log::warn!("invoke_trustlet: id {} out of range", id);
        params.rcx = super::TrustletReturnType::ERROR as u64;
        return Ok(());
    }
    {
        let target = PROCESS_STORE.get(ProcessID(id as usize));
        if target.process_type != crate::process_manager::process::TrustedProcessType::Trustlet
            || target.dead {
            log::warn!("invoke_trustlet: refusing to resume trustlet {} ({})",
                       id,
                       if target.dead { "exited or faulted" } else { "not a trustlet" });
            params.rcx = super::TrustletReturnType::ERROR as u64;
            return Ok(());
        }
    }

    // Get the invoke_data given from the guest
    // The structure of the invoke_data is as follows:
    // struct data {
    //    void* ptr;
    //    uint64_t size;
    // }
    // struct invoke_data {
    //   uint64_t invocation_type;      // invoke_data_struct[0]
    //   struct data function_arg;      // invoke_data_struct[1-2]
    //   struct data result;            // invoke_data_struct[3-4]
    //   struct data guest_request_arg; // invoke_data_struct[5-6]
    //}
    let guest_data = params.r8;
    let guest_data_size = params.r9;
    let guest_page_table = params.rdx;
    breakdown_outb(210);
    let (invoke_data, range) = ProcessPageTableRef::copy_data_from_guest(guest_data, guest_data_size, guest_page_table);
    let invoke_data_struct = vaddr_as_u64_slice!(invoke_data);

    let invocation_type : TrustletInvocationType = invoke_data_struct[0].try_into().unwrap();

    let function_arg = invoke_data_struct[1];
    let function_arg_size = invoke_data_struct[2];

    let result_addr = invoke_data_struct[3];
    let result_size = invoke_data_struct[4];

    let invocation_arg_guest_vaddr = invoke_data_struct[5];
    let invocation_arg_size = invoke_data_struct[6] as usize;
    breakdown_outb(211);
    range.unmount();
    range.delete();

    let trustlet = PROCESS_STORE.get(ProcessID(id.try_into().unwrap()));

    /*log::debug!("{:x?}", trustlet.infer_context);
    let (_m, p) = paddr_as_slice!(trustlet.context.page_table_ref.process_page_table);
    log::debug!("{:x?}", p[7]);
    log::debug!("{:x?}", p[6]);
    use crate::strip_paddr;
    use crate::process_manager::memory_helper::strip_c_bit;
    let (_m2, p2) = paddr_as_slice!(strip_paddr!(p[7].into()));
    log::debug!("{:x?}", p2[0]);
    let (_m2, p2) = paddr_as_slice!(strip_paddr!(p[6].into()));
    log::debug!("{:x?}", p2[0]);

    //panic!();*/

    // Getting the current processes VMSA
    let vmsa_paddr = trustlet.context.vmsa;
    let vmsa_mapping = PerCPUPageMappingGuard::create_4k(trustlet.context.vmsa).unwrap();
    let vmsa: &mut VMSA = unsafe { vmsa_mapping.virt_addr().as_mut_ptr::<VMSA>().as_mut().unwrap() };
    let string_buf: [u8;256] = [0;256];
    let string_pos: usize = 0;
    let sev_features = trustlet.context.sev_features;

    //let apic_id = this_cpu().get_apic_id();
    breakdown_outb(212);
    match invocation_type {
        TrustletInvocationType::NORMAL => {
            // log::info!("Invoking Trustlet: Normal");
            trustlet.context.channel.inflate_input(vmsa.cr3, function_arg_size as usize);
            trustlet.context.channel.inflate_output(vmsa.cr3, result_size as usize);
            if function_arg_size > 1 {
                trustlet.context.channel.copy_into(function_arg, guest_page_table, function_arg_size as usize);
            }
            #[cfg(not(feature = "boottime"))]
            {
            breakdown_outb(190);
            trustlet.measurements.input_data = trustlet.context.channel.measure_input();
            breakdown_outb(191);
            }
            breakdown_outb(213);
        } TrustletInvocationType::FILEATTR | TrustletInvocationType::OPEN | TrustletInvocationType::READ => {
            // log::info!("Invoking Trustlet: gueset request: {:?}", invocation_type);
            let mut guest_page_table_ref = ProcessPageTableRef::default();
            guest_page_table_ref.set_external_table(guest_page_table);
            let arg_page = guest_page_table_ref.get_page(VirtAddr::from(invocation_arg_guest_vaddr));
            let (_mapping, arg_mapping) = map_paddr!(arg_page);
            let arg = unsafe { core::slice::from_raw_parts_mut(arg_mapping.as_mut_ptr::<u8>(), invocation_arg_size) };

            // Copy the request arg data from the guest to the trustlet
            let data_ptr = vmsa.rcx;
            let mut page_table_ref = ProcessPageTableRef::default();
            page_table_ref.set_external_table(vmsa.cr3);
            let data_page = page_table_ref.get_page(VirtAddr::from(data_ptr));
            let offset = (data_ptr & 0xFFF) as usize;
            let (_mapping, data_mapping) = map_paddr!(data_page);
            assert!(offset + invocation_arg_size <= PAGE_SIZE_4K as usize, "Data size exceeds page size");
            let data = unsafe { core::slice::from_raw_parts_mut(data_mapping.as_mut_ptr::<u8>().wrapping_add(offset), invocation_arg_size) };
            //log::info!("invocation_arg_size: {}", invocation_arg_size);
            for i in 0..invocation_arg_size {
                data[i] = arg[i];
            }
        }
        TrustletInvocationType::MMAP => {
            // Handle page fault due to the mmap
            let mut guest_page_table_ref = ProcessPageTableRef::default();
            guest_page_table_ref.set_external_table(guest_page_table);
            let arg_page = guest_page_table_ref.get_page(VirtAddr::from(invocation_arg_guest_vaddr));
            let (_mapping, arg_mapping) = map_paddr!(arg_page);
            let arg = unsafe { core::slice::from_raw_parts_mut(arg_mapping.as_mut_ptr::<u64>(), 5) };

            // map guest provided buffer that cointains the file content for the faulting mmap
            // struct mmap_arg {
            //     uint64_t fd;
            //     uint64_t offset;
            //     uint64_t size;
            //     uint64_t addr_offset;
            //     uint64_t buf_addr;
            // }
            let buf_guest_addr = arg[4];
            let buf_page = guest_page_table_ref.get_page(VirtAddr::from(buf_guest_addr));
            let (_mapping, buf_mapping) = map_paddr!(buf_page);
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_mapping.as_mut_ptr::<u64>(), 512) };

            // allocate new physical page for the trustlet
            let mut page_table_ref = ProcessPageTableRef::default();
            page_table_ref.set_external_table(vmsa.cr3);
            let new_page = allocate_page();
            let (mapping, new_page_mapped) = paddr_as_slice!(new_page);
            rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX , PageSize::Regular).unwrap();
            // copy data from the guest buffer to the new page
            for i in 0..512 {
               new_page_mapped[i] = buf[i];
            }
            assert!(trustlet.pf_target_vaddr != 0);
            let dst = VirtAddr::from(trustlet.pf_target_vaddr);
            // update trustlet's page table
            let flags = ProcessPageFlags::FLAG_REUSE;
            page_table_ref.map_4k_page(dst, new_page, flags);
            log::info!("Mapped new page for the trustlet at 0x{:x}", trustlet.pf_target_vaddr);
        }
        TrustletInvocationType::INFERREGISTER | TrustletInvocationType::INFERPROMPT => {
            let mut guest_page_table_ref = ProcessPageTableRef::default();
            guest_page_table_ref.set_external_table(guest_page_table);
            let arg_page = guest_page_table_ref.get_page(VirtAddr::from(invocation_arg_guest_vaddr));
            let (_mapping, arg_mapping) = map_paddr!(arg_page);
            let arg: u64 = unsafe { *arg_mapping.as_ptr::<u64>() };
            log::debug!("\n\n\nINFER REGISTER/PROMPT : {}\n\n\n", arg);

            vmsa.rdx = arg;
        }

    }

    let mut rc = PALContext{
            process: trustlet,
            vmsa,
            string_buf,
            string_pos,
            result_addr,
            result_size,
            guest_page_table,
            invocation_arg_guest_vaddr,
            invocation_arg_size,
            nested_call: false,
            return_values:
                ReturnValues {
                    rcx: &mut params.rcx,
                    rdx: &mut params.rdx,
                    r8:  &mut params.r8,
                    r9:  &mut params.r9,
                }
                //TrustletReturnType::ERROR as u64,
        };

    // Execution loop of the trustlet
    // Currently the trustlet runs to completion

    _ = register_guest_vmsa(vmsa_paddr, TRUSTLET_VMPL, sev_features);

    loop {
        switch_to_vmpl(TRUSTLET_VMPL);
        if !rc.handle_process_request() {
            break;
        }
    }
    //params.rcx = rc.return_value;
    breakdown_outb(214);
    Ok(())
}
