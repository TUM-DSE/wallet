use cpuarch::vmsa::VMSA;
use crate::address::PhysAddr;
use crate::process_manager::process_memory::{PGD, addr_to_idx};
use crate::process_manager::memory_channels::{INPUT_VADDR, OUTPUT_VADDR};
use crate::memory::paging::PerCPUPageMappingGuard;
use crate::process_manager::process::ProcessID;
use crate::process_manager::PROCESS_STORE;
use crate::MonitorError;
use crate::RequestParams;
use crate::vaddr_as_u64_slice;

pub fn create_channel(params: &mut RequestParams) -> Result<(), MonitorError> {
    let tid1 = params.rcx;
    let tid2 = params.rdx;

    log::info!("Creating Channel: tid={} tid={}", tid1, tid2);

    // map tid1's output channel to tid2's input channel

    let trustlet1 = PROCESS_STORE.get(ProcessID(tid1.try_into().unwrap()));
    let trustlet2 = PROCESS_STORE.get(ProcessID(tid2.try_into().unwrap()));

    let trustlet1_vmsa_paddr = trustlet1.context.vmsa;
    let trustlet1_vmsa_mapping = PerCPUPageMappingGuard::create_4k(trustlet1_vmsa_paddr).unwrap();
    let trustlet1_vmsa: &mut VMSA = unsafe { trustlet1_vmsa_mapping.virt_addr().as_mut_ptr::<VMSA>().as_mut().unwrap() };
    let trustlet1_cr3 = trustlet1_vmsa.cr3;
    let trustlet1_cr3_mapping = PerCPUPageMappingGuard::create_4k(PhysAddr::from(trustlet1_cr3)).unwrap();
    let trustlet1_pgd_table = vaddr_as_u64_slice!(trustlet1_cr3_mapping.virt_addr());
    let trustlet1_output_channel_pgd_idx = addr_to_idx(OUTPUT_VADDR as usize, PGD);

    let trustlet2_vmsa_paddr = trustlet2.context.vmsa;
    let trustlet2_vmsa_mapping = PerCPUPageMappingGuard::create_4k(trustlet2_vmsa_paddr).unwrap();
    let trustlet2_vmsa: &mut VMSA = unsafe { trustlet2_vmsa_mapping.virt_addr().as_mut_ptr::<VMSA>().as_mut().unwrap() };
    let trustlet2_cr3 = trustlet2_vmsa.cr3;
    let trustlet2_cr3_mapping = PerCPUPageMappingGuard::create_4k(PhysAddr::from(trustlet2_cr3)).unwrap();
    let trustlet2_pgd_table = vaddr_as_u64_slice!(trustlet2_cr3_mapping.virt_addr());
    let trustlet2_input_channel_pgd_idx = addr_to_idx(INPUT_VADDR as usize, PGD);

    log::info!("trustlet1_output_channel_pgd_idx: 0x{:x}", trustlet1_output_channel_pgd_idx);
    log::info!("trustlet2_input_channel_pgd_idx: 0x{:x}", trustlet2_input_channel_pgd_idx);

    // Update trustlet2's pgd entry
    //  Trustlet1 CR3 -> PGD [OUTPUT_VADDR] -> <PUD A> -> ...
    //  Trustlet2 CR3 -> PGD [INPUT_VADDR]  -> <PUD B> -> ...
    // change trustlet2's PGD entry of INPUT_VADDR to point to trustlet1's output channel
    //  Trustlet2 CR3 -> PGD [INPUT_VADDR]  -> <PUD A> -> ...
    let target_entry = trustlet1_pgd_table[trustlet1_output_channel_pgd_idx];
    trustlet2_pgd_table[trustlet2_input_channel_pgd_idx] = target_entry;

    trustlet2.context.channel.input = trustlet1.context.channel.output;
    /* Slot 5 now aliases trustlet1's output subtree - teardown must
       not walk it (F4). Trustlet2's ORIGINAL input subtree is orphaned
       here (pre-existing TODO below); it is trustlet2-owned, so a
       future fix can free it at this point. */
    trustlet2.context.channel.input_borrowed = true;

    // Record where trustlet1's output leads. This is the routing the
    // inference call uses: a trustlet asks for inference and the monitor
    // sends it to whichever trustlet the guest linked it to at
    // deployment time - the guest decides who may call whom, and never
    // sees the payload.
    trustlet1.context.channel.next = Some(ProcessID(tid2.try_into().unwrap()));
    trustlet1.context.channel.last_in_channel = false;

    // TODO: free trustlet2's old input channel pages

    Ok(())
}
