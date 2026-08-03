use crate::address::PhysAddr;
use crate::memory::paging::PerCPUPageMappingGuard;
use crate::model_store::MODEL_STORE;
use crate::process_manager::memory_helper::strip_c_bit;
use crate::process_runtime::ReturnTarget;
use crate::process_runtime::RETURN_TO_PROCESS;
use crate::{map_paddr, paddr_as_slice, strip_paddr, vaddr_as_slice};

use super::super::PALContext;

/// Where the model store maps in the trustlet address space: one whole
/// PML4 slot, like the guest's model_get (guest uses slot 1 / VA
/// 0x80_0000_0000, which for a trustlet collides with Gramine's PAL
/// range). Slot 8 is free: 0-2 are PAL/LibOS/trustlet code, 5-7 are
/// the INPUT/GPU/OUTPUT/INFERENCE channels.
pub const MODEL_CHANNEL_VADDR: u64 = 0x400_0000_0000u64;
const MODEL_CHANNEL_PML4_IDX: usize = (MODEL_CHANNEL_VADDR >> 39) as usize;

pub trait ProcessRuntimeModel {
    fn pal_svsm_model_channel(&mut self) -> ReturnTarget;
}

impl ProcessRuntimeModel for PALContext {
    /// Map a model-store entry read-only into the trustlet
    /// (memredirect's MEM:<id> path; the trustlet-side equivalent of
    /// the guest's model_get monitor call).
    ///
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFF1)
    /// * rbx: model store id
    ///
    /// Return:
    /// * rcx: model size in bytes; 0 if the id is out of range or the
    ///        slot is empty
    /// * rdx: the VA the model is mapped at (MODEL_CHANNEL_VADDR)
    ///
    /// The store entry's whole subtree hangs off one page-table entry
    /// (data.0), so the mapping is a single PML4-slot write into the
    /// trustlet's page table plus an RMP pass granting VMPL1 read on
    /// the data pages (~1 rmpadjust per 4 KiB; one-time, at first
    /// model open). The pages stay VMPL0-owned and guest-readable —
    /// nothing is copied.
    fn pal_svsm_model_channel(&mut self) -> ReturnTarget {
        let id = self.vmsa.rbx as usize;
        self.vmsa.rdx = MODEL_CHANNEL_VADDR;

        if id >= MODEL_STORE.len() {
            log::warn!("model_channel: id {} out of range", id);
            self.vmsa.rcx = 0;
            return RETURN_TO_PROCESS;
        }
        let e = MODEL_STORE.get(id);
        if e.state {
            log::warn!("model_channel: store slot {} is empty (model_load first)", id);
            self.vmsa.rcx = 0;
            return RETURN_TO_PROCESS;
        }

        e.data.trustlet_read_access();

        let page_table = self.vmsa.cr3;
        let (_mapping, pml4) = paddr_as_slice!(strip_paddr!(PhysAddr::from(page_table)));
        pml4[MODEL_CHANNEL_PML4_IDX] = e.data.0;

        log::info!("model_channel: model {} ({} bytes) mapped at {:#x}",
                   id, e.real_size, MODEL_CHANNEL_VADDR);
        self.vmsa.rcx = e.real_size;
        RETURN_TO_PROCESS
    }
}
