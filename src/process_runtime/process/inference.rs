use crate::address::VirtAddr;
use crate::interop::memory::flush_tlb_global;
use crate::interop::memory::read_cr3;
use crate::model_store::ENGINE_STORE;
use crate::model_store::LORA_STORE;
use crate::model_store::MODEL_STORE;
use crate::paddr_as_slice;
use crate::process_manager::process::ProcessID;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::map_paddr;
use crate::strip_paddr;
use crate::process_manager::memory_helper::strip_c_bit;
use crate::address::PhysAddr;
use crate::vaddr_as_slice;
use crate::process_manager::PROCESS_STORE;
use crate::process_runtime::ReturnTarget;
use crate::process_runtime::RETURN_TO_GUEST;
use crate::process_runtime::RETURN_TO_PROCESS;
use crate::MonitorError;
use crate::RequestParams;
use num_enum::TryFromPrimitive;
use crate::memory::paging::PerCPUPageMappingGuard;

use super::super::TrustletReturnType;
use super::super::PALContext;


#[derive(Debug,Clone,Copy,Eq,PartialEq,TryFromPrimitive)]
#[repr(u64)]
enum PalInferenceRequestType {
    REGISTER=0,
    INFERENCE=2,
}

pub trait ProcessRuntimeInference {
    fn pal_inference(&mut self) -> ReturnTarget;
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct InferContextData {
    pub model: [u8; 64],
    pub lora: [u8; 64],
    pub engine: [u8; 64],
    pub id: u64,
}

#[allow(dead_code)]
#[repr(C)]
pub struct InferRequestData {
    pub prompt: [u8; 0],
}

impl ProcessRuntimeInference for PALContext {
    fn pal_inference(&mut self) -> ReturnTarget {
        let request_type: PalInferenceRequestType = self.vmsa.rcx.try_into().unwrap();

        if request_type == PalInferenceRequestType::REGISTER {

            let page_table = self.vmsa.cr3;
            let mut page_table_ref = ProcessPageTableRef::default();
            page_table_ref.set_external_table(page_table);
            use crate::process_manager::memory_channels::INFERENCE_VADDR;
            let paddr = page_table_ref.get_page(VirtAddr::from(INFERENCE_VADDR));
            let (_mapping, addr_mapping) = map_paddr!(paddr);
            let data: &mut InferContextData = unsafe {addr_mapping.as_mut_ptr::<InferContextData>().as_mut().unwrap()};

            let mid = MODEL_STORE.find(data.model);
            let lid = LORA_STORE.find(data.lora);
            let eid = ENGINE_STORE.find(data.engine);

            if mid == -1 || eid == -1 {
                data.id = 0;
                self.vmsa.rdx = 0;
                log::debug!("Unable to find minimal set for Inference runtime");
                return RETURN_TO_PROCESS;
            }

            self.return_values.result(TrustletReturnType::INFERENCEREGISTER as u64);
            self.return_values.set_rdx(u64::from_ne_bytes(mid.to_ne_bytes()));
            self.return_values.set_r8(u64::from_ne_bytes(lid.to_ne_bytes()));
            self.return_values.set_r9(u64::from_ne_bytes(eid.to_ne_bytes()));


            log::debug!("{} {} {}", mid, lid, eid);

            log::debug!("{:#?}", data);
            return RETURN_TO_GUEST;
        }

        if request_type == PalInferenceRequestType::INFERENCE {
            /* VMPL1 path: if the guest linked this trustlet to an engine
               trustlet with create_channel, serve the request there and
               return straight to the caller. The prompt is already in
               the shared channel page, so nothing is copied and nothing
               crosses into VMPL2.

               This is what retires inference/manager: on the old path
               the monitor returned to the guest, which then used
               prompt_get/response_store to pull the plaintext prompt
               into a VMPL2 process and push the completion back - the
               untrusted guest saw both. */
            if let Some(engine) = self.process.context.channel.next {
                let status = super::call::run_nested(self, engine.0 as u64);
                if status != 0 {
                    log::warn!("inference: engine trustlet {} call failed: {}",
                               engine.0, status);
                }
                self.vmsa.rcx = u64::from_ne_bytes(status.to_ne_bytes());
                return RETURN_TO_PROCESS;
            }

            /* No engine linked: fall back to the guest manager. Kept so
               the guest-side path still works as a measurement baseline
               - it must not be how a trustlet gets inference done. */
            let page_table = self.vmsa.cr3;
            let mut page_table_ref = ProcessPageTableRef::default();
            page_table_ref.set_external_table(page_table);

            self.return_values.result(TrustletReturnType::INFERENCE as u64);
            self.return_values.set_rdx(self.vmsa.rdx);
            self.return_values.set_r8(self.vmsa.rbx);
            let s = self.vmsa.rbx;
            log::warn!("inference: no engine trustlet linked, falling back to                         the guest manager (prompt crosses into VMPL2);                         prompt size {}", s);

            return RETURN_TO_GUEST
        }

        return RETURN_TO_PROCESS;
    }
}

pub fn prompt_get(params: &mut RequestParams) -> Result<(), MonitorError> {
    let page_table = params.rdx;
    let process = params.rcx;
    let addr = params.r8;
    let size = params.r9;

    let trustlet = PROCESS_STORE.get(ProcessID(process.try_into().unwrap()));

    log::debug!("PromptGet: Addr: {:x}, ID: {}, Table: {:x}, Size: {}",
                addr, process, page_table, size);

    if (addr & 0x7FFFFFFFFF) != 0 {
        params.rcx = 0;
        return Err(MonitorError::invalid_params());
    }

    let idx = ((addr >> (9*3)) >> 12) & 0x1FF;
    log::debug!("Using index: {}", idx);
    let (_mapping, page_table_mapping) = paddr_as_slice!(strip_paddr!(PhysAddr::from(page_table)));
    let pgd_entry = page_table_mapping[idx as usize];

    let idx2 = 7;
    let (_mapping, pgd) = paddr_as_slice!(read_cr3());
    pgd[idx2] = pgd_entry;
    flush_tlb_global();

    trustlet.infer_context.mount();

    if trustlet.infer_context.1 * 4096 < size{
        params.rcx = 0;
        return Err(MonitorError::invalid_params());
    }

    let src = 0x30000000000u64 as *const u8;
    let dst = 0x38000000000u64 as *mut u8;

    unsafe { core::ptr::copy(src, dst, size.try_into().unwrap()) };

    params.rcx = size;

    Ok(())
}

pub fn response_store(params: &mut RequestParams) -> Result<(), MonitorError> {
    let page_table = params.rdx;
    let process = params.rcx;
    let addr = params.r8;
    let size = params.r9;

    let trustlet = PROCESS_STORE.get(ProcessID(process.try_into().unwrap()));

    log::debug!("PromptGet: Addr: {:x}, ID: {}, Table: {:x}, Size: {}",
                addr, process, page_table, size);


    if (addr & 0x7FFFFFFFFF) != 0 {
        params.rcx = 0;
        return Err(MonitorError::invalid_params());
    }

    let idx = ((addr >> (9*3)) >> 12) & 0x1FF;
    let (_mapping, page_table_mapping) = paddr_as_slice!(PhysAddr::from(page_table));
    let pgd_entry = page_table_mapping[idx as usize];

    let idx2 = 7;
    let (_mapping, pgd) = paddr_as_slice!(read_cr3());
    pgd[idx2] = pgd_entry;
    flush_tlb_global();

    trustlet.infer_context.mount();

    if trustlet.infer_context.1 * 4096 < size{
        params.rcx = 0;
        return Err(MonitorError::invalid_params());
    }

    let dst = 0x30000000000u64 as *mut u8;
    let src = 0x38000000000u64 as *const u8;

    unsafe { core::ptr::copy(src, dst, size.try_into().unwrap()) };

    params.rcx = size;

    Ok(())
}
