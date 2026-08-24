extern crate alloc;
use crate::{map_paddr, paddr_as_slice, process_manager::process::{ProcessID, PROCESS_STORE}, MonitorError};
use crate::RequestParams;
use crate::memory::paging::PerCPUPageMappingGuard;
use super::process_call_type::ProcessCallType;

use crate::vaddr_as_slice;

use super::PALContext;

#[cfg(feature = "stat")]
use core::sync::atomic;

#[no_mangle]
pub static TRUSTLET_VMPL: u64 = 1;
use super::process::print::ProcessRuntimePrint;
use super::process::exception::ProcessRuntimeException;
use super::process::memory::ProcessRuntimeMemory;
use super::process::misc::ProcessRuntimeMisc;
use super::process::channel::ProcessRuntimeChannel;
use super::process::fin::ProcessRuntimeFin;
use super::process::exit::ProcessRuntimeExit;
use super::process::request::ProcessRuntimeGuestRequest;
use super::process::inference::ProcessRuntimeInference;
use super::process::gpu::ProcessRuntimeGpu;
use super::process::model::ProcessRuntimeModel;
use super::process::call::ProcessRuntimeCall;
pub use super::early_invoke::early_invoke;
pub use super::invoke::invoke_trustlet;

pub trait ProcessRuntime:
    ProcessRuntimePrint +
    ProcessRuntimeException +
    ProcessRuntimeMemory +
    ProcessRuntimeMisc +
    ProcessRuntimeChannel +
    ProcessRuntimeFin +
    ProcessRuntimeExit +
    ProcessRuntimeGuestRequest +
    ProcessRuntimeInference +
    ProcessRuntimeGpu +
    ProcessRuntimeModel {
    fn handle_process_request(&mut self) -> bool;
}

impl ProcessRuntime for PALContext  {

    /// Handle request from the trustlet
    /// 
    /// CPUID instructions in a trustlet (VMPL1) results in control being passed to the SVSM
    /// We use this mechanism to implement monitor-call from the trustlet
    /// We use some part of (unused) cpuid leaf range for monitor calls
    /// Otherwise treat it as normal cpuid request and return the result
    /// 
    /// Monitor call arguments are passed in the trustlet's registers
    /// * rax: Monitor call code / cpuid leaf
    /// * others: arguments to the monitor call (depends on the call)
    fn handle_process_request(&mut self) -> bool {
        let vmsa = &mut self.vmsa;
        let rax = vmsa.rax;
        let rip = vmsa.rip;
        // Advance the trustlet's rip for the next execution (cpuid instruction is 2 bytes)
        vmsa.rip += 2;
        match ProcessCallType(rax) {
            // monitor calls from the Gramine PAL
            ProcessCallType::Fail => {
                return self.pal_svsm_fail();
            }
            ProcessCallType::Exit => {
                return self.pal_svsm_exit();
            }
            ProcessCallType::DebugPrint => {
                return self.pal_svsm_debug_print();
            }
            ProcessCallType::VirtAlloc => {
                return self.pal_svsm_virt_alloc();
            }
            ProcessCallType::Map => {
                return self.pal_svsm_map();
            }
            ProcessCallType::SetTcb => {
                return self.pal_svsm_set_tcb();
            }
            ProcessCallType::Mprotect => {
                return self.pal_svsm_mprotect();
            }
            ProcessCallType::GetResult => {
                return self.pal_svsm_get_result();
            }
            ProcessCallType::GuestRequest => {
                return self.pal_svsm_guest_request();
            }
            ProcessCallType::VirtFree => {
                return self.pal_svsm_virt_free();
            }
            ProcessCallType::Nop => {
                return self.pal_nop();
            }
            ProcessCallType::Finalize => {
                return self.pal_svsm_finalize();
            }

            ProcessCallType::Inference => {
                return self.pal_inference();
            }

            ProcessCallType::GpuChannel => {
                return self.pal_svsm_gpu_channel();
            }

            ProcessCallType::CallTrustlet => {
                return self.pal_call_trustlet();
            }

            ProcessCallType::ModelChannel => {
                return self.pal_svsm_model_channel();
            }

            // monitor calls (other)
            ProcessCallType::Exception => {
                return self.handle_exception();
            }
            ProcessCallType::HandleDf => {
                return self.handle_df();
            }
            // Trustlet exit calls
            ProcessCallType::CallOutb => {
                return self.pal_svsm_call_outb();
            }
            ProcessCallType::CallExit => {
                return self.pal_svsm_call_exit();
            }
            ProcessCallType::CallOutbWithValue => {
                return self.pal_svsm_call_outb_with_value();
            }
            ProcessCallType::CallInflateChannel => {
                return self.pal_svsm_inflate_channel();
            }
            // debug
            ProcessCallType::TbrDebug => {
                let c = vmsa.rbx;
                log::info!("{}", c);

                let     c_str = core::char::from_digit(c as u32, 10).unwrap();
                log::info!("{}",c_str);
                return true
            }
            ProcessCallType::TbrDebugPrint => {
                return self.pal_svsm_print_info();
            }
            _ => {
                // Regular CPUID
                if (rax <= 0x24) || (0x80000000 <= rax && rax <= 0x80000021){
                    return self.pal_svsm_cpuid();
                }

                log::info!("Unknown request code: {} (rip={:x})", rax, rip);
                let rbx = vmsa.rbx;
                log::info!("rbx {:?}", rbx);
                log::info!("vmsa CS: {:?}", self.vmsa.cs);
                return false;
            }

        }
       
    }

}

pub fn infer_call(params: &mut RequestParams) -> Result<(), MonitorError> {
    let tid = params.rcx;
    let guest_pgt = params.rdx;
    let trustlet = PROCESS_STORE.get(ProcessID(tid.try_into().unwrap()));

    let (_map, page_table) = paddr_as_slice!(guest_pgt.into());
    trustlet.infer_context.guest_write_access();
    page_table[1] = trustlet.infer_context.0;

    Ok(())
}

pub fn infer_call_ret(params: &mut RequestParams) -> Result<(), MonitorError> {
    let tid = params.rcx;
    let guest_pgt = params.rdx;
    let trustlet = PROCESS_STORE.get(ProcessID(tid.try_into().unwrap()));

    let (_map, page_table) = paddr_as_slice!(guest_pgt.into());
    trustlet.infer_context.guest_remove_write_access();
    page_table[1] = 0;

    Ok(())
}
