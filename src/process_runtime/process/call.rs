use cpuarch::vmsa::VMSA;
use crate::interop::ap::register_guest_vmsa;
use crate::interop::ap::switch_to_vmpl;
use crate::memory::paging::PerCPUPageMappingGuard;
use crate::process_manager::process::ProcessID;
use crate::process_manager::process::TrustedProcessType;
use crate::process_manager::PROCESS_STORE;
use crate::process_runtime::runtime::ProcessRuntime;
use crate::process_runtime::runtime::TRUSTLET_VMPL;
use crate::process_runtime::ReturnTarget;
use crate::process_runtime::ReturnValues;
use crate::process_runtime::RETURN_TO_PROCESS;

use super::super::PALContext;

/// Nesting depth guard. A callee is free to call on to a third
/// trustlet, but unbounded recursion would exhaust the monitor stack,
/// and a cycle (A calls B calls A) would re-enter a VMSA that is
/// already running - which corrupts it. One level is what the service
/// design needs; deeper nesting is rejected loudly rather than
/// silently misbehaving.
const MAX_CALL_DEPTH: u32 = 4;
static mut CALL_DEPTH: u32 = 0;

/// Ids of the trustlets currently on the call stack, so a cycle can be
/// detected before it re-enters a running VMSA.
static mut CALL_STACK: [u64; MAX_CALL_DEPTH as usize] = [0; MAX_CALL_DEPTH as usize];

pub trait ProcessRuntimeCall {
    fn pal_call_trustlet(&mut self) -> ReturnTarget;
}

impl ProcessRuntimeCall for PALContext {
    /// Synchronous trustlet -> trustlet call.
    ///
    /// Register arguments:
    /// * rax: process call code (0x4FFFFFF0)
    /// * rbx: callee ProcessID
    ///
    /// Return:
    /// * rcx: 0 on success, -1 unknown/!trustlet callee, -2 self-call,
    ///        -3 call depth exceeded, -4 cycle detected
    ///
    /// The untrusted guest is deliberately not involved: the monitor
    /// runs the callee here, on the caller's monitor stack, and returns
    /// to the caller when the callee yields. Payload does not travel
    /// through this call at all - it goes through the memory channels
    /// that create_channel already shares between the pair, so a prompt
    /// never leaves VMPL0/VMPL1.
    ///
    /// The callee runs exactly like a guest-invoked trustlet (same
    /// handle_process_request loop); the only difference is that its
    /// get_result copies nothing out to a guest buffer, because the
    /// caller reads the answer straight out of the shared channel (see
    /// `nested_call` in exit.rs).
    fn pal_call_trustlet(&mut self) -> ReturnTarget {
        let callee_id = self.vmsa.rbx;
        let caller_id = self.process.id;

        if callee_id == caller_id {
            self.vmsa.rcx = u64::from_ne_bytes((-2i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }
        if callee_id as usize >= PROCESS_STORE.len() {
            log::warn!("call_trustlet: id {} out of range", callee_id);
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }

        let callee = PROCESS_STORE.get(ProcessID(callee_id as usize));
        if callee.process_type != TrustedProcessType::Trustlet {
            log::warn!("call_trustlet: {} is not a trustlet", callee_id);
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }

        let depth = unsafe { CALL_DEPTH };
        if depth >= MAX_CALL_DEPTH {
            log::warn!("call_trustlet: depth {} exceeded", depth);
            self.vmsa.rcx = u64::from_ne_bytes((-3i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }
        for i in 0..depth as usize {
            if unsafe { CALL_STACK[i] } == callee_id {
                log::warn!("call_trustlet: cycle back into {}", callee_id);
                self.vmsa.rcx = u64::from_ne_bytes((-4i64).to_ne_bytes());
                return RETURN_TO_PROCESS;
            }
        }

        let callee_vmsa_paddr = callee.context.vmsa;
        let callee_sev_features = callee.context.sev_features;
        let caller_vmsa_paddr = self.process.context.vmsa;
        let caller_sev_features = self.process.context.sev_features;

        let callee_mapping = PerCPUPageMappingGuard::create_4k(callee_vmsa_paddr).unwrap();
        let callee_vmsa: &mut VMSA = unsafe {
            callee_mapping.virt_addr().as_mut_ptr::<VMSA>().as_mut().unwrap()
        };

        /* The callee returns to US, not to the guest, so there is no
           guest result buffer and no guest page table in play. The
           return-value slots point at locals: callee handlers write
           them (get_result sets a result code), and nobody upstream
           reads them. */
        let mut sink: [u64; 4] = [0; 4];
        let mut callee_ctx = PALContext {
            process: callee,
            vmsa: callee_vmsa,
            string_buf: [0; 256],
            string_pos: 0,
            result_addr: 0,
            result_size: 0,
            guest_page_table: 0,
            invocation_arg_guest_vaddr: 0,
            invocation_arg_size: 0,
            nested_call: true,
            return_values: ReturnValues {
                rcx: &mut sink[0],
                rdx: &mut sink[1],
                r8: &mut sink[2],
                r9: &mut sink[3],
            },
        };

        unsafe {
            CALL_STACK[depth as usize] = callee_id;
            CALL_DEPTH = depth + 1;
        }

        log::debug!("call_trustlet: {} -> {} (depth {})", caller_id, callee_id, depth + 1);

        if !register_guest_vmsa(callee_vmsa_paddr, TRUSTLET_VMPL, callee_sev_features) {
            unsafe { CALL_DEPTH = depth; }
            log::error!("call_trustlet: register_guest_vmsa failed for {}", callee_id);
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }

        /* Same loop invoke_trustlet runs, one level down. It ends when
           the callee yields (get_result) or exits. */
        loop {
            switch_to_vmpl(TRUSTLET_VMPL);
            if !callee_ctx.handle_process_request() {
                break;
            }
        }

        unsafe { CALL_DEPTH = depth; }

        /* Put the caller back at VMPL1 before returning, otherwise the
           enclosing loop's switch_to_vmpl would resume the callee. */
        if !register_guest_vmsa(caller_vmsa_paddr, TRUSTLET_VMPL, caller_sev_features) {
            log::error!("call_trustlet: could not restore caller {} - cannot continue",
                        caller_id);
            panic!("call_trustlet: caller VMSA re-registration failed");
        }

        self.vmsa.rcx = 0;
        RETURN_TO_PROCESS
    }
}
