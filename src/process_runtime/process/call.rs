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
    ///        -3 call depth exceeded, -4 cycle detected, -5 callee
    ///        over watchdog budget (marked dead)
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
        let status = run_nested(self, callee_id);
        self.vmsa.rcx = u64::from_ne_bytes(status.to_ne_bytes());
        RETURN_TO_PROCESS
    }
}

/// Run `callee_id` to its next yield and come back here. Shared by the
/// explicit call_trustlet process call and by the inference call, which
/// resolves its callee from the channel link instead of an argument.
///
/// Returns 0, or a negative status: -1 unknown/!trustlet callee,
/// -2 self-call, -3 depth exceeded, -4 cycle, -5 callee ran past the
/// invoke watchdog budget (callee marked dead).
pub fn run_nested(ctx: &mut PALContext, callee_id: u64) -> i64 {
    {
        let caller_id = ctx.process.id;

        if callee_id == caller_id {
            return -2;
        }
        if callee_id as usize >= PROCESS_STORE.len() {
            log::warn!("call_trustlet: id {} out of range", callee_id);
            return -1;
        }

        let callee = PROCESS_STORE.get(ProcessID(callee_id as usize));
        if callee.process_type != TrustedProcessType::Trustlet {
            log::warn!("call_trustlet: {} is not a trustlet", callee_id);
            return -1;
        }
        if callee.dead {
            /* Same contract as invoke_trustlet: an exited/faulted
               callee cannot be resumed. */
            log::warn!("call_trustlet: {} has exited or faulted", callee_id);
            return -1;
        }
        if callee.running {
            /* A concurrent caller (another vCPU) is inside this
               callee - two vCPUs on one VMSA is undefined behavior.
               The CALL_STACK cycle check only covers this vCPU. */
            log::warn!("call_trustlet: {} is already running", callee_id);
            return -1;
        }

        let depth = unsafe { CALL_DEPTH };
        if depth >= MAX_CALL_DEPTH {
            log::warn!("call_trustlet: depth {} exceeded", depth);
            return -3;
        }
        for i in 0..depth as usize {
            if unsafe { CALL_STACK[i] } == callee_id {
                log::warn!("call_trustlet: cycle back into {}", callee_id);
                return -4;
            }
        }

        let callee_vmsa_paddr = callee.context.vmsa;
        let callee_sev_features = callee.context.sev_features;
        let caller_vmsa_paddr = ctx.process.context.vmsa;
        let caller_sev_features = ctx.process.context.sev_features;

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
            return -1;
        }

        /* Same loop invoke_trustlet runs, one level down - including
           its watchdog budget, with the callee's own clock. It ends
           when the callee yields (get_result) or exits. */
        let budget = crate::utils::tsc::ticks_for_secs(
            crate::process_runtime::INVOKE_BUDGET_SECS);
        let nstart = crate::utils::tsc::rdtsc();
        let mut status: i64 = 0;
        callee_ctx.process.invoke_owner_apic = crate::exclusive::get_apic_id();
        callee_ctx.process.invoke_start_tsc = nstart;
        callee_ctx.process.running = true;
        loop {
            switch_to_vmpl(TRUSTLET_VMPL);
            let cont = callee_ctx.handle_process_request();
            callee_ctx.process.in_pcall = false;
            if !cont {
                break;
            }
            if crate::utils::tsc::rdtsc().wrapping_sub(nstart) > budget {
                /* VMSA fields are unaligned - copy before formatting. */
                let rip = callee_ctx.vmsa.rip;
                let rsp = callee_ctx.vmsa.rsp;
                log::error!("invoke watchdog: nested callee {} over budget ({} s) \
                             - rip {:#x} rsp {:#x} - marking dead",
                            callee_id, crate::process_runtime::INVOKE_BUDGET_SECS,
                            rip, rsp);
                callee_ctx.mark_dead();
                status = -5;
                break;
            }
        }
        callee_ctx.process.running = false;
        callee_ctx.process.invoke_start_tsc = 0;
        callee_ctx.process.invoke_owner_apic = u32::MAX;

        unsafe { CALL_DEPTH = depth; }

        /* Put the caller back at VMPL1 before returning, otherwise the
           enclosing loop's switch_to_vmpl would resume the callee. */
        if !register_guest_vmsa(caller_vmsa_paddr, TRUSTLET_VMPL, caller_sev_features) {
            log::error!("call_trustlet: could not restore caller {} - cannot continue",
                        caller_id);
            panic!("call_trustlet: caller VMSA re-registration failed");
        }

        status
    }
}
