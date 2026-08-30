pub mod runtime;
pub mod process;
pub mod early_invoke;
pub mod invoke;
pub mod channels;
pub mod process_call_type;

use cpuarch::vmsa::VMSA;
use num_enum::TryFromPrimitive;
use crate::process_manager::process::TrustedProcess;

type ReturnTarget = bool;

pub const RETURN_TO_GUEST: ReturnTarget = false;
pub const RETURN_TO_PROCESS: ReturnTarget = true;

/// Per-invoke wall-clock budget for the watchdog. The clock starts at
/// invoke entry and stops at the trustlet's next yield/exit, so an
/// idle-parked serve instance is never on the clock - the budget
/// bounds one init or one request. Generous: 7B init is ~14 s;
/// re-check against the 20B probe before its batch.
pub const INVOKE_BUDGET_SECS: u64 = 600;


#[derive(Debug)]
pub struct ReturnValues {
    rcx: *mut u64,
    rdx: *mut u64,
    r8:  *mut u64,
    r9:  *mut u64,
}

#[allow(dead_code)]
impl ReturnValues {
    pub fn result(&self, v: u64){
        self.set_rcx(v);
    }
    pub fn set_rcx(&self, v: u64) {
        unsafe { *self.rcx = v };
    }
    pub fn set_rdx(&self, v: u64) {
        unsafe { *self.rdx = v };
    }
    pub fn set_r8(&self, v: u64) {
        unsafe { *self.r8 = v };
    }
    pub fn set_r9(&self, v: u64) {
        unsafe { *self.r9 = v };
    }
}
#[derive(Debug)]
pub struct PALContext {
    process: &'static mut TrustedProcess,
    vmsa: &'static mut VMSA,
    string_buf: [u8;256],
    string_pos: usize,
    result_addr: u64,
    result_size: u64,
    guest_page_table: u64,
    invocation_arg_guest_vaddr: u64,
    invocation_arg_size: usize,
    /// True when this process was entered from another trustlet
    /// (process/call.rs) rather than from the guest. There is no guest
    /// result buffer in that case - the answer is read straight out of
    /// the shared channel - so get_result must not copy anything out.
    nested_call: bool,
    return_values: ReturnValues,
}

impl PALContext {
    /// Mark this process dead and release the monitor resources tied
    /// to it - its GPU engine slot today. Every give-up path (exit,
    /// PAL error, unhandled fault) goes through here so a dead session
    /// never squats on a donated core.
    pub(crate) fn mark_dead(&mut self) {
        self.process.dead = true;
        if self.process.gpu_core >= 0 {
            crate::gpu::direct::free_engine_slot(self.process.gpu_core as usize);
            self.process.gpu_core = -1;
        }
    }
}

/// Detection half of the invoke watchdog, run from donated cores. The
/// in-loop budget in invoke.rs can only fire while the trustlet still
/// makes monitor calls; one spinning silently at VMPL1 never returns
/// control, and nothing can abort it from another core (PLAN.md:
/// switch_to_vmpl is blocking, mark_dead is owner-vCPU-only). This
/// turns that invisible wedge into an attributable alert.
///
/// Concurrency: dead/running/invoke_* are written only by the owning
/// vCPU inside the invoke; this scan only READS the unlocked store, so
/// the worst case is one spurious or missed log line, never a new
/// race. `relay_last_id` is the poller's last seen call id, -1 when
/// the scanning core has no relay context.
pub fn log_overbudget_invokes(scanning_core: usize, relay_last_id: i64) {
    use crate::utils::tsc::{rdtsc, ticks_for_secs, TSC_HZ};
    use crate::process_manager::PROCESS_STORE;
    use crate::process_manager::process::{ProcessID, TrustedProcessType};
    // Per-core rate limit: callers sit in poll loops, so without it a
    // stuck invoke would log every iteration instead of every ~10 s.
    use core::sync::atomic::{AtomicU64, Ordering};
    #[allow(clippy::declare_interior_mutable_const)]
    const AU64_ZERO: AtomicU64 = AtomicU64::new(0);
    static LAST_REPORT: [AtomicU64; 64] = [AU64_ZERO; 64];
    if scanning_core >= 64 {
        return;
    }
    let now = rdtsc();
    let last = LAST_REPORT[scanning_core].load(Ordering::Relaxed);
    if now.wrapping_sub(last) < ticks_for_secs(10) {
        return;
    }
    LAST_REPORT[scanning_core].store(now, Ordering::Relaxed);
    let budget = ticks_for_secs(INVOKE_BUDGET_SECS);
    for i in 0..PROCESS_STORE.len() {
        let p = PROCESS_STORE.get(ProcessID(i));
        if p.process_type != TrustedProcessType::Trustlet
            || !p.running
            || p.invoke_start_tsc == 0 {
            continue;
        }
        let elapsed = now.wrapping_sub(p.invoke_start_tsc);
        if elapsed <= budget {
            continue;
        }
        /* Best-effort VMSA peek: for a VMPL1-resident spinner the
           values are from its LAST exit, not the spin location. A
           concurrent exit+delete between the running check and here
           would read a freed page - vanishingly rare after a >600 s
           invoke, and the damage is one garbage log line. */
        let mut rip = 0u64;
        let mut rsp = 0u64;
        if p.running {
            if let Ok(m) = crate::memory::paging::PerCPUPageMappingGuard::create_4k(p.context.vmsa) {
                let vmsa: &VMSA = unsafe { &*m.virt_addr().as_ptr::<VMSA>() };
                rip = vmsa.rip;
                rsp = vmsa.rsp;
            }
        }
        log::error!("watchdog[poller {}]: trustlet {} invoke over budget \
                     (~{} s, apic {}, gpu_core {}, relay last id {}) \
                     rip {:#x} rsp {:#x} (stale-at-last-exit) - {} pcall {:#x}",
                    scanning_core, i, elapsed / TSC_HZ, p.invoke_owner_apic,
                    p.gpu_core, relay_last_id, rip, rsp,
                    if p.in_pcall { "STUCK INSIDE" } else { "silent at VMPL1 after" },
                    p.last_pcall);
    }
}

/// Return value to the guest from invokeTrustlet
#[derive(Debug,Clone,Copy,Eq,PartialEq,TryFromPrimitive)]
#[repr(u64)]
enum TrustletReturnType {
    EXIT=0,
    GETRESULT=1,
    ERROR=2,
    FILEATTR=3,
    OPEN=4,
    READ=5,
    MMAP=6,
    INFERENCEREGISTER=12,
    INFERENCE=13
}
