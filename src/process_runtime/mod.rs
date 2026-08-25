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
