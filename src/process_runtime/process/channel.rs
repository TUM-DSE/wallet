use crate::process_runtime::{ReturnTarget, RETURN_TO_PROCESS};

use super::super::PALContext;

pub trait ProcessRuntimeChannel {
    fn pal_svsm_inflate_channel(&mut self) -> ReturnTarget;
}
impl ProcessRuntimeChannel for PALContext {
    fn pal_svsm_inflate_channel(&mut self) -> ReturnTarget {
        let select = self.vmsa.rcx;
        let size = self.vmsa.rdx;
        if select == 0 {
            self.process.context.channel.inflate_input(self.vmsa.cr3, size as usize);
        }
        if select == 1 {
            self.process.context.channel.inflate_output(self.vmsa.cr3, size as usize);
        }
        RETURN_TO_PROCESS
    }
}
