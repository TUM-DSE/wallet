use crate::process_manager::outb::outb;
use crate::interop::cpuid::CpuidResult;
use crate::interop::cpuid::cpuid_table_raw;
use crate::process_runtime::RETURN_TO_PROCESS;
use crate::process_runtime::ReturnTarget;
use super::super::PALContext;


pub trait ProcessRuntimeMisc {
    fn pal_nop(&mut self) -> ReturnTarget;
    fn pal_svsm_cpuid(&mut self) -> ReturnTarget;
    fn pal_svsm_set_tcb(&mut self) -> ReturnTarget;
    fn pal_svsm_call_outb(&mut self) -> ReturnTarget;
    fn pal_svsm_call_outb_with_value(&mut self) -> ReturnTarget;
}

impl ProcessRuntimeMisc for PALContext {
    fn pal_nop(&mut self) -> ReturnTarget {
        RETURN_TO_PROCESS
    }

    /// Handle CPUID instruction from the trustlet
    ///
    /// Register arguments:
    /// * rax: cpuid leaf
    /// * rcx: subleaf (if applicable)
    ///
    /// Return:
    /// * rax: eax value of the cpuid result
    /// * rbx: ebx value of the cpuid result
    /// * rcx: ecx value of the cpuid result
    /// * rdx: edx value of the cpuid result
    fn pal_svsm_cpuid(&mut self) -> ReturnTarget {
        let eax =  self.vmsa.rax as u32;
        //let eax_tmp = self.vmsa.rax;
        //let ecx_tmp = self.vmsa.rcx;
        // Some cpuid leafs have subleaf (ecx) and some don't
        // for the ones that don't we set ecx to 0 (otherwise CPUID table lookup fails)
        let ecx = match eax {
            4 | 7 | 0xb | 0xd | 0xf|
            0x10 | 0x12 | 0x14 | 0x17 |
            0x18 | 0x1d | 0x1e | 0x1f |
            0x24 | 0x8000001d => {
                self.vmsa.rcx as u32
            }
            _ => 0
        };

        // NOTE: we must consult the cpuid table or make explict VMGEXIT, otherwise we'll get another #VC
        let res = match cpuid_table_raw(eax, ecx, 0, 0){
            Some(r) => r,
            None => CpuidResult{eax: 0,ebx: 0, ecx: 0, edx: 0}
        };

        self.vmsa.rax = res.eax as u64;
        self.vmsa.rbx = res.ebx as u64;
        if eax == 1 {
            self.vmsa.rcx = res.ecx as u64 | 0x8000000;
        } else {
            self.vmsa.rcx = res.ecx as u64;
        }
        self.vmsa.rdx = res.edx as u64;
        RETURN_TO_PROCESS
    }

    /// Set the TCB (Thread Control Block) for the trustlet
    ///
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFA)
    /// * rbx: TCB address
    ///
    /// Return:
    /// * no return value
    fn pal_svsm_set_tcb(&mut self) -> ReturnTarget {
      let tcb = self.vmsa.rbx;
      self.vmsa.gs.base = tcb; // Set the base of the GS segment
      RETURN_TO_PROCESS
    }

    fn pal_svsm_call_outb(&mut self) -> ReturnTarget {
        outb(110);
        RETURN_TO_PROCESS
    }

    fn pal_svsm_call_outb_with_value(&mut self) -> ReturnTarget {
        let value = self.vmsa.rcx;
        outb(value);
        RETURN_TO_PROCESS
    }
}
