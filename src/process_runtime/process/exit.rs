use crate::process_runtime::{ReturnTarget, RETURN_TO_GUEST};
use crate::process_manager::outb::breakdown_outb;
use crate::process_runtime::TrustletReturnType;
use core::ffi::CStr;
use crate::address::VirtAddr;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::map_paddr;
use crate::memory::paging::PerCPUPageMappingGuard;

use super::super::PALContext;

pub trait ProcessRuntimeExit {
    fn pal_svsm_fail(&mut self) -> ReturnTarget;
    fn pal_svsm_exit(&mut self) -> ReturnTarget;
    fn pal_svsm_get_result(&mut self) -> ReturnTarget;
    fn pal_svsm_call_exit(&mut self) -> ReturnTarget;
}

impl ProcessRuntimeExit for PALContext {
    /// Handle a PAL error
    ///
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFF)
    /// * rbx: error string address
    /// * rcx: error number
    ///
    /// Return:
    /// * no return to the trustlet (exit the trustlet)
    fn pal_svsm_fail(&mut self) -> ReturnTarget{
        // PAL reports error, exit the trustlet

        let page_table = self.vmsa.cr3;
        let string = self.vmsa.rbx;
        let errno = self.vmsa.rcx;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        let string_address = string & !0xFFF;
        let string_phys_address = page_table_ref.get_page(VirtAddr::from(string_address));
        let (_mapping, string_mapping) = map_paddr!(string_phys_address);
        let c_string: *const i8 = unsafe {{ string_mapping.as_ptr::<i8>() }.offset((string & 0xFFF).try_into().unwrap())};
        let s = unsafe { CStr::from_ptr(c_string) };

        log::info!(" [Trustlet] PAL Error: {} {}",s.to_str().unwrap(), errno);
        RETURN_TO_GUEST
    }
    /// Exit the trustlet
    ///
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFE)
    /// * rbx: exit code
    ///
    /// Return:
    /// * no return to the trustlet (exit the trustlet)
    fn pal_svsm_exit(&mut self) -> ReturnTarget{
        // PAL exits, exit the trustlet
        let exit_code = self.vmsa.rbx;
        log::info!(" [Trustlet] Exit with Status Code: {}", exit_code);
        self.return_values.result(TrustletReturnType::EXIT as u64);
        RETURN_TO_GUEST
    }

        /// Inidicated that results are ready
    ///
    /// Return:
    /// Sets the trustlet return value to 0
    /// Copies the reuslts into the provided buffer
    fn pal_svsm_get_result(&mut self) -> ReturnTarget {
        breakdown_outb(220);
        self.process.context.channel.copy_out(
            self.result_addr,
            self.guest_page_table,
            self.result_size as usize);
        self.return_values.result(TrustletReturnType::GETRESULT as u64);
        #[cfg(not(feature = "boottime"))]
        {
        breakdown_outb(192);
        self.process.measurements.output_data = self.process.context.channel.measure_output();
        breakdown_outb(193);
        }
        breakdown_outb(221);

        #[cfg(feature="stat")]
        {
            let page_table = self.vmsa.cr3;
            let mut page_table_ref = ProcessPageTableRef::default();
            page_table_ref.set_external_table(page_table);
            page_table_ref.mem_stat();
        }

        RETURN_TO_GUEST
    }

    fn pal_svsm_call_exit(&mut self) -> ReturnTarget {
        RETURN_TO_GUEST
    }
}
