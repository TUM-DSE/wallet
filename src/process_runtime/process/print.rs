use crate::address::VirtAddr;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::map_paddr;
use crate::memory::paging::PerCPUPageMappingGuard;
use crate::process_runtime::{ReturnTarget, RETURN_TO_PROCESS};
use igvm_defs::PAGE_SIZE_4K;

use super::super::PALContext;


pub trait ProcessRuntimePrint {
    fn pal_svsm_debug_print(&mut self) -> ReturnTarget;
    fn pal_svsm_print_info(&mut self) -> ReturnTarget;
}


impl ProcessRuntimePrint for PALContext {
    /// Print debug message from the trustlet
    ///
    /// This function expects that the trustlet calls this function with each character,
    /// and the final character is 0
    ///
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFD)
    /// * rbx: character to print
    ///
    /// Return:
    /// * no return value
    fn pal_svsm_debug_print(&mut self) -> ReturnTarget {
        let c = self.vmsa.rbx;
        if self.string_pos < 255{
            self.string_buf[self.string_pos] = c as u8;
            self.string_pos += 1;
        } else {
            log::info!("Trustlet Debug Message to long");
            /* The bytes come from the trustlet: from_utf8().unwrap()
               panicked the monitor (and with it the whole VM) on any
               non-UTF-8 byte a trustlet chose to print. */
            log::info!(" [Trustlet](partial) {}",
                       str::from_utf8(&self.string_buf).unwrap_or("<non-utf8>"));
            self.string_pos = 0;
            self.string_buf = [0;256];
        }
        if c == 0 {
            log::info!(" [Trustlet] {}",
                       str::from_utf8(&self.string_buf).unwrap_or("<non-utf8>"));
            self.string_pos = 0;
            self.string_buf = [0;256];
        }
        RETURN_TO_PROCESS
    }

    fn pal_svsm_print_info(&mut self) -> ReturnTarget {
        let addr = self.vmsa.rbx;
        let len = self.vmsa.rcx;
        //let print_vmsa = if self.vmsa.rdx == 0 { false } else { true };

        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        let addr_start = addr & !0xFFF;
        let paddr = page_table_ref.get_page(VirtAddr::from(addr_start));
        let (_mapping, addr_mapping) = map_paddr!(paddr);
        let content: *const u8 = unsafe {{ addr_mapping.as_ptr::<u8>() }.offset((addr & 0xFFF).try_into().unwrap())};
        let slice = unsafe {core::slice::from_raw_parts(content, len as usize)};

        if addr + len > addr_start + PAGE_SIZE_4K {
            log::info!("Unable to print -- Not within page");
        }
        if len % 8 != 0 {
            log::info!("Unable to print -- len not multiple of 8")
        }
        let mut i:usize = 0;
        while i != (len as usize){

            log::info!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                       slice[i],
                       slice[i+1],
                       slice[i+2],
                       slice[i+3],
                       slice[i+4],
                       slice[i+5],
                       slice[i+6],
                       slice[i+7]
            );
            i = i + 8;

        }
        //log::info!(" [Trustlet] PAL Error: {} {}",s.to_str().unwrap(), errno);
        let rdx = self.vmsa.rdx;
        log::info!("RDX: {:#x}", rdx);

        RETURN_TO_PROCESS
    }
}
