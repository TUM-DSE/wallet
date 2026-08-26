use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::address::VirtAddr;
use crate::process_runtime::ReturnTarget;
use crate::process_runtime::RETURN_TO_GUEST;
use crate::process_runtime::RETURN_TO_PROCESS;
use crate::address::Address;
use igvm_defs::PAGE_SIZE_4K;
use num_enum::TryFromPrimitive;
use crate::map_paddr;
use crate::memory::paging::PerCPUPageMappingGuard;

use super::super::TrustletReturnType;
use super::super::PALContext;

/// Guest request type from the trustlet (PAL)
#[derive(Debug,Clone,Copy,Eq,PartialEq,TryFromPrimitive)]
#[repr(u64)]
enum PalSvsmGuestRequestType {
    FILEATTR=0,
    OPEN=1,
    READ=2,
}

pub trait ProcessRuntimeGuestRequest {
    fn pal_svsm_guest_request(&mut self) -> ReturnTarget;
}

impl ProcessRuntimeGuestRequest for PALContext {
    /// Make a guest request
    ///
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFF7)
    /// * rbx: request type
    /// * rcx: additional data (pointer to the trustlet's data)
    /// * rdx: data size
    ///
    /// Retrun:
    /// This function does not return to the trustle but return to the guest.
    /// The guest will call another invokeTruslet() after completing the request.
    fn pal_svsm_guest_request(&mut self) -> ReturnTarget {
        /* rbx, rcx and rdx are all trustlet-chosen: the unwrap and both
           asserts below were monitor panics (the whole VM), reachable
           by any trustlet passing an unknown request type or an
           oversized length. Refuse in rcx and resume the trustlet. */
        let request_type: PalSvsmGuestRequestType = match self.vmsa.rbx.try_into() {
            Ok(t) => t,
            Err(_) => {
                let rbx = self.vmsa.rbx;
                log::warn!("guest_request: invalid request type {}", rbx);
                self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
                return RETURN_TO_PROCESS;
            }
        };
        let data_ptr = self.vmsa.rcx;
        let data_size = self.vmsa.rdx as usize;
        if data_size > self.invocation_arg_size {
            log::warn!("guest_request: data size {} exceeds invocation arg size {}",
                       data_size, self.invocation_arg_size);
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }

        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        // Map user provided arguments
        // FIXME: for now we assume that the data is within a single page
        let data_page = page_table_ref.get_page(VirtAddr::from(data_ptr));
        let offset = (data_ptr & 0xFFF) as usize;
        /* An unmapped trustlet vaddr yields phys 0, which map_paddr
           happily maps (guest page 0). Check before mapping, and bound
           the copy to the page WITHOUT the overflow the old assert
           could not survive. */
        if data_page.is_null() || data_size > PAGE_SIZE_4K as usize
            || offset + data_size > PAGE_SIZE_4K as usize {
            log::warn!("guest_request: data {:#x} size {} crosses a page or is unmapped",
                       data_ptr, data_size);
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }
        let (_mapping, data_mapping) = map_paddr!(data_page);
        let data = unsafe { core::slice::from_raw_parts(data_mapping.as_ptr::<u8>().wrapping_add(offset), data_size) };

        // copy the path into the guest arg struct
        let mut guest_page_table_ref = ProcessPageTableRef::default();
        guest_page_table_ref.set_external_table(self.guest_page_table);
        let arg_page = guest_page_table_ref.get_page(VirtAddr::from(self.invocation_arg_guest_vaddr));
        let (_mapping, arg_mapping) = map_paddr!(arg_page);
        let arg = unsafe { core::slice::from_raw_parts_mut(arg_mapping.as_mut_ptr::<u8>(), self.invocation_arg_size) };
        for i in 0..data_size {
            arg[i] = data[i];
        }


        self.return_values.result(
            match request_type {
                PalSvsmGuestRequestType::FILEATTR => {
                    TrustletReturnType::FILEATTR as u64
                }
                PalSvsmGuestRequestType::OPEN => {
                    TrustletReturnType::OPEN as u64
                }
                PalSvsmGuestRequestType::READ => {
                    TrustletReturnType::READ as u64
                }
        });
        RETURN_TO_GUEST
    }


}
