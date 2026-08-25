use super::super::PALContext;
use crate::process_runtime::{ReturnTarget, RETURN_TO_GUEST, RETURN_TO_PROCESS};
use crate::{address::VirtAddr, map_paddr, process_manager::process_paging::ProcessPageTableRef};
use crate::memory::paging::PerCPUPageMappingGuard;

use super::super::TrustletReturnType;

pub trait ProcessRuntimeException {
    fn handle_exception(&mut self) -> ReturnTarget;
    fn handle_df(&mut self) -> ReturnTarget;
}

impl ProcessRuntimeException for PALContext {
    /// Handle an exception occured in the trustlet
    // XXX: Currently this function assumes that the exception is a #PF
    fn handle_exception(&mut self) -> ReturnTarget {
        let exception = self.vmsa.rcx;
        match exception {
            13 => {
                let cr2 = self.vmsa.cr2;
                let error_code = self.vmsa.rbx;
                let rsp = self.vmsa.rsp;
                log::info!("[Trustlet] #GP: CR2=0x{:x}, error_code = {}", cr2, error_code);
                let mut process_page_table_ref = ProcessPageTableRef::default();
                process_page_table_ref.set_external_table(self.vmsa.cr3);
                // dump stack
                let stack_base_paddr = process_page_table_ref.get_page(VirtAddr::from(rsp));
                let offset = (rsp & 0xFFF) / 8;
                let (_mapping, stack_mapping) = map_paddr!(stack_base_paddr);
                for i in 0..9 {
                    log::info!("[Trustlet] Stack (rsp+{}): {:#x}", i*8, unsafe{stack_mapping.as_ptr::<u64>().offset((offset + i).try_into().unwrap()).read()});
                }
                let efer = self.vmsa.efer;
                let rip = self.vmsa.rip;
                let cr2 = self.vmsa.cr2;
                let cr4 = self.vmsa.cr4;
                let rsp = self.vmsa.rsp;
                let rflags = self.vmsa.rflags;
                let rdi = self.vmsa.rdi;
                log::info!("vmsa EFER: {:?}", efer);
                log::info!("vmsa CR2: {:?}", cr2);
                log::info!("vmsa cr4: {:?}", cr4);
                log::info!("vmsa rip: {:?}", rip);
                log::info!("vmsa CS: {:?}", self.vmsa.cs);
                log::info!("vmsa SS: {:?}", self.vmsa.ss);
                log::info!("vmsa DS: {:?}", self.vmsa.ds);
                log::info!("vmsa RFLAGS: {:?}", rflags);
                log::info!("vmsa rsp: {:?}", rsp);
                log::info!("vmsa rdi: {:?}", rdi);
                log::info!("Unhandled #GP");
                /* Give the guest a defined failure and refuse future
                   resumes. Before this, the un-set return values left
                   the guest's own input in rcx - which can alias a
                   guest-request code (3 = fileattr was observed) and
                   send the guest into an endless retry-and-#GP loop
                   that floods the console and wedges the VM. */
                self.process.dead = true;
                self.return_values.result(TrustletReturnType::ERROR as u64);
                return RETURN_TO_GUEST;
            }
            14 => {
                #[cfg(feature = "stat")]
                crate::sev::utils::stat::PF_COUNT.fetch_add(1, atomic::Ordering::Relaxed);

                let rip= self.vmsa.rip;
                let cr2 = self.vmsa.cr2;
                let error_code = self.vmsa.rbx;
                const PF_PRESENT: u64 = 1 << 0;
                const PF_WRITE: u64 = 1 << 1;
                const PF_USER: u64 = 1 << 2;
                const PF_RESERVED: u64 = 1 << 3;
                const PF_INSTRUCTION: u64 = 1 << 4;
                let mmap_manager = &self.process.mmap_manager;
                log::trace!("[Trustlet] #PF: CR2=0x{:x}", cr2);
                if let Some(mmap_info) = mmap_manager.lookup(cr2 as usize) {
                    log::trace!("Found file mapping: mmap_info={:?}", mmap_info);
                    if error_code & PF_PRESENT == 0 {
                        // non-presente page
                        log::debug!("[Trustlet] Page fault: not present page");
                        let target_page_addr = cr2 & !0xFFF;
                        self.process.pf_target_vaddr = target_page_addr;
                        assert!(target_page_addr >= mmap_info.addr as u64);
                        let addr_offset = target_page_addr - mmap_info.addr as u64;
                        assert!(addr_offset % 4096 == 0);

                        // guest arg structure:
                        // struct {
                        //   u64 fd;
                        //   u64 offset;
                        //   u64 size;
                        //   u64 addr_offset;
                        // }
                        let mut guest_page_table_ref = ProcessPageTableRef::default();
                        guest_page_table_ref.set_external_table(self.guest_page_table);
                        let arg_page = guest_page_table_ref.get_page(VirtAddr::from(self.invocation_arg_guest_vaddr));
                        let (_mapping, arg_mapping) = map_paddr!(arg_page);
                        let arg = unsafe { core::slice::from_raw_parts_mut(arg_mapping.as_mut_ptr::<u64>(), 4) };
                        arg[0] = mmap_info.fd as u64;
                        arg[1] = mmap_info.offset as u64;
                        arg[2] = mmap_info.size as u64;
                        arg[3] = addr_offset;

                        // make a guest request to load the page
                        self.return_values.result(TrustletReturnType::MMAP as u64);
                        return RETURN_TO_GUEST;
                    } else {
                        log::trace!("[Trustlet] #PF on present mmaped-page");
                    }
                } else {
                    log::trace!("[Trustlet] #PF: address is not mmaped-page");
                }
                if error_code & PF_PRESENT != 0 && error_code & PF_WRITE != 0 {
                    // CoW
                    #[cfg(feature = "stat")]
                    crate::sev::utils::stat::COW_COUNT.fetch_add(1, atomic::Ordering::Relaxed);

                    let mut page_table_ref = ProcessPageTableRef::default();
                    page_table_ref.set_external_table(self.vmsa.cr3);
                    // Handle CoW
                    log::trace!("[Trustlet] CoW: RIP={:#x}, CR2={:#x}, Error code={:?}", rip, cr2, error_code);
                    let user_access = error_code & PF_USER != 0;
                    let handled = page_table_ref.handle_cow(VirtAddr::from(cr2), user_access);
                    if handled {
                        log::trace!("[Trustlet] CoW: handled");
                        return RETURN_TO_PROCESS;
                    }
                    log::info!("[Trustlet] [BUG] CoW: not handled");
                }

                // XXX: it should not come here
                // debug
                let efer = self.vmsa.efer;
                let rip = self.vmsa.rip;
                let cr2 = self.vmsa.cr2;
                let cr4 = self.vmsa.cr4;
                let rsp = self.vmsa.rsp;
                let rflags = self.vmsa.rflags;
                log::info!("[Trustlet] [BUG] Unhandled Page Fault!");
                log::info!("vmsa EFER: {:?}", efer);
                log::info!("vmsa CR2: {:?}", cr2);
                log::info!("vmsa cr4: {:?}", cr4);
                log::info!("vmsa rip: {:?}", rip);
                log::info!("vmsa CS: {:?}", self.vmsa.cs);
                log::info!("vmsa SS: {:?}", self.vmsa.ss);
                log::info!("vmsa DS: {:?}", self.vmsa.ds);
                log::info!("vmsa RFLAGS: {:?}", rflags);
                log::info!("vmsa rsp: {:?}", rsp);
                let mut process_page_table_ref = ProcessPageTableRef::default();
                process_page_table_ref.set_external_table(self.vmsa.cr3);
                // dump stack
                let stack_base_paddr = process_page_table_ref.get_page(VirtAddr::from(rsp));
                let offset = (rsp & 0xFFF) / 8;
                let (_mapping, stack_mapping) = map_paddr!(stack_base_paddr);
                for i in 0..9 {
                    log::info!("[Trustlet] Stack (rsp+{}): {:#x}", i*8, unsafe{stack_mapping.as_ptr::<u64>().offset((offset + i).try_into().unwrap()).read()});
                }

                /*
                // debug: allocate a page for the faulting address
                let mut page_table_ref = ProcessPageTableRef::default();
                page_table_ref.set_external_table(self.vmsa.cr3);
                page_table_ref.add_pages(VirtAddr::from(cr2), 1, ProcessPageFlags::data());
                return true;
                 */

                log::info!("[Trustlet] #PF: RIP={:#x}, CR2={:#x}, Error code={:?}", rip, cr2, error_code);
                if error_code & PF_PRESENT == 0 {
                    log::info!("[Trustlet] Page fault: not present");
                }
                if error_code & PF_WRITE != 0 {
                    log::info!("[Trustlet] Page fault: write");
                }
                if error_code & PF_USER != 0 {
                    log::info!("[Trustlet] Page fault: user");
                }
                if error_code & PF_RESERVED != 0 {
                    log::info!("[Trustlet] Page fault: reserved");
                }
                if error_code & PF_INSTRUCTION != 0 {
                    log::info!("[Trustlet] Page fault: instruction fetch");
                }
                /* Same contract as the #GP arm: unhandled means dead,
                   and dead means a defined ERROR to the guest. */
                self.process.dead = true;
                self.return_values.result(TrustletReturnType::ERROR as u64);
                RETURN_TO_GUEST
            }
            _ => {
                todo!();
            }
        }
    }

    // handle double fault
    fn handle_df(&mut self) -> ReturnTarget {
        log::info!(" [Trustlet] ---------------------------------");
        log::info!(" [Trustlet] Double Fault!");

        let error_code = self.vmsa.rbx;
        log::info!(" [Trustlet] Error Code: {:#x}", error_code);

        // Dump stack
        // Stak layout:
        // rsp + 0: rcx  (pushed by the hanlder)
        // rsp + 8: rbx  (pushed by the hanlder)
        // rsp + 16: rax (pushed by the hanlder)
        // rsp + 24: error_code
        // rsp + 32: rip
        // rsp + 40: cs
        // rsp + 48: rflags
        // rsp + 54: rsp
        // rsp + 64: ss
        let mut process_page_table_ref = ProcessPageTableRef::default();
        process_page_table_ref.set_external_table(self.vmsa.cr3);
        let rsp = self.vmsa.rsp;
        let stack_base_paddr = process_page_table_ref.get_page(VirtAddr::from(rsp));
        let offset = (rsp & 0xFFF) / 8;
        let (_mapping, stack_mapping) = map_paddr!(stack_base_paddr);
        for i in 0..9 {
            log::info!(" [Trustlet] Stack (rsp+{}): {:#x}", i*8, unsafe{stack_mapping.as_ptr::<u64>().offset((offset + i).try_into().unwrap()).read()});
        }

        // Dump GDT
        // RCX register points to the GDT (limit (2byte) + base (4byte))
        let gdt_ptr = self.vmsa.rcx;
        let page = process_page_table_ref.get_page(VirtAddr::from(gdt_ptr));
        let gdt_offset = (gdt_ptr & 0xFFF) as usize;
        let (_mapping, gdt_mapping) = map_paddr!(page);
        let gdt_limit = unsafe{gdt_mapping.as_ptr::<u8>().add(gdt_offset).cast::<u16>().read()};
        let gdt_base = unsafe{gdt_mapping.as_ptr::<u8>().add(gdt_offset+2).cast::<u64>().read()};
        log::info!(" [Trustlet] gdt_ptr: {:#x}", gdt_ptr);
        log::info!(" [Trustlet] GDT: limit={:#x}, base={:#x}", gdt_limit, gdt_base);
        let gdt_page = process_page_table_ref.get_page(VirtAddr::from(gdt_base));
        let (_mapping, gdt_mapping) = map_paddr!(gdt_page);
        let gdt_entries = gdt_limit as usize / 8;
        let gdt_entry_offset = (gdt_base & 0xFFF) as usize;
        for i in 0..=gdt_entries {
            let entry = unsafe{gdt_mapping.as_ptr::<u8>().add(gdt_entry_offset).cast::<u64>().add(i).read()};
            log::info!(" [Trustlet] GDT[{}]: {:#x}", i, entry);
        }

        // Dump CPU state
        // rax, rbx are pushed to the stack
        let rax = unsafe{stack_mapping.as_ptr::<u64>().offset((offset + 2).try_into().unwrap()).read()};
        let rbx = unsafe{stack_mapping.as_ptr::<u64>().offset((offset + 1).try_into().unwrap()).read()};
        let rcx = unsafe{stack_mapping.as_ptr::<u64>().offset((offset + 0).try_into().unwrap()).read()};
        let rdx = self.vmsa.rdx;
        let rsi = self.vmsa.rsi;
        let rdi = self.vmsa.rdi;
        let r8 = self.vmsa.r8;
        let r9 = self.vmsa.r9;
        let r10 = self.vmsa.r10;
        let r11 = self.vmsa.r11;
        let r12 = self.vmsa.r12;
        let r13 = self.vmsa.r13;
        let r14 = self.vmsa.r14;
        let r15 = self.vmsa.r15;

        log::info!(" [Trustlet] rax: {:#x}", rax);
        log::info!(" [Trustlet] rbx: {:#x}", rbx);
        log::info!(" [Trustlet] rcx: {:#x}", rcx);
        log::info!(" [Trustlet] rdx: {:#x}", rdx);
        log::info!(" [Trustlet] rsi: {:#x}", rsi);
        log::info!(" [Trustlet] rdi: {:#x}", rdi);
        log::info!(" [Trustlet] r8: {:#x}", r8);
        log::info!(" [Trustlet] r9: {:#x}", r9);
        log::info!(" [Trustlet] r10: {:#x}", r10);
        log::info!(" [Trustlet] r11: {:#x}", r11);
        log::info!(" [Trustlet] r12: {:#x}", r12);
        log::info!(" [Trustlet] r13: {:#x}", r13);
        log::info!(" [Trustlet] r14: {:#x}", r14);
        log::info!(" [Trustlet] r15: {:#x}", r15);

        let rip = self.vmsa.rip;
        let rsp = self.vmsa.rsp;

        log::info!(" [Trustlet] rip: {:#x}", rip);
        log::info!(" [Trustlet] rsp: {:#x}", rsp);

        let cr2 = self.vmsa.cr2;
        let cr3 = self.vmsa.cr3;
        let cr4 = self.vmsa.cr4;
        let rflags = self.vmsa.rflags;
        let efer = self.vmsa.efer;

        log::info!(" [Trustlet] cr2: {:#x}", cr2);
        log::info!(" [Trustlet] cr3: {:#x}", cr3);
        log::info!(" [Trustlet] cr4: {:#x}", cr4);
        log::info!(" [Trustlet] efer: {:#x}", efer);
        log::info!(" [Trustlet] rflags: {:#x}", rflags);

        let cs = self.vmsa.cs;
        let ss = self.vmsa.ss;
        let ds = self.vmsa.ds;
        log::info!(" [Trustlet] cs: {:?}", cs);
        log::info!(" [Trustlet] ss: {:?}", ss);
        log::info!(" [Trustlet] ds: {:?}", ds);

        log::info!(" [Trustlet] ---------------------------------");
        /* A double fault is as dead as it gets. */
        self.process.dead = true;
        self.return_values.result(TrustletReturnType::ERROR as u64);
        RETURN_TO_GUEST
    }
}
