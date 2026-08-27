use crate::paddr_as_slice;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::process_manager::process_paging::ProcessPageFlags;
use crate::process_manager::process_paging::GraminePalProtFlags;
use crate::address::VirtAddr;
use crate::process_runtime::ReturnTarget;
use crate::process_runtime::RETURN_TO_PROCESS;
use igvm_defs::PAGE_SIZE_4K;
use crate::sev::RMPFlags;
use crate::process_manager::process_memory::allocate_page;
use crate::sev::rmp_adjust;
use crate::map_paddr;
use crate::types::PageSize;
use crate::address::PhysAddr;
use crate::memory::paging::PerCPUPageMappingGuard;
use crate::vaddr_as_slice;

use super::super::PALContext;

extern crate alloc;
use crate::process_manager::process_paging::TP_LIBOS_START_VADDR;


pub trait ProcessRuntimeMemory {
    fn pal_svsm_virt_alloc(&mut self) -> ReturnTarget;
    fn pal_svsm_virt_free(&mut self) -> ReturnTarget;
    fn pal_svsm_map(&mut self) -> ReturnTarget;
    fn pal_svsm_mprotect(&mut self) -> ReturnTarget;

}

impl ProcessRuntimeMemory for PALContext {
    /// Allocate virtual memory in the trustlet's page table
    ///
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFC)
    /// * rbx: trustlet's virtual address to allocate
    /// * rcx: size of memory to allocate
    /// * rdx: flags (GraminePalProtFlags)
    ///
    /// Retrun:
    /// * rcx: 0 on success, -1 on failure
    fn pal_svsm_virt_alloc(&mut self) -> ReturnTarget {
        // Getting the Page Table of the current Trustlet being executed
        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        let addr = self.vmsa.rbx;
        let size = self.vmsa.rcx;
        let flags = self.vmsa.rdx;

        // Check if size is a multiple of pages
        if size % 4096 != 0 {
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }

        // Check if address starts at page boundary
        if addr % 4096 != 0 {
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }
        let mut page_flags = ProcessPageFlags::data();
        if flags & GraminePalProtFlags::WRITE.bits() != 0 {
            page_flags = page_flags | ProcessPageFlags::WRITABLE;
        }
        /*
        // XXX: we can omit this for now as currently we support only one thread
        if flags & GraminePalProtFlags::WRITECOPY.bits() != 0 {
            page_flags = page_flags | ProcessPageFlags::COPY_ON_WRITE;
            page_flags = page_flags & !ProcessPageFlags::WRITABLE;
        }
        */
        if flags & GraminePalProtFlags::EXEC.bits() != 0 {
            page_flags = page_flags & !ProcessPageFlags::NO_EXECUTE;
        }

        /* addr is the trustlet's: asking for a range that is already
           mapped used to panic the monitor (VM death for every
           tenant). Same -1 failure the checks above return. */
        if !page_table_ref.add_pages(VirtAddr::from(addr), size / 4096, page_flags) {
            log::warn!("virt_alloc: {:#x} ({} pages) not free", addr, size / 4096);
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }

        self.vmsa.rcx = u64::from_ne_bytes((0i64).to_ne_bytes());

        RETURN_TO_PROCESS
    }

    /// Free virtual memory in the trustlet's page table
    ///
    /// Register arguments:
    /// * rax: monitor call code ()
    /// * rbx: trustlet's virtual address to free
    /// *
    fn pal_svsm_virt_free(&mut self) -> ReturnTarget {
        //log::info!("FREE");
        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        let addr = self.vmsa.rbx;
        let size = self.vmsa.rcx;

        //TODO: Check if Address can used
        if size % 4096 != 0 {
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }

        if addr % 4096 != 0 {
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }
        page_table_ref.remove_pages(VirtAddr::from(addr), size / 4096);
        RETURN_TO_PROCESS
    }

    /// Map a file into the trustlet's memory space
    ///
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFB)
    /// * rbx: virtual address to map
    /// * rcx: size of memory to map
    /// * rdx: flags (GraminePalProtFlags)
    /// * r8: file descriptor
    /// * r9: offset
    ///
    /// Return:
    /// * rcx: 0 on success, -1 on failure
    fn pal_svsm_map(&mut self) -> ReturnTarget {
        let addr = self.vmsa.rbx;
        let size = self.vmsa.rcx;
        let flags = self.vmsa.rdx;
        let fd = self.vmsa.r8;
        let offset = self.vmsa.r9;

        log::debug!("[pal_svsm_map] addr={:#x}, size={}", addr, size);
        log::debug!("{:#}, {}", addr, size);

        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        /* addr/size/offset are trustlet registers: the asserts were a
           monitor panic, i.e. the whole VM, and they fired BEFORE the
           graceful size check below could ever run (that check was
           dead code). Refuse in rcx and resume the trustlet, the
           convention the other VMPL1 handlers use. */
        if addr % 4096 != 0 || size % 4096 != 0 || offset % 4096 != 0 {
            log::warn!("map: unaligned request addr {:#x} size {:#x} offset {:#x}",
                       addr, size, offset);
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }
        let num_pages = size / 4096;
        /* size is trustlet-chosen and the writecopy branch allocates a
           page per iteration. */
        let available = crate::process_manager::process_memory::pages_available();
        if num_pages + 16 >= available {
            log::warn!("map: {} pages requested, {} available", num_pages, available);
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }

        let writable = (flags & GraminePalProtFlags::WRITE.bits()) != 0;
        let executable = (flags & GraminePalProtFlags::EXEC.bits()) != 0;
        let writecopy = (flags & GraminePalProtFlags::WRITECOPY.bits()) != 0;
        let mut flags = ProcessPageFlags::USER_ACCESSIBLE | ProcessPageFlags::ACCESSED;
        if writable {
            flags |= ProcessPageFlags::WRITABLE;
        }
        if writecopy {
            //flags |= ProcessPageFlags::COPY_ON_WRITE;
            flags &= !ProcessPageFlags::WRITABLE;
        }
        if !executable {
            flags |= ProcessPageFlags::NO_EXECUTE;
        }

        let vaddr = VirtAddr::from(addr);
        let libos_fd = u64::from_ne_bytes((-2i64).to_ne_bytes());

        if fd == libos_fd {
            // the monitor loads the libos file into the predefined address (TP_LIBOS_START_VADDR) at the start
            let s_vaddr = VirtAddr::from(TP_LIBOS_START_VADDR);

            flags |= ProcessPageFlags::PRESENT;

            for i in 0..num_pages {
                let src = s_vaddr + ((i * PAGE_SIZE_4K) as usize) + (offset as usize);
                let dst = vaddr + (i * PAGE_SIZE_4K).try_into().unwrap();
                let t = page_table_ref.virt_to_phys(src);

                /*
                // CoW version
                // FIXME: this does not work (unknown #PF with non-present page occurs)
                page_table_ref.map_4k_page(dst, t, flags);

                if writecopy {
                    page_table_ref.change_attr(src, true, false, true, true);
                    // TODO: flush trustleet's TLB
                }
                // check
                let t2 = page_table_ref.virt_to_phys(dst);
                assert!(t == t2, "Address mapping failed");
                continue;
                */

                // Non-CoW version (copy page content at this point for writecopy)
                if writecopy {
                    let (_old_mapping, old_page_mapped) = paddr_as_slice!(t);
                    let new_page = allocate_page();
                    let (mapping, new_page_mapped) = paddr_as_slice!(new_page);
                    rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX , PageSize::Regular).unwrap();
                    for i in 0..512 {
                       new_page_mapped[i] = old_page_mapped[i];
                    }
                    let flags = flags | ProcessPageFlags::WRITABLE;
                    page_table_ref.map_4k_page(dst, new_page, flags);
                } else {
                    page_table_ref.map_4k_page(dst, t, flags);

                    let t2 = page_table_ref.virt_to_phys(dst);
                    assert!(t == t2, "Address mapping failed");
                }
            }
            self.vmsa.rcx = u64::from_ne_bytes((0i64).to_ne_bytes());
            return RETURN_TO_PROCESS;
        }

        // Update mmap information
        let mmap_manger = &mut self.process.mmap_manager;
        /*
        // check if the address is already mapped
        let mmap_info = mmap_manger.lookup(addr as usize);
        if !mmap_info.is_none() {
            log::info!("[pal_svsm_map] Address already mapped: {:?}", mmap_info);
            self.vmsa.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
            return true;

        }
        */
        // XXX: apparently overlapping mapping happens, so we allow it
        // mmap_manager keeps the address range like the following order
        // example: [1..3] < [2..4] < [2..5] < [3..4]
        // page fault hander uses mmap infomation whose range contains the faulting address
        // and priority is given to the latter one in the order
        // FIXME: as the ordering above does not consider the time of mapping,
        // the mmap handler might not use the latest mapping that includes the faulting address
        mmap_manger.add_mapping(addr as usize, size as usize, fd as i32, offset as usize);

        // Allocate virtul memory address
        // The actual content is loaded upon #PF
        for i in 0..num_pages {
            let dst = vaddr + (i * PAGE_SIZE_4K).try_into().unwrap();
            page_table_ref.map_4k_page(dst, PhysAddr::new(0), flags);
        }

        self.vmsa.rcx = u64::from_ne_bytes((0i64).to_ne_bytes());
        RETURN_TO_PROCESS
    }

    /// Update the trusted process' page entry permissions
    ///
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFF9)
    /// * rbx: virtual address
    /// * rcx: size of memory to update
    /// * rdx: flags (GraminePalProtFlags)
    ///
    /// Return:
    /// * rcx: 0 on success, -1 on failure
    fn pal_svsm_mprotect(&mut self) -> ReturnTarget {
        let addr = self.vmsa.rbx;
        let size = self.vmsa.rcx;
        let flags = self.vmsa.rdx;

        // log::info!("svsm_mprotect: addr={:#}, size={}, flags={}", addr, size, flags);

        let process_page_table = self.vmsa.cr3;
        let mut process_page_table_ref = ProcessPageTableRef::default();
        process_page_table_ref.set_external_table(process_page_table);

        let offset = addr & 0xFFF;
        let page_num = (offset + size + 4095) / PAGE_SIZE_4K;
        let aligned_addr = addr & !0xFFF;
        let vaddr = VirtAddr::from(aligned_addr);

        let readbable = flags & GraminePalProtFlags::READ.bits() != 0;
        let writable = flags & GraminePalProtFlags::WRITE.bits() != 0;
        let executable = flags & GraminePalProtFlags::EXEC.bits() != 0;
        let writecopy = flags & GraminePalProtFlags::WRITECOPY.bits() != 0;

        // FIXME: this walks the page table every time. we can optimize this by updating entries while walking
        for i in 0..page_num {
            let target = vaddr + (i* PAGE_SIZE_4K).try_into().unwrap();
            process_page_table_ref.change_attr(target, readbable, writable, executable, writecopy);
        }

        RETURN_TO_PROCESS
    }
}
