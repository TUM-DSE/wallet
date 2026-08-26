use crate::interop::memory::flush_tlb_global;
use crate::process_manager::process_memory::{allocate_page, free_page};
//use crate::mm::PAGE_SIZE;
pub const PAGE_SIZE: usize = 4096;
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::process_manager::process_paging::{ProcessPageTableEntry, ProcessPageTablePage, ProcessPageTableRef};
use crate::process_manager::process_paging::ProcessPageFlags;
use super::process_memory::PGD;
use crate::interop::memory::read_cr3;
use crate::sev::{rmp_adjust, RMPFlags};
use crate::types::PageSize;
use crate::{paddr_as_slice, map_paddr, vaddr_as_slice, paddr_as_table, strip_paddr};
use crate::process_manager::memory_helper::strip_c_bit;
//use crate::mm::PerCPUPageMappingGuard;
use crate::memory::paging::PerCPUPageMappingGuard;

const ALLOCATION_VADDR_START: u64 = 0x30000000000u64;
pub const DEFAULT_ALLOCATION_RANGE_MOUNT: usize = 6;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AllocationRange(pub u64, pub u64);

#[allow(dead_code)]
/// PML4 slot 6 (VA 0x30000000000) is a per-vCPU scratch mount: each
/// request-loop task has a PRIVATE PML4 (COCONUT clone_shared copies
/// only slot 511), and guest calls land on arbitrary, migrating
/// vCPUs. A populated slot here is a LEAK from an earlier call
/// (PLAN.md F2/F3): building through it grafts the new pages into the
/// old subtree — map_region/page_walk silently ADOPT a present entry —
/// and the caller's later unmount()+delete() then frees pages still
/// owned by e.g. the model store into the LIFO allocator. That is the
/// root cause of the intermittent monitor #PF at CR2 0x30000000000
/// and the trustlet model-range faults. Clear it, loudly.
fn clear_stale_mount(tag: &str) {
    let (_mapping, pgd) = paddr_as_slice!(read_cr3());
    let stale = pgd[DEFAULT_ALLOCATION_RANGE_MOUNT];
    if stale != 0 {
        log::warn!("[{}] stale PML4[{}]={:#x} in cr3 {:#x} - clearing",
                   tag, DEFAULT_ALLOCATION_RANGE_MOUNT, stale,
                   u64::from(read_cr3()));
        pgd[DEFAULT_ALLOCATION_RANGE_MOUNT] = 0;
        flush_tlb_global();
    }
}

impl AllocationRange {

    pub fn allocate(&mut self, pages: u64){
        // Allocates a new memory range for the Monitor
        // Currently the start virtual address is fixed to ALLOCATION_RANGE_VIRT_START
        // Reuses the Process page managment to add new memory to the Monitor
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(read_cr3().bits() as u64);
        self.allocate_(&mut page_table_ref, pages, ALLOCATION_VADDR_START, true, false);
        //page_table_ref.print_table();
    }

    #[allow(dead_code)] // no callers; kept for symmetry, see PLAN.md
    pub fn allocate_trustlet(&mut self, pages: u64){
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(read_cr3().bits() as u64);
        self.allocate_(&mut page_table_ref, pages, ALLOCATION_VADDR_START, false, true);
    }

    pub fn allocate_with_start_addr(&mut self, page_table_ref: &mut ProcessPageTableRef, pages: u64, start_addr: u64){
        self.allocate_(page_table_ref, pages, start_addr, false, true);
    }

    pub fn allocate_for_guest(&mut self, pages: u64) {
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(read_cr3().bits() as u64);

        clear_stale_mount("allocate_for_guest");

        let start_addr = ALLOCATION_VADDR_START;

        //&mut self, page_table_ref: &mut ProcessPageTableRef, pages: u64, start_addr: u64, mount: bool, user: bool

        let table_flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE |
        ProcessPageFlags::DIRTY | ProcessPageFlags::ACCESSED | ProcessPageFlags::USER_ACCESSIBLE;

        let start_address = VirtAddr::from(start_addr);

        page_table_ref.map_region(start_address, pages, table_flags);

        let (_mapping, pgd) = paddr_as_slice!(read_cr3());
        self.0 = pgd[DEFAULT_ALLOCATION_RANGE_MOUNT];
        self.1 = pages;

        flush_tlb_global();

    }

    pub fn guest_write_access(&mut self){
        let pgd_table_entry = ProcessPageTableEntry(PhysAddr::from(self.0));
        let (mapping1, pud_table) = paddr_as_table!(strip_paddr!(pgd_table_entry.0));
        let _  = rmp_adjust(mapping1.virt_addr(), RMPFlags::VMPL2 | RMPFlags::RWX, PageSize::Regular);
        for i in 0..512 {
            let pud_table_entry = pud_table[i];
            if !pud_table_entry.flags().contains(ProcessPageFlags::PRESENT) {
                break
            }

            let (mapping2, pmd_table) = paddr_as_table!(strip_paddr!(pud_table_entry.0));
            let _  = rmp_adjust(mapping2.virt_addr(), RMPFlags::VMPL2 | RMPFlags::RWX, PageSize::Regular);
            for i in 0..512 {
                let pmd_table_entry = pmd_table[i];
                if !pmd_table_entry.flags().contains(ProcessPageFlags::PRESENT) {
                    break
                }

                let (mapping3, _pte_table) = paddr_as_table!(strip_paddr!(pmd_table_entry.0));
                let _  = rmp_adjust(mapping3.virt_addr(), RMPFlags::VMPL2 | RMPFlags::RWX, PageSize::Regular);
            }
        }
        for i in 0..(self.1 as usize) {
            let _ = rmp_adjust((ALLOCATION_VADDR_START as usize + i * PAGE_SIZE).into(), RMPFlags::VMPL2 | RMPFlags::RWX, PageSize::Regular);
        }
    }
    pub fn guest_remove_write_access(&mut self) {

        for i in 0..(self.1 as usize) {
            let _ = rmp_adjust((ALLOCATION_VADDR_START as usize + i * PAGE_SIZE).into(), RMPFlags::VMPL2 | RMPFlags::READ, PageSize::Regular);
        }

    }

    /// Grant a VMPL1 trustlet read access to this range (model_channel:
    /// the model store maps read-only into the trustlet). The subtree's
    /// page-table pages get RWX like in guest_write_access — the
    /// hardware walker reads them and writes A/D bits at the accessing
    /// VMPL; the data pages get READ only. Mounts the range into the
    /// monitor's PT for the data-page pass, mirroring the load path.
    pub fn trustlet_read_access(&self) {
        let pgd_table_entry = ProcessPageTableEntry(PhysAddr::from(self.0));
        let (mapping1, pud_table) = paddr_as_table!(strip_paddr!(pgd_table_entry.0));
        let _ = rmp_adjust(mapping1.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular);
        for i in 0..512 {
            let pud_table_entry = pud_table[i];
            if !pud_table_entry.flags().contains(ProcessPageFlags::PRESENT) {
                break
            }

            let (mapping2, pmd_table) = paddr_as_table!(strip_paddr!(pud_table_entry.0));
            let _ = rmp_adjust(mapping2.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular);
            for i in 0..512 {
                let pmd_table_entry = pmd_table[i];
                if !pmd_table_entry.flags().contains(ProcessPageFlags::PRESENT) {
                    break
                }

                let (mapping3, _pte_table) = paddr_as_table!(strip_paddr!(pmd_table_entry.0));
                let _ = rmp_adjust(mapping3.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular);
            }
        }
        self.mount();
        for i in 0..(self.1 as usize) {
            let _ = rmp_adjust((ALLOCATION_VADDR_START as usize + i * PAGE_SIZE).into(), RMPFlags::VMPL1 | RMPFlags::READ, PageSize::Regular);
        }
        self.unmount();
    }

    fn allocate_(&mut self, page_table_ref: &mut ProcessPageTableRef, pages: u64, start_addr: u64, mount: bool, user: bool){
        // Reuses the Process page managment to add new memory to the Monitor
        //let mut page_table_ref = ProcessPageTableRef::default();
        //page_table_ref.set_external_table(read_cr3().bits() as u64);
        let mut table_flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE |
        ProcessPageFlags::DIRTY | ProcessPageFlags::ACCESSED;

        if user {
            table_flags = table_flags | ProcessPageFlags::USER_ACCESSIBLE;
        }

        let start_address = VirtAddr::from(start_addr);

        /* Never build through a leaked slot (see clear_stale_mount).
           Only the mount path targets slot 6; the !mount path builds
           into a process table where extending an entry is intended. */
        if mount {
            clear_stale_mount("allocate_");
        }

        for i in 0..(pages as usize) {
            //log::debug!("allocate_: {}", i);
            let current_page = allocate_page();
            //log::debug!("New data page: {:x?}", current_page);
            if !mount {
                let (mapping, _page_mapped) = paddr_as_slice!(current_page);
                let _ = rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular);
            }
            page_table_ref.map_4k_page(start_address + i * PAGE_SIZE, current_page, table_flags);
        };

        if mount {
            let (_mapping, pgd) = paddr_as_slice!(read_cr3());
            self.0 = pgd[DEFAULT_ALLOCATION_RANGE_MOUNT];
            self.1 = pages;
        } else {
            let offset: usize = start_address.to_pgtbl_idx::<PGD>();
            let (_mapping, pgd) = paddr_as_slice!(page_table_ref.process_page_table);
            self.0 = pgd[offset];
            self.1 = pages;
        }
        flush_tlb_global();
    }

    pub fn inflate(&mut self, page_table_ref: &mut ProcessPageTableRef, pages: u64, start_addr: u64) {
        if self.1 >= pages {
            return;
        }
        let table_flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE |
        ProcessPageFlags::DIRTY | ProcessPageFlags::ACCESSED | ProcessPageFlags::USER_ACCESSIBLE;
        let start_address = VirtAddr::from(start_addr);
        let begin = self.1 as usize;
        for i in begin..(pages as usize) {
            let current_page = allocate_page();
            let (mapping, _page_mapped) = paddr_as_slice!(current_page);
            let _ = rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular);
            page_table_ref.map_4k_page(start_address + i * PAGE_SIZE, current_page, table_flags);
        }
        self.1 = pages;
    }

    pub fn mount(&self) {
        let (_mapping, pgd) = paddr_as_slice!(read_cr3());
        /* A non-empty slot means an earlier call leaked its mount.
           Replacing wholesale is safe (unlike the builders, which
           MERGE into a present entry), but log it - the old entry
           identifies the leaker. */
        let old = pgd[DEFAULT_ALLOCATION_RANGE_MOUNT];
        if old != 0 && old != self.0 {
            log::warn!("mount: PML4[{}] already {:#x} (cr3 {:#x}, mounting {:#x}) - leaked mount",
                       DEFAULT_ALLOCATION_RANGE_MOUNT, old,
                       u64::from(read_cr3()), self.0);
        }
        pgd[DEFAULT_ALLOCATION_RANGE_MOUNT] = self.0;
        flush_tlb_global();
    }

    pub fn unmount(&self) {
        let (_mapping, pgd) = paddr_as_slice!(read_cr3());
        /* Empty slot on unmount of a real range: the mount and the
           unmount ran on DIFFERENT vCPUs (per-vCPU PML4s; guest calls
           migrate) - the mount is still live on the other vCPU. The
           self.0 guard keeps the degenerate (0,0) ranges quiet. */
        if pgd[DEFAULT_ALLOCATION_RANGE_MOUNT] == 0 && self.0 != 0 {
            log::warn!("unmount: PML4[{}] already empty (cr3 {:#x}, range {:#x}) - split mount?",
                       DEFAULT_ALLOCATION_RANGE_MOUNT,
                       u64::from(read_cr3()), self.0);
        }
        pgd[DEFAULT_ALLOCATION_RANGE_MOUNT] = 0;
        flush_tlb_global();
    }

    /* mount_at()/reset_mount() removed 2026-08-26: zero callers, and
       they were the only remaining arbitrary-slot writers. */

    pub fn delete(mut self) {
        if self.0 == 0 {
            log::debug!("Trying to delete empty allocationRange");
            return;
        }
        log::debug!("Deleting allocationRange {:#x?}", self);
        let pgd_table_entry = ProcessPageTableEntry(PhysAddr::from(self.0));
        let (_mapping, pud_table) = paddr_as_table!(strip_paddr!(pgd_table_entry.0));
        for i in 0..512 {
            let pud_table_entry = pud_table[i];
            if !pud_table_entry.flags().contains(ProcessPageFlags::PRESENT) {
                break
            }

            let (_mapping, pmd_table) = paddr_as_table!(strip_paddr!(pud_table_entry.0));
            for i in 0..512 {
                let pmd_table_entry = pmd_table[i];
                if !pmd_table_entry.flags().contains(ProcessPageFlags::PRESENT) {
                    break
                }

                let (_mapping, pte_table) = paddr_as_table!(strip_paddr!(pmd_table_entry.0));
                for i in 0..512 {
                    let pte_table_entry = pte_table[i];
                    if !pte_table_entry.flags().contains(ProcessPageFlags::PRESENT) {
                        break
                    }
                    //log::debug!("Freeing PTE: {:x?}", strip_paddr!(pte_table_entry.0));
                    free_page(strip_paddr!(pte_table_entry.0));
                }
                //log::debug!("Freeing PMD: {:x?}", strip_paddr!(pmd_table_entry.0));
                free_page(strip_paddr!(pmd_table_entry.0));
            }
            //log::debug!("Freeing PUD: {:x?}", strip_paddr!(pud_table_entry.0));
            free_page(strip_paddr!(pud_table_entry.0));
        }
        //log::debug!("Freeing PGD: {:x?}", strip_paddr!(pgd_table_entry.0));
        free_page(strip_paddr!(pgd_table_entry.0));
        self.0 = 0;
        self.1 = 0;
    }
}
