use crate::utils::MemoryRegion;
use crate::address::VirtAddr;
use core::arch::asm;
use crate::address::PhysAddr;

extern "Rust" {
    fn wallet_map_page_table_return_entry(reg: MemoryRegion<VirtAddr>, phys: PhysAddr) -> u64;
}

pub fn map_svsm_page_table(reg: MemoryRegion<VirtAddr>, phys: PhysAddr) -> u64 {
    unsafe{ wallet_map_page_table_return_entry(reg, phys) }
}


pub fn flush_tlb_global() {
    unsafe {
        asm!("invlpgb",
             in("rax") 1u64 << 2,
             in("rcx") 0,
             in("rdx") 0,
             options(att_syntax));
        asm!("tlbsync", options(att_syntax));
    }
}

pub fn read_cr3() -> PhysAddr{
    let ret: usize;
    unsafe {
        asm!("mov %cr3, %rax",
             out("rax") ret,
             options(att_syntax));
    }
    PhysAddr::from(ret)
}
