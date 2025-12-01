use crate::{address::PhysAddr, utils::MemoryRegion};

extern "Rust" {
    fn wallet_get_memory_region_from_map(index: usize) -> MemoryRegion<PhysAddr>;
}


pub fn get_memory_region_from_map(index: usize) -> MemoryRegion<PhysAddr> {
    unsafe { wallet_get_memory_region_from_map(index) }
}
