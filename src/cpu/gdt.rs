use crate::types::SVSM_TSS;
use core::mem;

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct GDTEntry(u64);

impl GDTEntry {
    pub const fn from_raw(entry: u64) -> Self {
        Self(entry)
    }

    pub const fn null() -> Self {
        Self(0u64)
    }

    pub const fn code_64_kernel() -> Self {
        Self(0x00af9b000000ffffu64)
    }

    pub const fn data_64_kernel() -> Self {
        Self(0x00cf93000000ffffu64)
    }

    pub const fn code_64_user() -> Self {
        Self(0x00affb000000ffffu64)
    }

    pub const fn data_64_user() -> Self {
        Self(0x00cff3000000ffffu64)
    }
}

const GDT_SIZE: u16 = 8;

#[derive(Copy, Clone, Debug)]
#[repr(align(4096))]
pub struct GDT {
    entries: [GDTEntry; GDT_SIZE as usize],
}

impl GDT {
    pub const fn new() -> Self {
        GDT {
            entries: [
                GDTEntry::null(),
                GDTEntry::code_64_kernel(),
                GDTEntry::data_64_kernel(),
                GDTEntry::code_64_user(),
                GDTEntry::data_64_user(),
                GDTEntry::null(),
                GDTEntry::null(),
                GDTEntry::null(),
            ],
        }
    }

    pub fn base_limit(&self) -> (u64, u32) {
        let gdt_entries = GDT_SIZE as usize;
        let base = (self as *const GDT) as u64;
        let limit = ((mem::size_of::<u64>() * gdt_entries) - 1) as u32;
        (base, limit)
    }

    pub unsafe fn set_tss_entry(&mut self, desc0: GDTEntry, desc1: GDTEntry) {
        let idx = (SVSM_TSS / 8) as usize;

        let tss_entries = &self.entries[idx..idx + 1].as_mut_ptr();

        tss_entries.add(0).write_volatile(desc0);
        tss_entries.add(1).write_volatile(desc1);
    }
}
