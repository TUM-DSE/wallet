pub mod paging;
pub mod regions;

use crate::address::VirtAddr;

extern "Rust" {
    pub static SVSM_PERCPU_VMSA_BASE: VirtAddr;
}
