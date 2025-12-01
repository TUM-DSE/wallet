use crate::{address::PhysAddr, process_manager::process_memory::PageStateChangeOp, sev::utils::SvsmError, types::PageSize};

extern "Rust" {
    fn wallet_current_ghcb_page_state_change(start: PhysAddr, end: PhysAddr, size: PageSize, op: PageStateChangeOp) -> bool;
}

pub fn page_state_change(start: PhysAddr, end: PhysAddr, size: PageSize, op: PageStateChangeOp) -> bool {
    unsafe{ wallet_current_ghcb_page_state_change(start, end, size, op) }
}
