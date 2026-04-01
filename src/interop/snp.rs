use crate::{address::PhysAddr, types::PageSize};

extern "Rust" {
    fn wallet_current_ghcb_page_state_change(start: PhysAddr, end: PhysAddr, size: PageSize, op: PageStateChangeOp) -> bool;
}

#[allow(dead_code)]
pub fn page_state_change(start: PhysAddr, end: PhysAddr, size: PageSize, op: PageStateChangeOp) -> bool {
    unsafe{ wallet_current_ghcb_page_state_change(start, end, size, op) }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum PageStateChangeOp {
    PscPrivate,
    PscShared,
    PscPsmash,
    PscUnsmash,
}
