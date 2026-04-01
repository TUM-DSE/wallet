use crate::address::PhysAddr;

extern "Rust" {
    fn wallet_register_guest_vmsa(vmsa: PhysAddr, vmpl: u64, sev_features: u64) -> bool;
    fn wallet_switch_to_vmpl(vmpl: u64);
}

pub fn register_guest_vmsa(vmsa: PhysAddr, vmpl: u64, sev_features: u64) -> bool {
   unsafe { wallet_register_guest_vmsa(vmsa, vmpl, sev_features) }
}

pub fn switch_to_vmpl(vmpl: u64) {
    unsafe { wallet_switch_to_vmpl(vmpl) };
}
