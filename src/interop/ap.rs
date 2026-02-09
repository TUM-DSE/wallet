use crate::{address::PhysAddr, sev::utils::SvsmError};

extern "Rust" {
    fn wallet_ap_create(vmsa: PhysAddr, apic_id: u64, vmpl: u64, sev_features: u64) -> Result<(), SvsmError>;
    fn wallet_ap_create_current(vmsa: PhysAddr, vmpl: u64, sev_features: u64) -> bool;
    fn wallet_ap_create_current2(vmsa: PhysAddr, vmpl: u64, sev_features: u64) -> bool;
    fn wallet_register_guest_vmsa(vmsa: PhysAddr, vmpl: u64, sev_features: u64) -> bool;
    fn wallet_switch_to_vmpl(vmpl: u64);
}

pub fn ap_create_current(vmsa: PhysAddr, vmpl: u64, sev_features: u64) -> bool {
    unsafe{ wallet_ap_create_current(vmsa, vmpl, sev_features) }
}

pub fn ap_create_current2(vmsa: PhysAddr, vmpl: u64, sev_features: u64) -> bool {
    unsafe{ wallet_ap_create_current2(vmsa, vmpl, sev_features) }
}

pub fn register_guest_vmsa(vmsa: PhysAddr, vmpl: u64, sev_features: u64) -> bool {
   unsafe { wallet_register_guest_vmsa(vmsa, vmpl, sev_features) }
}

pub fn switch_to_vmpl(vmpl: u64) {
    unsafe { wallet_switch_to_vmpl(vmpl) };
}
