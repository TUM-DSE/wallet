use crate::{address::PhysAddr, sev::utils::SvsmError};

extern "Rust" {
    fn wallet_ap_create(vmsa: PhysAddr, apic_id: u64, vmpl: u64, sev_features: u64) -> Result<(), SvsmError>;
    fn wallet_ap_create_current(vmsa: PhysAddr, vmpl: u64, sev_features: u64) -> Result<(), SvsmError>;
}

pub fn ap_create_current(vmsa: PhysAddr, vmpl: u64, sev_features: u64) -> Result<(), SvsmError> {
    unsafe{ wallet_ap_create_current(vmsa, vmpl, sev_features) }
}
