use cpuarch::vmsa::VMSA;
use ghcb::GHCBRef;
pub mod gdt;
pub mod ghcb;
pub mod idt;
pub mod registers;
pub mod tss;

extern "Rust" {
    fn wallet_get_current_guest_vmsa() -> &'static mut VMSA;
    //fn wallet_get_ghcb() -> GHCBRef;
}

pub fn get_current_guest_vmsa() -> &'static mut VMSA {
    unsafe { wallet_get_current_guest_vmsa() }
}

//pub fn current_ghcb() -> GHCBRef {
//    unsafe { wallet_get_ghcb() }
//}
