extern crate alloc;

use core::any::Any;
use alloc::boxed::Box;
use crate::{address::{PhysAddr, VirtAddr}, sev::utils::SvsmError};
use crate::sev::utils::SevSnpError;

extern "Rust" {
    fn wallet_memory_drop_guard(b: Box<dyn Any>);
    fn wallet_memory_map_4k(p: PhysAddr) -> (Box<dyn Any>, VirtAddr);

    fn wallet_phys_to_virt(paddr: PhysAddr) -> VirtAddr;
}


#[derive(Debug)]
#[must_use = "if unused the mapping will immediately be unmapped"]
pub struct PerCPUPageMappingGuard {
    pub guard: Option<Box<dyn Any>>,
    pub vaddr: VirtAddr,
}

impl PerCPUPageMappingGuard {
    pub fn create_4k(paddr: PhysAddr) -> Result<Self, SvsmError> {
        unsafe {
            let (b, v) = wallet_memory_map_4k(paddr);
            if v == VirtAddr::null() {
                let e = SvsmError::SevSnp(SevSnpError::FAIL_INPUT(1));
                return Err(e);
            } else {
                return Ok(PerCPUPageMappingGuard{
                    guard: Some(b),
                    vaddr: v,
                });
            }
        }
    }
    pub fn virt_addr(&self) -> VirtAddr {
        self.vaddr
    }
}

impl Drop for PerCPUPageMappingGuard {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            unsafe { wallet_memory_drop_guard(guard) };
        }
    }
}

pub fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    unsafe { wallet_phys_to_virt(paddr) }
}
