// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};
//use crate::error::SvsmError;
use crate::types::{PageSize, GUEST_VMPL};
use core::arch::asm;
use core::fmt;

#[allow(dead_code)]
pub mod stat {
    use core::sync::atomic::AtomicU64;
    pub static PVALIDATE_COUNT: AtomicU64 = AtomicU64::new(0);
    pub static PF_COUNT: AtomicU64 = AtomicU64::new(0);
    pub static COW_COUNT: AtomicU64 = AtomicU64::new(0);
}

#[derive(Clone, Copy, Debug)]
pub enum SvsmError {
  SevSnp(SevSnpError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum SevSnpError {
    FAIL_INPUT(u64),
    FAIL_PERMISSION(u64),
    FAIL_SIZEMISMATCH(u64),
    // Not a real error value, but we want to keep track of this,
    // especially for protocol-specific messaging
    FAIL_UNCHANGED(u64),
}

impl From<SevSnpError> for SvsmError {
    fn from(e: SevSnpError) -> Self {
        Self::SevSnp(e)
    }
}

impl fmt::Display for SevSnpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FAIL_INPUT(_) => write!(f, "FAIL_INPUT"),
            Self::FAIL_UNCHANGED(_) => write!(f, "FAIL_UNCHANGED"),
            Self::FAIL_PERMISSION(_) => write!(f, "FAIL_PERMISSION"),
            Self::FAIL_SIZEMISMATCH(_) => write!(f, "FAIL_SIZEMISMATCH"),
        }
    }
}

/// The desired state of the page passed to PVALIDATE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum PvalidateOp {
    #[allow(dead_code)]
    Invalid = 0,
    Valid = 1,
}

pub fn pvalidate(vaddr: VirtAddr, size: PageSize, valid: PvalidateOp) -> Result<(), SvsmError> {
    let rax = vaddr.bits();
    let rcx: u64 = match size {
        PageSize::Regular => 0,
        PageSize::Huge => 1,
    };
    let rdx = valid as u64;
    let ret: u64;
    let cf: u64;

    #[cfg(feature = "stat")]
    stat::PVALIDATE_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    unsafe {
        asm!("xorq %r8, %r8",
            ".byte 0xf2, 0x0f, 0x01, 0xff",
             "jnc 1f",
             "incq %r8",
             "1:",
             in("rax")  rax,
             in("rcx")  rcx,
             in("rdx")  rdx,
             lateout("rax") ret,
             lateout("r8") cf,
             options(att_syntax));
    }
    let changed = cf == 0;
    match ret {
        0 if changed => Ok(()),
        0 if !changed => Err(SevSnpError::FAIL_UNCHANGED(0x10).into()),
        1 => Err(SevSnpError::FAIL_INPUT(ret).into()),
        6 => Err(SevSnpError::FAIL_SIZEMISMATCH(ret).into()),
        _ => {
            log::error!("PVALIDATE: unexpected return value: {}", ret);
            unreachable!();
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug)]
    pub struct RMPFlags: u64 {
        const VMPL0 = 0;
        const VMPL1 = 1;
        const VMPL2 = 2;
        const VMPL3 = 3;
        const GUEST_VMPL = GUEST_VMPL as u64;
        const READ = 1u64 << 8;
        const WRITE = 1u64 << 9;
        const X_USER = 1u64 << 10;
        const X_SUPER = 1u64 << 11;
        const BIT_VMSA = 1u64 << 16;
        const NONE = 0;
        const RWX = Self::READ.bits() | Self::WRITE.bits() | Self::X_USER.bits() | Self::X_SUPER.bits();
        const VMSA = Self::READ.bits() | Self::BIT_VMSA.bits();
    }
}

pub fn rmp_adjust(addr: VirtAddr, flags: RMPFlags, size: PageSize) -> Result<(), SvsmError> {
    let rcx: u64 = match size {
        PageSize::Regular => 0,
        PageSize::Huge => 1,
    };
    let rax: u64 = addr.bits() as u64;
    let rdx: u64 = flags.bits();
    let mut ret: u64;
    let mut ex: u64;
    //log::debug!("rmp_adjust setting flags to : {:?}",flags);
    unsafe {
        asm!("1: .byte 0xf3, 0x0f, 0x01, 0xfe
                 xorq %rcx, %rcx
              2:
              .pushsection \"__exception_table\",\"a\"
              .balign 16
              .quad (1b)
              .quad (2b)
              .popsection",
                inout("rax") rax => ret,
                inout("rcx") rcx => ex,
                in("rdx") rdx,
                options(att_syntax));
    }

    if ex != 0 {
        // Report exceptions just as FAIL_INPUT
        return Err(SevSnpError::FAIL_INPUT(1).into());
    }

    match ret {
        0 => Ok(()),
        1 => Err(SevSnpError::FAIL_INPUT(ret).into()),
        2 => Err(SevSnpError::FAIL_PERMISSION(ret).into()),
        6 => Err(SevSnpError::FAIL_SIZEMISMATCH(ret).into()),
        _ => {
            log::error!("RMPADJUST: Unexpected return value: {:#x}", ret);
            unreachable!();
        }
    }
}

pub fn rmp_revoke_guest_access(vaddr: VirtAddr, size: PageSize) -> Result<(), SvsmError> {
    for vmpl in RMPFlags::GUEST_VMPL.bits()..=RMPFlags::VMPL3.bits() {
        let vmpl = RMPFlags::from_bits_truncate(vmpl);
        rmp_adjust(vaddr, vmpl | RMPFlags::NONE, size)?;
    }
    Ok(())
}

pub fn rmp_set_guest_vmsa(vaddr: VirtAddr) -> Result<(), SvsmError> {
    rmp_revoke_guest_access(vaddr, PageSize::Regular)?;
    rmp_adjust(
        vaddr,
        RMPFlags::GUEST_VMPL | RMPFlags::VMSA,
        PageSize::Regular,
    )
}
