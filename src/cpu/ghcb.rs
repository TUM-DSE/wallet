// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

//use crate::sev::ghcb::GHCB;

use core::ops::{Deref, DerefMut};

const GHCB_BUFFER_SIZE: usize = 0x7f0;

#[repr(C, packed)]
#[derive(Debug)]
pub struct GHCB {
    reserved_1: [u8; 0xcb],
    cpl: u8,
    reserved_2: [u8; 0x74],
    xss: u64,
    reserved_3: [u8; 0x18],
    dr7: u64,
    reserved_4: [u8; 0x90],
    rax: u64,
    reserved_5: [u8; 0x100],
    reserved_6: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    reserved_7: [u8; 0x70],
    sw_exit_code: u64,
    sw_exit_info_1: u64,
    sw_exit_info_2: u64,
    sw_scratch: u64,
    reserved_8: [u8; 0x38],
    xcr0: u64,
    valid_bitmap: [u64; 2],
    x87_state_gpa: u64,
    reserved_9: [u8; 0x3f8],
    buffer: [u8; GHCB_BUFFER_SIZE],
    reserved_10: [u8; 0xa],
    version: u16,
    usage: u32,
}


#[derive(Debug)]
pub struct GHCBRef {
    ghcb: *mut GHCB,
}

impl Deref for GHCBRef {
    type Target = GHCB;
    fn deref(&self) -> &'static GHCB {
        unsafe { &*self.ghcb }
    }
}

impl DerefMut for GHCBRef {
    fn deref_mut(&mut self) -> &'static mut GHCB {
        unsafe { &mut *self.ghcb }
    }
}
