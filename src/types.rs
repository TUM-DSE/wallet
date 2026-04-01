// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

const VMPL_MAX: usize = 4;

pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_SIZE_2M: usize = PAGE_SIZE * 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageSize {
    Regular,
    Huge,
}

impl From<PageSize> for usize {
    fn from(psize: PageSize) -> Self {
        match psize {
            PageSize::Regular => PAGE_SIZE,
            PageSize::Huge => PAGE_SIZE_2M,
        }
    }
}

#[allow(clippy::identity_op)]
pub const SVSM_CS: u16 = 1 * 8;
pub const SVSM_TSS: u16 = 6 * 8;

/// VMPL level the guest OS will be executed at.
/// Keep VMPL 1 for the SVSM and execute the OS at VMPL-2. This leaves VMPL-3
/// free for the OS to use in the future.
pub const GUEST_VMPL: usize = 2;

#[allow(clippy::assertions_on_constants)]
const _: () = assert!(GUEST_VMPL > 0 && GUEST_VMPL < VMPL_MAX);

