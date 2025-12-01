// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod rwlock;
pub mod spinlock;

#[allow(unused_imports)]
pub use rwlock::{RWLock, ReadLockGuard, WriteLockGuard};
#[allow(unused_imports)]
pub use spinlock::{LockGuard, SpinLock};

extern "Rust" {
    fn wallet_get_pvalidate_lock() -> &'static RWLock<()>;
}

pub fn get_pvalidate_lock() -> &'static RWLock<()> {
    unsafe { wallet_get_pvalidate_lock() }
}
