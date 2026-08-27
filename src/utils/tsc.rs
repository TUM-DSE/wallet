//! Time source for VMPL0.
//!
//! The wallet crate had none: every "timeout" in the monitor was a spin
//! counter, whose wall-clock meaning depends on what the loop does per
//! iteration. `asm!` is already used in this crate (process_manager::outb),
//! so reading the TSC needs no new dependency and no SVSM shim.

use core::arch::asm;

/// Raw timestamp counter.
#[inline(always)]
pub fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi,
             options(att_syntax, nomem, nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Measured guest TSC frequency (2400.008 MHz), the same constant the
/// guest-side bench drivers use. Only ever used for coarse timeouts, so
/// a few ppm of drift is irrelevant; if this monitor is ever run on
/// another host, timeouts scale with the error and nothing else.
pub const TSC_HZ: u64 = 2_400_008_000;

/// Ticks in `secs` seconds.
#[inline(always)]
pub fn ticks_for_secs(secs: u64) -> u64 {
    TSC_HZ.saturating_mul(secs)
}

/// Ticks in `us` microseconds (bounded-poll yield budgets).
#[inline(always)]
pub fn ticks_for_micros(us: u64) -> u64 {
    (TSC_HZ / 1_000_000).saturating_mul(us)
}
