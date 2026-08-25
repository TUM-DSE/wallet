
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

pub mod r#loop;
pub mod scheduling;

static mut VMSA_PHYS: [PhysAddr; 64] = [PhysAddr::null(); 64];
static mut VMSA_FEAT: [u64; 64] = [0; 64];

static mut COM_PAGES: [PhysAddr; 64] = [PhysAddr::null(); 64];

#[derive(Debug)]
pub struct ControlStruct {
    pub next: AtomicU64,
    //pub addr: AtomicU64,
    pub hlt: AtomicU64,
}

pub fn set_next(next: &mut AtomicU64, o: u64, n: u64) {
    loop {
        if next.compare_exchange(o,
                                 n,
                                 Ordering::Acquire,
                                 Ordering::SeqCst) == Ok(o){
            break;
        }
    };
}

pub static mut CONTROL: [PhysAddr; 64] = [PhysAddr::null(); 64];

/// The core currently donated to the monitor (its exclusive command
/// loop is live), if any. Used to route trustlet GPU channels to the
/// polling core.
pub fn donated_core() -> Option<usize> {
    for i in 0..64 {
        if is_donated(i) {
            return Some(i);
        }
    }
    None
}

/// Is this specific core donated (running the exclusive command loop)?
pub fn is_donated(core: usize) -> bool {
    core < 64 && unsafe { CONTROL[core] } != PhysAddr::null()
}

/// A donated core to REPLACE when no free one exists, rotating over
/// the donated cores. Before this, every new trustlet arriving with
/// all slots dirty landed on the FIRST donated core - two concurrent
/// engines then shared one slot, the second replacing the first's comm
/// page, and the first session died (Phase 0 root cause, PLAN.md).
/// Rotation keeps concurrent engines on distinct cores even when every
/// slot holds a dead session's registration.
static NEXT_REPLACEMENT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

pub fn replacement_donated_core() -> Option<usize> {
    let mut n = 0;
    for i in 0..64 {
        if is_donated(i) {
            n += 1;
        }
    }
    if n == 0 {
        return None;
    }
    let k = NEXT_REPLACEMENT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) % n;
    let mut seen = 0;
    for i in 0..64 {
        if is_donated(i) {
            if seen == k {
                return Some(i);
            }
            seen += 1;
        }
    }
    None
}

/// A donated core with no engine registered on it yet.
///
/// One engine per donated core is what gives each engine its own
/// service process, and therefore its own CUDA context - the only thing
/// that actually isolates engines from each other (Stage D-0: separate
/// contexts inside one process do not). Donate one core per engine you
/// want to run concurrently.
pub fn free_donated_core() -> Option<usize> {
    for i in 0..64 {
        if is_donated(i) && !crate::gpu::direct::engine_registered(i) {
            return Some(i);
        }
    }
    None
}
pub static LOOP_CLEAR: u64 = 0;
pub static LOOP_EXIT: u64 = 1;
pub static LOOP_SLEEP: u64 = 2;
pub static LOOP_WAKEUP: u64 = 3;

 use crate::address::PhysAddr;
extern "Rust" {
    fn wallet_get_apic_id() -> u32;
}

fn get_apic_id() -> u32 {
    unsafe { wallet_get_apic_id() }
}
