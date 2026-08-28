
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
#[allow(dead_code)] // unused since gpu_channel switched to replacement_donated_core
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
    /* Restrict the rotation to SERVICED cores when any exist: an
       unserviced alloc-helper core must never receive an engine even
       when every serviced slot is dirty (replacing a dirty serviced
       registration beats a working-looking session with no GPU).
       Legacy single-service setups see no change - the global
       SERVICE_PAGE fallback makes every core serviced. */
    let serviced = |i: usize| crate::gpu::direct::service_registered(i);
    let mut n_serviced = 0;
    let mut n_all = 0;
    for i in 0..64 {
        if is_donated(i) {
            n_all += 1;
            if serviced(i) {
                n_serviced += 1;
            }
        }
    }
    let (n, need_service) = if n_serviced > 0 { (n_serviced, true) } else { (n_all, false) };
    if n == 0 {
        return None;
    }
    let k = NEXT_REPLACEMENT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) % n;
    let mut seen = 0;
    for i in 0..64 {
        if is_donated(i) && (!need_service || serviced(i)) {
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
    /* Three passes. Serviced first: cores donated purely as stream
       alloc helpers run NO service process - an engine landing there
       relays every CUDA call into the 802 arm and llama silently
       falls back to CPU inference (the loud NO SERVICE error in
       gpu_channel is the tripwire). Within the serviced cores, prefer
       one whose service owes no deferred session reset: the stop of a
       dead session is delivered at the NEXT session's entry, and the
       CC driver can stretch that reset to minutes on large sessions -
       debt the new session should not inherit when a clean engine is
       available. (This is also what keeps the e2e lukewarm instance
       off the deleted instance's engine.) The unserviced last pass
       keeps no-service smoke setups working; with only the legacy
       global SERVICE_PAGE fallback, service_registered is true
       everywhere and the picker behaves exactly as before. */
    for i in 0..64 {
        if is_donated(i)
            && !crate::gpu::direct::engine_registered(i)
            && !crate::gpu::direct::engine_slot_owes_stop(i)
            && crate::gpu::direct::service_registered(i) {
            return Some(i);
        }
    }
    for i in 0..64 {
        if is_donated(i)
            && !crate::gpu::direct::engine_registered(i)
            && crate::gpu::direct::service_registered(i) {
            return Some(i);
        }
    }
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
/// Not a command: poll_engine's "yield budget expired" return, only
/// possible on the bounded parked path (deadline given). Never written
/// to a control page and never reaches handle_command.
pub static LOOP_YIELD: u64 = 4;

 use crate::address::PhysAddr;
extern "Rust" {
    fn wallet_get_apic_id() -> u32;
}

pub fn get_apic_id() -> u32 {
    unsafe { wallet_get_apic_id() }
}
