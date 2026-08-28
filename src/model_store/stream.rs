/// Streaming model-store load: while the guest downloads into the
/// store window, ONE donated core allocates the window ahead of the
/// writer and SHA-512-hashes behind it, so load_init shrinks to an
/// initial chunk and load_fin only drains a small hash tail. The
/// guest's curl write callback announces progress with the cheap
/// ModelStreamUpdate call and spins on the allocation watermark only
/// when a chunk would cross it.
///
/// Single stream instance (vmpl.ko serializes loaders with a kernel
/// semaphore). Field ownership, in the unlocked-static style the
/// watchdog uses: the guest vCPU writes WRITTEN (its monitor call)
/// and runs the REQUEST_EAGER fallback; the claimed worker owns
/// RANGE_PAGES/WATERMARK/HASHED/DIGEST/hasher; begin/finish (both on
/// the loading vCPU, serialized by the kernel lock) own the
/// lifecycle. Cross-core reads are aligned u64 atomics.
///
/// Write-once contract: curl appends sequentially and never rewrites
/// [0, written) - the hashed prefix and the granted tail are stable.
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use crate::address::{Address, VirtAddr};
use crate::process_manager::allocation::AllocationRange;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::interop::memory::read_cr3;
use crate::sev::{rmp_adjust, RMPFlags};
use crate::types::PageSize;
use crate::{MonitorError, RequestParams};

/// Guest request flag (rdx): allocate the rest synchronously on the
/// calling vCPU - the no-worker fallback, the legacy cost paid once.
pub const REQUEST_EAGER: u64 = 1 << 0;

/// Reply state bits, packed into rcx bits 56.. (the watermark lives
/// in bits 0..56; a single-register reply because the guest kernel's
/// svsm_call only surfaces rcx_out).
pub const STATE_ACTIVE: u64 = 1 << 56;
pub const STATE_CLAIMED: u64 = 1 << 57;
pub const STATE_FAILED: u64 = 1 << 58;
const WATERMARK_MASK: u64 = (1 << 56) - 1;

/// Initial allocation load_init still pays synchronously: 256 MB (or
/// the whole model if smaller).
pub const INITIAL_PAGES: u64 = 65536;
/// The worker keeps the window this far ahead of the writer.
const LOOKAHEAD_PAGES: u64 = 16384; // 64 MB
/// One hash quantum per poll - the worker returns to the exclusive
/// loop between bites so LOOP_* commands stay responsive.
const HASH_BITE: u64 = 16 << 20;
/// Refuse to grow within this many pages of allocator exhaustion -
/// a clean stream failure, never allocate_page's panic.
const ALLOC_MARGIN_PAGES: u64 = 1024;

const WORKER_NONE: i64 = -1;
/// The guest vCPU claims the allocator role for REQUEST_EAGER through
/// the same slot, so worker and eager growth can never interleave.
const WORKER_EAGER: i64 = 1000;

static EPOCH: AtomicU64 = AtomicU64::new(0);
static ACTIVE: AtomicU64 = AtomicU64::new(0);
static RANGE0: AtomicU64 = AtomicU64::new(0);
static RANGE_PAGES: AtomicU64 = AtomicU64::new(0);
static TOTAL: AtomicU64 = AtomicU64::new(0);
static WATERMARK: AtomicU64 = AtomicU64::new(0);
static WRITTEN: AtomicU64 = AtomicU64::new(0);
static HASHED: AtomicU64 = AtomicU64::new(0);
static HASH_TSC: AtomicU64 = AtomicU64::new(0);
static ALLOC_TSC: AtomicU64 = AtomicU64::new(0);
static BEGIN_TSC: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static FINISH: AtomicU64 = AtomicU64::new(0);
static WORKER: AtomicI64 = AtomicI64::new(WORKER_NONE);
/// Written by the worker before the DONE release-store; read by
/// finish() after the DONE acquire-load.
static mut DIGEST: [u8; 64] = [0; 64];
/// Worker-only after claim: hacl sha512 state handle, mount flag and
/// the epoch the claim belongs to (a bumped epoch = this load was
/// cancelled or superseded - abort without touching the digest).
static WORKER_HASHER: AtomicU64 = AtomicU64::new(0);
static WORKER_MOUNTED: AtomicU64 = AtomicU64::new(0);
static WORKER_EPOCH: AtomicU64 = AtomicU64::new(0);

fn pages_of(bytes: u64) -> u64 {
    bytes.div_ceil(4096)
}

/// Arm the stream. Called from load_init on the loading vCPU, after
/// the INITIAL allocation+grant, with the range as allocated so far.
/// The kernel semaphore serializes loaders, so the only concurrency
/// here is a leftover worker from an ABANDONED load (curl died, fin
/// never ran): deactivate, then wait briefly for it to abort at its
/// next quantum before resetting the state it owns.
pub fn begin(range: &AllocationRange, total_bytes: u64) {
    EPOCH.fetch_add(1, Ordering::SeqCst);
    ACTIVE.store(0, Ordering::SeqCst);
    let deadline = crate::utils::tsc::rdtsc()
        .wrapping_add(crate::utils::tsc::ticks_for_secs(2));
    while WORKER.load(Ordering::SeqCst) != WORKER_NONE {
        if crate::utils::tsc::rdtsc() > deadline {
            log::warn!("model stream: stale worker (core {}) did not abort - \
                        proceeding; its donated core may be stuck",
                       WORKER.load(Ordering::SeqCst));
            break;
        }
        core::hint::spin_loop();
    }
    RANGE0.store(range.0, Ordering::SeqCst);
    RANGE_PAGES.store(range.1, Ordering::SeqCst);
    TOTAL.store(total_bytes, Ordering::SeqCst);
    WATERMARK.store(core::cmp::min(range.1 * 4096, total_bytes), Ordering::SeqCst);
    WRITTEN.store(0, Ordering::SeqCst);
    HASHED.store(0, Ordering::SeqCst);
    HASH_TSC.store(0, Ordering::SeqCst);
    ALLOC_TSC.store(0, Ordering::SeqCst);
    BEGIN_TSC.store(crate::utils::tsc::rdtsc(), Ordering::SeqCst);
    FAILED.store(0, Ordering::SeqCst);
    DONE.store(0, Ordering::SeqCst);
    FINISH.store(0, Ordering::SeqCst);
    WORKER.store(WORKER_NONE, Ordering::SeqCst);
    ACTIVE.store(1, Ordering::SeqCst);
}

/// Grow the window to `new_pages` and grant the NEW tail to the
/// guest. Runs on whoever holds the WORKER claim (donated worker or
/// the eager guest vCPU); requires the range mounted on the CALLING
/// task's PML4 (mounts are per-task private). inflate() alone is not
/// enough: it skips the VMPL2 grant, and its new mappings need no TLB
/// shootdown (not-present -> present is never cached; the trustlet
/// heap-grow path documents the same argument).
fn grow_to(new_pages: u64) -> bool {
    let cur = RANGE_PAGES.load(Ordering::SeqCst);
    if new_pages <= cur {
        return true;
    }
    let need = new_pages - cur;
    if crate::process_manager::process_memory::pages_available()
        < need + ALLOC_MARGIN_PAGES
    {
        log::warn!("model stream: {} pages needed, allocator low - failing the stream",
                   need);
        FAILED.store(1, Ordering::SeqCst);
        return false;
    }
    let t0 = crate::utils::tsc::rdtsc();
    let mut range = AllocationRange(RANGE0.load(Ordering::SeqCst), cur);
    let mut pt = ProcessPageTableRef::default();
    pt.set_external_table(read_cr3().bits() as u64);
    range.inflate(&mut pt, new_pages, 0x30000000000u64);
    /* The VMPL2 write grant inflate() does not do - tail pages only,
       via the mounted VA (the data-page half of guest_write_access). */
    for i in cur..new_pages {
        let _ = rmp_adjust(VirtAddr::from(0x30000000000u64 + i * 4096),
                           RMPFlags::VMPL2 | RMPFlags::RWX, PageSize::Regular);
    }
    RANGE_PAGES.store(new_pages, Ordering::SeqCst);
    let total = TOTAL.load(Ordering::SeqCst);
    WATERMARK.store(core::cmp::min(new_pages * 4096, total), Ordering::SeqCst);
    ALLOC_TSC.fetch_add(crate::utils::tsc::rdtsc().wrapping_sub(t0), Ordering::SeqCst);
    true
}

fn reply(params: &mut RequestParams) {
    let mut state = 0u64;
    if ACTIVE.load(Ordering::SeqCst) != 0 {
        state |= STATE_ACTIVE;
    }
    if WORKER.load(Ordering::SeqCst) != WORKER_NONE || DONE.load(Ordering::SeqCst) != 0 {
        state |= STATE_CLAIMED;
    }
    if FAILED.load(Ordering::SeqCst) != 0 {
        state |= STATE_FAILED;
    }
    params.rcx = (WATERMARK.load(Ordering::SeqCst) & WATERMARK_MASK) | state;
}

/// ModelStreamUpdate handler (guest vCPU, O(1) on the hot path):
/// record download progress, report the watermark. REQUEST_EAGER is
/// the no-worker fallback: allocate everything remaining right here.
pub fn update(params: &mut RequestParams) -> Result<(), MonitorError> {
    if ACTIVE.load(Ordering::SeqCst) == 0 {
        params.rcx = 0;
        return Ok(());
    }
    let total = TOTAL.load(Ordering::SeqCst);
    let announced = core::cmp::min(params.rcx, total);
    WRITTEN.fetch_max(announced, Ordering::SeqCst);

    if params.rdx & REQUEST_EAGER != 0 {
        /* Claim the allocator role so a late worker cannot interleave
           growth. If a worker already holds it, just report - it is
           making progress. */
        if WORKER.compare_exchange(WORKER_NONE, WORKER_EAGER,
                                   Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            let range = AllocationRange(RANGE0.load(Ordering::SeqCst),
                                        RANGE_PAGES.load(Ordering::SeqCst));
            range.mount();
            let ok = grow_to(pages_of(total));
            range.unmount();
            WORKER.store(WORKER_NONE, Ordering::SeqCst);
            if ok {
                log::info!("model stream: eager allocation fallback served \
                            ({} pages)", pages_of(total));
            }
        }
    }
    reply(params);
    Ok(())
}

/// One bounded quantum of worker progress; called from the donated
/// loop's heartbeat branch every iteration. Claims the stream on
/// first sight, keeps the range mounted on ITS OWN task PML4 across
/// quanta (the donated core never migrates while donated), and
/// returns between bites so LOOP_* commands stay responsive.
#[cfg(all(not(feature = "rustcrypto"), not(feature = "boottime")))]
pub fn poll_worker(core: usize) {
    use crate::crypto::{sha512_create, sha512_digest, sha512_update};

    if ACTIVE.load(Ordering::SeqCst) == 0 || FAILED.load(Ordering::SeqCst) != 0 {
        return;
    }
    let me = core as i64;
    let owner = WORKER.load(Ordering::SeqCst);
    if owner == WORKER_NONE {
        let epoch = EPOCH.load(Ordering::SeqCst);
        if WORKER.compare_exchange(WORKER_NONE, me,
                                   Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return;
        }
        if EPOCH.load(Ordering::SeqCst) != epoch {
            WORKER.store(WORKER_NONE, Ordering::SeqCst);
            return;
        }
        let range = AllocationRange(RANGE0.load(Ordering::SeqCst),
                                    RANGE_PAGES.load(Ordering::SeqCst));
        range.mount();
        WORKER_MOUNTED.store(1, Ordering::SeqCst);
        WORKER_EPOCH.store(epoch, Ordering::SeqCst);
        WORKER_HASHER.store(unsafe { sha512_create() }, Ordering::SeqCst);
        log::info!("model stream: worker on core {} claimed ({} B)",
                   core, TOTAL.load(Ordering::SeqCst));
        return;
    }
    if owner != me {
        return;
    }

    let abort = |msg: &str| {
        log::warn!("model stream: worker aborting - {}", msg);
        if WORKER_MOUNTED.swap(0, Ordering::SeqCst) != 0 {
            AllocationRange(RANGE0.load(Ordering::SeqCst),
                            RANGE_PAGES.load(Ordering::SeqCst)).unmount();
        }
        WORKER.store(WORKER_NONE, Ordering::SeqCst);
    };

    /* finish() bumps the epoch to cancel a stuck worker; a fresh
       begin() deactivates and bumps it for an abandoned load's
       worker. Either signal aborts this claim. */
    if ACTIVE.load(Ordering::SeqCst) == 0
        || EPOCH.load(Ordering::SeqCst) != WORKER_EPOCH.load(Ordering::SeqCst)
    {
        abort("stream cancelled");
        return;
    }

    let total = TOTAL.load(Ordering::SeqCst);
    let written = WRITTEN.load(Ordering::SeqCst);
    let cur_pages = RANGE_PAGES.load(Ordering::SeqCst);

    /* Allocation first: the window must outrun the writer. Grow one
       lookahead chunk whenever the writer is within a chunk of the
       watermark. */
    if cur_pages * 4096 < total
        && pages_of(written) + LOOKAHEAD_PAGES >= cur_pages
    {
        let target = core::cmp::min(pages_of(total), cur_pages + LOOKAHEAD_PAGES);
        if !grow_to(target) {
            abort("allocation shortage");
            return;
        }
        return; // one quantum
    }

    /* Hash behind the writer, one bite per quantum. HASH_TSC is the
       PURE hash cost - the benchmarks need it separately from the
       download it hides behind. */
    let hashed = HASHED.load(Ordering::SeqCst);
    let limit = core::cmp::min(written, RANGE_PAGES.load(Ordering::SeqCst) * 4096);
    if hashed < limit {
        let len = core::cmp::min(HASH_BITE, limit - hashed) as u32;
        let t0 = crate::utils::tsc::rdtsc();
        unsafe {
            sha512_update((0x30000000000u64 + hashed) as *mut u8, len,
                          WORKER_HASHER.load(Ordering::SeqCst));
        }
        HASH_TSC.fetch_add(crate::utils::tsc::rdtsc().wrapping_sub(t0),
                           Ordering::SeqCst);
        HASHED.store(hashed + len as u64, Ordering::SeqCst);
        return;
    }

    if FINISH.load(Ordering::SeqCst) != 0 && hashed == total {
        let t0 = crate::utils::tsc::rdtsc();
        unsafe {
            sha512_digest(DIGEST.as_mut_ptr(), WORKER_HASHER.load(Ordering::SeqCst));
        }
        HASH_TSC.fetch_add(crate::utils::tsc::rdtsc().wrapping_sub(t0),
                           Ordering::SeqCst);
        if WORKER_MOUNTED.swap(0, Ordering::SeqCst) != 0 {
            AllocationRange(RANGE0.load(Ordering::SeqCst),
                            RANGE_PAGES.load(Ordering::SeqCst)).unmount();
        }
        DONE.store(1, Ordering::Release);
        WORKER.store(WORKER_NONE, Ordering::SeqCst);
        // The core returns to its idle loop - back to sleep.
    }
}

#[cfg(any(feature = "rustcrypto", feature = "boottime"))]
pub fn poll_worker(_core: usize) {}

/// The final page count after worker/eager growth - load_fin needs it
/// so the store entry, the revoke walk and the legacy fallback cover
/// the whole grown range.
pub fn final_pages() -> u64 {
    RANGE_PAGES.load(Ordering::SeqCst)
}

pub fn is_active() -> bool {
    ACTIVE.load(Ordering::SeqCst) != 0
}

/// Consume the stream at load_fin. Some(digest) when the worker
/// finished; None -> caller falls back to the legacy full measure().
/// Either way the stream deactivates and ONE parseable line reports
/// the split the benchmark lanes need: pure hash time vs the wall
/// time it overlapped.
pub fn finish() -> Option<[u8; 64]> {
    use crate::utils::tsc::{rdtsc, ticks_for_secs, TSC_HZ};

    if ACTIVE.load(Ordering::SeqCst) == 0 {
        return None;
    }
    FINISH.store(1, Ordering::SeqCst);
    let deadline = rdtsc().wrapping_add(ticks_for_secs(120));
    let digest = loop {
        if DONE.load(Ordering::Acquire) != 0 {
            break Some(unsafe { DIGEST });
        }
        if WORKER.load(Ordering::SeqCst) == WORKER_NONE {
            break None; // never claimed (or eager-only): nobody will finish
        }
        if rdtsc() > deadline {
            /* Cancel the stuck worker: it aborts at its next quantum
               via the epoch/active checks. */
            log::warn!("model stream: worker did not finish within 120 s - \
                        falling back to the synchronous measure");
            break None;
        }
    };
    ACTIVE.store(0, Ordering::SeqCst);
    EPOCH.fetch_add(1, Ordering::SeqCst);
    let ms = |tsc: u64| tsc / (TSC_HZ / 1000);
    log::info!("model measure: {} B hash_ms={} alloc_ms={} wall_ms={} streamed={}",
               TOTAL.load(Ordering::SeqCst),
               ms(HASH_TSC.load(Ordering::SeqCst)),
               ms(ALLOC_TSC.load(Ordering::SeqCst)),
               ms(rdtsc().wrapping_sub(BEGIN_TSC.load(Ordering::SeqCst))),
               digest.is_some() as u32);
    digest
}
