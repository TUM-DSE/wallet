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

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::process_manager::allocation::AllocationRange;
use crate::process_manager::process_paging::{ProcessPageFlags, ProcessPageTablePage,
                                             ProcessPageTableRef, ProcessTableLevelMapping};
use crate::memory::paging::PerCPUPageMappingGuard;
use crate::interop::memory::read_cr3;
use crate::sev::{pvalidate, rmp_adjust, PvalidateOp, RMPFlags, SevSnpError};
use crate::sev::utils::SvsmError;
use crate::types::PageSize;
use crate::{map_paddr, paddr_as_table, paddr_as_u64_slice, vaddr_as_u64_slice};
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

/// Initial allocation load_init still pays synchronously: 8 MB (or
/// the whole model if smaller). Was 256 MB - with the fused fill the
/// worker outruns the writer from the first quantum, and the big
/// initial chunk's map_region+grant walk was ~1-1.5 s of synchronous
/// register wall the worker makes unnecessary (F1).
pub const INITIAL_PAGES: u64 = 2048;
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
/// Worker-claim bookkeeping. The hacl sha512 handle is a core-
/// agnostic heap pointer: preserved (with HASHED) across a graceful
/// GPU detach, keyed by HASHER_EPOCH + HASHER_LIVE so a re-claimer
/// RESUMES instead of restarting - and never resumes a freed handle
/// (sha512_digest frees it) or another load's (epoch mismatch).
/// WORKER_EPOCH is the claim's epoch; a bump means this load was
/// cancelled or superseded - abort without touching the digest.
static WORKER_HASHER: AtomicU64 = AtomicU64::new(0);
static WORKER_EPOCH: AtomicU64 = AtomicU64::new(0);
static HASHER_EPOCH: AtomicU64 = AtomicU64::new(0);
static HASHER_LIVE: AtomicU64 = AtomicU64::new(0);

/// Parallel-fill state. Unit u = pages [u*512, min((u+1)*512, total))
/// - exactly one PTE table. ALLOC_NEXT is the CAS-only claim cursor
/// (F8: never a blind fetch_add past what is published);
/// ALLOC_PUBLISHED counts units whose PTE tables the coordinator has
/// created (helpers claim only below it, so table creation stays
/// single-writer); UNIT_DONE bits are set with Release by the filler
/// and swept with Acquire by the coordinator - the ONLY non-SeqCst
/// pair in this file, ordering a unit's PTE/pvalidate/zero/grant
/// writes before the watermark that exposes them. SWEEP_UNIT is the
/// completed prefix. MOUNT_EPOCH[core] = the epoch whose range this
/// core mounted at its own slot 6 (0 = none; EPOCH starts at 1).
/// HELPERS_BUSY counts helpers inside a quantum - begin()/finish()/
/// the eager arm drain it before touching state a straggler uses.
/// ALLOC_T0 = rdtsc at the first claim with units outstanding;
/// ALLOC_TSC becomes the SPAN to the last unit's completion (the
/// parallel fill's wall clock, ~linear in the worker count - the T_*
/// buckets stay per-core work SUMS), except on the eager path where
/// grow_to's own measured time lands as before.
#[allow(clippy::declare_interior_mutable_const)]
const AU64_ZERO: AtomicU64 = AtomicU64::new(0);
static ALLOC_NEXT: AtomicU64 = AtomicU64::new(0);
static ALLOC_PUBLISHED: AtomicU64 = AtomicU64::new(0);
static SWEEP_UNIT: AtomicU64 = AtomicU64::new(0);
static UNIT_DONE: [AtomicU64; 2048] = [AU64_ZERO; 2048];
static MOUNT_EPOCH: [AtomicU64; 64] = [AU64_ZERO; 64];
static HELPERS_BUSY: AtomicU64 = AtomicU64::new(0);
static ALLOC_T0: AtomicU64 = AtomicU64::new(0);

/// The mounted flat VA of the store window (slot-6 mount).
const ALLOC_VA: u64 = 0x30000000000;

/// Fill instrumentation: rdtsc deltas per fill_unit phase, reset in
/// begin(), appended to finish()'s measure line AFTER streamed= (the
/// hashing lane's sed carries a trailing .* - appending is safe). No
/// capture() here: one outb per unit is a VM exit (F9).
static T_LOCK_TSC: AtomicU64 = AtomicU64::new(0);
static T_TABLE_TSC: AtomicU64 = AtomicU64::new(0);
static T_PTE_TSC: AtomicU64 = AtomicU64::new(0);
static T_PVAL_TSC: AtomicU64 = AtomicU64::new(0);
static T_ZERO_TSC: AtomicU64 = AtomicU64::new(0);
static T_RMP_TSC: AtomicU64 = AtomicU64::new(0);

fn pages_of(bytes: u64) -> u64 {
    bytes.div_ceil(4096)
}

fn unit_done(u: u64) -> bool {
    UNIT_DONE[(u / 64) as usize].load(Ordering::Acquire) & (1u64 << (u % 64)) != 0
}

fn set_unit_done(u: u64) {
    UNIT_DONE[(u / 64) as usize].fetch_or(1u64 << (u % 64), Ordering::Release);
}

/// This task's page-table handle (the walk root for the slot-6 walk).
fn own_pt() -> ProcessPageTableRef {
    let mut pt = ProcessPageTableRef::default();
    pt.set_external_table(read_cr3().bits() as u64);
    pt
}

/// Clear THIS task's slot-6 mount directly: a helper after an epoch
/// change cannot rely on RANGE0 still describing its stale mount, so
/// no AllocationRange bookkeeping - mounts are per-task private.
fn unmount_own_slot() {
    let (_m, pgd) = paddr_as_u64_slice!(read_cr3());
    pgd[crate::process_manager::allocation::DEFAULT_ALLOCATION_RANGE_MOUNT] = 0;
    crate::interop::memory::flush_tlb_global();
}

/// Drop this core's claim (if it holds one) and its slot-6 mount.
/// Hash state is deliberately NOT touched - that is the preservation
/// detach_core relies on; a stale preserved handle is fenced by the
/// epoch check at the next claim and leaks at worst (parity with the
/// old abort path, which never freed it either).
fn release_core(core: usize) {
    if WORKER.load(Ordering::SeqCst) == core as i64 {
        WORKER.store(WORKER_NONE, Ordering::SeqCst);
    }
    if MOUNT_EPOCH[core].load(Ordering::SeqCst) != 0
        && MOUNT_EPOCH[core].swap(0, Ordering::SeqCst) != 0
    {
        unmount_own_slot();
    }
}

/// Graceful coordinator hand-off, called by the exclusive loop
/// immediately BEFORE it enters poll_engine for a GPU session: that
/// branch precedes the poll_worker call and blocks for the whole
/// session, so a claim held into it starved the stream while
/// STATE_CLAIMED kept the guest's eager fallback off - the writer
/// spun on the watermark FOREVER. Releasing preserves the hash state
/// (see release_core) so the next claimer RESUMES; with no free
/// donated core left, CLAIMED clears and the guest's existing 2 s
/// eager fallback fires. Feature-independent: no crypto symbols, so
/// the rustcrypto/boottime builds (whose poll_worker is a stub) link
/// it unchanged.
pub fn detach_core(core: usize) {
    if WORKER.load(Ordering::SeqCst) == core as i64 {
        log::info!("model stream: worker on core {} detaching for a GPU session \
                    ({} B hashed, state preserved)",
                   core, HASHED.load(Ordering::SeqCst));
    }
    release_core(core);
}

/// A fresh, ZEROED page-table page for the store subtree, granted
/// VMPL1|RWX + VMPL2|RWX at creation: the VMPL1 walker and the guest's
/// hardware walker both READ table pages (and write A/D bits) - grant
/// once here instead of per chunk (the old grant_tables_for pass) or
/// per data page (map_4k_page's 512x-redundant PTE-table RMPADJUST).
/// allocate_page keeps its zeroed-page contract for table pages (F7).
fn new_granted_table_page() -> PhysAddr {
    let page = crate::process_manager::process_memory::allocate_page();
    let (guard, _va) = map_paddr!(page);
    rmp_adjust(guard.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX,
               PageSize::Regular).unwrap();
    rmp_adjust(guard.virt_addr(), RMPFlags::VMPL2 | RMPFlags::RWX,
               PageSize::Regular).unwrap();
    page
}

/// Walk-and-create to the PTE table covering `va` (under the calling
/// task's slot-6 mount), reusing page_walk's deepest-present handle.
/// Missing PMD/PTE tables come from new_granted_table_page. The PGD
/// arm is unreachable while the range is mounted - hitting it means
/// the caller forgot to mount, which nothing downstream survives.
/// `create: false` = lookup only (helpers, whose units the
/// coordinator published): a missing table there is an invariant
/// violation, not a request to race the skeleton - panic.
fn ensure_pte_table(pt: &ProcessPageTableRef, va: VirtAddr, create: bool) -> PhysAddr {
    let table_flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE
        | ProcessPageFlags::USER_ACCESSIBLE | ProcessPageFlags::ACCESSED;
    loop {
        let (_g, pgd_table) = paddr_as_table!(pt.process_page_table);
        match pt.page_walk(&pgd_table, pt.process_page_table, va) {
            ProcessTableLevelMapping::PTE(table_phys, _idx) => return table_phys,
            ProcessTableLevelMapping::PMD(pmd_phys, idx) => {
                if !create {
                    panic!("ensure_pte_table: unpublished unit at {:#x}", u64::from(va));
                }
                let new = new_granted_table_page();
                let (_g2, pmd_table) = paddr_as_table!(pmd_phys);
                pmd_table[idx].set(new, table_flags);
                return new;
            }
            ProcessTableLevelMapping::PUD(pud_phys, idx) => {
                if !create {
                    panic!("ensure_pte_table: unpublished unit at {:#x}", u64::from(va));
                }
                let new = new_granted_table_page();
                let (_g2, pud_table) = paddr_as_table!(pud_phys);
                pud_table[idx].set(new, table_flags);
                // loop: the re-walk descends into the new PMD table
                // and creates the PTE table (once per GiB - cheap).
            }
            ProcessTableLevelMapping::PGD(..) => {
                panic!("ensure_pte_table: range not mounted at slot 6");
            }
        }
    }
}

/// Fused fill of pages [start_page, start_page+count) of the mounted
/// range - ONE PTE table (count <= 512, never crossing a table
/// boundary), through the slot-6 mount. Order is load-bearing:
/// (1) install PTEs (one guard, direct writes - no per-page walk),
/// (2) pvalidate the BUMP-origin pages via the mounted VA (pool pages
///     are pre-validated; FAIL_UNCHANGED = already valid = skip),
/// (3) zero ALL pages via the mounted VA - pool pages carry
///     freed-trustlet/model data; the zero MUST precede any grant
///     issued here (confidentiality),
/// (4) grant VMPL2|RWX per page via the mounted VA (the guest
///     writes the download here; VMPL1 read access is granted by
///     trustlet_read_access at model_channel time, so a per-page
///     VMPL1 grant during the fill is pure waste - table pages DO
///     keep VMPL1, the VMPL1 walker reads them).
/// Not-present->present PTEs need no TLB flush (monitor task and
/// guest walker alike), and pvalidate/rmp_adjust are VA-based, so a
/// guest racing the watermark can only fault-loop itself - no monitor
/// invariant rests on it.
/// false = allocator exhausted: the pages obtained are installed AND
/// validated (delete()'s presence walk recovers them into the free
/// list, whose contract is "pvalidated"), nothing further is; FAILED
/// is set for the guest.
fn fill_unit(pt: &ProcessPageTableRef, start_page: u64, count: usize,
             create_tables: bool) -> bool {
    use crate::utils::tsc::rdtsc;
    debug_assert!(count >= 1 && (start_page as usize & 0x1ff) + count <= 512);
    let va = ALLOC_VA + start_page * 4096;

    let t0 = rdtsc();
    let pte_phys = ensure_pte_table(pt, VirtAddr::from(va), create_tables);
    let t1 = rdtsc();
    T_TABLE_TSC.fetch_add(t1.wrapping_sub(t0), Ordering::SeqCst);

    let mut pages = [PhysAddr::null(); 512];
    let (pool_n, n) = crate::process_manager::process_memory::allocate_pages_batch_unzeroed(&mut pages[..count]);
    let t2 = rdtsc();
    T_LOCK_TSC.fetch_add(t2.wrapping_sub(t1), Ordering::SeqCst);

    let data_flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE
        | ProcessPageFlags::DIRTY | ProcessPageFlags::ACCESSED
        | ProcessPageFlags::USER_ACCESSIBLE;
    {
        let (_g, pte_table) = paddr_as_table!(pte_phys);
        let idx0 = start_page as usize & 0x1ff;
        for i in 0..n {
            pte_table[idx0 + i].set(pages[i], data_flags);
        }
    }
    let t3 = rdtsc();
    T_PTE_TSC.fetch_add(t3.wrapping_sub(t2), Ordering::SeqCst);

    /* Bump pages only: pool pages are pre-validated. Sub-batches keep
       the pvalidate read-lock hold short (core_create_vcpu takes the
       write side). */
    let mut i = pool_n;
    while i < n {
        let end = core::cmp::min(i + 64, n);
        let lock = crate::locking::get_pvalidate_lock().lock_read();
        for j in i..end {
            match pvalidate(VirtAddr::from(va + j as u64 * 4096),
                            PageSize::Regular, PvalidateOp::Valid) {
                Ok(()) => (),
                /* Already valid (a re-installed page after a failed
                   unit): exactly the state we need. An explicit skip,
                   never a blanket ign_cf. */
                Err(SvsmError::SevSnp(SevSnpError::FAIL_UNCHANGED(_))) => (),
                /* Anything else is a monitor bug; a soft failure here
                   would let delete() feed unvalidated pages into the
                   free list. Same severity as validate_and_clear's
                   unwrap. */
                Err(e) => panic!("fill_unit: pvalidate {:#x}: {:?}",
                                 va + j as u64 * 4096, e),
            }
        }
        drop(lock);
        i = end;
    }
    let t4 = rdtsc();
    T_PVAL_TSC.fetch_add(t4.wrapping_sub(t3), Ordering::SeqCst);

    if n < count {
        log::warn!("model stream: allocator exhausted mid-unit ({} of {} pages) - \
                    failing the stream", n, count);
        FAILED.store(1, Ordering::SeqCst);
        return false;
    }

    /* Zero through the mounted VA BEFORE step (4) issues any grant.
       Recycled pool pages may still carry a stale VMPL2 grant from a
       previous model (delete() reclaims without revoking) - those
       bytes were guest-visible in their prior life, so the window
       discloses nothing new; fresh bump pages stay RMP-blocked for
       every non-VMPL0 access until (4). */
    unsafe {
        core::ptr::write_bytes(va as *mut u8, 0, count * 4096);
    }
    let t5 = rdtsc();
    T_ZERO_TSC.fetch_add(t5.wrapping_sub(t4), Ordering::SeqCst);

    for k in 0..count {
        let page_va = VirtAddr::from(va + k as u64 * 4096);
        let _ = rmp_adjust(page_va, RMPFlags::VMPL2 | RMPFlags::RWX, PageSize::Regular);
    }
    T_RMP_TSC.fetch_add(rdtsc().wrapping_sub(t5), Ordering::SeqCst);
    true
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
    while WORKER.load(Ordering::SeqCst) != WORKER_NONE
        || HELPERS_BUSY.load(Ordering::SeqCst) != 0
    {
        if crate::utils::tsc::rdtsc() > deadline {
            log::warn!("model stream: stale worker (core {}, {} helpers) did not \
                        abort - proceeding; a donated core may be stuck",
                       WORKER.load(Ordering::SeqCst),
                       HELPERS_BUSY.load(Ordering::SeqCst));
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
    T_LOCK_TSC.store(0, Ordering::SeqCst);
    T_TABLE_TSC.store(0, Ordering::SeqCst);
    T_PTE_TSC.store(0, Ordering::SeqCst);
    T_PVAL_TSC.store(0, Ordering::SeqCst);
    T_ZERO_TSC.store(0, Ordering::SeqCst);
    T_RMP_TSC.store(0, Ordering::SeqCst);
    BEGIN_TSC.store(crate::utils::tsc::rdtsc(), Ordering::SeqCst);
    FAILED.store(0, Ordering::SeqCst);
    DONE.store(0, Ordering::SeqCst);
    FINISH.store(0, Ordering::SeqCst);
    WORKER.store(WORKER_NONE, Ordering::SeqCst);
    /* Unit cursors start past the initial chunk (a 512-multiple, or
       the whole model - div_ceil skips a partial final unit either
       way, so nothing load_init allocated is ever re-filled). */
    let u0 = range.1.div_ceil(512);
    ALLOC_NEXT.store(u0, Ordering::SeqCst);
    ALLOC_PUBLISHED.store(u0, Ordering::SeqCst);
    SWEEP_UNIT.store(u0, Ordering::SeqCst);
    for w in UNIT_DONE.iter() {
        w.store(0, Ordering::SeqCst);
    }
    ALLOC_T0.store(0, Ordering::SeqCst);
    /* An abandoned load's preserved hasher must not be resumed (its
       epoch is stale anyway); the handle leaks, parity with the old
       abort path. */
    HASHER_LIVE.store(0, Ordering::SeqCst);
    ACTIVE.store(1, Ordering::SeqCst);
}

/// Grow the window to `new_pages` and grant the NEW tail to the
/// guest. Runs on whoever holds the WORKER claim (donated worker or
/// the eager guest vCPU); requires the range mounted on the CALLING
/// task's PML4 (mounts are per-task private). Fused per-2MB fill:
/// fill_unit installs PTEs, validates, zeroes and grants one PTE
/// table per pass, and new table pages are granted at creation - no
/// inflate/map_4k_page walk, no grant_tables_for chunk pass, no
/// per-page VMPL2 loop. The new mappings need no TLB shootdown
/// (not-present -> present is never cached; the trustlet heap-grow
/// path documents the same argument). RANGE_PAGES/WATERMARK publish
/// per unit, so the guest unblocks progressively.
fn grow_to(new_pages: u64) -> bool {
    let cur = RANGE_PAGES.load(Ordering::SeqCst);
    if new_pages <= cur {
        return true;
    }
    let need = new_pages - cur;
    /* need/512: the PTE-table pages the fill itself allocates (PMD/
       PUD are covered by the margin) - the margin alone does not
       cover a 120B eager fill's ~31k table pages. */
    if crate::process_manager::process_memory::pages_available()
        < need + need / 512 + ALLOC_MARGIN_PAGES
    {
        log::warn!("model stream: {} pages needed, allocator low - failing the stream",
                   need);
        FAILED.store(1, Ordering::SeqCst);
        return false;
    }
    let t0 = crate::utils::tsc::rdtsc();
    let pt = own_pt();
    let total = TOTAL.load(Ordering::SeqCst);
    let mut page = cur;
    while page < new_pages {
        let count = core::cmp::min(512 - (page & 0x1ff), new_pages - page) as usize;
        /* UNIT_DONE-aware: a unit a parallel filler completed (its
           bit is set only when the WHOLE unit is filled) is skipped,
           never re-filled - the eager fallback can take over from a
           partially parallel load. Publication uses fetch_max so a
           sweep-advanced watermark is never regressed. */
        let u = page >> 9;
        if (page & 0x1ff) == 0 && unit_done(u) {
            page += count as u64;
        } else {
            if !fill_unit(&pt, page, count, true) {
                ALLOC_TSC.fetch_add(crate::utils::tsc::rdtsc().wrapping_sub(t0),
                                    Ordering::SeqCst);
                return false;
            }
            page += count as u64;
            if (page & 0x1ff) == 0 || page == pages_of(total) {
                set_unit_done(u);
            }
        }
        RANGE_PAGES.fetch_max(page, Ordering::SeqCst);
        WATERMARK.fetch_max(core::cmp::min(page * 4096, total), Ordering::SeqCst);
    }
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
            /* Helpers stop claiming the moment WORKER leaves the
               donated-core range; drain the in-flight ones (bounded -
               at most one fill_unit each) so the sequential fill
               below cannot double-fill a unit a straggler is midway
               through. */
            let drain = crate::utils::tsc::rdtsc()
                .wrapping_add(crate::utils::tsc::ticks_for_secs(5));
            while HELPERS_BUSY.load(Ordering::SeqCst) != 0 {
                if crate::utils::tsc::rdtsc() > drain {
                    log::warn!("model stream: eager fallback proceeding with {} \
                                helper(s) busy", HELPERS_BUSY.load(Ordering::SeqCst));
                    break;
                }
                core::hint::spin_loop();
            }
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
/// loop's idle branch every iteration. CLAIM-OR-HELP: the first core
/// to see the active stream claims it (the COORDINATOR - sole owner
/// of the hasher, the completion sweep and the PTE-table skeleton);
/// every other idle donated core HELPS by CAS-claiming published
/// units and filling them in parallel. Each core keeps the range
/// mounted on ITS OWN task PML4 (mounts are per-task private), keyed
/// by MOUNT_EPOCH, and returns between bites so LOOP_* commands stay
/// responsive.
#[cfg(all(not(feature = "rustcrypto"), not(feature = "boottime")))]
pub fn poll_worker(core: usize) {
    if ACTIVE.load(Ordering::SeqCst) == 0 || FAILED.load(Ordering::SeqCst) != 0 {
        /* Stream over/failed/cancelled: drop a claim this core still
           holds and its slot-6 mount (helper mount hygiene after
           finish()'s epoch bump). */
        release_core(core);
        return;
    }
    let me = core as i64;
    let owner = WORKER.load(Ordering::SeqCst);
    if owner == WORKER_NONE {
        claim(core);
        return;
    }
    if owner == me {
        /* finish() bumps the epoch to cancel a stuck worker; a fresh
           begin() deactivates and bumps it for an abandoned load's
           worker. Either signal drops this claim. */
        if EPOCH.load(Ordering::SeqCst) != WORKER_EPOCH.load(Ordering::SeqCst) {
            log::warn!("model stream: worker aborting - stream cancelled");
            release_core(core);
            return;
        }
        coordinator_quantum(core);
        return;
    }
    if owner >= 0 && owner < 64 {
        helper_quantum(core);
    }
    /* owner == WORKER_EAGER: the guest vCPU owns the allocator role -
       helpers idle so eager and parallel growth never interleave. */
}

/// Claim arm: become the coordinator. On a RE-claim after a graceful
/// GPU detach (detach_core) the preserved hash state is resumed -
/// HASHED marks the resume point.
#[cfg(all(not(feature = "rustcrypto"), not(feature = "boottime")))]
fn claim(core: usize) {
    use crate::crypto::sha512_create;

    let epoch = EPOCH.load(Ordering::SeqCst);
    if WORKER.compare_exchange(WORKER_NONE, core as i64,
                               Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return;
    }
    if EPOCH.load(Ordering::SeqCst) != epoch || ACTIVE.load(Ordering::SeqCst) == 0 {
        WORKER.store(WORKER_NONE, Ordering::SeqCst);
        return;
    }
    /* Preflight the WHOLE remaining need once per claim: the parallel
       unit path bypasses grow_to and its preflight. need/512 covers
       the PTE tables, the margin covers PMD/PUD and races. */
    let total_pages = pages_of(TOTAL.load(Ordering::SeqCst));
    let cur = RANGE_PAGES.load(Ordering::SeqCst);
    if total_pages > cur {
        let need = total_pages - cur;
        if crate::process_manager::process_memory::pages_available()
            < need + need / 512 + ALLOC_MARGIN_PAGES
        {
            log::warn!("model stream: {} pages needed, allocator low - failing the stream",
                       need);
            FAILED.store(1, Ordering::SeqCst);
            WORKER.store(WORKER_NONE, Ordering::SeqCst);
            return;
        }
        let _ = ALLOC_T0.compare_exchange(0, crate::utils::tsc::rdtsc(),
                                          Ordering::SeqCst, Ordering::SeqCst);
    }
    mount_own(core, epoch);
    WORKER_EPOCH.store(epoch, Ordering::SeqCst);
    if HASHER_LIVE.load(Ordering::SeqCst) != 0
        && HASHER_EPOCH.load(Ordering::SeqCst) == epoch
    {
        log::info!("model stream: worker on core {} resumed ({} B hashed)",
                   core, HASHED.load(Ordering::SeqCst));
    } else {
        WORKER_HASHER.store(unsafe { sha512_create() }, Ordering::SeqCst);
        HASHER_EPOCH.store(epoch, Ordering::SeqCst);
        HASHER_LIVE.store(1, Ordering::SeqCst);
        log::info!("model stream: worker on core {} claimed ({} B)",
                   core, TOTAL.load(Ordering::SeqCst));
    }
}

/// (Re)mount the given epoch's range at this core's own slot 6.
#[cfg(all(not(feature = "rustcrypto"), not(feature = "boottime")))]
fn mount_own(core: usize, epoch: u64) {
    if MOUNT_EPOCH[core].load(Ordering::SeqCst) == epoch {
        return;
    }
    if MOUNT_EPOCH[core].swap(0, Ordering::SeqCst) != 0 {
        unmount_own_slot();
    }
    AllocationRange(RANGE0.load(Ordering::SeqCst), 0).mount();
    MOUNT_EPOCH[core].store(epoch, Ordering::SeqCst);
}

/// One coordinator quantum: sweep completions into the watermark,
/// publish PTE-table skeleton, then ONE bounded piece of work (a
/// unit fill under writer pressure, else a hash bite, else the
/// digest).
#[cfg(all(not(feature = "rustcrypto"), not(feature = "boottime")))]
fn coordinator_quantum(core: usize) {
    use crate::crypto::{sha512_digest, sha512_update};
    use crate::utils::tsc::rdtsc;

    /* Belt-and-braces: the exclusive loop detaches BEFORE entering
       poll_engine; this covers a registration racing that branch. */
    if crate::gpu::direct::engine_registered(core) {
        detach_core(core);
        return;
    }

    let total = TOTAL.load(Ordering::SeqCst);
    let total_pages = pages_of(total);
    let n_units = total_pages.div_ceil(512);

    /* (i) completion sweep - every quantum, cheap. The Acquire loads
       in unit_done pair with the fillers' Release fetch_or: a unit's
       PTE/pvalidate/zero/grant writes are ordered before the
       watermark that exposes it (the guest POLLS the watermark via
       update - there is no wakeup to lose). */
    let mut sw = SWEEP_UNIT.load(Ordering::SeqCst);
    while sw < n_units && unit_done(sw) {
        sw += 1;
    }
    SWEEP_UNIT.store(sw, Ordering::SeqCst);
    let done_pages = core::cmp::min(sw * 512, total_pages);
    if done_pages > RANGE_PAGES.load(Ordering::SeqCst) {
        RANGE_PAGES.fetch_max(done_pages, Ordering::SeqCst);
        WATERMARK.fetch_max(core::cmp::min(done_pages * 4096, total),
                            Ordering::SeqCst);
    }
    if sw == n_units && ALLOC_TSC.load(Ordering::SeqCst) == 0 {
        /* Allocation complete: alloc_ms = span from the first claim
           to the last unit's completion - the parallel fill's WALL,
           not the summed work (the T_* buckets carry that). */
        let t0 = ALLOC_T0.load(Ordering::SeqCst);
        if t0 != 0 {
            ALLOC_TSC.store(rdtsc().wrapping_sub(t0), Ordering::SeqCst);
        }
    }

    /* (ii) skeleton publish: create PTE tables ahead of the claim
       cursor, a bounded batch per quantum. Helpers only claim BELOW
       ALLOC_PUBLISHED, so table creation stays single-writer (and
       F8's CAS cursor never passes it). Never done in load_init -
       that would re-serialize the table creation into the register
       wall (F6). */
    let published = ALLOC_PUBLISHED.load(Ordering::SeqCst);
    if published < n_units {
        let goal = core::cmp::min(n_units, published + 32);
        let pt = own_pt();
        let t0 = rdtsc();
        for u in published..goal {
            ensure_pte_table(&pt, VirtAddr::from(ALLOC_VA + u * 512 * 4096), true);
        }
        T_TABLE_TSC.fetch_add(rdtsc().wrapping_sub(t0), Ordering::SeqCst);
        ALLOC_PUBLISHED.store(goal, Ordering::SeqCst);
        return; // one quantum
    }

    /* (iii) one bounded piece of work. Writer pressure or an idle
       hasher -> pull a unit ourselves (same CAS protocol as the
       helpers); otherwise hash - helpers keep the cursor moving. */
    let written = WRITTEN.load(Ordering::SeqCst);
    let hashed = HASHED.load(Ordering::SeqCst);
    let hash_limit = core::cmp::min(written,
                                    RANGE_PAGES.load(Ordering::SeqCst) * 4096);
    let units_left = ALLOC_NEXT.load(Ordering::SeqCst) < n_units;
    let hash_ready = hashed < hash_limit;
    let pressure = WATERMARK.load(Ordering::SeqCst)
        < core::cmp::min(written + LOOKAHEAD_PAGES * 4096, total);
    if units_left && (pressure || !hash_ready) {
        claim_and_fill_one_unit();
        return;
    }
    if hash_ready {
        let len = core::cmp::min(HASH_BITE, hash_limit - hashed) as u32;
        let t0 = rdtsc();
        unsafe {
            sha512_update((ALLOC_VA + hashed) as *mut u8, len,
                          WORKER_HASHER.load(Ordering::SeqCst));
        }
        HASH_TSC.fetch_add(rdtsc().wrapping_sub(t0), Ordering::SeqCst);
        HASHED.store(hashed + len as u64, Ordering::SeqCst);
        return;
    }
    if FINISH.load(Ordering::SeqCst) != 0 && hashed == total {
        let t0 = rdtsc();
        /* sha512_digest frees the hacl state - kill the resume flag
           BEFORE the claim release could let anyone resume it. */
        HASHER_LIVE.store(0, Ordering::SeqCst);
        unsafe {
            sha512_digest(DIGEST.as_mut_ptr(),
                          WORKER_HASHER.load(Ordering::SeqCst));
        }
        HASH_TSC.fetch_add(rdtsc().wrapping_sub(t0), Ordering::SeqCst);
        if MOUNT_EPOCH[core].swap(0, Ordering::SeqCst) != 0 {
            unmount_own_slot();
        }
        DONE.store(1, Ordering::Release);
        WORKER.store(WORKER_NONE, Ordering::SeqCst);
        // The core returns to its idle loop - back to sleep.
    }
}

/// Helper quantum: idle donated cores (not the claim owner) pull
/// published units in parallel with the coordinator. HELPERS_BUSY is
/// announced FIRST and the gates re-checked after, so the drains in
/// begin()/finish()/the eager arm never miss an in-flight fill.
#[cfg(all(not(feature = "rustcrypto"), not(feature = "boottime")))]
fn helper_quantum(core: usize) {
    HELPERS_BUSY.fetch_add(1, Ordering::SeqCst);
    let owner = WORKER.load(Ordering::SeqCst);
    let epoch = EPOCH.load(Ordering::SeqCst);
    if ACTIVE.load(Ordering::SeqCst) != 0
        && FAILED.load(Ordering::SeqCst) == 0
        && owner >= 0 && owner < 64 && owner != core as i64
        && epoch == WORKER_EPOCH.load(Ordering::SeqCst)
    {
        mount_own(core, epoch);
        claim_and_fill_one_unit();
    }
    HELPERS_BUSY.fetch_sub(1, Ordering::SeqCst);
}

/// CAS-claim the next published unit and fill it through this task's
/// own mount. Shared by coordinator pulls and helpers - one code
/// path, one failure behavior (fill_unit sets FAILED and the claimed
/// index is abandoned: FAILED ends the stream for everyone).
#[cfg(all(not(feature = "rustcrypto"), not(feature = "boottime")))]
fn claim_and_fill_one_unit() {
    let published = ALLOC_PUBLISHED.load(Ordering::SeqCst);
    loop {
        let u = ALLOC_NEXT.load(Ordering::SeqCst);
        if u >= published {
            return;
        }
        if ALLOC_NEXT.compare_exchange(u, u + 1, Ordering::SeqCst,
                                       Ordering::SeqCst).is_err() {
            continue;
        }
        let total_pages = pages_of(TOTAL.load(Ordering::SeqCst));
        let start = u * 512;
        let count = core::cmp::min(512, total_pages - start) as usize;
        let pt = own_pt();
        if fill_unit(&pt, start, count, false) {
            set_unit_done(u);
        }
        return;
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
    /* Helpers observe the bump/deactivation at their next gate check
       and never start a new unit; drain the in-flight ones (bounded -
       at most one fill_unit each) before the caller mounts the range
       for the synchronous fallback, revokes write access, or a later
       delete() tears the subtree down under a straggler. */
    let drain = rdtsc().wrapping_add(ticks_for_secs(5));
    while HELPERS_BUSY.load(Ordering::SeqCst) != 0 {
        if rdtsc() > drain {
            log::warn!("model stream: {} helper(s) still busy 5 s after finish - \
                        proceeding", HELPERS_BUSY.load(Ordering::SeqCst));
            break;
        }
        core::hint::spin_loop();
    }
    let ms = |tsc: u64| tsc / (TSC_HZ / 1000);
    log::info!("model measure: {} B hash_ms={} alloc_ms={} wall_ms={} streamed={} \
                alloc_lock_ms={} alloc_pte_ms={} alloc_pval_ms={} alloc_zero_ms={} \
                alloc_rmp_ms={} alloc_table_ms={}",
               TOTAL.load(Ordering::SeqCst),
               ms(HASH_TSC.load(Ordering::SeqCst)),
               ms(ALLOC_TSC.load(Ordering::SeqCst)),
               ms(rdtsc().wrapping_sub(BEGIN_TSC.load(Ordering::SeqCst))),
               digest.is_some() as u32,
               ms(T_LOCK_TSC.load(Ordering::SeqCst)),
               ms(T_PTE_TSC.load(Ordering::SeqCst)),
               ms(T_PVAL_TSC.load(Ordering::SeqCst)),
               ms(T_ZERO_TSC.load(Ordering::SeqCst)),
               ms(T_RMP_TSC.load(Ordering::SeqCst)),
               ms(T_TABLE_TSC.load(Ordering::SeqCst)));
    digest
}
