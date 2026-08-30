extern crate alloc;
use crate::process_manager::memory_channels::MemoryChannel;
use crate::attestation::monitor::ProcessMeasurements;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::address::PhysAddr;
use crate::address::VirtAddr;
use cpuarch::vmsa::VMSA;
use core::cell::UnsafeCell;
use crate::process_manager::allocation::AllocationRange;
use alloc::vec::Vec;
use crate::process_runtime::process::mmap::MmapManager;
use crate::process_manager::exception_handling::gdt_trustlet;
use crate::process_manager::process_paging::revoke_and_free;
use crate::process_manager::exception_handling::tss_trustlet;
use crate::process_manager::exception_handling::asm_entry_trustlet_pf;
use crate::process_manager::exception_handling::gdt_desc;
use crate::process_manager::exception_handling::idt_trustlet;

#[cfg(not(feature = "no_cow"))]
pub mod process_cow;

#[cfg(feature = "no_cow")]
pub mod process_no_cow;

#[cfg(not(feature = "no_cow"))]
pub use process_cow::*;

#[cfg(feature = "no_cow")]
pub use process_no_cow::*;


#[derive(Debug, Copy, Clone)]
pub struct ProcessContext {
    pub base: ProcessBaseContext,
    pub vmsa: PhysAddr,
    pub channel: MemoryChannel,
    pub sev_features: u64,
    pub measurements: ProcessMeasurements,
    pub page_table_ref: ProcessPageTableRef,
}

impl Default for ProcessContext {
    fn default() -> Self {
        return ProcessContext {
            base: ProcessBaseContext::default(),
            vmsa: PhysAddr::null(),
            channel: MemoryChannel::default(),
            sev_features: 0,
            measurements: ProcessMeasurements::default(),
            page_table_ref: ProcessPageTableRef::default(),
        }
    }
}

trait FromVAddr {
    fn from_virt_addr(v: VirtAddr) -> &'static mut VMSA;
}

impl FromVAddr for VMSA {
    fn from_virt_addr(v: VirtAddr) -> &'static mut VMSA{
        unsafe { v.as_mut_ptr::<VMSA>().as_mut().unwrap() }
    }
}

#[derive(Clone,Copy,Debug,PartialEq)]
pub enum TrustedProcessType {
    Undefined,
    Zygote,
    Trustlet,
}

pub static PROCESS_STORE: TrustedProcessStore = TrustedProcessStore::new();

#[derive(Debug)]
pub struct TrustedProcessStore{
    processes: UnsafeCell<Vec<TrustedProcess>>,
}

unsafe impl Sync for TrustedProcessStore {}

impl TrustedProcessStore {
    const fn new() -> Self {
        Self {
            processes: UnsafeCell::new(Vec::new()),
        }
    }
    fn push(&self, process: TrustedProcess) {
        let ptr: &mut Vec<TrustedProcess> = unsafe { self.processes.get().as_mut().unwrap() };
        ptr.push(process);
    }
    pub fn init(&self, size: u32){
        for _ in 0..size  {
            let empty_process = TrustedProcess::empty();
            self.push(empty_process);
        }
    }
    pub fn insert(&self, mut p: TrustedProcess) -> i64 {
        let ptr: &mut Vec<TrustedProcess> = unsafe { self.processes.get().as_mut().unwrap() };
        for i in 0..(ptr.len()) {
            if ptr[i].process_type == TrustedProcessType::Undefined {
                // ID of the Process is set when inserting into the
                // store. Only after the insert is the process id valid
                p.id = i.try_into().unwrap();
                ptr[i] = p;
                return i.try_into().unwrap();
            }
        }
        -1
    }

    /// Number of process slots. `get` indexes straight into the Vec,
    /// so anything taking an id from a trustlet must bounds-check with
    /// this first rather than panicking the monitor.
    pub fn len(&self) -> usize {
        let ptr = unsafe { self.processes.get().as_ref().unwrap() };
        ptr.len()
    }

    pub fn get(&self, pid: ProcessID) -> &mut TrustedProcess {
        let ptr = unsafe { self.processes.get().as_mut().unwrap() };
        &mut ptr[pid.0]
    }

    pub fn delete(&self, pid: ProcessID) {
        let ptr: &mut Vec<TrustedProcess> = unsafe { self.processes.get().as_mut().unwrap() };
        ptr[pid.0] = TrustedProcess::empty();
    }
}

#[derive(Clone,Copy,Debug, Default)]
pub struct ProcessID(pub usize);

#[derive(Debug, Copy, Clone)]
pub struct ProcessBaseContext {
    pub page_table_ref: ProcessPageTableRef,
    pub entry_point: VirtAddr,
    pub alloc_range: AllocationRange,
    pub alloc_range_manifest: AllocationRange,
    pub alloc_range_libos: AllocationRange,
    pub alloc_range_function: AllocationRange,
}

impl Default for ProcessBaseContext {
  fn default() -> Self {
      return ProcessBaseContext {
          page_table_ref: ProcessPageTableRef::default(),
          entry_point: VirtAddr::null(),
          alloc_range: AllocationRange(0,0),
          alloc_range_manifest: AllocationRange(0,0),
          alloc_range_libos: AllocationRange(0,0),
          alloc_range_function: AllocationRange(0,0),
      }
  }
}

/* No Clone: Drop now frees the process page table and VMSA (F4).
   A cloned-and-dropped TrustedProcess would free a LIVE process's
   memory - make that unrepresentable. */
#[derive(Debug)]
pub struct TrustedProcess {
    pub process_type: TrustedProcessType,
    pub id: u64,
    pub parent_id: u64,
    //#[cfg(feature = "attestation_benchmark")]
    pub base: ProcessBaseContext,
    pub measurements: ProcessMeasurements,
    #[allow(dead_code)]
    pub context: ProcessContext,
    pub mmap_manager: MmapManager,
    pub pf_target_vaddr: u64,
    pub infer_context: AllocationRange,
    /// Set when the trustlet is gone for good - it exited, hit a PAL
    /// error, or took an exception the monitor could not handle.
    /// invoke_trustlet refuses to resume it (resuming an exited
    /// context #GPs on garbage state, and the un-set return values
    /// then read as a guest-request code, which retries forever -
    /// observed 2026-08-25, see PLAN.md).
    pub dead: bool,
    /// GPU engine slot (donated core) this trustlet registered via
    /// gpu_channel; -1 = none. Freed when the trustlet dies so the
    /// core is reusable without the replacement fallback.
    pub gpu_core: i64,
    /// True while a vCPU is inside this trustlet's execution loop
    /// (invoke_trustlet or a nested call_trustlet). Deletion requires
    /// !running: an idle trustlet's VMSA is not loaded and no walk of
    /// its page table is in flight, so teardown is safe even if it
    /// never exited (F4 - session trustlets park between invokes and
    /// are deleted while idle-alive).
    pub running: bool,
    /// APIC id of the vCPU inside this trustlet's invoke loop
    /// (u32::MAX = none). Attribution for the watchdog only; written
    /// only by the owning vCPU, donated pollers just read it.
    pub invoke_owner_apic: u32,
    /// rdtsc at invoke entry (0 = no invoke in flight). Same ownership
    /// contract as invoke_owner_apic; the poller compares it against
    /// INVOKE_BUDGET_SECS to spot invokes the in-loop watchdog cannot
    /// reach (silent VMPL1 spins).
    pub invoke_start_tsc: u64,
    /// rax of the last process call dispatched for this trustlet, and
    /// whether the vCPU is still inside its handler. Written by the
    /// owning vCPU (handle_process_request entry / invoke-loop
    /// return); the watchdog poller reads them to split "stuck inside
    /// monitor call X" from "spinning silently at VMPL1 after call X"
    /// - the two stall families need different fixes.
    pub last_pcall: u64,
    pub in_pcall: bool,
}

impl ProcessBaseContext {
    pub fn init(&mut self, elf: VirtAddr, size: u64) {
        let mut ptr = ProcessPageTableRef::default();
        self.entry_point = ptr.build_from_file(elf, size);
        self.page_table_ref = ptr;
    }

    #[allow(unused_variables)]
    pub fn add_manifest(&mut self, manifest: VirtAddr, size: u64, data: AllocationRange) {
        //let orig_size = size;
        let size = (4096 - (size & 0xFFF)) + size;
        self.page_table_ref.add_manifest(manifest, size);
        //self.alloc_range_manifest.0 = data.0;
        //self.alloc_range_manifest.1 = orig_size;
    }

    #[allow(unused_variables)]
    pub fn add_libos(&mut self, libos: VirtAddr, size: u64, data: AllocationRange){
        let orig_size = size;
        let size = (4096 - (size & 0xFFF)) + size;
        self.page_table_ref.add_libos(libos,size);
        //self.alloc_range_libos.0 = data.0;
        //self.alloc_range_libos.1 = orig_size;
    }

    /// Fused replacement for copy_data_from_guest + measure +
    /// add_libos on the libos blob: install straight from the guest
    /// walk, hash inline, return the measurement. Same installed
    /// layout as add_libos (incl. its +1-page rounding, zeroed).
    pub fn add_libos_from_guest(&mut self, guest_va: u64, size: u64,
                                guest_pgt: u64) -> [u8; 64] {
        self.page_table_ref.install_libos_from_guest(guest_va, size, guest_pgt)
    }

    #[allow(unused_variables)]
    pub fn init_with_data(&mut self, elf: VirtAddr, size: u64, data: AllocationRange) {
        self.init(elf, size);
        //self.alloc_range.0 = data.0;
        //self.alloc_range.1 = size;
    }

}

pub fn check_vmsa_ind(new: &VMSA, sev_features: u64, svme_mask: u64, vmpl_level: u64) -> bool {
    new.vmpl == vmpl_level as u8
        && new.efer & svme_mask == svme_mask
        && new.sev_features == sev_features
}

impl TrustedProcess {
    fn dublicate(pid: ProcessID) -> TrustedProcess {
        let process = PROCESS_STORE.get(pid);
        let base: ProcessBaseContext = process.base;
        let measurements: ProcessMeasurements = process.measurements;
        let mut context = ProcessContext::default();
        context.init(base, measurements, process.context);
        let inf = AllocationRange(0,0);
        //inf.allocate_trustlet(512);
        //inf.allocate_inference(512);

        TrustedProcess {
            process_type: TrustedProcessType::Trustlet,
            id: 0,
            parent_id: pid.0 as u64, // set the id of the parent zygote
            base,
            measurements,
            context,
            mmap_manager: MmapManager::new(),
            pf_target_vaddr: 0,
            infer_context: inf,
            dead: false,
            gpu_core: -1,
            running: false,
            invoke_owner_apic: u32::MAX,
            invoke_start_tsc: 0,
            last_pcall: 0,
            in_pcall: false,
        }

    }
}

/// Leaf pages the page-table teardown must never free: monitor-global
/// idt/gdt/tss/#PF-entry pages that setup_exceptions maps into EVERY
/// process page table. Load-bearing for the zygote's cow_descend walk
/// (F4): finalize runs after setup_exceptions, so these are CoW-marked
/// in the zygote PT and would otherwise be walked and freed - putting
/// monitor .text/.data into the pool, where the allocator's pop path
/// zero-fills it.
fn exception_keep_list() -> [VirtAddr; 5] {
    [
        idt_trustlet().base_limit().0.into(),
        (asm_entry_trustlet_pf as u64).into(),
        unsafe { &gdt_desc as *const u8 as u64 }.into(),
        tss_trustlet().base().into(),
        gdt_trustlet().base_limit().0.into(),
    ]
}

impl Drop for TrustedProcess {
    fn drop(&mut self) {
        match self.process_type {
            TrustedProcessType::Undefined => {}
            TrustedProcessType::Zygote => {
                /* cow_descend: finalize CoW-marked the whole zygote PT,
                   and delete_trusted_process guarantees no trustlet
                   sharers remain, so the CoW subtrees are exclusively
                   zygote-owned - this is where the ~600 MB per zygote
                   comes back (F4, PLAN.md). */
                self.base.page_table_ref.delete(&exception_keep_list(), true, &[]);
                /* The old "context is empty for zygotes" claim was
                   false: early_init allocates the zygote VMSA the
                   trustlet VMSAs are cloned from. revoke_and_free
                   clears the RMP VMSA attribute before the free -
                   mandatory, the allocator writes to popped pages. */
                revoke_and_free(self.context.vmsa);
            }
            TrustedProcessType::Trustlet => {
                /* Channel slots shared with a LIVING peer trustlet via
                   create_channel must not be walked: slot 5 if our
                   input was adopted from the producer's output, slot 6
                   if our output feeds a consumer (which aliases it as
                   its slot 5). The shared subtree is reclaimed with
                   whichever end still owns it exclusively; a linked
                   pair thus leaks the link subtree - bounded, logged,
                   accepted for now (PLAN.md F4). */
                let mut skip = [0usize; 2];
                let mut n = 0;
                if self.context.channel.input_borrowed {
                    skip[n] = 5;
                    n += 1;
                }
                if self.context.channel.next.is_some() {
                    skip[n] = 6;
                    n += 1;
                }
                // do not delete self.base as this belongs to the zygote
                self.context.page_table_ref.delete(&exception_keep_list(), false, &skip[..n]);
                /* Clears the VMSA RMP attribute, then frees. The LIFO
                   allocator makes immediate reuse of this page the
                   common case, so the clear-before-free ordering is
                   the single most load-bearing line of F4. */
                revoke_and_free(self.context.vmsa);
            }
        }
    }
}

impl TrustedProcess {
    pub fn empty() -> Self {
        Self {
            process_type: TrustedProcessType::Undefined,
            id: 0,
            parent_id: 0,
            base: ProcessBaseContext::default(),
            measurements: ProcessMeasurements::default(),
            context: ProcessContext::default(),
            mmap_manager: MmapManager::new(),
            pf_target_vaddr: 0,
            infer_context: AllocationRange(0,0),
            dead: false,
            gpu_core: -1,
            running: false,
            invoke_owner_apic: u32::MAX,
            invoke_start_tsc: 0,
            last_pcall: 0,
            in_pcall: false,
        }
    }
}
