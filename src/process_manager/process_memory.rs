extern crate alloc;
use crate::address::{PhysAddr, VirtAddr};
use crate::interop::memory::read_cr3;
use crate::locking::SpinLock;
use crate::MonitorError;
use crate::sev::SevSnpError;
use crate::types::PageSize;
use crate::sev::PvalidateOp;
use crate::sev::pvalidate;
use crate::locking::get_pvalidate_lock;
use crate::sev::utils::SvsmError;
pub const PAGE_SIZE: usize = 4096;
use crate::memory::paging::PerCPUPageMappingGuard;
use crate::utils::MemoryRegion;
use crate::{paddr_as_u64_slice, map_paddr, vaddr_as_u64_slice};
use crate::memory::regions::get_memory_region_from_map;
use crate::address::Address;

#[allow(dead_code)]
const PREALLOCATED_SIZE: u64 = 4194304; // 16 GiB
const ADDITIONAL_GUEST_MEMORY: usize = 32 * GiB;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessMemConfig {
    initilized: bool,

    total_size: usize,
    free: usize,

    //Page List
    free_page_list: u64,
    free_page_list_used_len: usize,
    //Current Addresses
    page_top: PhysAddr,
    page_base: PhysAddr,
    page_limit: PhysAddr,
    //Allocation
    allocation_offset: u64,
    mapping_table: PhysAddr,
    free_page_list_table_entry: u64,
}

pub const ALLOCATION_RANGE_VIRT_START: u64 = 0x300_0000_0000u64;

static PROCESS_MEM_CONFIG: SpinLock<ProcessMemConfig> = SpinLock::new(ProcessMemConfig::new());

#[allow(non_upper_case_globals)]
const KiB: usize = 1024;
#[allow(non_upper_case_globals)]
const MiB: usize = KiB * 1024;
#[allow(non_upper_case_globals)]
const GiB: usize = MiB * 1024;

const ADDRESS_START_FREE_PAGE_LIST: usize = 0x80_0000_0000;

const CONDITION_MIN_MEM_SIZE: usize = 1 * GiB;

const ADDRESS_LENGTH: u64 = 8;

pub const PGD: usize = 3;
pub const PUD: usize = 2;
pub const PMD: usize = 1;
pub const PTE: usize = 0;

pub fn addr_to_idx(addr: usize, lvl: usize) -> usize {
    (addr >> (lvl * 9 + 12)) & 0x1FF
}

impl ProcessMemConfig{

    const fn new() -> ProcessMemConfig{
        ProcessMemConfig{
            initilized: false,
            total_size: 0,
            free: 0,
            free_page_list: ADDRESS_START_FREE_PAGE_LIST as u64,
            free_page_list_used_len: 0,
            page_top: PhysAddr::null(),
            page_base: PhysAddr::null(),
            page_limit: PhysAddr::null(),
            allocation_offset: 0,
            mapping_table: PhysAddr::null(),
            free_page_list_table_entry: 0,
        }
    }
    fn check_requirements() -> usize{
        //We only use the first two regions for now
        //The first should go from 0-2 GiB and the second starts
        //from 3 GiB and represents the userable Monitor memory
        let memory_region_count = 2;
        let mut total_size = 0;

        //The first region belongs to the guest OS running Linux
        //If this region is not 2 GiB in size we are not accounint for that
        let initial_memory_region = get_memory_region_from_map(0);
        if initial_memory_region.end() - initial_memory_region.start() < 2 * GiB {
            log::error!("Initial Memory Region to small (not implemented)");
            panic!();
        }
        let initial_memory_region_2 = get_memory_region_from_map(1);
        if initial_memory_region_2.end() - initial_memory_region_2.start() < ADDITIONAL_GUEST_MEMORY + 4 * GiB {
            log::error!("Initial Memory Region 2 to small (not implemented)");
            panic!();
        }


        for i in 1..memory_region_count {
            let region = get_memory_region_from_map(i);
            total_size += region.end() - region.start();
        }
        total_size -= ADDITIONAL_GUEST_MEMORY;

        if CONDITION_MIN_MEM_SIZE > total_size {
            log::error!("Not enough memory given to VMPL0 (second memory region is to small)");
            panic!();
        }

        total_size
    }

    fn free_memory_list(total_memory_size: usize) -> (usize, usize) {
        //Each entry represents one page of memory
        //Thus the required list size is size / page_size * address_size
        //address_size is 8 bytes
        let free_memory_list_size = (total_memory_size / PAGE_SIZE) * 8;
        let region = get_memory_region_from_map(1);
        let usable_memory_region = region.start() + ADDITIONAL_GUEST_MEMORY + free_memory_list_size;

        if usize::from(usable_memory_region) % PAGE_SIZE != 0 {
            log::error!("Something went wrong. Memory start is not page aligned.");
            panic!();
        }

        log::info!("Total available memory: {} B", total_memory_size);
        log::info!("Usable available memory: {} B", total_memory_size - free_memory_list_size);
        log::info!("Total Memory Region: {:#x} - {:#x}", region.start() + ADDITIONAL_GUEST_MEMORY, region.end());
        log::info!("Usable Memory Region: {:#x} - {:#x}", usable_memory_region, region.end());

        (free_memory_list_size, usable_memory_region.into())
    }

    fn prepare_free_memory_list(free_memory_list_size: usize) -> u64 {

        let free_memory_list_memory_range =
            MemoryRegion::<VirtAddr>::new(VirtAddr::from(ADDRESS_START_FREE_PAGE_LIST), free_memory_list_size);
        log::info!("Reserved Memory({:#x}-{:#x}): {} B",
                   free_memory_list_memory_range.start(),
                   free_memory_list_memory_range.end(),
                   free_memory_list_memory_range.end() - free_memory_list_memory_range.start());

        //Map the memory region for the Page list into the current core's page table
        let region = get_memory_region_from_map(1);
        //let mut pgtable = get_init_pgtable_locked(); //Gets the shared page table for all cores (Does not affect cores)
        //pgtable.map_region_4k(free_memory_list_memory_range, region.start() + ADDITIONAL_GUEST_MEMORY, PTEntryFlags::data()).unwrap();
        //let page_table_entry = PTEntry::from(read_cr3()); // Get current core's page table
        //let address = phys_to_virt(page_table_entry.address());
        //let page_table_page = unsafe { &mut *address.as_mut_ptr::<PageTable>() };
        //page_table_page.get_root()[1] = pgtable.get_root()[1]; // Copy page table for free memory list to active page table
        use crate::paddr_as_table;
        use crate::process_manager::process_paging::ProcessPageTablePage;
        use crate::process_manager::process_paging::ProcessPageTableEntry;
        let (_mapping, pg) = paddr_as_table!(read_cr3());

        let pt_1 = crate::interop::memory::map_svsm_page_table(free_memory_list_memory_range, region.start() + ADDITIONAL_GUEST_MEMORY);
        pg[1] = ProcessPageTableEntry(pt_1.into());
        for p in 0..(free_memory_list_size / PAGE_SIZE) { //Iterate over every require page
            let offset = p * PAGE_SIZE;
            let vaddr = VirtAddr::from(ADDRESS_START_FREE_PAGE_LIST);
            let paddr = region.start() + ADDITIONAL_GUEST_MEMORY;
            match monitor_pvalidate_vaddr_4k(vaddr + offset, paddr + offset) {
                Ok(_) => (),
                Err(e) => {log::error!("{:?}",e); panic!("Failed to pvalidate initial list");}
            };
            let v = vaddr + offset;
            let e: &mut [u64; 512] = unsafe { &mut *v.as_mut_ptr::<[u64;512]>() };
            for i in 0..512 {
                e[i] = 0;
            }
        }
        //let (_m, pt) = paddr_as_u64_slice!(read_cr3());
        //pt[1]
        pt_1
    }

    fn validate_and_clear(addr: u64){
        let mapping = PerCPUPageMappingGuard::create_4k(PhysAddr::from(addr)).unwrap();
        let virt = mapping.virt_addr();
        let entry: &mut [u64;512] = unsafe { &mut *virt.as_mut_ptr::<[u64;512]>() };
        monitor_pvalidate_vaddr_4k(virt, PhysAddr::from(addr)).unwrap();

        for i in 0..512 {
            entry[i] = 0;
        }
    }

    fn init(&mut self) {

        if self.initilized {
            let (_m, pt) = paddr_as_u64_slice!(read_cr3());
            pt[1] = self.free_page_list_table_entry;
            return;
        }
        // Configure the initial additional memory
        // For now it just assumes one more memory r gion
        let total_size = ProcessMemConfig::check_requirements();

        // We need to be able to store every page that might get freed
        // With using the total size we overestimate the size we might need
        // since we require some of the memory for other purposes (pagetable etc)
        let free_memory_list_size: usize;
        let _usable_memory_region_start: usize;

        (free_memory_list_size, _usable_memory_region_start) = ProcessMemConfig::free_memory_list(total_size);

        self.free_page_list_table_entry = ProcessMemConfig::prepare_free_memory_list(free_memory_list_size);

        //Setting the base values for the current amount of memory
        //Removing the space required for the memory managment
        self.total_size = total_size - free_memory_list_size;
        self.free = total_size - free_memory_list_size;
        self.free_page_list_used_len = 0; //No pages used yet
        let region = get_memory_region_from_map(1);
        self.page_base = region.start() + free_memory_list_size + ADDITIONAL_GUEST_MEMORY;
        self.page_limit = region.end();
        self.initilized = true;
    }

    #[cfg(feature = "prealloc")]
    pub fn preallocate_memory(&mut self) {
        log::info!("Memory Preallocation ({} Pages)", PREALLOCATED_SIZE);
        let page_count = PREALLOCATED_SIZE;
        for _ in 0..page_count {
            let p = self.get_next_page();
            self.free_page(u64::from(p));
        }
    }


    fn check_for_free_page(&mut self) -> PhysAddr {
        if self.free_page_list_used_len == 0 {
            return PhysAddr::null();
        }
        self.free_page_list_used_len -= 1;
        let addr = self.free_page_list + (self.free_page_list_used_len as u64 * ADDRESS_LENGTH);
        let entry: &mut PhysAddr = unsafe {&mut *((addr) as *mut PhysAddr)};
        let tmp = *entry;
        *entry = PhysAddr::null();

        let (_mapping, a) = paddr_as_u64_slice!(tmp);
        a.fill(0);
        tmp
    }

    /// Pages still obtainable: free list + what is left of the bump
    /// region. Guest-driven allocations size themselves from guest
    /// numbers, so their entry points pre-flight against this rather
    /// than discovering exhaustion mid-build.
    pub fn pages_available(&self) -> u64 {
        let base = self.page_base.bits() as u64;
        let limit = self.page_limit.bits() as u64;
        let bump = if limit > base { (limit - base) / PAGE_SIZE as u64 } else { 0 };
        bump + self.free_page_list_used_len as u64
    }

    pub fn get_free_page(&mut self) -> PhysAddr {
        let mut addr = self.check_for_free_page();
        if addr == PhysAddr::null() {
            /* page_limit was recorded at init and never consulted: the
               bump pointer walked past the region and validate_and_clear
               panicked on the pvalidate one page later. Return the
               "no page" sentinel check_for_free_page already uses. */
            if self.page_base.bits() as u64 + PAGE_SIZE as u64 > self.page_limit.bits() as u64 {
                log::error!("get_free_page: monitor memory region exhausted at {:#x?}",
                            self.page_base);
                return PhysAddr::null();
            }
            addr = PhysAddr::from(self.page_base);
            ProcessMemConfig::validate_and_clear(u64::from(addr));
            self.page_base = self.page_base + PAGE_SIZE;
        }

        addr
    }

    pub fn add_free_page(&mut self, free: PhysAddr) {
        debug_assert_eq!(free.bits() & PAGE_SIZE - 1, 0);

        if false && cfg!(debug_assertions) {
            for addr in (self.free_page_list..(self.free_page_list + (self.free_page_list_used_len as u64 * ADDRESS_LENGTH)))
                .step_by(ADDRESS_LENGTH as usize) {
                //unsafe { log::debug!("{:x?}/{:x?}", *(addr as *mut PhysAddr), free); }
                unsafe { assert_ne!(*(addr as *mut PhysAddr), free); }
            }

            // This check does does not make sense free.bits should never be in this range
            if free.bits() < 0x100c00000 || free.bits() > 0x10e000000 {
                //log::info!("freeing wrong page? {:#x}", free);
            }
        }
        //        log::debug!("Deleting {:x?} to index {}", free, self.free_page_list_used_len);

        //log::debug!("Page List: {:x?}, offset: {:x?}({:?})", self.free_page_list, self.free_page_list_used_len as u64 * ADDRESS_LENGTH, self.free_page_list_used_len);
        let addr = self.free_page_list + (self.free_page_list_used_len as u64 * ADDRESS_LENGTH);
        let entry = addr as *mut PhysAddr;
        unsafe {
            debug_assert_eq!(entry.read(), PhysAddr::null());
            entry.write(free);
        }
        self.free_page_list_used_len += 1;
    }

    fn allocated_amount(&mut self) -> usize {
        self.page_base.bits() - self.free_page_list_used_len * PAGE_SIZE
    }

}

#[cfg(feature = "prealloc")]
pub fn preallocate_memory() {
    PROCESS_MEM_CONFIG.lock().preallocate_memory()
}

pub fn allocate_page() -> PhysAddr {
    PROCESS_MEM_CONFIG.lock().get_free_page()
}

/// Pages the monitor can still hand out. Guest-facing handlers use
/// this to reject an oversized request up front instead of failing
/// (or panicking) partway through building it.
pub fn pages_available() -> u64 {
    PROCESS_MEM_CONFIG.lock().pages_available()
}

/// A page usable as a guest VMSA. KVM's sev_snp_ap_creation REJECTS
/// any AP-creation whose VMSA GPA is 2 MiB-aligned (upstream SNP
/// hugepage-erratum workaround), and the bump allocator's
/// near-deterministic session cost walked the zygote VMSA onto such a
/// boundary at exactly the 5th session of a boot - the
/// "register_guest_vmsa failed" panic, root-caused 2026-08-25 (the
/// probed VMSA low bits drifted 0x84000 -> 0x63000 -> 0x42000 ->
/// 0x21000 -> 0x00000 across sessions). Skip aligned pages; rejects
/// go back to the free list AFTER a good page is in hand (the free
/// list is LIFO - freeing first would hand the same page straight
/// back).
pub fn allocate_vmsa_page() -> PhysAddr {
    const TWO_MIB_MASK: u64 = 0x1F_FFFF;
    let mut rejected: [PhysAddr; 8] = [PhysAddr::null(); 8];
    let mut n = 0;
    let page = loop {
        let p = PROCESS_MEM_CONFIG.lock().get_free_page();
        if u64::from(p) & TWO_MIB_MASK != 0 {
            break p;
        }
        log::warn!("allocate_vmsa_page: skipping 2 MiB-aligned {:#x}", u64::from(p));
        if n < rejected.len() {
            rejected[n] = p;
            n += 1;
        }
        // more than 8 consecutive aligned pages cannot come from the
        // bump path (1 in 512) - and a free list that pathological
        // just leaks the ninth; a page is 4 KiB, acceptable.
    };
    for r in rejected.iter().take(n) {
        PROCESS_MEM_CONFIG.lock().add_free_page(*r);
    }
    page
}

//pub fn free_page(paddr: u64) {
//    PROCESS_MEM_CONFIG.lock().free_page(paddr);
//}

pub fn free_page(addr: PhysAddr) {
    PROCESS_MEM_CONFIG.lock().add_free_page(addr)
}

pub fn allocated_amount() -> usize {
    PROCESS_MEM_CONFIG.lock().allocated_amount()
}

pub fn additional_monitor_memory_init() -> Result<(), MonitorError> {
    PROCESS_MEM_CONFIG.lock().init();
    Ok(())
}

fn monitor_pvalidate_vaddr_4k(vaddr: VirtAddr, paddr: PhysAddr) -> Result<(), MonitorError>{
    //log::debug!("pvalidating: {:x?}", paddr);
    monitor_pvalidate_vaddr(vaddr, paddr,PAGE_SIZE, PageSize::Regular, PvalidateOp::Valid, false)
}

fn monitor_pvalidate_vaddr(vaddr: VirtAddr, _paddr: PhysAddr, _ps_s: usize, _ps: PageSize, _pvop: PvalidateOp, ign_cf: bool) -> Result<(), MonitorError> {
    let lock = get_pvalidate_lock().lock_read();
    pvalidate(vaddr,PageSize::Regular, PvalidateOp::Valid).or_else(
        |err| match err{
            SvsmError::SevSnp(SevSnpError::FAIL_UNCHANGED(_)) if ign_cf => Ok(()),
            _ => {log::error!("{:?}",err); Err(MonitorError::validate_failed())}
        }
    )?;
    drop(lock);
    Ok(())
}
