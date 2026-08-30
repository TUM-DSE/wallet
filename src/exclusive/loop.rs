use core::sync::atomic::Ordering;
use crate::exclusive::scheduling::sleep;
use crate::{MonitorError, RequestParams};
use crate::process_manager::process_memory::{allocate_page, free_page};
use crate::memory::paging::PerCPUPageMappingGuard;
use crate::exclusive::{get_apic_id, ControlStruct, CONTROL, LOOP_CLEAR, LOOP_EXIT, LOOP_SLEEP, LOOP_WAKEUP, VMSA_FEAT, VMSA_PHYS};
use crate::address::PhysAddr;

extern "Rust" {
    fn wallet_get_vmsa() -> PhysAddr;
    fn wallet_get_features() -> u64;
    fn wallet_enter_guest();
}

fn enter_guest(){
    unsafe {wallet_enter_guest();};
}

/// Handle a LOOP_* command consumed off the control page. Returns true
/// when the exclusive loop should exit (LOOP_EXIT). LOOP_SLEEP hlt-s
/// until LOOP_WAKEUP.
fn handle_command(ctr: &mut ControlStruct, cmd: u64) -> bool {
    if cmd == LOOP_EXIT {
        return true;
    }
    if cmd == LOOP_SLEEP {
        loop {
            sleep(ctr);
            let cmd = ctr.next.swap(LOOP_CLEAR, Ordering::Relaxed);
            if cmd == LOOP_WAKEUP {
                break;
            }
        }
    }
    false
}

pub fn run_exclusive(_params: &mut RequestParams) -> Result<(), MonitorError> {
    let id = get_apic_id() as usize;


    let ctr_page = allocate_page();
    let ctr_mapping = PerCPUPageMappingGuard::create_4k(ctr_page).unwrap();
    let ctr_ptr: *mut ControlStruct = ctr_mapping.virt_addr().as_mut_ptr::<ControlStruct>();
    let ctr = unsafe {&mut *ctr_ptr};
    ctr.next.store(LOOP_CLEAR, Ordering::Relaxed);
    ctr.hlt.store(0, Ordering::Relaxed);

    /* COM_PAGES deleted (write-only, zero readers in the crate); its
       comm page allocation went with it. Publication order: control
       page contents + VMSA pair FIRST, then CONTROL (the "poller
       live" gate is_donated/register_engine/wakeup read) LAST with
       Release - the old order raised the gate before the state
       existed. */
    unsafe {
        VMSA_PHYS[id].store(u64::from(wallet_get_vmsa()), Ordering::Relaxed);
        VMSA_FEAT[id].store(wallet_get_features(), Ordering::Relaxed);
    };
    CONTROL[id].store(u64::from(ctr_page), Ordering::Release);
    //use core::arch::asm;
    log::warn!("Reserving CPU for Monitor: {}", id);
    //unsafe { asm!("hlt"); };
    enter_guest();
    log::warn!("\n\nAfter return: {}\n\n", get_apic_id());

    //let comm_ptr: *mut u64 = mapping.virt_addr().as_mut_ptr::<u64>();
    //let comm: &mut u64 = unsafe {&mut *comm_ptr};

    let mut heartbeat: u64 = 0;
    loop {
        let cmd = ctr.next.swap(LOOP_CLEAR, Ordering::Relaxed);
        if cmd != LOOP_CLEAR {
            if handle_command(ctr, cmd) {
                break;
            }
            continue;
        }
        // GPU polling: when a client has registered a comm page for
        // this core (register_engine with explicit target core), relay
        // its calls until the session ends (stop id 500 clears the
        // registration) or a LOOP_* command arrives. poll_engine
        // re-reads the registration every iteration, so a crashed
        // client is replaced by the next one's registration without
        // any reboot.
        if crate::gpu::direct::engine_registered(id)
            || crate::gpu::direct::engine_slot_owes_stop(id) {
            /* Hand a claimed stream worker off BEFORE blocking for the
               whole GPU session: the hash state is preserved for the
               next claimer (stream::detach_core), and with no free
               donated core left the guest's eager fallback fires.
               Without this the claimed-but-starved worker kept
               STATE_CLAIMED set and the guest writer spun on the
               watermark forever. Also drops a stale helper mount. */
            crate::model_store::stream::detach_core(id);
            log::warn!("Donated core {}: polling GPU engine page", id);
            /* No deadline: donated cores are offline in the guest, so
               there is nothing to yield to (and no IPI hazard). */
            let cmd = crate::gpu::direct::poll_engine(id, Some(&*ctr), None);
            log::warn!("Donated core {}: GPU session ended ({})", id, cmd);
            if cmd != LOOP_CLEAR && handle_command(ctr, cmd) {
                break;
            }
            continue;
        }
        heartbeat += 1;
        if(heartbeat % 1000000000 == 0) {
            log::warn!("shuttle heartbeat: {}", heartbeat);
        }
        // Watchdog detection for invokes with no GPU channel yet (the
        // engine-registered case runs the same scan inside
        // poll_engine's idle branch). Rate-limited inside.
        crate::process_runtime::log_overbudget_invokes(id, -1);
        // Streaming model load: one bounded quantum (claim-or-help:
        // coordinate the hash/sweep or fill units in parallel) per
        // iteration, so LOOP_* commands stay responsive between
        // bites. No-op when no load is in flight; the core "goes back
        // to sleep" (this idle loop) when the digest is finalized. A
        // core whose engine registers mid-load detaches gracefully
        // above - another donated core resumes the preserved hash, or
        // the guest's eager fallback covers the allocation.
        crate::model_store::stream::poll_worker(id);
    }

    // teardown: gate down first, then the payload
    CONTROL[id].store(0, Ordering::Release);
    VMSA_PHYS[id].store(0, Ordering::Relaxed);
    VMSA_FEAT[id].store(0, Ordering::Relaxed);
    free_page(ctr_page);
    Ok(())
}
