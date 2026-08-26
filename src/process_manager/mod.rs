use memory_helper::set_ecryption_mask_address_size;
use process_memory::additional_monitor_memory_init;
use crate::crypto::{gen_keys, KeyPair};

#[cfg(feature = "bench_mem")]
use process_memory::bench_mem;

#[cfg(feature = "prealloc")]
use process_memory::preallocate_memory;

pub use process::PROCESS_STORE;

use crate::{model_store::{LORA_STORE, MODEL_STORE, ENGINE_STORE}, utils::immut_after_init::ImmutAfterInitCell};

pub mod call_handler;
pub mod process;
pub mod process_memory;
pub mod process_paging;
pub mod memory_helper;
pub mod allocation;
pub mod memory_channels;
pub mod outb;
pub mod exception_handling;

static MONITOR_INIT_STATE: ImmutAfterInitCell<bool> = ImmutAfterInitCell::new(false);
const MONITOR_INIT_STATE_TRUE: bool = true;
pub const PROCESS_STORE_SIZE: u32 = 64;

/* Guest-visible status classes, mirrored by
   lib/guest/wallet/include/wallet/monitor_status.h (kept in sync by
   hand - they are NOT part of the generated call-id enums).
   Deliberately coarse: they name the CLASS of a failure so the guest
   can react, never monitor internals. */
pub const STATUS_REJECTED: i64 = -1;
pub const STATUS_BAD_ID: i64 = -2;
pub const STATUS_BAD_STATE: i64 = -3;
pub const STATUS_BAD_ARGS: i64 = -4;
pub const STATUS_NO_RESOURCES: i64 = -5;
pub const STATUS_UNSUPPORTED: i64 = -6;

/* Rejections on guest-reachable paths MUST be Ok(()) + a negative
   status in rcx, never Err: the wallet protocol maps Err to
   SVSM_ERR_INCOMPLETE, and the guest kernel's
   svsm_perform_call_protocol retries INCOMPLETE forever - an Err on a
   guest-reachable path wedges the calling guest CPU in an infinite
   loop (observed with the F4 bad-pid negative test). */
pub fn reject(params: &mut crate::RequestParams, status: i64) -> Result<(), crate::MonitorError> {
    params.rcx = u64::from_ne_bytes(status.to_ne_bytes());
    Ok(())
}

pub fn monitor_init(){
    if *MONITOR_INIT_STATE {
        let _ = additional_monitor_memory_init();
        return;
    }
    set_ecryption_mask_address_size();
    let _ = additional_monitor_memory_init();
    PROCESS_STORE.init(PROCESS_STORE_SIZE);
    MODEL_STORE.init(10);
    LORA_STORE.init(10);
    ENGINE_STORE.init(10);
    let _ = MONITOR_INIT_STATE.reinit(&MONITOR_INIT_STATE_TRUE);

    let encryption_keys: KeyPair = unsafe{*gen_keys()};
    log::info!("Monitor generated keys: private key {:?}, public key {:?}", encryption_keys.private_key, encryption_keys.public_key);

    #[cfg(feature = "prealloc")]
    preallocate_memory();
}
