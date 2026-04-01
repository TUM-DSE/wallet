#![no_std]
mod types;
mod interop;
mod address;
mod crypto;
mod process_manager;
mod process_runtime;
mod attestation;
mod sev;
mod utils;
mod memory;
mod locking;
mod cpu;
mod model_store;
mod monitor_call_type;
mod error;
mod gpu;
use error::*;

#[derive(Debug, Default, Clone, Copy)]
pub struct RequestParams {
    pub sev_features: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
}

use crate::process_manager::monitor_init;
pub fn wallet_memory_init() {
    monitor_init();
    //let _ = additional_monitor_memory_init();
}

pub fn wallet_process_protocol_request(request: u32, params: &mut RequestParams) -> i64 {
    log::debug!("{:x?}",params);
    match process_manager::call_handler::monitor_call_handler(request, params) {
        Err(e) => {log::error!("{}", e); return -1;},
        _ => 0
    }
}

pub fn wallet_init() {

}
