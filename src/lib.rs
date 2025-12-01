#![no_std]

use process_manager::process_memory::additional_monitor_memory_init;
mod types;
mod interop;
mod address;
mod my_crypto_wrapper;
mod process_manager;
mod process_runtime;
mod attestation;
mod sev;
mod utils;
mod memory;
mod locking;
mod cpu;
//pub use my_crypto_wrapper::get_keys;
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestParams {
    pub sev_features: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
}


#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types, dead_code, clippy::upper_case_acronyms)]
pub enum SvsmResultCode {
    SUCCESS,
    INCOMPLETE,
    UNSUPPORTED_PROTOCOL,
    UNSUPPORTED_CALL,
    INVALID_ADDRESS,
    INVALID_FORMAT,
    INVALID_PARAMETER,
    INVALID_REQUEST,
    BUSY,
    PROTOCOL_BASE(u64),
}

impl From<SvsmResultCode> for u64 {
    fn from(res: SvsmResultCode) -> u64 {
        match res {
            SvsmResultCode::SUCCESS => 0x0000_0000,
            SvsmResultCode::INCOMPLETE => 0x8000_0000,
            SvsmResultCode::UNSUPPORTED_PROTOCOL => 0x8000_0001,
            SvsmResultCode::UNSUPPORTED_CALL => 0x8000_0002,
            SvsmResultCode::INVALID_ADDRESS => 0x8000_0003,
            SvsmResultCode::INVALID_FORMAT => 0x8000_0004,
            SvsmResultCode::INVALID_PARAMETER => 0x8000_0005,
            SvsmResultCode::INVALID_REQUEST => 0x8000_0006,
            SvsmResultCode::BUSY => 0x8000_0007,
            SvsmResultCode::PROTOCOL_BASE(code) => 0x8000_1000 + code,
        }
    }
}



#[derive(Debug, Clone, Copy)]
pub enum SvsmReqError {
    RequestError(SvsmResultCode),
}

macro_rules! impl_req_err {
    ($name:ident, $v:ident) => {
        pub fn $name() -> Self {
            Self::RequestError(SvsmResultCode::$v)
        }
    };
}

#[allow(dead_code)]
impl SvsmReqError {
    impl_req_err!(incomplete, INCOMPLETE);
    impl_req_err!(unsupported_protocol, UNSUPPORTED_PROTOCOL);
    impl_req_err!(unsupported_call, UNSUPPORTED_CALL);
    impl_req_err!(invalid_address, INVALID_ADDRESS);
    impl_req_err!(invalid_format, INVALID_FORMAT);
    impl_req_err!(invalid_parameter, INVALID_PARAMETER);
    impl_req_err!(invalid_request, INVALID_REQUEST);
    impl_req_err!(busy, BUSY);
    fn protocol(code: u64) -> Self {
        Self::RequestError(SvsmResultCode::PROTOCOL_BASE(code))
    }
}

pub fn wallet_memory_init() {
    let _ = additional_monitor_memory_init();
}

pub fn wallet_process_protocol_request(request: u32, params: &mut RequestParams) -> i64 {
    log::debug!("{:x?}",params);
    match process_manager::call_handler::monitor_call_handler(request, params) {
        _ => return 0
    }
}

pub fn wallet_init() {

}
