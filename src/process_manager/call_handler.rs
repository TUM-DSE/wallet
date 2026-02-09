use crate::RequestParams;
use crate::SvsmReqError;
//use crate::protocols::errors::SvsmReqError;
//use crate::protocols::RequestParams;
use crate::attestation;
use crate::process_manager::process::TrustedProcessType;

use super::outb::breakdown_outb;

const MONITOR_INIT: u32 = 0;
// const MONITOR: u32 = 1;
const DIFF_ATTEST: u32 = 2;
//const LOAD_POLICY: u32 = 3;
const CREATE_ZYGOTE: u32 = 4;
const DELETE_ZYGOTE: u32 = 5;
const CREATE_TRUSTLET: u32 = 6;
const DELETE_TRUSTLET: u32 = 7;
const INVOKE_TRUSTLET: u32 = 8; 
const _WAIT_FOR_TRUSTLET_RESULT: u32 = 9;  // unused but defined in vmpl.h
const CREATE_CHANNEL: u32 = 10;
#[allow(dead_code)]
const DELETE_CHANNEL: u32 = 11;

const GET_PUBLIC_KEY: u32 = 30;
const SEND_POLICY: u32 = 31;

const GET_STAT: u32 = 100;
const RESET_STAT: u32 = 101;

// Model Store
const MODEL_LOAD_INIT: u32 = 50;
const MODEL_LOAD_DATA: u32 = 51;
const MODEL_DELETE: u32 = 52;
const LORA_LOAD_INIT: u32 = 53;
const LORA_LOAD_DATA: u32 = 54;
const LORA_DELETE: u32 = 55;

// Engines
const ENGINE_LOAD_INIT: u32 = 60;
const ENGINE_LOAD_DATA: u32 = 61;
const ENGINE_DELETE: u32 = 62;

const INFER_CALL: u32 = 70;
const INFER_CALL_RET: u32 = 71;

pub fn get_stat(_params: &mut RequestParams) -> Result<(), SvsmReqError> {
    #[allow(unused_imports)]
    use core::sync::atomic::Ordering;
    log::error!("Stat");
    //log::error!("PVALIDATE: {}", crate::sev::utils::stat::PVALIDATE_COUNT.load(Ordering::Relaxed));
    //log::error!("PF: {}", crate::sev::utils::stat::PF_COUNT.load(Ordering::Relaxed));
    //log::error!("COW: {}", crate::sev::utils::stat::COW_COUNT.load(Ordering::Relaxed));
    log::error!("COW_PAGES: {}", super::process_paging::stat::COW_PAGE_COUNT.load(Ordering::Relaxed));
    log::error!("NON_COW_PAGES: {}", super::process_paging::stat::NON_COW_PAGE_COUNT.load(Ordering::Relaxed));
    Ok(())
}

pub fn reset_stat(_params: &mut RequestParams) -> Result<(), SvsmReqError> {
    #[allow(unused_imports)]
    use core::sync::atomic::Ordering;
    log::info!("Stat Reset");
    //crate::sev::utils::stat::PVALIDATE_COUNT.store(0, Ordering::Relaxed);
    //crate::sev::utils::stat::PF_COUNT.store(0, Ordering::Relaxed);
    //crate::sev::utils::stat::COW_COUNT.store(0, Ordering::Relaxed);
    Ok(())
}

pub fn diff_attestation(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    attestation::monitor::diff_attestation(params)
}

fn monitor_init(params: &mut RequestParams) -> Result<(), SvsmReqError>{

    log::info!("Initilization Monitor");
    /* Request a monitor measurement upon initialization */
    params.rdx = attestation::monitor::MONITOR_ATTESTATION;
    params.rcx = 0;
    let _ = attestation::monitor::diff_attestation(params);
    //add_monitor_memory();
    //super::process::PROCESS_STORE.init(10);
    //crate::sp_pagetable::set_ecryption_mask_address_size();
    log::info!("Initilization Done");
    Ok(())
}

fn create_zygote(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    super::process::create_trusted_process(params, TrustedProcessType::Zygote)
}

fn delete_zygote(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::process::delete_trusted_process(params)
}

fn create_trustlet(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::process::create_trusted_process(params, TrustedProcessType::Trustlet)
}

fn delete_trustlet(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::process::delete_trusted_process(params)
}

fn get_public_key(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    attestation::monitor::get_public_key(params)
}

fn send_policy(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    attestation::monitor::send_policy(params)
}

fn invoke_trustlet(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::super::process_runtime::runtime::invoke_trustlet(params)
}

fn create_channel(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::super::process_runtime::runtime::create_channel(params)
}

fn model_load_init(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::super::model_store::model::model_load_init(params)
}

fn model_load_data(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::super::model_store::model::model_load_data(params)
}

fn model_delete(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::super::model_store::model::model_delete(params)
}

fn lora_load_init(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::super::model_store::model::lora_load_init(params)
}

fn lora_load_data(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::super::model_store::model::lora_load_data(params)
}

fn lora_delete(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::super::model_store::model::lora_delete(params)
}

fn engine_load_init(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::super::model_store::model::engine_load_init(params)
}

fn engine_load_data(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::super::model_store::model::engine_load_data(params)
}

fn engine_delete(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::super::model_store::model::engine_delete(params)
}

fn infer_call(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::super::process_runtime::runtime::infer_call(params)
}

fn infer_call_ret(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::super::process_runtime::runtime::infer_call_ret(params)
}


pub fn monitor_call_handler(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    breakdown_outb(254);
    //log::info!("{}, {}, {}, {}, {}",request,params.rcx, params.rdx, params.r8, params.r9);
    //panic!("YEAH");
    let res = match request {
        MONITOR_INIT => monitor_init(params),
        DIFF_ATTEST => diff_attestation(params),
        CREATE_ZYGOTE => create_zygote(params),
        DELETE_ZYGOTE => delete_zygote(params),
        CREATE_TRUSTLET => create_trustlet(params),
        DELETE_TRUSTLET => delete_trustlet(params),
        GET_PUBLIC_KEY => get_public_key(params),
        SEND_POLICY => send_policy(params),
        INVOKE_TRUSTLET => invoke_trustlet(params),
        CREATE_CHANNEL => create_channel(params),
        GET_STAT => get_stat(params),
        RESET_STAT => reset_stat(params),

        MODEL_LOAD_INIT => model_load_init(params),
        MODEL_LOAD_DATA => model_load_data(params),
        MODEL_DELETE => model_delete(params),

        LORA_LOAD_INIT => lora_load_init(params),
        LORA_LOAD_DATA => lora_load_data(params),
        LORA_DELETE => lora_delete(params),

        ENGINE_LOAD_INIT => engine_load_init(params),
        ENGINE_LOAD_DATA => engine_load_data(params),
        ENGINE_DELETE => engine_delete(params),

        INFER_CALL => infer_call(params),
        INFER_CALL => infer_call_ret(params),

        _ => Err(SvsmReqError::unsupported_call()),
    };
    breakdown_outb(255);
    return res;
}
