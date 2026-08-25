use crate::MonitorError;
use crate::RequestParams;
use crate::attestation;
use crate::process_manager::process::TrustedProcessType;

use super::outb::breakdown_outb;

pub fn get_stat(_params: &mut RequestParams) -> Result<(), MonitorError> {
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

pub fn reset_stat(_params: &mut RequestParams) -> Result<(), MonitorError> {
    #[allow(unused_imports)]
    use core::sync::atomic::Ordering;
    log::info!("Stat Reset");
    //crate::sev::utils::stat::PVALIDATE_COUNT.store(0, Ordering::Relaxed);
    //crate::sev::utils::stat::PF_COUNT.store(0, Ordering::Relaxed);
    //crate::sev::utils::stat::COW_COUNT.store(0, Ordering::Relaxed);
    Ok(())
}

pub fn diff_attestation(params: &mut RequestParams) -> Result<(), MonitorError>{
    attestation::monitor::diff_attestation(params)
}

fn monitor_init(params: &mut RequestParams) -> Result<(), MonitorError>{

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

fn create_zygote(params: &mut RequestParams) -> Result<(), MonitorError>{
    super::process::create_trusted_process(params, TrustedProcessType::Zygote)
}

fn delete_zygote(params: &mut RequestParams) -> Result<(), MonitorError> {
    super::process::delete_trusted_process(params)
}

fn create_trustlet(params: &mut RequestParams) -> Result<(), MonitorError> {
    super::process::create_trusted_process(params, TrustedProcessType::Trustlet)
}

fn delete_trustlet(params: &mut RequestParams) -> Result<(), MonitorError> {
    super::process::delete_trusted_process(params)
}

fn get_public_key(params: &mut RequestParams) -> Result<(), MonitorError> {
    attestation::monitor::get_public_key(params)
}

fn send_policy(params: &mut RequestParams) -> Result<(), MonitorError> {
    attestation::monitor::send_policy(params)
}

fn invoke_trustlet(params: &mut RequestParams) -> Result<(), MonitorError> {
    super::super::process_runtime::runtime::invoke_trustlet(params)
}

fn create_channel(params: &mut RequestParams) -> Result<(), MonitorError> {
    super::super::process_runtime::channels::create_channel(params)
}

fn infer_call(params: &mut RequestParams) -> Result<(), MonitorError> {
    super::super::process_runtime::runtime::infer_call(params)
}

fn infer_call_ret(params: &mut RequestParams) -> Result<(), MonitorError> {
    super::super::process_runtime::runtime::infer_call_ret(params)
}

pub fn monitor_call_handler(request: u32, params: &mut RequestParams) -> Result<(), MonitorError> {
    breakdown_outb(254);
    //log::info!("{}, {}, {}, {}, {}",request,params.rcx, params.rdx, params.r8, params.r9);
    //panic!("YEAH");
    use crate::monitor_call_type::MonitorCallType;
    if request > crate::monitor_call_type::MONITOR_CALL_TYPE_MAX_VALUE {
        return Err(MonitorError::unsupported());
    }
    let call: MonitorCallType = unsafe {core::mem::transmute(request)};
    log::debug!("Montior calle: {:?}", call);
    let res = match call {
        MonitorCallType::InitMonitor =>
            monitor_init(params),
        MonitorCallType::AttestMonitor =>
            diff_attestation(params),
        MonitorCallType::LoadPolicy =>
            Ok(()),
        MonitorCallType::CreateZygote =>
            create_zygote(params),
        MonitorCallType::DeleteZygote =>
            delete_zygote(params),
        MonitorCallType::CreateTrustlet =>
            create_trustlet(params),
        MonitorCallType::DeleteTrustlet =>
            delete_trustlet(params),
        MonitorCallType::InvokeTrustlet =>
            invoke_trustlet(params),
        MonitorCallType::WaitForTrustletResult =>
            Ok(()),
        MonitorCallType::CreateChannel =>
            create_channel(params),
        MonitorCallType::DeleteChannel =>
            Ok(()),
        MonitorCallType::GetPublicKey =>
            get_public_key(params),
        MonitorCallType::SendPolicy =>
            send_policy(params),
        MonitorCallType::ExecuteElf =>
            Ok(()),
        MonitorCallType::InferCall =>
            infer_call(params),
        MonitorCallType::InferCallRet =>
            infer_call_ret(params),
        MonitorCallType::GetStat =>
            get_stat(params),
        MonitorCallType::ResetStat =>
            reset_stat(params),
        MonitorCallType::TestCall =>
            Ok(()),
        MonitorCallType::ArgTest =>
            Ok(()),
        MonitorCallType::ModelStoreLoadInit =>
            crate::model_store::model::model_load_init(params),
        MonitorCallType::ModelStoreLoadData =>
            crate::model_store::model::model_load_data(params),
        MonitorCallType::ModelStoreDelete =>
            crate::model_store::model::model_delete(params),
        MonitorCallType::ModelStoreGet =>
            crate::model_store::model::model_get(params),
        MonitorCallType::ModelStoreGetUndo =>
            crate::model_store::model::model_get_undo(params),
        MonitorCallType::LoraStoreLoadInit =>
            crate::model_store::lora::lora_load_init(params),
        MonitorCallType::LoraStoreLoadData =>
            crate::model_store::lora::lora_load_data(params),
        MonitorCallType::LoraStoreDelete =>
            crate::model_store::lora::lora_delete(params),
        MonitorCallType::LoraStoreGet =>
            crate::model_store::lora::lora_get(params),
        MonitorCallType::LoraStoreGetUndo =>
            crate::model_store::lora::lora_get_undo(params),
        MonitorCallType::EngineStoreLoadInit =>
            crate::model_store::engine::engine_load_init(params),
        MonitorCallType::EngineStoreLoadData =>
            crate::model_store::engine::engine_load_data(params),
        MonitorCallType::EngineStoreDelete =>
            crate::model_store::engine::engine_delete(params),
        MonitorCallType::EngineStoreGet =>
            crate::model_store::engine::engine_get(params),
        MonitorCallType::EngineStoreGetUndo =>
            crate::model_store::engine::engine_get_undo(params),
        MonitorCallType::PromptGet =>
            crate::process_runtime::process::inference::prompt_get(params),
        MonitorCallType::ResponseStore =>
            crate::process_runtime::process::inference::response_store(params),
        MonitorCallType::GpuApi =>
            crate::gpu::handle_api_call(params),
        MonitorCallType::GpuSetup =>
            crate::gpu::direct::register_engine(params),
        MonitorCallType::GpuRun =>
            crate::gpu::direct::run(params),
        MonitorCallType::DonateCpu =>
            crate::exclusive::r#loop::run_exclusive(params),
        MonitorCallType::RunCpu =>
            crate::exclusive::scheduling::run_wakeup(params),
        MonitorCallType::PauseCpu =>
            crate::exclusive::scheduling::run_sleep(params),
        MonitorCallType::ReturnCpu =>
            crate::exclusive::scheduling::run_exit(params),
        MonitorCallType::RegisterCpuClient =>
            crate::gpu::direct::register_service(params),
        MonitorCallType::RegisterGpuWindow =>
            crate::gpu::direct::register_window(params),
        MonitorCallType::RegisterGpuHeap =>
            crate::gpu::direct::register_heap(params),
        _ => Err(MonitorError::unsupported()),
    };

    log::debug!("Monitor call finished: {:?}",res);
    log::debug!("{:#x?}",params);
    breakdown_outb(255);
    return res;
}
