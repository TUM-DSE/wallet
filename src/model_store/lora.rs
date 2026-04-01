use crate::MonitorError;

use super::{*};

pub fn lora_load_init(params: &mut RequestParams) -> Result<(), MonitorError> {
    let range = load_init(params);

    let l = StoreEntry {
        measurement: [0; 64],
        data: range,
        real_size: params.rcx,
        state: false,
    };
    params.rcx = convert(LORA_STORE.insert(l));
    Ok(())
}

pub fn lora_load_data(params: &mut RequestParams) -> Result<(), MonitorError> {
    load_fin(params, &LORA_STORE);
    Ok(())
}

pub fn lora_delete(params: &mut RequestParams) -> Result<(), MonitorError> {
    delete(params, &LORA_STORE)
}

pub fn lora_get(params: &mut RequestParams) -> Result<(), MonitorError> {
    get(params, &LORA_STORE)
}

pub fn lora_get_undo(params: &mut RequestParams) -> Result<(), MonitorError> {
    get(params, &LORA_STORE)
}
