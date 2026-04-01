use crate::MonitorError;

use super::{*};
use super::store::StoreEntry;

pub fn model_load_init(params: &mut RequestParams) -> Result<(), MonitorError> {
    let range = load_init(params);

    let m = StoreEntry {
        measurement: [0; 64],
        data: range,
        real_size: params.rcx,
        state: false,
    };
    let num = MODEL_STORE.insert(m);
    params.rcx = convert(num);
    Ok(())
}

pub fn model_load_data(params: &mut RequestParams) -> Result<(), MonitorError> {
    load_fin(params, &MODEL_STORE);
    Ok(())
}

pub fn model_delete(params: &mut RequestParams) -> Result<(), MonitorError> {
    delete(params, &MODEL_STORE)
}

pub fn model_get(params: &mut RequestParams) -> Result<(), MonitorError> {
    log::debug!("{:#x?}", params);
    get(params, &MODEL_STORE)
}

pub fn model_get_undo(params: &mut RequestParams) -> Result<(), MonitorError> {
    get_undo(params, &MODEL_STORE)
}
