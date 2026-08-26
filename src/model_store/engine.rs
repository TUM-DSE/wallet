use crate::MonitorError;

use super::{*};
use super::store::StoreEntry;

pub fn engine_load_init(params: &mut RequestParams) -> Result<(), MonitorError> {
    let range = load_init(params);

    let e = StoreEntry {
        measurement: [0; 64],
        data: range,
        real_size: params.rcx,
        state: false,
    };
    params.rcx = convert(ENGINE_STORE.insert(e));
    Ok(())
}

pub fn engine_load_data(params: &mut RequestParams) -> Result<(), MonitorError> {
    load_fin(params, &ENGINE_STORE);
    Ok(())
}

pub fn engine_delete(params: &mut RequestParams) -> Result<(), MonitorError> {
    delete(params, &ENGINE_STORE)
}

pub fn engine_get(params: &mut RequestParams) -> Result<(), MonitorError> {
    get(params, &ENGINE_STORE)
}

pub fn engine_get_undo(params: &mut RequestParams) -> Result<(), MonitorError> {
    /* Was `get`: copy-paste bug, so undo RE-mapped instead of
       unmapping (model_get_undo always had this right). */
    get_undo(params, &ENGINE_STORE)
}
