use crate::error::WasmUtxoError;
use crate::wasm::try_into_js_value::TryIntoJsValue;
use wasm_bindgen::prelude::*;

/// Top-level package info namespace
#[wasm_bindgen]
pub struct WasmUtxoNamespace;

#[wasm_bindgen]
impl WasmUtxoNamespace {
    /// Returns the wasm-utxo build version as `{ version: string, gitHash: string }`.
    pub fn get_wasm_utxo_version() -> Result<JsValue, WasmUtxoError> {
        use crate::fixed_script_wallet::bitgo_psbt::WasmUtxoVersionInfo;
        WasmUtxoVersionInfo::from_build_info().try_to_js_value()
    }
}
