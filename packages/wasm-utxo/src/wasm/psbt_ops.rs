use crate::error::WasmUtxoError;
use crate::psbt_ops::PsbtAccess;
use crate::wasm::try_from_js_value::{PsbtKvKey, TryFromJsValue};
use wasm_bindgen::JsValue;

/// WASM-layer trait providing shared method implementations for any `PsbtAccess` implementor.
/// Blanket-impl'd so both `WrapPsbt` and the inner `BitGoPsbt` get these for free.
pub(crate) trait WasmPsbtOps: PsbtAccess {
    fn wasm_input_count(&self) -> usize {
        PsbtAccess::input_count(self)
    }

    fn wasm_output_count(&self) -> usize {
        PsbtAccess::output_count(self)
    }

    fn wasm_version(&self) -> i32 {
        PsbtAccess::version(self)
    }

    fn wasm_lock_time(&self) -> u32 {
        PsbtAccess::lock_time(self)
    }

    fn wasm_unsigned_tx_id(&self) -> String {
        PsbtAccess::unsigned_tx_id(self)
    }

    fn wasm_remove_input(&mut self, index: usize) -> Result<(), WasmUtxoError> {
        PsbtAccess::remove_input(self, index).map_err(|e| WasmUtxoError::new(&e))
    }

    fn wasm_remove_output(&mut self, index: usize) -> Result<(), WasmUtxoError> {
        PsbtAccess::remove_output(self, index).map_err(|e| WasmUtxoError::new(&e))
    }

    fn wasm_get_inputs(&self) -> Result<JsValue, WasmUtxoError> {
        crate::wasm::psbt::get_inputs_from_psbt(self.psbt())
    }

    fn wasm_get_outputs(&self) -> Result<JsValue, WasmUtxoError> {
        crate::wasm::psbt::get_outputs_from_psbt(self.psbt())
    }

    fn wasm_get_global_xpubs(&self) -> JsValue {
        crate::wasm::psbt::get_global_xpubs_from_psbt(self.psbt())
    }

    fn wasm_set_kv(&mut self, key: JsValue, value: Vec<u8>) -> Result<(), WasmUtxoError> {
        match PsbtKvKey::try_from_js_value(&key)? {
            PsbtKvKey::Unknown(k) => PsbtAccess::set_global_unknown_kv(self, k, value),
            PsbtKvKey::Proprietary(k) => PsbtAccess::set_global_proprietary_kv(self, k, value),
        }
        Ok(())
    }

    fn wasm_get_kv(&self, key: JsValue) -> Result<Option<Vec<u8>>, WasmUtxoError> {
        Ok(match PsbtKvKey::try_from_js_value(&key)? {
            PsbtKvKey::Unknown(k) => PsbtAccess::get_global_unknown_kv(self, &k),
            PsbtKvKey::Proprietary(k) => PsbtAccess::get_global_proprietary_kv(self, &k),
        })
    }

    fn wasm_set_input_kv(
        &mut self,
        index: usize,
        key: JsValue,
        value: Vec<u8>,
    ) -> Result<(), WasmUtxoError> {
        match PsbtKvKey::try_from_js_value(&key)? {
            PsbtKvKey::Unknown(k) => PsbtAccess::set_input_unknown_kv(self, index, k, value),
            PsbtKvKey::Proprietary(k) => {
                PsbtAccess::set_input_proprietary_kv(self, index, k, value)
            }
        }
        .map_err(|e| WasmUtxoError::new(&e))
    }

    fn wasm_get_input_kv(
        &self,
        index: usize,
        key: JsValue,
    ) -> Result<Option<Vec<u8>>, WasmUtxoError> {
        match PsbtKvKey::try_from_js_value(&key)? {
            PsbtKvKey::Unknown(k) => PsbtAccess::get_input_unknown_kv(self, index, &k),
            PsbtKvKey::Proprietary(k) => PsbtAccess::get_input_proprietary_kv(self, index, &k),
        }
        .map_err(|e| WasmUtxoError::new(&e))
    }

    fn wasm_set_output_kv(
        &mut self,
        index: usize,
        key: JsValue,
        value: Vec<u8>,
    ) -> Result<(), WasmUtxoError> {
        match PsbtKvKey::try_from_js_value(&key)? {
            PsbtKvKey::Unknown(k) => PsbtAccess::set_output_unknown_kv(self, index, k, value),
            PsbtKvKey::Proprietary(k) => {
                PsbtAccess::set_output_proprietary_kv(self, index, k, value)
            }
        }
        .map_err(|e| WasmUtxoError::new(&e))
    }

    fn wasm_get_output_kv(
        &self,
        index: usize,
        key: JsValue,
    ) -> Result<Option<Vec<u8>>, WasmUtxoError> {
        match PsbtKvKey::try_from_js_value(&key)? {
            PsbtKvKey::Unknown(k) => PsbtAccess::get_output_unknown_kv(self, index, &k),
            PsbtKvKey::Proprietary(k) => PsbtAccess::get_output_proprietary_kv(self, index, &k),
        }
        .map_err(|e| WasmUtxoError::new(&e))
    }
}

impl<T: PsbtAccess> WasmPsbtOps for T {}
