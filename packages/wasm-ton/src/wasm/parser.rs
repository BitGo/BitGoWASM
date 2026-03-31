use crate::parser;
use crate::wasm::transaction::WasmTransaction;
use crate::wasm::try_into_js_value::TryIntoJsValue;
use wasm_bindgen::prelude::*;

/// Namespace for transaction parsing operations.
#[wasm_bindgen]
pub struct ParserNamespace;

#[wasm_bindgen]
impl ParserNamespace {
    /// Parse a serialized TON transaction (BOC bytes) into structured data.
    ///
    /// @param bytes - Raw BOC bytes
    /// @returns ParsedTransaction object
    #[wasm_bindgen(js_name = parseTransaction)]
    pub fn parse_transaction(bytes: &[u8]) -> Result<JsValue, JsValue> {
        let parsed =
            parser::parse_transaction(bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
        parsed
            .try_to_js_value()
            .map_err(|e| JsValue::from_str(&format!("Conversion error: {e}")))
    }

    /// Parse a pre-deserialized WasmTransaction into structured data.
    ///
    /// @param tx - A WasmTransaction instance
    /// @returns ParsedTransaction object
    #[wasm_bindgen(js_name = parseFromTransaction)]
    pub fn parse_from_transaction(tx: &WasmTransaction) -> Result<JsValue, JsValue> {
        let parsed = parser::parse_from_transaction(tx.inner())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        parsed
            .try_to_js_value()
            .map_err(|e| JsValue::from_str(&format!("Conversion error: {e}")))
    }
}
