//! WASM bindings for transaction parsing
//!
//! ParserNamespace provides static methods for parsing DOT transactions

use crate::parser::{parse_transaction, ParsedTransaction};
use crate::wasm::transaction::ParseContextJs;
use wasm_bindgen::prelude::*;

/// Namespace for parsing operations
#[wasm_bindgen]
pub struct ParserNamespace;

#[wasm_bindgen]
impl ParserNamespace {
    /// Parse a transaction from raw bytes
    ///
    /// # Arguments
    /// * `bytes` - Raw extrinsic bytes
    /// * `context` - Optional parsing context with chain material
    ///
    /// # Returns
    /// Parsed transaction as JSON-compatible JS object
    #[wasm_bindgen(js_name = parseTransaction)]
    pub fn parse_transaction_wasm(
        bytes: &[u8],
        context: Option<ParseContextJs>,
    ) -> Result<JsValue, JsValue> {
        let ctx = context.map(|c| c.into_inner());
        let parsed = parse_transaction(bytes, ctx)?;
        to_js_value(&parsed)
    }

    /// Parse a transaction from hex string
    ///
    /// # Arguments
    /// * `hex` - Hex-encoded extrinsic bytes (with or without 0x prefix)
    /// * `context` - Optional parsing context
    #[wasm_bindgen(js_name = parseTransactionHex)]
    pub fn parse_transaction_hex(
        hex: &str,
        context: Option<ParseContextJs>,
    ) -> Result<JsValue, JsValue> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes =
            hex::decode(hex).map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))?;
        let ctx = context.map(|c| c.into_inner());
        let parsed = parse_transaction(&bytes, ctx)?;
        to_js_value(&parsed)
    }

    /// Get the transaction type from raw bytes
    ///
    /// Quickly determines the transaction type without full parsing
    #[wasm_bindgen(js_name = getTransactionType)]
    pub fn get_transaction_type(bytes: &[u8]) -> Result<String, JsValue> {
        let parsed = parse_transaction(bytes, None)?;
        Ok(parsed.tx_type)
    }

    /// Extract outputs (recipients and amounts) from transaction
    #[wasm_bindgen(js_name = getOutputs)]
    pub fn get_outputs(bytes: &[u8], context: Option<ParseContextJs>) -> Result<JsValue, JsValue> {
        let ctx = context.map(|c| c.into_inner());
        let parsed = parse_transaction(bytes, ctx)?;

        let arr = js_sys::Array::new();
        for output in parsed.outputs {
            let obj = js_sys::Object::new();
            js_sys::Reflect::set(&obj, &"address".into(), &output.address.into())?;
            js_sys::Reflect::set(&obj, &"amount".into(), &output.amount.into())?;
            arr.push(&obj);
        }
        Ok(arr.into())
    }
}

/// Convert ParsedTransaction to JsValue using serde_wasm_bindgen
fn to_js_value(parsed: &ParsedTransaction) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(parsed)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

#[cfg(test)]
mod tests {
    // Tests would run in wasm-pack test environment
}
