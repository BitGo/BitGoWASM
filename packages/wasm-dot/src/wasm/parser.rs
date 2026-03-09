//! WASM bindings for transaction parsing
//!
//! ParserNamespace provides static methods for parsing DOT transactions

use serde::Serialize;

use crate::parser::{parse_from_transaction, parse_transaction, ParsedTransaction};
use crate::wasm::transaction::{ParseContextJs, WasmTransaction};
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

    /// Parse a pre-deserialized Transaction into structured data.
    ///
    /// Same as `parseTransaction(bytes)` but accepts an already-deserialized
    /// WasmTransaction, avoiding double deserialization when the caller already
    /// has a DotTransaction from `fromBytes()`.
    ///
    /// @param tx - A WasmTransaction instance
    /// @param context - Optional parsing context with chain material
    /// @returns Parsed transaction as JSON-compatible JS object
    #[wasm_bindgen(js_name = parseFromTransaction)]
    pub fn parse_from_transaction_wasm(
        tx: &WasmTransaction,
        context: Option<ParseContextJs>,
    ) -> Result<JsValue, JsValue> {
        let ctx = context.map(|c| c.into_inner());
        let parsed = parse_from_transaction(tx.inner(), ctx.as_ref())?;
        to_js_value(&parsed)
    }

    /// Get the proxy deposit cost from runtime metadata.
    ///
    /// Returns `ProxyDepositBase + ProxyDepositFactor` from the Proxy pallet
    /// as a decimal string (for BigInt conversion).
    ///
    /// This matches the legacy account-lib `getAddProxyCost()` / `getRemoveProxyCost()`.
    ///
    /// @param metadataHex - Runtime metadata hex string (0x-prefixed or bare)
    /// @returns Proxy deposit cost as decimal string
    #[wasm_bindgen(js_name = getProxyDepositCost)]
    pub fn get_proxy_deposit_cost(metadata_hex: &str) -> Result<String, JsValue> {
        let cost = crate::metadata_constants::get_proxy_deposit_cost(metadata_hex)?;
        Ok(cost.to_string())
    }
}

/// Convert ParsedTransaction to JsValue using serde_wasm_bindgen (JSON-compatible mode).
///
/// Uses `json_compatible()` so that serde_json::Value objects (used for method args)
/// are serialized as plain JS objects instead of JS Maps.
fn to_js_value(parsed: &ParsedTransaction) -> Result<JsValue, JsValue> {
    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    parsed
        .serialize(&serializer)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

#[cfg(test)]
mod tests {
    // Tests would run in wasm-pack test environment
}
