//! WASM binding for high-level transaction parsing.
//!
//! Exposes transaction parsing functions that return fully decoded
//! transaction data.

use crate::parser;
use crate::wasm::transaction::WasmTransaction;
use crate::wasm::try_into_js_value::TryIntoJsValue;
use wasm_bindgen::prelude::*;

/// Namespace for transaction parsing operations.
#[wasm_bindgen]
pub struct ParserNamespace;

#[wasm_bindgen]
impl ParserNamespace {
    /// Parse a pre-deserialized Transaction into structured data.
    ///
    /// Takes a WasmTransaction and returns a JavaScript object with:
    /// - `sender`: The sender wallet address (base64url)
    /// - `recipients`: Array of { address, amount (BigInt), bounceable }
    /// - `seqno`: Sequence number
    /// - `expireTime`: Expiration timestamp
    /// - `walletId`: Sub-wallet ID
    /// - `memo`: Optional text comment
    /// - `transactionType`: "Send", "SendToken", "SingleNominatorWithdraw", etc.
    /// - `id`: Transaction ID (base64url hash)
    /// - `jettonTransfer`: Optional Jetton transfer details
    /// - `walletVersion`: Wallet version string
    ///
    /// @param tx - A WasmTransaction instance
    /// @returns A ParsedTonTransaction object
    #[wasm_bindgen(js_name = parseFromTransaction)]
    pub fn parse_from_transaction(tx: &WasmTransaction) -> Result<JsValue, JsValue> {
        let parsed =
            parser::parse_transaction(tx.inner()).map_err(|e| JsValue::from_str(&e.to_string()))?;

        parsed
            .try_to_js_value()
            .map_err(|e| JsValue::from_str(&format!("Conversion error: {}", e)))
    }

    /// Parse raw BOC bytes into structured data.
    ///
    /// Convenience method that combines deserialization and parsing.
    ///
    /// @param bytes - Raw BOC bytes
    /// @returns A ParsedTonTransaction object
    #[wasm_bindgen(js_name = parseTransaction)]
    pub fn parse_transaction(bytes: &[u8]) -> Result<JsValue, JsValue> {
        let tx = crate::transaction::TonTransaction::from_boc(bytes)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let parsed =
            parser::parse_transaction(&tx).map_err(|e| JsValue::from_str(&e.to_string()))?;

        parsed
            .try_to_js_value()
            .map_err(|e| JsValue::from_str(&format!("Conversion error: {}", e)))
    }
}
