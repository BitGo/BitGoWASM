//! WASM binding for high-level transaction parsing.
//!
//! Exposes transaction parsing functions that return fully decoded
//! transaction data matching BitGoJS's TxData format.

use crate::parser;
use crate::wasm::transaction::WasmTransaction;
use crate::wasm::try_into_js_value::TryIntoJsValue;
use wasm_bindgen::prelude::*;

/// Namespace for transaction parsing operations.
#[wasm_bindgen]
pub struct ParserNamespace;

#[wasm_bindgen]
impl ParserNamespace {
    /// Parse a serialized Solana transaction into structured data.
    ///
    /// Takes raw transaction bytes and returns a JavaScript object with:
    /// - `feePayer`: The fee payer address (base58)
    /// - `numSignatures`: Number of required signatures
    /// - `nonce`: The blockhash/nonce value (base58)
    /// - `durableNonce`: Optional durable nonce info (if tx uses nonce)
    /// - `instructionsData`: Array of decoded instructions with semantic types
    /// - `accountKeys`: Array of all account addresses (base58)
    ///
    /// Each instruction in `instructionsData` has a `type` field identifying the
    /// instruction type (e.g., "Transfer", "StakingActivate", "TokenTransfer").
    ///
    /// Amount fields (amount, fee, lamports, poolTokens) are returned as BigInt.
    ///
    /// @param bytes - The raw transaction bytes (wire format)
    /// @returns A ParsedTransaction object
    #[wasm_bindgen]
    pub fn parse_transaction(bytes: &[u8]) -> Result<JsValue, JsValue> {
        let parsed = parser::parse_transaction(bytes).map_err(|e| JsValue::from_str(&e))?;

        parsed
            .try_to_js_value()
            .map_err(|e| JsValue::from_str(&format!("Conversion error: {}", e)))
    }

    /// Parse a pre-deserialized Transaction into structured data.
    ///
    /// Same as `parse_transaction(bytes)` but accepts an already-deserialized
    /// WasmTransaction, avoiding double deserialization when the caller already
    /// has a Transaction from `fromBytes()`.
    ///
    /// @param tx - A WasmTransaction instance
    /// @returns A ParsedTransaction object
    #[wasm_bindgen]
    pub fn parse_from_transaction(tx: &WasmTransaction) -> Result<JsValue, JsValue> {
        let parsed =
            parser::parse_from_transaction(tx.inner()).map_err(|e| JsValue::from_str(&e))?;

        parsed
            .try_to_js_value()
            .map_err(|e| JsValue::from_str(&format!("Conversion error: {}", e)))
    }
}
