//! WASM binding for high-level transaction parsing.
//!
//! Exposes a single `parseTransaction` function that returns fully decoded
//! transaction data matching BitGoJS's TxData format.

use crate::parser;
use wasm_bindgen::prelude::*;

/// Namespace for transaction parsing operations.
#[wasm_bindgen]
pub struct ParserNamespace;

#[wasm_bindgen]
impl ParserNamespace {
    /// Parse a serialized Solana transaction into structured data.
    ///
    /// Takes raw transaction bytes and returns a JSON object with:
    /// - `feePayer`: The fee payer address (base58)
    /// - `numSignatures`: Number of required signatures
    /// - `nonce`: The blockhash/nonce value (base58)
    /// - `durableNonce`: Optional durable nonce info (if tx uses nonce)
    /// - `instructionsData`: Array of decoded instructions with semantic types
    /// - `signatures`: Array of signatures (base64 encoded)
    /// - `accountKeys`: Array of all account addresses (base58)
    ///
    /// Each instruction in `instructionsData` has a `type` field identifying the
    /// instruction type (e.g., "Transfer", "StakingActivate", "TokenTransfer").
    ///
    /// @param bytes - The raw transaction bytes (wire format)
    /// @returns A ParsedTransaction object as JSON
    #[wasm_bindgen]
    pub fn parse_transaction(bytes: &[u8]) -> Result<JsValue, JsValue> {
        let parsed = parser::parse_transaction(bytes).map_err(|e| JsValue::from_str(&e))?;

        serde_wasm_bindgen::to_value(&parsed)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
}
