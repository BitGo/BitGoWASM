//! WASM binding for high-level transaction parsing.
//!
//! Exposes transaction parsing that returns fully decoded
//! transaction data with BigInt amounts.

use crate::js_obj;
use crate::parser::{self, ParsedOutput, ParsedTransaction, TransactionType};
use crate::wasm::transaction::WasmTransaction;
use crate::wasm::try_into_js_value::{JsConversionError, TryIntoJsValue};
use wasm_bindgen::prelude::*;

// =============================================================================
// TryIntoJsValue implementations for parser types
// =============================================================================

impl TryIntoJsValue for TransactionType {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_str(self.as_str()))
    }
}

impl TryIntoJsValue for ParsedOutput {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "address" => self.address,
            "amount" => self.amount
        )
    }
}

impl TryIntoJsValue for ParsedTransaction {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => self.transaction_type,
            "walletId" => self.wallet_id,
            "seqno" => self.seqno,
            "expireTime" => self.expire_time,
            "outputs" => self.outputs,
            "outputAmount" => self.output_amount,
            "bounceable" => self.bounceable,
            "memo" => self.memo,
            "sendMode" => self.send_mode,
            "withdrawAmount" => self.withdraw_amount,
            "jettonAmount" => self.jetton_amount,
            "jettonDestination" => self.jetton_destination,
            "forwardTonAmount" => self.forward_ton_amount
        )
    }
}

// =============================================================================
// ParserNamespace
// =============================================================================

/// Namespace for transaction parsing operations.
#[wasm_bindgen]
pub struct ParserNamespace;

#[wasm_bindgen]
impl ParserNamespace {
    /// Parse a TON transaction into structured data.
    ///
    /// Takes a WasmTransaction and returns a JavaScript object with:
    /// - `type`: Transaction type string (Send, SendToken, etc.)
    /// - `walletId`: Wallet ID (number)
    /// - `seqno`: Sequence number (number)
    /// - `expireTime`: Expiration time as BigInt
    /// - `outputs`: Array of { address, amount (BigInt) }
    /// - `outputAmount`: Total output as BigInt
    /// - `bounceable`: Whether destination is bounceable
    /// - `memo`: Optional text comment
    /// - `sendMode`: Send mode byte
    /// - `withdrawAmount`: Optional withdrawal amount as BigInt
    /// - `jettonAmount`: Optional jetton amount as BigInt
    /// - `jettonDestination`: Optional jetton destination address
    /// - `forwardTonAmount`: Optional forward TON amount as BigInt
    ///
    /// @param tx - A WasmTransaction instance
    /// @returns ParsedTransaction object
    #[wasm_bindgen(js_name = parseTransaction)]
    pub fn parse_transaction(tx: &WasmTransaction) -> Result<JsValue, JsValue> {
        let parsed =
            parser::parse_transaction(tx.inner()).map_err(|e| JsValue::from_str(&e.to_string()))?;

        parsed
            .try_to_js_value()
            .map_err(|e| JsValue::from_str(&format!("Conversion error: {}", e)))
    }
}
