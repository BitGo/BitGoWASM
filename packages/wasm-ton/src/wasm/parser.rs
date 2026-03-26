//! WASM bindings for transaction parsing.
//!
//! ParserNamespace provides static methods for parsing TON transactions.

use crate::js_obj;
use crate::parser::{self, ParsedTonTransaction, TonTransactionType};
use crate::wasm::transaction::WasmTransaction;
use crate::wasm::try_into_js_value::{JsConversionError, TryIntoJsValue};
use wasm_bindgen::prelude::*;

impl TryIntoJsValue for TonTransactionType {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_str(self.as_str()))
    }
}

impl TryIntoJsValue for ParsedTonTransaction {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "id" => self.id,
            "sender" => self.sender,
            "destination" => self.destination,
            "destinationAlias" => self.destination_alias,
            "amount" => self.amount,
            "withdrawAmount" => self.withdraw_amount,
            "memo" => self.memo,
            "seqno" => self.seqno,
            "expirationTime" => self.expiration_time,
            "bounceable" => self.bounceable,
            "transactionType" => self.transaction_type,
            "subWalletId" => self.sub_wallet_id,
            "isSigned" => self.is_signed,
            "sendMode" => self.send_mode
        )
    }
}

/// Namespace for transaction parsing operations.
#[wasm_bindgen]
pub struct ParserNamespace;

#[wasm_bindgen]
impl ParserNamespace {
    /// Parse a TON transaction from raw BOC bytes into structured data.
    ///
    /// Returns a JavaScript object with: id, sender, destination, amount,
    /// memo, seqno, expirationTime, bounceable, transactionType, etc.
    ///
    /// Amount fields are returned as BigInt.
    ///
    /// @param bytes - Raw BOC bytes
    /// @returns A ParsedTonTransaction object
    #[wasm_bindgen(js_name = parseTransaction)]
    pub fn parse_transaction(bytes: &[u8]) -> Result<JsValue, JsValue> {
        let tx = crate::transaction::Transaction::from_bytes(bytes)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let parsed =
            parser::parse_transaction(&tx).map_err(|e| JsValue::from_str(&e.to_string()))?;
        parsed
            .try_to_js_value()
            .map_err(|e| JsValue::from_str(&format!("Conversion error: {}", e)))
    }

    /// Parse a pre-deserialized Transaction into structured data.
    ///
    /// Avoids double deserialization when the caller already has a
    /// Transaction from fromBytes().
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
}
