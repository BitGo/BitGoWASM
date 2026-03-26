//! WASM binding for high-level transaction parsing.
//!
//! Exposes a standalone parseTransaction function that returns
//! fully decoded transaction data.

use crate::js_obj;
use crate::parser;
use crate::types::{ParsedTransaction, TonTransactionType};
use crate::wasm::transaction::WasmTransaction;
use crate::wasm::try_into_js_value::{JsConversionError, TryIntoJsValue};
use wasm_bindgen::prelude::*;

/// Namespace for transaction parsing operations.
#[wasm_bindgen]
pub struct ParserNamespace;

#[wasm_bindgen]
impl ParserNamespace {
    /// Parse a TON transaction into structured data.
    ///
    /// Takes a WasmTransaction and returns a JavaScript object with:
    /// - `type`: Transaction type string
    /// - `sender`: Sender address
    /// - `recipient`: Recipient address
    /// - `amount`: Transfer amount as BigInt (nanoTON)
    /// - `bounceable`: Whether recipient is bounceable
    /// - `seqno`: Wallet sequence number
    /// - `walletId`: Wallet ID
    /// - `expireTime`: Expiration timestamp as BigInt
    /// - `memo`: Optional text comment
    /// - `signature`: Signature hex string
    /// - `publicKey`: Public key hex (if StateInit present)
    /// - `tokenAmount`: Token amount as BigInt (for jetton transfers)
    /// - `tokenRecipient`: Token recipient address (for jetton transfers)
    #[wasm_bindgen(js_name = parseTransaction)]
    pub fn parse_transaction(tx: &WasmTransaction) -> Result<JsValue, JsValue> {
        let parsed = parser::parse_transaction(tx.inner()).map_err(|e| JsValue::from_str(&e))?;

        parsed
            .try_to_js_value()
            .map_err(|e| JsValue::from_str(&format!("Conversion error: {e}")))
    }
}

// =============================================================================
// TryIntoJsValue implementations for parsed types
// =============================================================================

impl TryIntoJsValue for TonTransactionType {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        let s = match self {
            TonTransactionType::Send => "Send",
            TonTransactionType::SendToken => "SendToken",
            TonTransactionType::SingleNominatorWithdraw => "SingleNominatorWithdraw",
            TonTransactionType::TonWhalesDeposit => "TonWhalesDeposit",
            TonTransactionType::TonWhalesWithdrawal => "TonWhalesWithdrawal",
            TonTransactionType::TonWhalesVestingDeposit => "TonWhalesVestingDeposit",
            TonTransactionType::TonWhalesVestingWithdrawal => "TonWhalesVestingWithdrawal",
        };
        Ok(JsValue::from_str(s))
    }
}

impl TryIntoJsValue for ParsedTransaction {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => self.tx_type,
            "sender" => self.sender,
            "recipient" => self.recipient,
            "amount" => self.amount,
            "bounceable" => self.bounceable,
            "seqno" => self.seqno,
            "walletId" => self.wallet_id,
            "expireTime" => self.expire_time,
            "memo" => self.memo,
            "signature" => self.signature,
            "publicKey" => self.public_key,
            "tokenAmount" => self.token_amount,
            "tokenRecipient" => self.token_recipient
        )
    }
}
