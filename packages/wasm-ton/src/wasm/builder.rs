//! WASM bindings for transaction building.
//!
//! BuilderNamespace provides the entry point for building TON transactions.
//! Follows the wallet-platform pattern: buildTransaction(intent, context).

use crate::builder::{
    build_transaction,
    types::{TonBuildContext, TonTransactionIntent},
};
use crate::wasm::transaction::WasmTransaction;
use wasm_bindgen::prelude::*;

/// Namespace for building operations.
#[wasm_bindgen]
pub struct BuilderNamespace;

#[wasm_bindgen]
impl BuilderNamespace {
    /// Build a transaction from a business-level intent and context.
    ///
    /// - intent: what to do (payment, delegate, undelegate, fillNonce, consolidate)
    /// - context: how to build it (sender, publicKey, seqno, expireTime, walletVersion, walletId)
    ///
    /// Returns an unsigned WasmTransaction ready for signing.
    ///
    /// # Intent Types
    /// - `payment`: Native TON or Jetton transfer
    /// - `fillNonce`: Self-send to advance seqno
    /// - `consolidate`: Sweep funds (7-day expiry)
    /// - `delegate`: Staking deposit (TON_WHALES, SINGLE_NOMINATOR, MULTI_NOMINATOR)
    /// - `undelegate`: Staking withdrawal
    #[wasm_bindgen(js_name = buildTransaction)]
    pub fn build_transaction_wasm(
        intent: JsValue,
        context: JsValue,
    ) -> Result<WasmTransaction, JsValue> {
        // Deserialize intent from JS
        let intent: TonTransactionIntent = serde_wasm_bindgen::from_value(intent)
            .map_err(|e| JsValue::from_str(&format!("Invalid intent: {}", e)))?;

        // Deserialize context from JS
        let context: TonBuildContext = serde_wasm_bindgen::from_value(context)
            .map_err(|e| JsValue::from_str(&format!("Invalid context: {}", e)))?;

        // Build the transaction
        let tx = build_transaction(intent, context)?;

        // Wrap in WasmTransaction
        Ok(WasmTransaction::from_inner(tx))
    }
}
