//! WASM bindings for transaction building
//!
//! BuilderNamespace provides the entry point for building DOT transactions.
//! Follows wallet-platform pattern: buildTransaction(intent, context)

use crate::builder::{
    build_transaction,
    types::{BuildContext, TransactionIntent},
};
use crate::wasm::transaction::WasmTransaction;
use wasm_bindgen::prelude::*;

/// Namespace for building operations
#[wasm_bindgen]
pub struct BuilderNamespace;

#[wasm_bindgen]
impl BuilderNamespace {
    /// Build a transaction from an intent and context
    ///
    /// Follows wallet-platform pattern: buildTransaction(intent, context)
    /// - intent: what to do (transfer, stake, etc.)
    /// - context: how to build it (sender, nonce, material, validity)
    ///
    /// # Arguments
    /// * `intent` - What to do (JSON object with type field)
    /// * `context` - Build context (sender, nonce, material, validity, referenceBlock)
    ///
    /// # Returns
    /// WasmTransaction ready for signing
    ///
    /// # Example Intent (Transfer)
    /// ```json
    /// { "type": "transfer", "to": "5FHneW46...", "amount": "1000000000000", "keepAlive": true }
    /// ```
    ///
    /// # Example Context
    /// ```json
    /// {
    ///   "sender": "5EGoFA95omzemRssELLDjVenNZ68aXyUeqtKQScXSEBvVJkr",
    ///   "nonce": 5,
    ///   "tip": "0",
    ///   "material": {
    ///     "genesisHash": "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
    ///     "chainName": "Polkadot",
    ///     "specName": "polkadot",
    ///     "specVersion": 9150,
    ///     "txVersion": 9
    ///   },
    ///   "validity": { "firstValid": 1000, "maxDuration": 2400 },
    ///   "referenceBlock": "0x91b171bb..."
    /// }
    /// ```
    ///
    /// # Intent Types
    /// - `transfer`: Transfer DOT (to, amount, keepAlive)
    /// - `transferAll`: Transfer all DOT (to, keepAlive)
    /// - `stake`: Bond DOT (amount, payee)
    /// - `unstake`: Unbond DOT (amount)
    /// - `withdrawUnbonded`: Withdraw unbonded (slashingSpans)
    /// - `chill`: Stop nominating
    /// - `addProxy`: Add proxy (delegate, proxyType, delay)
    /// - `removeProxy`: Remove proxy (delegate, proxyType, delay)
    /// - `batch`: Multiple calls (calls, atomic)
    #[wasm_bindgen(js_name = buildTransaction)]
    pub fn build_transaction_wasm(
        intent: JsValue,
        context: JsValue,
    ) -> Result<WasmTransaction, JsValue> {
        // Deserialize intent from JS
        let intent: TransactionIntent = serde_wasm_bindgen::from_value(intent)
            .map_err(|e| JsValue::from_str(&format!("Invalid intent: {}", e)))?;

        // Deserialize context from JS
        let context: BuildContext = serde_wasm_bindgen::from_value(context)
            .map_err(|e| JsValue::from_str(&format!("Invalid context: {}", e)))?;

        // Build the transaction
        let tx = build_transaction(intent, context)?;

        // Wrap in WasmTransaction
        Ok(WasmTransaction::from_inner(tx))
    }
}
