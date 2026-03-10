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
    /// Build a transaction from a business-level intent and context.
    ///
    /// - intent: what to do (payment, stake, unstake, etc.)
    /// - context: how to build it (sender, nonce, material, validity)
    ///
    /// Multi-call intents (e.g., new stake with proxy) are batched automatically.
    ///
    /// # Intent Types
    /// - `payment`: Transfer DOT (to, amount, keepAlive?)
    /// - `consolidate`: Sweep all DOT (to, keepAlive?)
    /// - `stake`: Bond DOT — with proxyAddress = new stake (bond+addProxy),
    ///   without = top-up (bondExtra)
    /// - `unstake`: Unbond DOT — stopStaking + proxyAddress = full
    ///   (removeProxy+chill+unbond), otherwise partial (unbond only)
    /// - `claim`: Withdraw unbonded (slashingSpans?)
    /// - `fillNonce`: Zero-value self-transfer to advance nonce
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
