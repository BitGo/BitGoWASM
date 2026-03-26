//! WASM bindings for transaction building.
//!
//! BuilderNamespace provides the entry point for building TON transactions
//! from business-level intents.

use crate::builder::{build_transaction, TonTransactionIntent};
use crate::wasm::transaction::WasmTransaction;
use wasm_bindgen::prelude::*;

/// Namespace for building operations.
#[wasm_bindgen]
pub struct BuilderNamespace;

#[wasm_bindgen]
impl BuilderNamespace {
    /// Build a transaction from a business-level intent.
    ///
    /// The intent describes what to do (payment, fillNonce, consolidate,
    /// delegate, undelegate). The crate handles message construction internally.
    ///
    /// # Intent Types
    /// - `payment`: Transfer TON or jettons (recipients, amount, memo?)
    /// - `fillNonce`: Zero-value self-send to advance nonce
    /// - `consolidate`: Sweep funds to recipient
    /// - `delegate`: Stake with a validator (whales/singleNominator/multiNominator)
    /// - `undelegate`: Unstake from a validator
    ///
    /// @param intent - JSON intent object with `intentType` discriminator
    /// @returns An unsigned WasmTransaction ready for signing
    #[wasm_bindgen(js_name = buildTransaction)]
    pub fn build_transaction_wasm(intent: JsValue) -> Result<WasmTransaction, JsValue> {
        let intent: TonTransactionIntent = serde_wasm_bindgen::from_value(intent)
            .map_err(|e| JsValue::from_str(&format!("Invalid intent: {}", e)))?;

        let tx = build_transaction(intent)?;

        Ok(WasmTransaction::from_inner(tx))
    }
}
