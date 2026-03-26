//! WASM bindings for intent-based transaction building.
//!
//! Thin wrapper that deserializes JS intent/context objects and delegates
//! to the core builder logic.

use crate::builder;
use crate::builder::{TonBuildContext, TonIntent};
use crate::wasm::transaction::WasmTransaction;
use wasm_bindgen::prelude::*;

/// Namespace for transaction building operations.
#[wasm_bindgen]
pub struct BuilderNamespace;

#[wasm_bindgen]
impl BuilderNamespace {
    /// Build an unsigned transaction from a business intent.
    ///
    /// @param intent - A tagged intent object with `intentType` discriminant
    /// @param context - Build context with sender, publicKey, seqno, expireTime
    /// @returns A WasmTransaction ready for signing
    #[wasm_bindgen(js_name = buildTransaction)]
    pub fn build_transaction(
        intent: JsValue,
        context: JsValue,
    ) -> Result<WasmTransaction, JsError> {
        let intent: TonIntent = serde_wasm_bindgen::from_value(intent)
            .map_err(|e| JsError::new(&format!("Failed to deserialize intent: {e}")))?;

        let context: TonBuildContext = serde_wasm_bindgen::from_value(context)
            .map_err(|e| JsError::new(&format!("Failed to deserialize build context: {e}")))?;

        let tx = builder::build_transaction(&intent, &context)
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(WasmTransaction::from_inner(tx))
    }
}
