//! WASM bindings for intent-based transaction building.

use crate::builder;
use crate::wasm::transaction::WasmTransaction;
use wasm_bindgen::prelude::*;

/// Namespace for intent-based transaction building.
#[wasm_bindgen]
pub struct BuilderNamespace;

#[wasm_bindgen]
impl BuilderNamespace {
    /// Build an unsigned transaction from a business intent.
    ///
    /// @param intent - The intent object (with intentType discriminator)
    /// @param context - Build context (senderAddress, seqno, expireTime, etc.)
    /// @returns A WasmTransaction ready for signing
    ///
    /// @example
    /// ```javascript
    /// const tx = BuilderNamespace.buildTransaction(
    ///   {
    ///     intentType: 'payment',
    ///     recipients: [{ address: 'EQ...', amount: '1000000000' }],
    ///     memo: 'hello',
    ///   },
    ///   {
    ///     senderAddress: 'EQ...',
    ///     seqno: 5,
    ///     expireTime: 1700000000,
    ///   }
    /// );
    /// ```
    #[wasm_bindgen(js_name = buildTransaction)]
    pub fn build_transaction(
        intent: JsValue,
        context: JsValue,
    ) -> Result<WasmTransaction, JsValue> {
        let intent: builder::TonTransactionIntent = serde_wasm_bindgen::from_value(intent)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse intent: {}", e)))?;

        let ctx: builder::BuildContext = serde_wasm_bindgen::from_value(context)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse build context: {}", e)))?;

        let tx = builder::build_transaction(&intent, &ctx).map_err(|e| JsValue::from(e))?;

        Ok(WasmTransaction::from_inner(tx))
    }
}
