//! WASM bindings for intent-based transaction building.

use crate::intent;
use crate::wasm::transaction::WasmTransaction;
use wasm_bindgen::prelude::*;

/// Namespace for intent-based building operations.
#[wasm_bindgen]
pub struct IntentNamespace;

#[wasm_bindgen]
impl IntentNamespace {
    /// Build a transaction directly from a BitGo intent.
    ///
    /// This function takes the full intent as-is and builds the transaction
    /// without requiring the caller to construct instructions.
    ///
    /// # Arguments
    ///
    /// * `intent` - The full BitGo intent object (with intentType, etc.)
    /// * `params` - Build parameters: { feePayer, nonce }
    ///
    /// # Returns
    ///
    /// An object with:
    /// * `transaction` - WasmTransaction object
    /// * `generatedKeypairs` - Array of keypairs generated (for stake accounts, etc.)
    ///
    /// # Example
    ///
    /// ```javascript
    /// const result = IntentNamespace.build_from_intent(
    ///   {
    ///     intentType: 'stake',
    ///     validatorAddress: '...',
    ///     amount: { value: 1000000000n }
    ///   },
    ///   {
    ///     feePayer: 'DgT9...',
    ///     nonce: { type: 'blockhash', value: 'GWaQ...' }
    ///   }
    /// );
    /// // result.transaction - WasmTransaction object
    /// // result.generatedKeypairs - [{ purpose, address, secretKey }]
    /// ```
    #[wasm_bindgen]
    pub fn build_from_intent(intent: JsValue, params: JsValue) -> Result<JsValue, JsValue> {
        // Parse intent as generic JSON
        let intent_json: serde_json::Value = serde_wasm_bindgen::from_value(intent)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse intent: {}", e)))?;

        // Parse build params
        let build_params: intent::BuildParams = serde_wasm_bindgen::from_value(params)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse build params: {}", e)))?;

        // Build the transaction
        let result = intent::build_from_intent(&intent_json, &build_params)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        // Wrap the Transaction directly (no serialize/deserialize round-trip)
        let wasm_tx = WasmTransaction::from_inner(result.transaction);

        // Build result object with WasmTransaction
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"transaction".into(), &wasm_tx.into())
            .map_err(|_| JsValue::from_str("Failed to set transaction"))?;

        // Serialize generated keypairs
        let keypairs = serde_wasm_bindgen::to_value(&result.generated_keypairs)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize keypairs: {}", e)))?;
        js_sys::Reflect::set(&obj, &"generatedKeypairs".into(), &keypairs)
            .map_err(|_| JsValue::from_str("Failed to set generatedKeypairs"))?;

        Ok(obj.into())
    }
}
