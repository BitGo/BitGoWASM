use crate::builder;
use wasm_bindgen::prelude::*;

/// Namespace for transaction building operations.
#[wasm_bindgen]
pub struct BuilderNamespace;

#[wasm_bindgen]
impl BuilderNamespace {
    /// Build a transaction from an intent and context.
    ///
    /// @param intent - TonIntent JS object
    /// @param context - BuildContext JS object
    /// @returns Raw BOC bytes as Uint8Array
    #[wasm_bindgen(js_name = buildTransaction)]
    pub fn build_transaction(
        intent: JsValue,
        context: JsValue,
    ) -> Result<js_sys::Uint8Array, JsValue> {
        let intent: builder::TonIntent = serde_wasm_bindgen::from_value(intent)
            .map_err(|e| JsValue::from_str(&format!("invalid intent: {e}")))?;
        let context: builder::BuildContext = serde_wasm_bindgen::from_value(context)
            .map_err(|e| JsValue::from_str(&format!("invalid context: {e}")))?;

        let bytes = builder::build_transaction(&context, &intent)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(js_sys::Uint8Array::from(&bytes[..]))
    }
}
