use crate::address::networks::{
    from_output_script_with_coin_and_format, to_output_script_or_shielded_receiver_with_coin,
    AddressFormat,
};
use miniscript::bitcoin::Script;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

#[wasm_bindgen]
pub struct AddressNamespace;

#[wasm_bindgen]
impl AddressNamespace {
    /// `can_be_shielded_output`: when set and `address` is a ZIP-316 unified address carrying an
    /// Orchard/Ironwood receiver, returns that raw 43-byte receiver instead of a transparent
    /// scriptPubKey. See [`to_output_script_or_shielded_receiver_with_coin`] for the exact
    /// fallback/error rules.
    #[wasm_bindgen]
    pub fn to_output_script_with_coin(
        address: &str,
        coin: &str,
        can_be_shielded_output: Option<bool>,
    ) -> std::result::Result<Vec<u8>, JsValue> {
        to_output_script_or_shielded_receiver_with_coin(
            address,
            coin,
            can_be_shielded_output.unwrap_or(false),
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn from_output_script_with_coin(
        script: &[u8],
        coin: &str,
        format: Option<String>,
    ) -> std::result::Result<String, JsValue> {
        let script_obj = Script::from_bytes(script);
        let format_str = format.as_deref();
        let address_format = AddressFormat::from_optional_str(format_str)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        from_output_script_with_coin_and_format(script_obj, coin, address_format)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
