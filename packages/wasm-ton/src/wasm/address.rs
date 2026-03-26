use wasm_bindgen::prelude::*;

use crate::address;
use crate::error::WasmTonError;

/// WASM bindings for TON address operations.
#[wasm_bindgen]
pub struct AddressNamespace;

#[wasm_bindgen]
impl AddressNamespace {
    /// Encode a public key into a TON user-friendly address.
    ///
    /// Uses v4R2 wallet contract with the default wallet ID (698983191).
    /// Returns a base64url-encoded user-friendly address.
    pub fn encode(pubkey: &[u8], bounceable: bool) -> Result<String, WasmTonError> {
        let pubkey: &[u8; 32] = pubkey
            .try_into()
            .map_err(|_| WasmTonError::new("public key must be 32 bytes"))?;
        address::encode(pubkey, bounceable, address::DEFAULT_WALLET_ID)
    }

    /// Encode a public key with a custom wallet ID.
    pub fn encode_with_wallet_id(
        pubkey: &[u8],
        bounceable: bool,
        wallet_id: u32,
    ) -> Result<String, WasmTonError> {
        let pubkey: &[u8; 32] = pubkey
            .try_into()
            .map_err(|_| WasmTonError::new("public key must be 32 bytes"))?;
        address::encode(pubkey, bounceable, wallet_id)
    }

    /// Decode a TON user-friendly address into its components.
    ///
    /// Returns a JS object with { workchain, hash, bounceable }.
    pub fn decode(addr: &str) -> Result<JsValue, WasmTonError> {
        let info = address::decode(addr)?;
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("workchain"),
            &JsValue::from(info.workchain),
        )
        .map_err(|_| WasmTonError::new("failed to set workchain"))?;
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("hash"),
            &JsValue::from(js_sys::Uint8Array::from(info.hash.as_slice())),
        )
        .map_err(|_| WasmTonError::new("failed to set hash"))?;
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("bounceable"),
            &JsValue::from(info.bounceable),
        )
        .map_err(|_| WasmTonError::new("failed to set bounceable"))?;
        Ok(obj.into())
    }

    /// Validate whether a string is a valid TON address.
    pub fn validate(addr: &str) -> bool {
        address::validate(addr)
    }

    /// Check if a user-friendly address is bounceable.
    pub fn is_bounceable(addr: &str) -> Result<bool, WasmTonError> {
        address::is_bounceable(addr)
    }

    /// Re-encode an address with a different bounceable flag.
    pub fn set_bounceable(addr: &str, bounceable: bool) -> Result<String, WasmTonError> {
        address::set_bounceable(addr, bounceable)
    }
}
