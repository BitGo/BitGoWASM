//! WASM bindings for address operations
//!
//! AddressNamespace provides static methods for SS58 address encoding,
//! decoding, and validation.

use crate::address;
use wasm_bindgen::prelude::*;

/// Namespace for address operations
#[wasm_bindgen]
pub struct AddressNamespace;

#[wasm_bindgen]
impl AddressNamespace {
    /// Encode a public key to SS58 address format.
    ///
    /// @param publicKey - 32-byte Ed25519 public key
    /// @param prefix - Network prefix (0 = Polkadot, 2 = Kusama, 42 = Substrate)
    /// @returns SS58-encoded address string
    #[wasm_bindgen(js_name = encodeSs58)]
    pub fn encode_ss58(public_key: &[u8], prefix: u16) -> Result<String, JsValue> {
        address::encode_ss58(public_key, prefix).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Decode an SS58 address to its public key and network prefix.
    ///
    /// Returns a JS object with `publicKey` (Uint8Array) and `prefix` (number).
    ///
    /// @param address - SS58-encoded address string
    /// @returns { publicKey: Uint8Array, prefix: number }
    #[wasm_bindgen(js_name = decodeSs58)]
    pub fn decode_ss58(addr: &str) -> Result<JsValue, JsValue> {
        let (pubkey, prefix) =
            address::decode_ss58(addr).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let obj = js_sys::Object::new();
        let pubkey_array = js_sys::Uint8Array::from(pubkey.as_slice());
        js_sys::Reflect::set(&obj, &"publicKey".into(), &pubkey_array)?;
        js_sys::Reflect::set(&obj, &"prefix".into(), &JsValue::from(prefix))?;
        Ok(obj.into())
    }

    /// Validate an SS58 address.
    ///
    /// @param address - SS58-encoded address string
    /// @param prefix - Optional expected network prefix to check against
    /// @returns true if the address is valid (and matches prefix if provided)
    #[wasm_bindgen(js_name = validateAddress)]
    pub fn validate_address(addr: &str, prefix: Option<u16>) -> bool {
        address::validate_address(addr, prefix)
    }
}
