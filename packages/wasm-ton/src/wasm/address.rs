//! WASM bindings for address operations
//!
//! AddressNamespace provides static methods for TON address encoding,
//! decoding, and validation.

use crate::address;
use wasm_bindgen::prelude::*;

/// Namespace for address operations
#[wasm_bindgen]
pub struct AddressNamespace;

#[wasm_bindgen]
impl AddressNamespace {
    /// Encode a V4R2 wallet address from an Ed25519 public key.
    ///
    /// @param publicKey - 32-byte Ed25519 public key
    /// @param bounceable - Whether the address should be bounceable
    /// @param testnet - Whether the address is for testnet
    /// @returns User-friendly base64url-encoded address string
    #[wasm_bindgen(js_name = encodeAddress)]
    pub fn encode_address(
        public_key: &[u8],
        bounceable: bool,
        testnet: bool,
    ) -> Result<String, JsValue> {
        address::encode_address(public_key, bounceable, testnet).map_err(JsValue::from)
    }

    /// Decode a TON address to its components.
    ///
    /// Returns a JS object with `workchainId` (number), `hash` (Uint8Array),
    /// `bounceable` (boolean), and `testnet` (boolean).
    ///
    /// @param address - User-friendly (base64url) or raw (workchain:hex) address
    /// @returns { workchainId: number, hash: Uint8Array, bounceable: boolean, testnet: boolean }
    #[wasm_bindgen(js_name = decodeAddress)]
    pub fn decode_address(addr: &str) -> Result<JsValue, JsValue> {
        let decoded = address::decode_address(addr).map_err(JsValue::from)?;

        let obj = js_sys::Object::new();
        let hash_array = js_sys::Uint8Array::from(decoded.hash.as_slice());
        js_sys::Reflect::set(
            &obj,
            &"workchainId".into(),
            &JsValue::from(decoded.workchain_id),
        )?;
        js_sys::Reflect::set(&obj, &"hash".into(), &hash_array)?;
        js_sys::Reflect::set(
            &obj,
            &"bounceable".into(),
            &JsValue::from(decoded.bounceable),
        )?;
        js_sys::Reflect::set(&obj, &"testnet".into(), &JsValue::from(decoded.testnet))?;
        Ok(obj.into())
    }

    /// Validate a TON address string.
    ///
    /// @param address - User-friendly (base64url) or raw (workchain:hex) address
    /// @returns true if the address is valid
    #[wasm_bindgen(js_name = validateAddress)]
    pub fn validate_address(addr: &str) -> bool {
        address::validate_address(addr)
    }

    /// Convert a TON address to raw format (workchain:hex_hash).
    ///
    /// @param address - User-friendly (base64url) address
    /// @returns Raw address string in format "workchain:hex_hash"
    #[wasm_bindgen(js_name = toRawAddress)]
    pub fn to_raw_address(addr: &str) -> Result<String, JsValue> {
        let decoded = address::decode_address(addr).map_err(JsValue::from)?;
        Ok(address::to_raw_address(&decoded))
    }
}
