//! WASM bindings for address operations
//!
//! AddressNamespace provides static methods for TON address encoding,
//! decoding, and validation.

use crate::address;
use crate::address::WalletVersion;
use wasm_bindgen::prelude::*;

/// Namespace for address operations
#[wasm_bindgen]
pub struct AddressNamespace;

#[wasm_bindgen]
impl AddressNamespace {
    /// Encode a public key to a TON address.
    ///
    /// @param publicKey - 32-byte Ed25519 public key
    /// @param bounceable - Whether the address should be bounceable
    /// @param walletVersion - Wallet version string: "V3R2", "V4R2", or "V5R1"
    /// @returns Base64url-encoded TON address
    #[wasm_bindgen(js_name = encodeAddress)]
    pub fn encode_address(
        public_key: &[u8],
        bounceable: bool,
        wallet_version: &str,
    ) -> Result<String, JsValue> {
        let version: WalletVersion = wallet_version
            .parse()
            .map_err(|e: crate::error::WasmTonError| JsValue::from_str(&e.to_string()))?;
        address::encode_address(public_key, bounceable, version)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Decode a TON address to its components.
    ///
    /// Returns a JS object with `workchain` (number), `hashPart` (Uint8Array),
    /// and `bounceable` (boolean).
    ///
    /// @param address - Base64url-encoded TON address
    /// @returns { workchain: number, hashPart: Uint8Array, bounceable: boolean }
    #[wasm_bindgen(js_name = decodeAddress)]
    pub fn decode_address(addr: &str) -> Result<JsValue, JsValue> {
        let decoded =
            address::decode_address(addr).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"workchain".into(), &JsValue::from(decoded.workchain))?;
        let hash_array = js_sys::Uint8Array::from(decoded.hash_part.as_slice());
        js_sys::Reflect::set(&obj, &"hashPart".into(), &hash_array)?;
        js_sys::Reflect::set(
            &obj,
            &"bounceable".into(),
            &JsValue::from(decoded.bounceable),
        )?;
        Ok(obj.into())
    }

    /// Validate a TON address string.
    ///
    /// @param address - Base64url-encoded TON address
    /// @returns true if the address is valid
    #[wasm_bindgen(js_name = validateAddress)]
    pub fn validate_address(addr: &str) -> bool {
        address::validate_address(addr)
    }
}
