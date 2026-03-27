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
    /// Encode a 32-byte Ed25519 public key to a TON user-friendly address.
    ///
    /// Derives the WalletV4R2 address from the public key using StateInit.
    ///
    /// @param publicKey - 32-byte Ed25519 public key
    /// @param bounceable - whether the address should be bounceable
    /// @param workchainId - workchain ID (0 for basechain, -1 for masterchain)
    /// @param walletId - optional wallet sub-ID (default: 0x29a9a317 for V4R2)
    /// @returns User-friendly base64url-encoded TON address
    #[wasm_bindgen(js_name = encodeAddress)]
    pub fn encode_address(
        public_key: &[u8],
        bounceable: bool,
        workchain_id: i32,
        wallet_id: Option<u32>,
    ) -> Result<String, JsValue> {
        address::encode_address(public_key, bounceable, workchain_id, wallet_id)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Decode a TON address to its components.
    ///
    /// Accepts both user-friendly (base64url) and raw (workchain:hex) formats.
    ///
    /// @param address - TON address string
    /// @returns { workchainId: number, hash: Uint8Array, bounceable: boolean }
    #[wasm_bindgen(js_name = decodeAddress)]
    pub fn decode_address(addr: &str) -> Result<JsValue, JsValue> {
        let (workchain_id, hash, bounceable) =
            address::decode_address(addr).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"workchainId".into(), &JsValue::from(workchain_id))?;
        let hash_array = js_sys::Uint8Array::from(hash.as_slice());
        js_sys::Reflect::set(&obj, &"hash".into(), &hash_array)?;
        js_sys::Reflect::set(&obj, &"bounceable".into(), &JsValue::from(bounceable))?;
        Ok(obj.into())
    }

    /// Validate a TON address string.
    ///
    /// Accepts both user-friendly (base64url) and raw (workchain:hex) formats.
    ///
    /// @param address - TON address string
    /// @returns true if the address is valid
    #[wasm_bindgen(js_name = validateAddress)]
    pub fn validate_address(addr: &str) -> bool {
        address::validate_address(addr)
    }

    /// Convert any valid TON address to user-friendly base64url format.
    ///
    /// @param address - TON address string (raw or user-friendly)
    /// @param bounceable - whether the output should be bounceable
    /// @returns User-friendly base64url-encoded address
    #[wasm_bindgen(js_name = toUserFriendly)]
    pub fn to_user_friendly(addr: &str, bounceable: bool) -> Result<String, JsValue> {
        address::to_user_friendly(addr, bounceable).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Convert any valid TON address to raw format (workchain:hex_hash).
    ///
    /// @param address - TON address string (user-friendly or raw)
    /// @returns Raw address string
    #[wasm_bindgen(js_name = toRaw)]
    pub fn to_raw(addr: &str) -> Result<String, JsValue> {
        address::to_raw(addr).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
