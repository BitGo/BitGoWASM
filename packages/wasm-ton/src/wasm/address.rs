use crate::address;
use wasm_bindgen::prelude::*;

/// Namespace for TON address operations.
#[wasm_bindgen]
pub struct AddressNamespace;

#[wasm_bindgen]
impl AddressNamespace {
    /// Encode an address hash and workchain into a user-friendly TON address.
    ///
    /// @param workchain_id - The workchain ID (0 for basechain)
    /// @param address_hash - 32-byte address hash
    /// @param bounceable - Whether the address is bounceable
    /// @returns User-friendly base64url address string
    #[wasm_bindgen]
    pub fn encode(
        workchain_id: i32,
        address_hash: &[u8],
        bounceable: bool,
    ) -> Result<String, JsValue> {
        let format = if bounceable {
            address::AddressFormat::Bounceable
        } else {
            address::AddressFormat::NonBounceable
        };
        address::encode_address(workchain_id, address_hash, format)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Encode a raw Ed25519 public key to a TON user-friendly address.
    ///
    /// Computes the wallet v4r2 StateInit hash internally (workchain 0, default wallet ID).
    ///
    /// @param public_key - 32-byte Ed25519 public key
    /// @param bounceable - Whether the address is bounceable (default: true)
    /// @returns User-friendly base64url address string
    #[wasm_bindgen(js_name = encodeAddress)]
    pub fn encode_address(public_key: &[u8], bounceable: bool) -> Result<String, JsValue> {
        address::encode_address_from_public_key(public_key, bounceable)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Encode an address hash and workchain into raw hex format.
    ///
    /// @param workchain_id - The workchain ID
    /// @param address_hash - 32-byte address hash
    /// @returns Raw hex address (workchain:hex)
    #[wasm_bindgen(js_name = encodeRawHex)]
    pub fn encode_raw_hex(workchain_id: i32, address_hash: &[u8]) -> Result<String, JsValue> {
        address::encode_address(workchain_id, address_hash, address::AddressFormat::RawHex)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Decode a TON address string.
    ///
    /// Returns a JS object with:
    /// - workchainId: number
    /// - addressHash: Uint8Array (32 bytes)
    /// - isBounceable: boolean
    /// - isTestnet: boolean
    ///
    /// @param address - TON address (user-friendly or raw hex)
    /// @returns Decoded address object
    #[wasm_bindgen]
    pub fn decode(addr: &str) -> Result<JsValue, JsValue> {
        let (wc, hash, bounceable, testnet) =
            address::decode_address(addr).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"workchainId".into(), &JsValue::from(wc))?;
        js_sys::Reflect::set(
            &obj,
            &"addressHash".into(),
            &js_sys::Uint8Array::from(hash.as_slice()),
        )?;
        js_sys::Reflect::set(&obj, &"isBounceable".into(), &JsValue::from(bounceable))?;
        js_sys::Reflect::set(&obj, &"isTestnet".into(), &JsValue::from(testnet))?;
        Ok(obj.into())
    }

    /// Validate a TON address string.
    ///
    /// @param address - TON address to validate
    /// @returns true if valid
    #[wasm_bindgen]
    pub fn validate(addr: &str) -> bool {
        address::validate_address(addr)
    }
}
