use crate::error::WasmUtxoError;
use crate::message;
use crate::wasm::ecpair::WasmECPair;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct MessageNamespace;

#[wasm_bindgen]
impl MessageNamespace {
    /// Sign a message using Bitcoin message signing (BIP-137)
    ///
    /// Returns 65-byte signature (1-byte header + 64-byte signature).
    /// The key must have a private key (cannot sign with public key only).
    #[wasm_bindgen]
    pub fn sign_message(
        key: &WasmECPair,
        message_str: &str,
    ) -> Result<js_sys::Uint8Array, WasmUtxoError> {
        let secret_key = key.get_private_key()?;
        let signature = message::sign_bitcoin_message(&secret_key, message_str)?;
        Ok(js_sys::Uint8Array::from(&signature[..]))
    }

    /// Verify a Bitcoin message signature (BIP-137)
    ///
    /// Signature must be 65 bytes (1-byte header + 64-byte signature).
    /// Returns true if the signature is valid for this key.
    #[wasm_bindgen]
    pub fn verify_message(
        key: &WasmECPair,
        message_str: &str,
        signature: &[u8],
    ) -> Result<bool, WasmUtxoError> {
        let public_key = key.get_public_key();
        message::verify_bitcoin_message(&public_key, message_str, signature)
    }
}
