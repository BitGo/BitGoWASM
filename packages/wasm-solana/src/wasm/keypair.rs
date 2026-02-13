//! WASM bindings for Solana keypair operations.
//!
//! Wraps `solana_keypair::Keypair` for JavaScript.

use crate::error::WasmSolanaError;
use crate::keypair::{Keypair, KeypairExt};
use wasm_bindgen::prelude::*;

/// WASM wrapper for Solana Ed25519 keypairs.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WasmKeypair {
    inner: Keypair,
}

#[wasm_bindgen]
impl WasmKeypair {
    /// Generate a new random keypair.
    #[wasm_bindgen]
    pub fn generate() -> WasmKeypair {
        WasmKeypair {
            inner: Keypair::new(),
        }
    }

    /// Create a keypair from a 32-byte secret key.
    #[wasm_bindgen]
    pub fn from_secret_key(secret_key: &[u8]) -> Result<WasmKeypair, WasmSolanaError> {
        Keypair::from_secret_key_bytes(secret_key).map(|inner| WasmKeypair { inner })
    }

    /// Create a keypair from a 64-byte Solana secret key (secret + public concatenated).
    #[wasm_bindgen]
    pub fn from_solana_secret_key(secret_key: &[u8]) -> Result<WasmKeypair, WasmSolanaError> {
        Keypair::from_solana_secret_key(secret_key).map(|inner| WasmKeypair { inner })
    }

    /// Get the public key as a 32-byte Uint8Array.
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> js_sys::Uint8Array {
        let bytes = self.inner.public_key_bytes();
        js_sys::Uint8Array::from(&bytes[..])
    }

    /// Get the secret key as a 32-byte Uint8Array.
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> js_sys::Uint8Array {
        let bytes = self.inner.secret_key_bytes();
        js_sys::Uint8Array::from(&bytes[..])
    }

    /// Get the address as a base58 string.
    #[wasm_bindgen]
    pub fn address(&self) -> String {
        self.inner.address()
    }

    /// Get the public key as a base58 string.
    #[wasm_bindgen]
    pub fn to_base58(&self) -> String {
        self.inner.address()
    }

    /// Sign a message with this keypair and return the 64-byte Ed25519 signature.
    ///
    /// @param message - The message bytes to sign
    /// @returns The 64-byte signature as a Uint8Array
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> js_sys::Uint8Array {
        use solana_signer::Signer;
        let sig = self.inner.sign_message(message);
        js_sys::Uint8Array::from(sig.as_ref())
    }
}

impl WasmKeypair {
    /// Get the inner Keypair for internal Rust use.
    pub fn inner(&self) -> &Keypair {
        &self.inner
    }
}
