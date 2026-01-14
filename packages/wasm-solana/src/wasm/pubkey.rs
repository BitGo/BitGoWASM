//! WASM bindings for Solana public key (address) operations.
//!
//! Wraps `solana_pubkey::Pubkey` for JavaScript.

use crate::error::WasmSolanaError;
use crate::pubkey::{Pubkey, PubkeyExt};
use wasm_bindgen::prelude::*;

/// WASM wrapper for Solana public key (address).
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmPubkey {
    inner: Pubkey,
}

#[wasm_bindgen]
impl WasmPubkey {
    /// Create a Pubkey from a base58 string.
    #[wasm_bindgen]
    pub fn from_base58(address: &str) -> Result<WasmPubkey, WasmSolanaError> {
        Pubkey::from_base58(address).map(|inner| WasmPubkey { inner })
    }

    /// Create a Pubkey from raw bytes (32 bytes).
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmPubkey, WasmSolanaError> {
        Pubkey::from_bytes_checked(bytes).map(|inner| WasmPubkey { inner })
    }

    /// Convert to base58 string (the standard Solana address format).
    #[wasm_bindgen]
    pub fn to_base58(&self) -> String {
        self.inner.to_string()
    }

    /// Get as raw bytes (32 bytes).
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> js_sys::Uint8Array {
        let bytes = self.inner.to_bytes();
        js_sys::Uint8Array::from(&bytes[..])
    }

    /// Check if two pubkeys are equal.
    #[wasm_bindgen]
    pub fn equals(&self, other: &WasmPubkey) -> bool {
        self.inner == other.inner
    }

    /// Check if this public key is on the Ed25519 curve.
    #[wasm_bindgen]
    pub fn is_on_curve(&self) -> bool {
        self.inner.is_on_curve()
    }
}

impl WasmPubkey {
    /// Create from inner Pubkey.
    pub fn from_inner(inner: Pubkey) -> Self {
        WasmPubkey { inner }
    }

    /// Get the inner Pubkey for internal Rust use.
    pub fn inner(&self) -> &Pubkey {
        &self.inner
    }
}
