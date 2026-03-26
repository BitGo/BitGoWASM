//! WASM bindings for TON transaction operations.
//!
//! Thin wrapper around core Transaction with #[wasm_bindgen].

use crate::transaction::Transaction;
use wasm_bindgen::prelude::*;

/// WASM wrapper for TON transactions.
///
/// Provides deserialization, signing, and serialization for V4R2 wallet
/// external messages in BOC format.
#[wasm_bindgen]
pub struct WasmTransaction {
    inner: Transaction,
}

#[wasm_bindgen]
impl WasmTransaction {
    /// Deserialize a transaction from raw BOC bytes.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmTransaction, JsValue> {
        Transaction::from_bytes(bytes)
            .map(|inner| WasmTransaction { inner })
            .map_err(JsValue::from)
    }

    /// Deserialize a transaction from base64-encoded BOC.
    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(b64: &str) -> Result<WasmTransaction, JsValue> {
        Transaction::from_base64(b64)
            .map(|inner| WasmTransaction { inner })
            .map_err(JsValue::from)
    }

    /// Deserialize a transaction from hex-encoded BOC.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<WasmTransaction, JsValue> {
        Transaction::from_hex(hex_str)
            .map(|inner| WasmTransaction { inner })
            .map_err(JsValue::from)
    }

    /// Get the signable payload (SHA-256 hash of the signing body cell).
    ///
    /// Returns 32 bytes that should be signed with Ed25519.
    #[wasm_bindgen(js_name = signablePayload)]
    pub fn signable_payload(&self) -> Result<js_sys::Uint8Array, JsValue> {
        let payload = self.inner.signable_payload().map_err(JsValue::from)?;
        Ok(js_sys::Uint8Array::from(payload.as_slice()))
    }

    /// Add an Ed25519 signature to the transaction.
    ///
    /// @param signature - 64-byte Ed25519 signature
    #[wasm_bindgen(js_name = addSignature)]
    pub fn add_signature(&mut self, signature: &[u8]) -> Result<(), JsValue> {
        self.inner.add_signature(signature).map_err(JsValue::from)
    }

    /// Serialize the transaction to BOC bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<js_sys::Uint8Array, JsValue> {
        let bytes = self.inner.to_bytes().map_err(JsValue::from)?;
        Ok(js_sys::Uint8Array::from(bytes.as_slice()))
    }

    /// Serialize to broadcast format (base64-encoded BOC).
    ///
    /// TON nodes accept base64-encoded BOC for broadcasting.
    #[wasm_bindgen(js_name = toBroadcastFormat)]
    pub fn to_broadcast_format(&self) -> Result<String, JsValue> {
        self.inner.to_broadcast_format().map_err(JsValue::from)
    }

    /// Get the transaction ID (hash of the external message cell).
    ///
    /// Returns undefined if the transaction is unsigned.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Result<Option<String>, JsValue> {
        self.inner.id().map_err(JsValue::from)
    }
}

impl WasmTransaction {
    /// Get a reference to the inner Transaction (for parser).
    pub fn inner(&self) -> &Transaction {
        &self.inner
    }

    /// Create from an inner Transaction (for builder).
    pub fn from_inner(inner: Transaction) -> Self {
        WasmTransaction { inner }
    }
}
