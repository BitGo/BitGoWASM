//! WASM bindings for TON transaction deserialization and signing.
//!
//! WasmTransaction wraps the core Transaction type with #[wasm_bindgen].

use crate::transaction::Transaction;
use wasm_bindgen::prelude::*;

/// WASM wrapper for TON transactions.
///
/// Provides methods for deserialization, signable payload extraction,
/// signature placement, and serialization.
#[wasm_bindgen]
pub struct WasmTransaction {
    inner: Transaction,
}

impl WasmTransaction {
    /// Get a reference to the inner Transaction (for parser access).
    pub fn inner(&self) -> &Transaction {
        &self.inner
    }

    /// Create from an inner Transaction (for builder access).
    pub fn from_inner(inner: Transaction) -> Self {
        WasmTransaction { inner }
    }
}

#[wasm_bindgen]
impl WasmTransaction {
    /// Deserialize a transaction from raw BOC bytes.
    ///
    /// @param bytes - Raw BOC bytes (Uint8Array)
    /// @returns A WasmTransaction instance
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmTransaction, JsValue> {
        Transaction::from_bytes(bytes)
            .map(|inner| WasmTransaction { inner })
            .map_err(|e| JsValue::from(e))
    }

    /// Get the signable payload (SHA-256 hash of sign body Cell).
    ///
    /// Returns 32 bytes that should be signed with Ed25519.
    ///
    /// @returns 32-byte Uint8Array
    #[wasm_bindgen(js_name = signablePayload)]
    pub fn signable_payload(&self) -> Result<js_sys::Uint8Array, JsValue> {
        let bytes = self
            .inner
            .signable_payload()
            .map_err(|e| JsValue::from(e))?;
        Ok(js_sys::Uint8Array::from(&bytes[..]))
    }

    /// Add a 64-byte Ed25519 signature.
    ///
    /// @param signature - 64-byte Ed25519 signature
    #[wasm_bindgen(js_name = addSignature)]
    pub fn add_signature(&mut self, signature: &[u8]) -> Result<(), JsValue> {
        self.inner
            .add_signature(signature)
            .map_err(|e| JsValue::from(e))
    }

    /// Serialize the transaction to BOC bytes.
    ///
    /// @returns Raw BOC bytes as Uint8Array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<js_sys::Uint8Array, JsValue> {
        let bytes = self.inner.to_bytes().map_err(|e| JsValue::from(e))?;
        Ok(js_sys::Uint8Array::from(&bytes[..]))
    }

    /// Serialize to base64 broadcast format (standard TON wire format).
    ///
    /// @returns Base64-encoded BOC string
    #[wasm_bindgen(js_name = toBroadcastFormat)]
    pub fn to_broadcast_format(&self) -> Result<String, JsValue> {
        self.inner
            .to_broadcast_format()
            .map_err(|e| JsValue::from(e))
    }

    /// Get the sequence number.
    #[wasm_bindgen(getter)]
    pub fn seqno(&self) -> u32 {
        self.inner.sign_body().seqno
    }

    /// Get the wallet ID.
    #[wasm_bindgen(getter, js_name = walletId)]
    pub fn wallet_id(&self) -> u32 {
        self.inner.sign_body().wallet_id
    }

    /// Get the expiration time (unix timestamp).
    #[wasm_bindgen(getter, js_name = expireTime)]
    pub fn expire_time(&self) -> u32 {
        self.inner.sign_body().expire_at.timestamp() as u32
    }

    /// Whether the transaction has a StateInit (seqno == 0 deploy).
    #[wasm_bindgen(getter, js_name = hasStateInit)]
    pub fn has_state_init(&self) -> bool {
        self.inner.has_state_init()
    }
}
