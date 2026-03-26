//! WASM bindings for TON transaction.
//!
//! Thin wrapper around core TonTransaction with #[wasm_bindgen].

use crate::error::WasmTonError;
use crate::transaction::TonTransaction;
use wasm_bindgen::prelude::*;

/// WASM wrapper for TON transactions.
///
/// Provides deserialization from BOC, signable payload extraction,
/// signature placement, and serialization.
#[wasm_bindgen]
pub struct WasmTransaction {
    inner: TonTransaction,
}

#[wasm_bindgen]
impl WasmTransaction {
    /// Deserialize a transaction from base64-encoded BOC.
    #[wasm_bindgen(js_name = fromBoc)]
    pub fn from_boc(boc: &str) -> Result<WasmTransaction, WasmTonError> {
        TonTransaction::from_boc(boc).map(|inner| WasmTransaction { inner })
    }

    /// Get the signable payload (SHA-256 hash of sign body cell).
    ///
    /// Returns a 32-byte Uint8Array that should be signed with Ed25519.
    #[wasm_bindgen(js_name = signablePayload)]
    pub fn signable_payload(&self) -> Result<js_sys::Uint8Array, WasmTonError> {
        let payload = self.inner.signable_payload()?;
        Ok(js_sys::Uint8Array::from(payload.as_slice()))
    }

    /// Add a pre-computed signature to the transaction.
    ///
    /// @param pubkey - 32-byte Ed25519 public key
    /// @param signature - 64-byte Ed25519 signature
    #[wasm_bindgen(js_name = addSignature)]
    pub fn add_signature(&mut self, pubkey: &[u8], signature: &[u8]) -> Result<(), WasmTonError> {
        let pubkey: &[u8; 32] = pubkey
            .try_into()
            .map_err(|_| WasmTonError::new("public key must be 32 bytes"))?;
        let signature: &[u8; 64] = signature
            .try_into()
            .map_err(|_| WasmTonError::new("signature must be 64 bytes"))?;
        self.inner.add_signature(pubkey, signature)
    }

    /// Serialize to base64 BOC (broadcast format).
    #[wasm_bindgen(js_name = toBroadcastFormat)]
    pub fn to_broadcast_format(&self) -> Result<String, WasmTonError> {
        self.inner.to_broadcast_format()
    }

    /// Serialize to raw BOC bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<js_sys::Uint8Array, WasmTonError> {
        let bytes = self.inner.to_bytes()?;
        Ok(js_sys::Uint8Array::from(bytes.as_slice()))
    }

    /// Get the transaction ID (base64url of cell hash).
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.inner.id()
    }

    /// Get the wallet sequence number.
    #[wasm_bindgen(getter)]
    pub fn seqno(&self) -> u32 {
        self.inner.sign_body().seqno
    }

    /// Get the wallet ID.
    #[wasm_bindgen(getter, js_name = walletId)]
    pub fn wallet_id(&self) -> u32 {
        self.inner.sign_body().wallet_id
    }

    /// Check if the transaction has a state init (wallet deploy).
    #[wasm_bindgen(getter, js_name = hasStateInit)]
    pub fn has_state_init(&self) -> bool {
        self.inner.has_state_init()
    }
}

impl WasmTransaction {
    /// Access the inner TonTransaction (for parser).
    pub fn inner(&self) -> &TonTransaction {
        &self.inner
    }

    /// Create from a core TonTransaction (for builder).
    pub fn from_inner(inner: TonTransaction) -> Self {
        WasmTransaction { inner }
    }
}
