//! WASM bindings for TON transaction deserialization.
//!
//! Wraps TonTransaction for JavaScript consumption.

use crate::transaction::TonTransaction;
use wasm_bindgen::prelude::*;

/// WASM wrapper for TON transactions.
///
/// Provides deserialization, signing, and serialization of TON external messages.
#[wasm_bindgen]
pub struct WasmTransaction {
    inner: TonTransaction,
}

#[wasm_bindgen]
impl WasmTransaction {
    /// Deserialize a transaction from BOC bytes.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmTransaction, JsValue> {
        let inner = TonTransaction::from_boc(bytes).map_err(|e| JsValue::from(e))?;
        Ok(WasmTransaction { inner })
    }

    /// Deserialize a transaction from base64-encoded BOC.
    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(b64: &str) -> Result<WasmTransaction, JsValue> {
        let inner = TonTransaction::from_base64(b64).map_err(|e| JsValue::from(e))?;
        Ok(WasmTransaction { inner })
    }

    /// Get the transaction ID (base64url hash of the signed message cell).
    /// Returns undefined if the transaction is not signed.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Option<String> {
        self.inner.id()
    }

    /// Get the sequence number.
    #[wasm_bindgen(getter)]
    pub fn seqno(&self) -> u32 {
        self.inner.seqno
    }

    /// Get the expiration time (unix timestamp).
    #[wasm_bindgen(getter, js_name = expireTime)]
    pub fn expire_time(&self) -> u32 {
        self.inner.expire_time
    }

    /// Get the sub-wallet ID.
    #[wasm_bindgen(getter, js_name = walletId)]
    pub fn wallet_id(&self) -> i32 {
        self.inner.wallet_id
    }

    /// Get the wallet version as string.
    #[wasm_bindgen(getter, js_name = walletVersion)]
    pub fn wallet_version(&self) -> String {
        format!("{:?}", self.inner.wallet_version)
    }

    /// Check if the transaction is signed.
    #[wasm_bindgen(getter, js_name = isSigned)]
    pub fn is_signed(&self) -> bool {
        self.inner.signature.is_some()
    }

    /// Get the signable payload (32-byte cell hash of unsigned body).
    #[wasm_bindgen(js_name = signablePayload)]
    pub fn signable_payload(&self) -> js_sys::Uint8Array {
        let payload = self.inner.signable_payload();
        js_sys::Uint8Array::from(&payload[..])
    }

    /// Add a 64-byte Ed25519 signature to the transaction.
    #[wasm_bindgen(js_name = addSignature)]
    pub fn add_signature(&mut self, signature: &[u8]) -> Result<(), JsValue> {
        self.inner
            .add_signature(signature)
            .map_err(|e| JsValue::from(e))
    }

    /// Serialize the transaction to BOC bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<js_sys::Uint8Array, JsValue> {
        let bytes = self.inner.to_boc().map_err(|e| JsValue::from(e))?;
        Ok(js_sys::Uint8Array::from(&bytes[..]))
    }

    /// Serialize to base64-encoded BOC (TON's broadcast format).
    #[wasm_bindgen(js_name = toBase64)]
    pub fn to_base64(&self) -> Result<String, JsValue> {
        self.inner.to_base64().map_err(|e| JsValue::from(e))
    }
}

impl WasmTransaction {
    /// Get a reference to the inner TonTransaction.
    pub fn inner(&self) -> &TonTransaction {
        &self.inner
    }

    /// Create from an inner TonTransaction.
    pub fn from_inner(inner: TonTransaction) -> Self {
        WasmTransaction { inner }
    }
}
