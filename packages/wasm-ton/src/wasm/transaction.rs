use crate::error::WasmTonError;
use crate::transaction::Transaction;
use wasm_bindgen::prelude::*;

/// Namespace for TON transaction operations.
#[wasm_bindgen]
pub struct TransactionNamespace;

#[wasm_bindgen]
impl TransactionNamespace {
    /// Deserialize a transaction from raw BOC bytes.
    ///
    /// @param bytes - Raw BOC bytes
    /// @returns Opaque transaction handle for further operations
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmTransaction, WasmTonError> {
        Transaction::from_bytes(bytes).map(|inner| WasmTransaction { inner })
    }
}

/// WASM wrapper for a TON transaction.
#[wasm_bindgen]
pub struct WasmTransaction {
    inner: Transaction,
}

#[wasm_bindgen]
impl WasmTransaction {
    /// Get the signable payload (SHA-256 of the sign body cell).
    /// This is what needs to be signed by Ed25519.
    ///
    /// @returns 32-byte hash as Uint8Array
    #[wasm_bindgen(js_name = signablePayload)]
    pub fn signable_payload(&self) -> Result<js_sys::Uint8Array, WasmTonError> {
        let bytes = self.inner.signable_payload()?;
        Ok(js_sys::Uint8Array::from(&bytes[..]))
    }

    /// Add a 64-byte Ed25519 signature to this transaction.
    ///
    /// @param signature - 64-byte signature
    #[wasm_bindgen(js_name = addSignature)]
    pub fn add_signature(&mut self, signature: &[u8]) -> Result<(), WasmTonError> {
        self.inner.add_signature(signature)
    }

    /// Serialize the transaction to BOC bytes.
    ///
    /// @returns Raw BOC bytes
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<js_sys::Uint8Array, WasmTonError> {
        let bytes = self.inner.to_bytes()?;
        Ok(js_sys::Uint8Array::from(&bytes[..]))
    }

    /// Serialize to broadcast format (raw BOC bytes).
    ///
    /// @returns Raw BOC bytes as Uint8Array
    #[wasm_bindgen(js_name = toBroadcastFormat)]
    pub fn to_broadcast_format(&self) -> Result<js_sys::Uint8Array, WasmTonError> {
        let bytes = self.inner.to_bytes()?;
        Ok(js_sys::Uint8Array::from(&bytes[..]))
    }

    /// Get the transaction ID (SHA-256 of BOC, base64url-encoded).
    ///
    /// @returns Transaction ID string
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.inner.id()
    }

    /// Get the destination address of this external message.
    ///
    /// @returns Bounceable address string, or undefined
    #[wasm_bindgen(getter)]
    pub fn destination(&self) -> Option<String> {
        self.inner.destination()
    }

    /// Get the current signature as hex string.
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> String {
        hex::encode(self.inner.signature())
    }
}

impl WasmTransaction {
    pub fn inner(&self) -> &Transaction {
        &self.inner
    }
}
