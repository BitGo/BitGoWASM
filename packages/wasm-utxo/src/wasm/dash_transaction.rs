use crate::error::WasmUtxoError;
use wasm_bindgen::prelude::*;

/// Dash transaction wrapper that supports Dash special transactions (EVO) by preserving extra payload.
#[wasm_bindgen]
pub struct WasmDashTransaction {
    parts: crate::dash::transaction::DashTransactionParts,
}

impl WasmDashTransaction {
    /// Create from parts (internal use)
    pub(crate) fn from_parts(parts: crate::dash::transaction::DashTransactionParts) -> Self {
        WasmDashTransaction { parts }
    }
}

#[wasm_bindgen]
impl WasmDashTransaction {
    /// Deserialize a Dash transaction from bytes (supports EVO special tx extra payload).
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmDashTransaction, WasmUtxoError> {
        let parts =
            crate::dash::transaction::decode_dash_transaction_parts(bytes).map_err(|e| {
                WasmUtxoError::new(&format!("Failed to deserialize Dash transaction: {}", e))
            })?;
        Ok(WasmDashTransaction { parts })
    }

    /// Serialize the Dash transaction to bytes (preserving tx_type and extra payload).
    pub fn to_bytes(&self) -> Result<Vec<u8>, WasmUtxoError> {
        crate::dash::transaction::encode_dash_transaction_parts(&self.parts).map_err(|e| {
            WasmUtxoError::new(&format!("Failed to serialize Dash transaction: {}", e))
        })
    }

    /// Get the transaction ID (txid)
    ///
    /// The txid is the double SHA256 of the full Dash transaction bytes,
    /// displayed in reverse byte order (big-endian) as is standard.
    ///
    /// # Returns
    /// The transaction ID as a hex string
    ///
    /// # Errors
    /// Returns an error if the transaction cannot be serialized
    pub fn get_txid(&self) -> Result<String, WasmUtxoError> {
        use miniscript::bitcoin::hashes::{sha256d, Hash};
        use miniscript::bitcoin::Txid;
        let tx_bytes = crate::dash::transaction::encode_dash_transaction_parts(&self.parts)
            .map_err(|e| {
                WasmUtxoError::new(&format!("Failed to serialize Dash transaction: {}", e))
            })?;
        let hash = sha256d::Hash::hash(&tx_bytes);
        let txid = Txid::from_raw_hash(hash);
        Ok(txid.to_string())
    }
}
