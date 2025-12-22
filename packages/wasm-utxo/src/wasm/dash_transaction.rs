use crate::error::WasmUtxoError;
use wasm_bindgen::prelude::*;

/// Dash transaction wrapper that supports Dash special transactions (EVO) by preserving extra payload.
#[wasm_bindgen]
pub struct WasmDashTransaction {
    parts: crate::dash::transaction::DashTransactionParts,
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
}
