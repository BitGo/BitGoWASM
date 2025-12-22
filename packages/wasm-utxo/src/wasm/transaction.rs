use crate::error::WasmUtxoError;
use miniscript::bitcoin::consensus::{Decodable, Encodable};
use miniscript::bitcoin::Transaction;
use wasm_bindgen::prelude::*;

/// A Bitcoin-like transaction (for all networks except Zcash)
///
/// This class provides basic transaction parsing and serialization for testing
/// compatibility with third-party transaction fixtures.
#[wasm_bindgen]
pub struct WasmTransaction {
    tx: Transaction,
}

#[wasm_bindgen]
impl WasmTransaction {
    /// Deserialize a transaction from bytes
    ///
    /// # Arguments
    /// * `bytes` - The serialized transaction bytes
    ///
    /// # Returns
    /// A WasmTransaction instance
    ///
    /// # Errors
    /// Returns an error if the bytes cannot be parsed as a valid transaction
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmTransaction, WasmUtxoError> {
        let tx = Transaction::consensus_decode(&mut &bytes[..]).map_err(|e| {
            WasmUtxoError::new(&format!("Failed to deserialize transaction: {}", e))
        })?;
        Ok(WasmTransaction { tx })
    }

    /// Serialize the transaction to bytes
    ///
    /// # Returns
    /// The serialized transaction bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.tx
            .consensus_encode(&mut bytes)
            .expect("encoding to vec should never fail");
        bytes
    }
}

/// A Zcash transaction with network-specific fields
///
/// This class provides basic transaction parsing and serialization for Zcash
/// transactions, which use the Overwinter transaction format.
#[wasm_bindgen]
pub struct WasmZcashTransaction {
    parts: crate::zcash::transaction::ZcashTransactionParts,
}

#[wasm_bindgen]
impl WasmZcashTransaction {
    /// Deserialize a Zcash transaction from bytes
    ///
    /// # Arguments
    /// * `bytes` - The serialized transaction bytes
    ///
    /// # Returns
    /// A WasmZcashTransaction instance
    ///
    /// # Errors
    /// Returns an error if the bytes cannot be parsed as a valid Zcash transaction
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmZcashTransaction, WasmUtxoError> {
        let parts =
            crate::zcash::transaction::decode_zcash_transaction_parts(bytes).map_err(|e| {
                WasmUtxoError::new(&format!("Failed to deserialize Zcash transaction: {}", e))
            })?;
        Ok(WasmZcashTransaction { parts })
    }

    /// Serialize the transaction to bytes
    ///
    /// # Returns
    /// The serialized transaction bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, WasmUtxoError> {
        crate::zcash::transaction::encode_zcash_transaction_parts(&self.parts).map_err(|e| {
            WasmUtxoError::new(&format!("Failed to serialize Zcash transaction: {}", e))
        })
    }
}
