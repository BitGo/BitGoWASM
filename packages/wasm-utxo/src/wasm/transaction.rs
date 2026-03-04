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
    pub(crate) tx: Transaction,
}

impl WasmTransaction {
    /// Create a WasmTransaction from a Transaction (internal use)
    pub(crate) fn from_tx(tx: Transaction) -> Self {
        WasmTransaction { tx }
    }
}

#[wasm_bindgen]
impl WasmTransaction {
    /// Create an empty transaction (version 1, locktime 0)
    pub fn create() -> WasmTransaction {
        use miniscript::bitcoin::{absolute::LockTime, transaction::Version, Transaction};
        WasmTransaction {
            tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
        }
    }

    /// Add an input to the transaction
    ///
    /// # Arguments
    /// * `txid` - The transaction ID (hex string) of the output being spent
    /// * `vout` - The output index being spent
    /// * `sequence` - Optional sequence number (default: 0xFFFFFFFF)
    ///
    /// # Returns
    /// The index of the newly added input
    pub fn add_input_at_index(
        &mut self,
        index: usize,
        txid: &str,
        vout: u32,
        sequence: Option<u32>,
    ) -> Result<usize, WasmUtxoError> {
        use miniscript::bitcoin::{transaction::Sequence, OutPoint, ScriptBuf, TxIn, Txid};
        use std::str::FromStr;
        if index > self.tx.input.len() {
            return Err(WasmUtxoError::new(&format!(
                "Input index {} out of bounds (have {} inputs)",
                index,
                self.tx.input.len()
            )));
        }
        let txid = Txid::from_str(txid)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid txid: {}", e)))?;
        self.tx.input.insert(
            index,
            TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: sequence.map(Sequence).unwrap_or(Sequence::MAX),
                witness: Default::default(),
            },
        );
        Ok(index)
    }

    pub fn add_input(
        &mut self,
        txid: &str,
        vout: u32,
        sequence: Option<u32>,
    ) -> Result<usize, WasmUtxoError> {
        self.add_input_at_index(self.tx.input.len(), txid, vout, sequence)
    }

    pub fn add_output_at_index(
        &mut self,
        index: usize,
        script: &[u8],
        value: u64,
    ) -> Result<usize, WasmUtxoError> {
        use miniscript::bitcoin::{Amount, ScriptBuf, TxOut};
        if index > self.tx.output.len() {
            return Err(WasmUtxoError::new(&format!(
                "Output index {} out of bounds (have {} outputs)",
                index,
                self.tx.output.len()
            )));
        }
        self.tx.output.insert(
            index,
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::from(script.to_vec()),
            },
        );
        Ok(index)
    }

    pub fn add_output(&mut self, script: &[u8], value: u64) -> usize {
        self.add_output_at_index(self.tx.output.len(), script, value)
            .expect("insert at len should never fail")
    }

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

    /// Get the virtual size of the transaction
    ///
    /// Virtual size is calculated as ceil(weight / 4), where weight accounts
    /// for the segwit discount on witness data.
    ///
    /// # Returns
    /// The virtual size in virtual bytes (vbytes)
    pub fn get_vsize(&self) -> usize {
        self.tx.vsize()
    }

    /// Get the transaction ID (txid)
    ///
    /// The txid is the double SHA256 of the transaction bytes (excluding witness
    /// data for segwit transactions), displayed in reverse byte order (big-endian)
    /// as is standard for Bitcoin.
    ///
    /// # Returns
    /// The transaction ID as a hex string
    pub fn get_txid(&self) -> String {
        self.tx.compute_txid().to_string()
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

impl WasmZcashTransaction {
    /// Create from parts (internal use)
    pub(crate) fn from_parts(parts: crate::zcash::transaction::ZcashTransactionParts) -> Self {
        WasmZcashTransaction { parts }
    }
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

    /// Get the transaction ID (txid)
    ///
    /// The txid is the double SHA256 of the full Zcash transaction bytes,
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
        let tx_bytes = crate::zcash::transaction::encode_zcash_transaction_parts(&self.parts)
            .map_err(|e| {
                WasmUtxoError::new(&format!("Failed to serialize Zcash transaction: {}", e))
            })?;
        let hash = sha256d::Hash::hash(&tx_bytes);
        let txid = Txid::from_raw_hash(hash);
        Ok(txid.to_string())
    }
}
