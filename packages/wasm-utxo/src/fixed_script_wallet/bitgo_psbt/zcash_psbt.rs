//! Zcash PSBT deserialization
//!
//! Zcash uses an "overwintered transaction format" that includes additional fields
//! not present in standard Bitcoin transactions.

use miniscript::bitcoin::consensus::{Decodable, Encodable};
use miniscript::bitcoin::psbt::Psbt;
use miniscript::bitcoin::{Transaction, VarInt};
use std::io::Read;

pub use crate::zcash::transaction::{
    decode_zcash_transaction_meta, ZcashTransactionMeta, ZCASH_SAPLING_VERSION_GROUP_ID,
};

/// A Zcash-compatible PSBT that can handle overwintered transactions
///
/// This struct handles Zcash-specific transaction formats including
/// version_group_id, expiry_height, and sapling fields.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZcashBitGoPsbt {
    /// The underlying Bitcoin-compatible PSBT
    pub psbt: Psbt,
    /// The network this PSBT is for (Zcash or ZcashTestnet)
    pub(crate) network: crate::Network,
    /// Zcash-specific: Version group ID for overwintered transactions
    pub version_group_id: Option<u32>,
    /// Zcash-specific: Expiry height
    pub expiry_height: Option<u32>,
    /// Zcash-specific: Additional Sapling fields (valueBalance, nShieldedSpend, nShieldedOutput, etc.)
    /// These are preserved as-is to maintain exact serialization
    pub sapling_fields: Vec<u8>,
}

impl ZcashBitGoPsbt {
    /// Get the network this PSBT is for
    pub fn network(&self) -> crate::Network {
        self.network
    }

    /// Serialize a transaction with Zcash-specific fields (version_group_id, expiry_height, sapling_fields)
    fn serialize_as_zcash_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<Vec<u8>, super::DeserializeError> {
        let parts = crate::zcash::transaction::ZcashTransactionParts {
            transaction: tx.clone(),
            is_overwintered: true,
            version_group_id: Some(
                self.version_group_id
                    .unwrap_or(ZCASH_SAPLING_VERSION_GROUP_ID),
            ),
            expiry_height: Some(self.expiry_height.unwrap_or(0)),
            sapling_fields: self.sapling_fields.clone(),
        };
        crate::zcash::transaction::encode_zcash_transaction_parts(&parts)
            .map_err(super::DeserializeError::Network)
    }

    /// Reconstruct the unsigned Zcash transaction bytes from the PSBT
    pub fn extract_unsigned_zcash_transaction(&self) -> Result<Vec<u8>, super::DeserializeError> {
        self.serialize_as_zcash_transaction(&self.psbt.unsigned_tx)
    }

    /// Extract the finalized Zcash transaction bytes from the PSBT
    ///
    /// This extracts the fully-signed transaction with Zcash-specific fields.
    /// Must be called after all inputs have been finalized.
    ///
    /// This method consumes the PSBT to avoid cloning.
    pub fn extract_tx(self) -> Result<Vec<u8>, super::DeserializeError> {
        use miniscript::bitcoin::psbt::ExtractTxError;

        // Capture Zcash-specific fields before consuming psbt
        let version_group_id = self
            .version_group_id
            .unwrap_or(ZCASH_SAPLING_VERSION_GROUP_ID);
        let expiry_height = self.expiry_height.unwrap_or(0);
        let sapling_fields = self.sapling_fields;

        let tx = self.psbt.extract_tx().map_err(|e| match e {
            ExtractTxError::AbsurdFeeRate { .. } => {
                super::DeserializeError::Network(format!("Absurd fee rate: {}", e))
            }
            ExtractTxError::MissingInputValue { .. } => {
                super::DeserializeError::Network(format!("Missing input value: {}", e))
            }
            ExtractTxError::SendingTooMuch { .. } => {
                super::DeserializeError::Network(format!("Sending too much: {}", e))
            }
            _ => super::DeserializeError::Network(format!("Failed to extract transaction: {}", e)),
        })?;

        let parts = crate::zcash::transaction::ZcashTransactionParts {
            transaction: tx,
            is_overwintered: true,
            version_group_id: Some(version_group_id),
            expiry_height: Some(expiry_height),
            sapling_fields,
        };
        crate::zcash::transaction::encode_zcash_transaction_parts(&parts)
            .map_err(super::DeserializeError::Network)
    }

    /// Compute the transaction ID for the unsigned Zcash transaction
    ///
    /// The txid is the double SHA256 of the full Zcash transaction bytes.
    pub fn compute_txid(&self) -> Result<[u8; 32], super::DeserializeError> {
        use miniscript::bitcoin::hashes::{sha256d, Hash};
        let tx_bytes = self.extract_unsigned_zcash_transaction()?;
        let hash = sha256d::Hash::hash(&tx_bytes);
        Ok(hash.to_byte_array())
    }

    /// Deserialize the PSBT by converting the Zcash transaction to Bitcoin format first
    fn decode_with_zcash_tx(
        bytes: &[u8],
        network: crate::Network,
    ) -> Result<Self, super::DeserializeError> {
        let mut r = bytes;

        // Read magic bytes
        let magic: [u8; 4] = Decodable::consensus_decode(&mut r)?;
        if &magic != b"psbt" {
            return Err(super::DeserializeError::Network(
                "Invalid PSBT magic".to_string(),
            ));
        }

        // Read separator
        let separator: u8 = Decodable::consensus_decode(&mut r)?;
        if separator != 0xff {
            return Err(super::DeserializeError::Network(
                "Invalid PSBT separator".to_string(),
            ));
        }

        // Find and replace the transaction in the PSBT
        let mut modified_psbt = Vec::new();
        modified_psbt.extend_from_slice(b"psbt\xff");

        let mut version_group_id = None;
        let mut expiry_height = None;
        let mut sapling_fields = Vec::new();
        let mut found_tx = false;

        // Decode global map - we'll copy everything byte-by-byte while transforming the TX
        loop {
            // Read key length
            let key_len: VarInt = Decodable::consensus_decode(&mut r)?;
            if key_len.0 == 0 {
                // End of global map
                0u8.consensus_encode(&mut modified_psbt).map_err(|e| {
                    super::DeserializeError::Network(format!("Failed to encode separator: {}", e))
                })?;
                break;
            }

            // Read key
            let mut key_data = vec![0u8; key_len.0 as usize];
            r.read_exact(&mut key_data)
                .map_err(|_| super::DeserializeError::Network("Failed to read key".to_string()))?;

            // Read value length
            let val_len: VarInt = Decodable::consensus_decode(&mut r)?;

            // Read value
            let mut val_data = vec![0u8; val_len.0 as usize];
            r.read_exact(&mut val_data).map_err(|_| {
                super::DeserializeError::Network("Failed to read value".to_string())
            })?;

            // Check if this is the unsigned transaction (key type 0x00 with empty key)
            if !key_data.is_empty() && key_data[0] == 0x00 && key_data.len() == 1 {
                // This is the unsigned transaction
                found_tx = true;
                let parts = crate::zcash::transaction::decode_zcash_transaction_parts(&val_data)
                    .map_err(super::DeserializeError::Network)?;
                version_group_id = parts.version_group_id;
                expiry_height = parts.expiry_height;
                sapling_fields = parts.sapling_fields;

                // Serialize the modified transaction
                let mut tx_bytes = Vec::new();
                parts
                    .transaction
                    .consensus_encode(&mut tx_bytes)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode transaction: {}",
                            e
                        ))
                    })?;

                // Write key
                VarInt(key_data.len() as u64)
                    .consensus_encode(&mut modified_psbt)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode key length: {}",
                            e
                        ))
                    })?;
                modified_psbt.extend_from_slice(&key_data);

                // Write new value
                VarInt(tx_bytes.len() as u64)
                    .consensus_encode(&mut modified_psbt)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode value length: {}",
                            e
                        ))
                    })?;
                modified_psbt.extend_from_slice(&tx_bytes);
            } else {
                // Copy key-value pair as-is
                VarInt(key_data.len() as u64)
                    .consensus_encode(&mut modified_psbt)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode key length: {}",
                            e
                        ))
                    })?;
                modified_psbt.extend_from_slice(&key_data);

                VarInt(val_data.len() as u64)
                    .consensus_encode(&mut modified_psbt)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode value length: {}",
                            e
                        ))
                    })?;
                modified_psbt.extend_from_slice(&val_data);
            }
        }

        if !found_tx {
            return Err(super::DeserializeError::Network(
                "Missing unsigned transaction".to_string(),
            ));
        }

        // Append the rest of the PSBT (inputs and outputs)
        modified_psbt.extend_from_slice(r);

        // Now deserialize as a standard PSBT
        let psbt = Psbt::deserialize(&modified_psbt)?;

        // Consensus branch ID must be set in the PSBT proprietary map
        if super::propkv::get_zec_consensus_branch_id(&psbt).is_none() {
            return Err(super::DeserializeError::Network(
                "Missing ZecConsensusBranchId in PSBT proprietary map".to_string(),
            ));
        }

        Ok(ZcashBitGoPsbt {
            psbt,
            network,
            version_group_id,
            expiry_height,
            sapling_fields,
        })
    }

    /// Deserialize a Zcash PSBT from bytes
    ///
    /// # Arguments
    /// * `bytes` - The serialized PSBT bytes
    /// * `network` - The network (must be Zcash or ZcashTestnet)
    pub fn deserialize(
        bytes: &[u8],
        network: crate::Network,
    ) -> Result<Self, super::DeserializeError> {
        Self::decode_with_zcash_tx(bytes, network)
    }

    /// Convert to a standard Bitcoin PSBT (losing Zcash-specific fields)
    pub fn into_bitcoin_psbt(self) -> Psbt {
        self.psbt
    }

    /// Serialize the Zcash PSBT back to bytes, including Zcash-specific fields
    pub fn serialize(&self) -> Result<Vec<u8>, super::DeserializeError> {
        // First serialize as standard Bitcoin PSBT
        let bitcoin_psbt_bytes = self.psbt.serialize();

        // Now we need to replace the transaction in the serialized PSBT
        // Parse the Bitcoin PSBT to find where the transaction is
        let mut result = Vec::new();
        let mut r = bitcoin_psbt_bytes.as_slice();

        // Copy magic and separator
        result.extend_from_slice(&bitcoin_psbt_bytes[0..5]); // "psbt\xff"
        r = &r[5..];

        // Now process the global map, replacing the transaction
        let zcash_tx_bytes = self.extract_unsigned_zcash_transaction()?;
        let mut found_tx = false;

        loop {
            // Read key length
            let key_len: VarInt = Decodable::consensus_decode(&mut r)?;
            if key_len.0 == 0 {
                // End of global map
                0u8.consensus_encode(&mut result).map_err(|e| {
                    super::DeserializeError::Network(format!("Failed to encode separator: {}", e))
                })?;
                break;
            }

            // Read key
            let mut key_data = vec![0u8; key_len.0 as usize];
            r.read_exact(&mut key_data)
                .map_err(|_| super::DeserializeError::Network("Failed to read key".to_string()))?;

            // Read value length
            let val_len: VarInt = Decodable::consensus_decode(&mut r)?;

            // Read value
            let mut val_data = vec![0u8; val_len.0 as usize];
            r.read_exact(&mut val_data).map_err(|_| {
                super::DeserializeError::Network("Failed to read value".to_string())
            })?;

            // Check if this is the unsigned transaction
            if !key_data.is_empty() && key_data[0] == 0x00 && key_data.len() == 1 {
                found_tx = true;
                // Write key
                VarInt(key_data.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode key length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&key_data);

                // Write Zcash transaction instead
                VarInt(zcash_tx_bytes.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode value length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&zcash_tx_bytes);
            } else {
                // Copy key-value pair as-is
                VarInt(key_data.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode key length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&key_data);

                VarInt(val_data.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode value length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&val_data);
            }
        }

        if !found_tx {
            return Err(super::DeserializeError::Network(
                "Missing unsigned transaction in PSBT".to_string(),
            ));
        }

        // Copy the rest (inputs and outputs)
        result.extend_from_slice(r);

        Ok(result)
    }

    /// Convert to the underlying Bitcoin PSBT, consuming self
    pub fn into_psbt(self) -> Psbt {
        self.psbt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::{general_purpose::STANDARD as BASE64_STANDARD, Engine};

    #[test]
    fn test_decode_zcash_transaction() {
        // Version with overwintered bit
        let version = 0x80000004u32;
        let mut tx_bytes = Vec::new();

        // Version
        version.consensus_encode(&mut tx_bytes).unwrap();

        // Version group ID
        ZCASH_SAPLING_VERSION_GROUP_ID
            .consensus_encode(&mut tx_bytes)
            .unwrap();

        // Empty inputs
        0u8.consensus_encode(&mut tx_bytes).unwrap();

        // Empty outputs
        0u8.consensus_encode(&mut tx_bytes).unwrap();

        // Lock time
        0u32.consensus_encode(&mut tx_bytes).unwrap();

        // Expiry height
        0u32.consensus_encode(&mut tx_bytes).unwrap();

        let parts = crate::zcash::transaction::decode_zcash_transaction_parts(&tx_bytes).unwrap();

        assert_eq!(parts.version_group_id, Some(ZCASH_SAPLING_VERSION_GROUP_ID));
        assert_eq!(parts.expiry_height, Some(0));
        assert_eq!(parts.transaction.input.len(), 0);
        assert_eq!(parts.transaction.output.len(), 0);
        // Should be empty for this simple test tx
        assert!(parts.sapling_fields.is_empty());
    }

    #[test]
    fn test_round_trip_zcash_psbt() {
        use crate::fixed_script_wallet::test_utils::fixtures::{
            load_psbt_fixture_with_network, SignatureState,
        };
        use crate::networks::Network;

        // Load the Zcash fixture
        let fixture = load_psbt_fixture_with_network(Network::Zcash, SignatureState::Unsigned)
            .expect("Failed to load Zcash fixture");

        // Deserialize from fixture
        let original_bytes = BASE64_STANDARD.decode(&fixture.psbt_base64).unwrap();
        let zcash_psbt = ZcashBitGoPsbt::deserialize(&original_bytes, Network::Zcash).unwrap();

        // Verify Zcash-specific fields were extracted
        assert!(zcash_psbt.version_group_id.is_some());
        assert!(zcash_psbt.expiry_height.is_some());

        // Verify transaction was parsed
        assert_eq!(zcash_psbt.psbt.unsigned_tx.input.len(), 2);
        assert_eq!(zcash_psbt.psbt.unsigned_tx.output.len(), 4);

        // Serialize back
        let serialized = zcash_psbt.serialize().unwrap();

        // Note: We don't assert byte-for-byte equality because PSBT serialization may reorder
        // global map entries. Instead, we verify that deserializing the serialized PSBT
        // produces the same data.

        // Deserialize again
        let round_trip = ZcashBitGoPsbt::deserialize(&serialized, Network::Zcash).unwrap();

        // Verify the data matches
        assert_eq!(
            zcash_psbt.version_group_id, round_trip.version_group_id,
            "Version group ID should match"
        );
        assert_eq!(
            zcash_psbt.expiry_height, round_trip.expiry_height,
            "Expiry height should match"
        );
        assert_eq!(
            zcash_psbt.psbt.unsigned_tx.input.len(),
            round_trip.psbt.unsigned_tx.input.len(),
            "Input count should match"
        );
        assert_eq!(
            zcash_psbt.psbt.unsigned_tx.output.len(),
            round_trip.psbt.unsigned_tx.output.len(),
            "Output count should match"
        );
        assert_eq!(
            zcash_psbt.psbt.inputs.len(),
            round_trip.psbt.inputs.len(),
            "PSBT input count should match"
        );
        assert_eq!(
            zcash_psbt.psbt.outputs.len(),
            round_trip.psbt.outputs.len(),
            "PSBT output count should match"
        );
    }
}
