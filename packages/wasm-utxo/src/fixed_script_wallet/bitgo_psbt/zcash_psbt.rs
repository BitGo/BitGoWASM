//! Zcash PSBT deserialization
//!
//! Zcash uses an "overwintered transaction format" that includes additional fields
//! not present in standard Bitcoin transactions.

use miniscript::bitcoin::consensus::{Decodable, Encodable};
use miniscript::bitcoin::psbt::Psbt;
use miniscript::bitcoin::{Transaction, TxIn, TxOut, VarInt};
use std::io::Read;

/// Zcash version group IDs
#[allow(dead_code)]
const ZCASH_OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C48270;
const ZCASH_SAPLING_VERSION_GROUP_ID: u32 = 0x892F2085;

/// Decoded Zcash transaction with extracted Zcash-specific fields
#[derive(Debug, Clone)]
struct DecodedZcashTransaction {
    /// The transaction in Bitcoin-compatible format
    transaction: Transaction,
    /// Zcash-specific: Version group ID for overwintered transactions
    version_group_id: Option<u32>,
    /// Zcash-specific: Expiry height
    expiry_height: Option<u32>,
    /// Zcash-specific: Additional Sapling fields (valueBalance, nShieldedSpend, nShieldedOutput, etc.)
    /// These are preserved as-is to maintain exact serialization
    sapling_fields: Vec<u8>,
}

/// A Zcash-compatible PSBT that can handle overwintered transactions
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZcashPsbt {
    /// The underlying Bitcoin-compatible PSBT
    pub psbt: Psbt,
    /// Zcash-specific: Version group ID for overwintered transactions
    pub version_group_id: Option<u32>,
    /// Zcash-specific: Expiry height
    pub expiry_height: Option<u32>,
    /// Zcash-specific: Additional Sapling fields (valueBalance, nShieldedSpend, nShieldedOutput, etc.)
    /// These are preserved as-is to maintain exact serialization
    pub sapling_fields: Vec<u8>,
}

/// Decode a Zcash transaction from bytes, extracting Zcash-specific fields
fn decode_zcash_transaction(
    bytes: &[u8],
) -> Result<DecodedZcashTransaction, super::DeserializeError> {
    let mut slice = bytes;

    // Read version
    let version = u32::consensus_decode(&mut slice)?;

    let is_overwintered = (version & 0x80000000) != 0;

    let version_group_id = if is_overwintered {
        Some(u32::consensus_decode(&mut slice)?)
    } else {
        None
    };

    // Read inputs
    let inputs: Vec<TxIn> = Vec::consensus_decode(&mut slice)?;

    // Read outputs
    let outputs: Vec<TxOut> = Vec::consensus_decode(&mut slice)?;

    // Read lock_time
    let lock_time =
        miniscript::bitcoin::locktime::absolute::LockTime::consensus_decode(&mut slice)?;

    // Read expiry height if overwintered
    let expiry_height = if is_overwintered {
        Some(u32::consensus_decode(&mut slice)?)
    } else {
        None
    };

    // Capture any remaining bytes (Sapling fields: valueBalance, nShieldedSpend, nShieldedOutput, etc.)
    let sapling_fields = slice.to_vec();

    // Create transaction with standard version (without overwintered bit)
    let transaction = Transaction {
        version: miniscript::bitcoin::transaction::Version::non_standard(
            (version & 0x7FFFFFFF) as i32,
        ),
        input: inputs,
        output: outputs,
        lock_time,
    };

    Ok(DecodedZcashTransaction {
        transaction,
        version_group_id,
        expiry_height,
        sapling_fields,
    })
}

impl ZcashPsbt {
    /// Reconstruct the Zcash transaction bytes from the Bitcoin transaction
    fn reconstruct_zcash_transaction(&self) -> Result<Vec<u8>, super::DeserializeError> {
        let mut tx_bytes = Vec::new();

        // Get the standard version and add overwintered bit back
        let version = self.psbt.unsigned_tx.version.0;
        let zcash_version = (version as u32) | 0x80000000;

        // Write version
        zcash_version.consensus_encode(&mut tx_bytes).map_err(|e| {
            super::DeserializeError::Network(format!("Failed to encode Zcash version: {}", e))
        })?;

        // Write version group ID
        self.version_group_id
            .unwrap_or(ZCASH_SAPLING_VERSION_GROUP_ID)
            .consensus_encode(&mut tx_bytes)
            .map_err(|e| {
                super::DeserializeError::Network(format!(
                    "Failed to encode version group ID: {}",
                    e
                ))
            })?;

        // Write inputs
        self.psbt
            .unsigned_tx
            .input
            .consensus_encode(&mut tx_bytes)
            .map_err(|e| {
                super::DeserializeError::Network(format!("Failed to encode inputs: {}", e))
            })?;

        // Write outputs
        self.psbt
            .unsigned_tx
            .output
            .consensus_encode(&mut tx_bytes)
            .map_err(|e| {
                super::DeserializeError::Network(format!("Failed to encode outputs: {}", e))
            })?;

        // Write lock_time
        self.psbt
            .unsigned_tx
            .lock_time
            .consensus_encode(&mut tx_bytes)
            .map_err(|e| {
                super::DeserializeError::Network(format!("Failed to encode lock_time: {}", e))
            })?;

        // Write expiry height
        self.expiry_height
            .unwrap_or(0)
            .consensus_encode(&mut tx_bytes)
            .map_err(|e| {
                super::DeserializeError::Network(format!("Failed to encode expiry height: {}", e))
            })?;

        // Append Sapling fields (valueBalance, nShieldedSpend, nShieldedOutput, etc.)
        tx_bytes.extend_from_slice(&self.sapling_fields);

        Ok(tx_bytes)
    }

    /// Deserialize the PSBT by converting the Zcash transaction to Bitcoin format first
    fn decode_with_zcash_tx(bytes: &[u8]) -> Result<Self, super::DeserializeError> {
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
                let decoded = decode_zcash_transaction(&val_data)?;
                version_group_id = decoded.version_group_id;
                expiry_height = decoded.expiry_height;
                sapling_fields = decoded.sapling_fields;

                // Serialize the modified transaction
                let mut tx_bytes = Vec::new();
                decoded
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

        Ok(ZcashPsbt {
            psbt,
            version_group_id,
            expiry_height,
            sapling_fields,
        })
    }

    fn consensus_decode(bytes: &[u8]) -> Result<Self, super::DeserializeError> {
        Self::decode_with_zcash_tx(bytes)
    }

    /// Deserialize a Zcash PSBT from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, super::DeserializeError> {
        Self::consensus_decode(bytes)
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
        let zcash_tx_bytes = self.reconstruct_zcash_transaction()?;
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

        let decoded = decode_zcash_transaction(&tx_bytes).unwrap();

        assert_eq!(
            decoded.version_group_id,
            Some(ZCASH_SAPLING_VERSION_GROUP_ID)
        );
        assert_eq!(decoded.expiry_height, Some(0));
        assert_eq!(decoded.transaction.input.len(), 0);
        assert_eq!(decoded.transaction.output.len(), 0);
        // Should be empty for this simple test tx
        assert!(decoded.sapling_fields.is_empty());
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
        let zcash_psbt = ZcashPsbt::deserialize(&original_bytes).unwrap();

        // Verify Zcash-specific fields were extracted
        assert!(zcash_psbt.version_group_id.is_some());
        assert!(zcash_psbt.expiry_height.is_some());

        // Verify transaction was parsed
        assert_eq!(zcash_psbt.psbt.unsigned_tx.input.len(), 2);
        assert_eq!(zcash_psbt.psbt.unsigned_tx.output.len(), 1);

        // Serialize back
        let serialized = zcash_psbt.serialize().unwrap();

        // Note: We don't assert byte-for-byte equality because PSBT serialization may reorder
        // global map entries. Instead, we verify that deserializing the serialized PSBT
        // produces the same data.

        // Deserialize again
        let round_trip = ZcashPsbt::deserialize(&serialized).unwrap();

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
