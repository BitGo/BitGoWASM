//! Zcash transaction encoding/decoding helpers
//!
//! Zcash uses an "overwintered transaction format" which includes extra fields
//! (version_group_id, expiry_height, and sapling fields) that are not part of
//! standard Bitcoin transaction consensus encoding.

use miniscript::bitcoin::consensus::{Decodable, Encodable};
use miniscript::bitcoin::{Transaction, TxIn, TxOut};

/// Zcash Sapling (v4) version group ID
pub const ZCASH_SAPLING_VERSION_GROUP_ID: u32 = 0x892F2085;

/// Zcash NU5 (v5) version group ID (ZIP-225)
pub const ZCASH_NU5_VERSION_GROUP_ID: u32 = 0x26A7270A;

/// Parsed Zcash transaction fields, preserving Zcash-specific data needed for round-tripping.
#[derive(Debug, Clone)]
pub struct ZcashTransactionParts {
    /// Bitcoin-compatible transaction (version without the overwintered bit)
    pub transaction: Transaction,
    /// Whether the original encoding had the overwintered bit set
    pub is_overwintered: bool,
    /// Zcash-specific: version group id (present only for overwintered transactions)
    pub version_group_id: Option<u32>,
    /// Zcash-specific: expiry height (present only for overwintered transactions)
    pub expiry_height: Option<u32>,
    /// Remaining bytes after transparent fields (Sapling/Orchard bundles, etc.)
    ///
    /// Preserved verbatim so the transaction can be serialized back to the exact same bytes.
    pub sapling_fields: Vec<u8>,
    /// Zcash-specific: consensus branch ID (v5 / ZIP-225 only; encoded before transparent fields)
    pub consensus_branch_id: Option<u32>,
}

impl ZcashTransactionParts {
    /// Wrap an already-extracted Bitcoin-compatible transaction as Zcash overwintered
    /// transaction parts, mirroring `ZcashBitGoPsbt::extract_tx`.
    pub fn from_extracted_transaction(
        transaction: Transaction,
        version_group_id: u32,
        expiry_height: u32,
    ) -> Self {
        ZcashTransactionParts {
            transaction,
            is_overwintered: true,
            version_group_id: Some(version_group_id),
            expiry_height: Some(expiry_height),
            sapling_fields: vec![0u8; 11],
            consensus_branch_id: None,
        }
    }

    /// Extract a finalized PSBT as Zcash overwintered transaction parts.
    pub fn extract_from_psbt(
        psbt: miniscript::bitcoin::psbt::Psbt,
        version_group_id: u32,
        expiry_height: u32,
    ) -> Result<Self, String> {
        let tx = psbt
            .extract_tx()
            .map_err(|e| format!("Failed to extract transaction: {}", e))?;
        Ok(Self::from_extracted_transaction(
            tx,
            version_group_id,
            expiry_height,
        ))
    }
}

/// Zcash transaction metadata extracted from transaction bytes
///
/// This struct provides the Zcash-specific fields without requiring
/// the full transaction to be stored.
#[derive(Debug, Clone)]
pub struct ZcashTransactionMeta {
    /// Number of inputs
    pub input_count: usize,
    /// Number of outputs
    pub output_count: usize,
    /// Zcash-specific: Version group ID for overwintered transactions
    pub version_group_id: Option<u32>,
    /// Zcash-specific: Expiry height
    pub expiry_height: Option<u32>,
    /// Whether this is a Zcash overwintered transaction
    pub is_overwintered: bool,
    /// Zcash-specific: Consensus branch ID (v5 only)
    pub consensus_branch_id: Option<u32>,
}

fn version_i32_to_u32(version: i32) -> Result<u32, String> {
    u32::try_from(version).map_err(|_| format!("Invalid tx version (negative): {}", version))
}

/// Decode Zcash transaction metadata from bytes
///
/// Extracts input/output counts and Zcash-specific fields (version_group_id, expiry_height)
/// from a Zcash overwintered transaction.
pub fn decode_zcash_transaction_meta(bytes: &[u8]) -> Result<ZcashTransactionMeta, String> {
    let parts = decode_zcash_transaction_parts(bytes)?;
    Ok(ZcashTransactionMeta {
        input_count: parts.transaction.input.len(),
        output_count: parts.transaction.output.len(),
        version_group_id: parts.version_group_id,
        expiry_height: parts.expiry_height,
        is_overwintered: parts.is_overwintered,
        consensus_branch_id: parts.consensus_branch_id,
    })
}

/// Decode a Zcash transaction, extracting Zcash-specific fields.
pub fn decode_zcash_transaction_parts(bytes: &[u8]) -> Result<ZcashTransactionParts, String> {
    let mut slice = bytes;

    // Read version
    let version = u32::consensus_decode(&mut slice)
        .map_err(|e| format!("Failed to decode version: {}", e))?;

    let is_overwintered = (version & 0x80000000) != 0;

    let version_group_id = if is_overwintered {
        Some(
            u32::consensus_decode(&mut slice)
                .map_err(|e| format!("Failed to decode version_group_id: {}", e))?,
        )
    } else {
        None
    };

    let is_v5 = version_group_id == Some(ZCASH_NU5_VERSION_GROUP_ID);

    // ZIP-225 (v5): consensus_branch_id | lock_time | expiry_height | inputs | outputs | bundles
    // ZIP-243 (v4): inputs | outputs | lock_time | expiry_height | sapling_fields
    let (inputs, outputs, lock_time, expiry_height, consensus_branch_id, sapling_fields) = if is_v5
    {
        let consensus_branch_id = u32::consensus_decode(&mut slice)
            .map_err(|e| format!("Failed to decode consensus_branch_id: {}", e))?;

        let lock_time =
            miniscript::bitcoin::locktime::absolute::LockTime::consensus_decode(&mut slice)
                .map_err(|e| format!("Failed to decode lock_time: {}", e))?;

        let expiry_height = u32::consensus_decode(&mut slice)
            .map_err(|e| format!("Failed to decode expiry_height: {}", e))?;

        let inputs: Vec<TxIn> = Vec::consensus_decode(&mut slice)
            .map_err(|e| format!("Failed to decode inputs: {}", e))?;

        let outputs: Vec<TxOut> = Vec::consensus_decode(&mut slice)
            .map_err(|e| format!("Failed to decode outputs: {}", e))?;

        let remaining = slice.to_vec();
        (
            inputs,
            outputs,
            lock_time,
            Some(expiry_height),
            Some(consensus_branch_id),
            remaining,
        )
    } else {
        let inputs: Vec<TxIn> = Vec::consensus_decode(&mut slice)
            .map_err(|e| format!("Failed to decode inputs: {}", e))?;

        let outputs: Vec<TxOut> = Vec::consensus_decode(&mut slice)
            .map_err(|e| format!("Failed to decode outputs: {}", e))?;

        let lock_time =
            miniscript::bitcoin::locktime::absolute::LockTime::consensus_decode(&mut slice)
                .map_err(|e| format!("Failed to decode lock_time: {}", e))?;

        let expiry_height = if is_overwintered {
            Some(
                u32::consensus_decode(&mut slice)
                    .map_err(|e| format!("Failed to decode expiry_height: {}", e))?,
            )
        } else {
            None
        };

        let remaining = slice.to_vec();
        (inputs, outputs, lock_time, expiry_height, None, remaining)
    };

    // Create transaction with standard version (without overwintered bit)
    let transaction = Transaction {
        version: miniscript::bitcoin::transaction::Version::non_standard(
            (version & 0x7FFFFFFF) as i32,
        ),
        input: inputs,
        output: outputs,
        lock_time,
    };

    Ok(ZcashTransactionParts {
        transaction,
        is_overwintered,
        version_group_id,
        expiry_height,
        sapling_fields,
        consensus_branch_id,
    })
}

/// Encode a Zcash transaction back to bytes, including Zcash-specific fields.
pub fn encode_zcash_transaction_parts(parts: &ZcashTransactionParts) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();

    let base_version = version_i32_to_u32(parts.transaction.version.0)?;
    let version = if parts.is_overwintered {
        base_version | 0x80000000
    } else {
        base_version
    };

    version
        .consensus_encode(&mut bytes)
        .map_err(|e| format!("Failed to encode version: {}", e))?;

    if parts.is_overwintered {
        let version_group_id = parts
            .version_group_id
            .ok_or_else(|| "Missing version_group_id for overwintered tx".to_string())?;
        version_group_id
            .consensus_encode(&mut bytes)
            .map_err(|e| format!("Failed to encode version_group_id: {}", e))?;
    } else if parts.version_group_id.is_some() {
        return Err("Non-overwintered tx must not have version_group_id".to_string());
    }

    let is_v5 = parts.version_group_id == Some(ZCASH_NU5_VERSION_GROUP_ID);

    if is_v5 {
        // ZIP-225: consensus_branch_id | lock_time | expiry_height | inputs | outputs | bundles
        let consensus_branch_id = parts
            .consensus_branch_id
            .ok_or_else(|| "Missing consensus_branch_id for v5 tx".to_string())?;
        consensus_branch_id
            .consensus_encode(&mut bytes)
            .map_err(|e| format!("Failed to encode consensus_branch_id: {}", e))?;

        parts
            .transaction
            .lock_time
            .consensus_encode(&mut bytes)
            .map_err(|e| format!("Failed to encode lock_time: {}", e))?;

        let expiry_height = parts
            .expiry_height
            .ok_or_else(|| "Missing expiry_height for v5 tx".to_string())?;
        expiry_height
            .consensus_encode(&mut bytes)
            .map_err(|e| format!("Failed to encode expiry_height: {}", e))?;

        parts
            .transaction
            .input
            .consensus_encode(&mut bytes)
            .map_err(|e| format!("Failed to encode inputs: {}", e))?;

        parts
            .transaction
            .output
            .consensus_encode(&mut bytes)
            .map_err(|e| format!("Failed to encode outputs: {}", e))?;

        bytes.extend_from_slice(&parts.sapling_fields);
    } else {
        // ZIP-243 (v4) and non-overwintered: inputs | outputs | lock_time [| expiry_height | sapling_fields]
        parts
            .transaction
            .input
            .consensus_encode(&mut bytes)
            .map_err(|e| format!("Failed to encode inputs: {}", e))?;

        parts
            .transaction
            .output
            .consensus_encode(&mut bytes)
            .map_err(|e| format!("Failed to encode outputs: {}", e))?;

        parts
            .transaction
            .lock_time
            .consensus_encode(&mut bytes)
            .map_err(|e| format!("Failed to encode lock_time: {}", e))?;

        if parts.is_overwintered {
            let expiry_height = parts
                .expiry_height
                .ok_or_else(|| "Missing expiry_height for overwintered tx".to_string())?;
            expiry_height
                .consensus_encode(&mut bytes)
                .map_err(|e| format!("Failed to encode expiry_height: {}", e))?;
            bytes.extend_from_slice(&parts.sapling_fields);
        } else {
            if parts.expiry_height.is_some() {
                return Err("Non-overwintered tx must not have expiry_height".to_string());
            }
            if !parts.sapling_fields.is_empty() {
                return Err("Non-overwintered tx must not have sapling_fields".to_string());
            }
        }
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v4 (Sapling) round-trip: inputs | outputs | lock_time | expiry_height | sapling_fields.
    #[test]
    fn test_v4_round_trip() {
        let mut tx_bytes = Vec::new();
        0x80000004u32.consensus_encode(&mut tx_bytes).unwrap(); // overwintered | v4
        ZCASH_SAPLING_VERSION_GROUP_ID
            .consensus_encode(&mut tx_bytes)
            .unwrap();
        0u8.consensus_encode(&mut tx_bytes).unwrap(); // 0 inputs
        0u8.consensus_encode(&mut tx_bytes).unwrap(); // 0 outputs
        7u32.consensus_encode(&mut tx_bytes).unwrap(); // lock_time
        99u32.consensus_encode(&mut tx_bytes).unwrap(); // expiry_height
        tx_bytes.extend_from_slice(&[0u8; 11]); // sapling_fields (valueBalance + counts)

        let parts = decode_zcash_transaction_parts(&tx_bytes).unwrap();
        assert_eq!(parts.version_group_id, Some(ZCASH_SAPLING_VERSION_GROUP_ID));
        assert_eq!(parts.expiry_height, Some(99));
        assert_eq!(parts.consensus_branch_id, None);
        assert_eq!(parts.sapling_fields.len(), 11);

        let re_encoded = encode_zcash_transaction_parts(&parts).unwrap();
        assert_eq!(re_encoded, tx_bytes, "v4 must round-trip byte-for-byte");
    }

    /// v5 (NU5/ZIP-225) round-trip:
    /// consensus_branch_id | lock_time | expiry_height | inputs | outputs | bundles.
    #[test]
    fn test_v5_round_trip() {
        let consensus_branch_id = crate::zcash::NetworkUpgrade::Nu5.branch_id();
        let mut tx_bytes = Vec::new();
        0x80000005u32.consensus_encode(&mut tx_bytes).unwrap(); // overwintered | v5
        ZCASH_NU5_VERSION_GROUP_ID
            .consensus_encode(&mut tx_bytes)
            .unwrap();
        consensus_branch_id.consensus_encode(&mut tx_bytes).unwrap();
        7u32.consensus_encode(&mut tx_bytes).unwrap(); // lock_time
        99u32.consensus_encode(&mut tx_bytes).unwrap(); // expiry_height
        0u8.consensus_encode(&mut tx_bytes).unwrap(); // 0 inputs
        0u8.consensus_encode(&mut tx_bytes).unwrap(); // 0 outputs
                                                      // empty Sapling + Orchard bundles (preserved opaquely as sapling_fields)
        tx_bytes.extend_from_slice(&[0u8; 3]);

        let parts = decode_zcash_transaction_parts(&tx_bytes).unwrap();
        assert_eq!(parts.version_group_id, Some(ZCASH_NU5_VERSION_GROUP_ID));
        assert_eq!(parts.expiry_height, Some(99));
        assert_eq!(parts.consensus_branch_id, Some(consensus_branch_id));
        assert_eq!(parts.transaction.lock_time.to_consensus_u32(), 7);
        assert_eq!(parts.sapling_fields.len(), 3);

        let re_encoded = encode_zcash_transaction_parts(&parts).unwrap();
        assert_eq!(re_encoded, tx_bytes, "v5 must round-trip byte-for-byte");
    }

    /// Encoding a v5 transaction without a consensus_branch_id must fail loudly.
    #[test]
    fn test_v5_requires_consensus_branch_id() {
        let parts = ZcashTransactionParts {
            transaction: Transaction {
                version: miniscript::bitcoin::transaction::Version::non_standard(5),
                lock_time: miniscript::bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            is_overwintered: true,
            version_group_id: Some(ZCASH_NU5_VERSION_GROUP_ID),
            expiry_height: Some(0),
            sapling_fields: vec![],
            consensus_branch_id: None,
        };
        assert!(encode_zcash_transaction_parts(&parts).is_err());
    }
}
