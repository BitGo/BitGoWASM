//! Zcash transaction encoding/decoding helpers
//!
//! Zcash uses an "overwintered transaction format" which includes extra fields
//! (version_group_id, expiry_height, and sapling fields) that are not part of
//! standard Bitcoin transaction consensus encoding.

use miniscript::bitcoin::consensus::{Decodable, Encodable};
use miniscript::bitcoin::{Transaction, TxIn, TxOut};

/// Zcash Sapling version group ID
pub const ZCASH_SAPLING_VERSION_GROUP_ID: u32 = 0x892F2085;

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
    /// Remaining bytes after lock_time / expiry_height (Sapling/Orchard fields, etc.)
    ///
    /// Preserved verbatim so the transaction can be serialized back to the exact same bytes.
    pub sapling_fields: Vec<u8>,
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

    // Read inputs
    let inputs: Vec<TxIn> =
        Vec::consensus_decode(&mut slice).map_err(|e| format!("Failed to decode inputs: {}", e))?;

    // Read outputs
    let outputs: Vec<TxOut> = Vec::consensus_decode(&mut slice)
        .map_err(|e| format!("Failed to decode outputs: {}", e))?;

    // Read lock_time
    let lock_time = miniscript::bitcoin::locktime::absolute::LockTime::consensus_decode(&mut slice)
        .map_err(|e| format!("Failed to decode lock_time: {}", e))?;

    // Read expiry height if overwintered
    let expiry_height = if is_overwintered {
        Some(
            u32::consensus_decode(&mut slice)
                .map_err(|e| format!("Failed to decode expiry_height: {}", e))?,
        )
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

    Ok(ZcashTransactionParts {
        transaction,
        is_overwintered,
        version_group_id,
        expiry_height,
        sapling_fields,
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

    Ok(bytes)
}
