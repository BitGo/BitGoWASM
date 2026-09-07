//! Zcash transaction encoding/decoding helpers
//!
//! Zcash uses an "overwintered transaction format" which includes extra fields
//! (version_group_id, expiry_height, and sapling fields) that are not part of
//! standard Bitcoin transaction consensus encoding.

use miniscript::bitcoin::consensus::{Decodable, Encodable};
use miniscript::bitcoin::{Transaction, TxIn, TxOut};

/// Zcash Sapling version group ID (v4 transactions)
pub const ZCASH_SAPLING_VERSION_GROUP_ID: u32 = 0x892F2085;

/// Zcash Ironwood version group ID (v6 / NU6.3 transactions)
pub const ZCASH_IRONWOOD_VERSION_GROUP_ID: u32 = 0xD884B698;

/// Transaction version header for v4 transactions (Sapling), overwintered bit set.
pub const ZCASH_V4_VERSION_HEADER: u32 = 0x80000004;

/// Transaction version header for v6 transactions (Ironwood/NU6.3), overwintered bit set.
pub const ZCASH_V6_VERSION_HEADER: u32 = 0x80000006;

/// Zcash transaction version in a PSBT or serialized transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZcashTransactionVersion {
    #[serde(rename = "v4")]
    V4,
    #[serde(rename = "v6")]
    V6,
}

impl ZcashTransactionVersion {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }

    pub const fn version_number(&self) -> u32 {
        match self {
            Self::V4 => 4,
            Self::V6 => 6,
        }
    }
}

impl std::fmt::Display for ZcashTransactionVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ZcashTransactionVersion {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "v4" | "4" => Ok(Self::V4),
            "v6" | "6" => Ok(Self::V6),
            _ => Err(format!("unknown Zcash transaction version: {s}")),
        }
    }
}

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

    // The v6 (Ironwood/NU6.3) wire format reorders the header (consensusBranchId,
    // lockTime, expiryHeight move to the front) and is not a v4 tail extension.
    // Route callers to the dedicated v6 codec instead of mis-parsing.
    if version_group_id == Some(ZCASH_IRONWOOD_VERSION_GROUP_ID) {
        return Err(
            "v6 (Ironwood) transaction detected; use crate::zcash::v6::decode_v6_transaction"
                .to_string(),
        );
    }

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

/// Detect whether the given PSBT bytes represent a Zcash v4 or v6 (Ironwood) transaction.
///
/// Returns `Ok(ZcashTransactionVersion::V4)` or `Ok(ZcashTransactionVersion::V6)`.
/// Returns an `Err` if the bytes cannot be parsed as a PSBT or if they do not represent
/// a recognized Zcash transaction version.
pub fn detect_zcash_transaction_version(
    psbt_bytes: &[u8],
) -> Result<ZcashTransactionVersion, String> {
    use miniscript::bitcoin::psbt::Psbt;
    use miniscript::bitcoin::VarInt;
    use std::io::Read;

    if psbt_bytes.len() < 5 || &psbt_bytes[0..5] != b"psbt\xff" {
        return Err("Invalid PSBT: missing magic bytes".to_string());
    }

    // Fast path: standard PSBT deserialization (covers v6 shielding PSBTs and hydrated v4/v6 PSBTs)
    if let Ok(psbt) = Psbt::deserialize(psbt_bytes) {
        if let Some((vgid, _)) =
            crate::fixed_script_wallet::bitgo_psbt::propkv::get_zec_v6_params(&psbt)
        {
            if vgid == ZCASH_IRONWOOD_VERSION_GROUP_ID {
                return Ok(ZcashTransactionVersion::V6);
            } else {
                return Err(format!(
                    "PSBT declares unrecognized Zcash version_group_id: {:#010x}",
                    vgid
                ));
            }
        }
        if psbt.unsigned_tx.version.0 == 6
            && crate::fixed_script_wallet::bitgo_psbt::propkv::get_zec_v6_consensus_branch_id(&psbt)
                .is_some()
        {
            return Ok(ZcashTransactionVersion::V6);
        }
        if (psbt.unsigned_tx.version.0 == 4 || psbt.unsigned_tx.version.0 == 5)
            && crate::fixed_script_wallet::bitgo_psbt::propkv::get_zec_consensus_branch_id(&psbt)
                .is_some()
        {
            return Ok(ZcashTransactionVersion::V4);
        }
    }

    // Scan the PSBT global key-value map to inspect PSBT_GLOBAL_UNSIGNED_TX and proprietary keys
    let mut r = psbt_bytes;
    let magic: [u8; 4] =
        Decodable::consensus_decode(&mut r).map_err(|e| format!("Invalid PSBT magic: {}", e))?;
    if &magic != b"psbt" {
        return Err("Invalid PSBT magic".to_string());
    }
    let separator: u8 = Decodable::consensus_decode(&mut r)
        .map_err(|e| format!("Invalid PSBT separator: {}", e))?;
    if separator != 0xff {
        return Err("Invalid PSBT separator".to_string());
    }

    let mut found_tx_bytes: Option<Vec<u8>> = None;
    let mut v6_vgid: Option<u32> = None;
    let mut has_zec_branch_id = false;

    loop {
        let key_len: VarInt = match Decodable::consensus_decode(&mut r) {
            Ok(k) => k,
            Err(e) => return Err(format!("Failed to decode PSBT key length: {}", e)),
        };
        if key_len.0 == 0 {
            break;
        }
        let mut key_data = vec![0u8; key_len.0 as usize];
        if r.read_exact(&mut key_data).is_err() {
            return Err("Failed to read PSBT key data".to_string());
        }

        let val_len: VarInt = match Decodable::consensus_decode(&mut r) {
            Ok(v) => v,
            Err(e) => return Err(format!("Failed to decode PSBT value length: {}", e)),
        };
        let mut val_data = vec![0u8; val_len.0 as usize];
        if r.read_exact(&mut val_data).is_err() {
            return Err("Failed to read PSBT value data".to_string());
        }

        if key_data.len() == 1 && key_data[0] == 0x00 {
            found_tx_bytes = Some(val_data);
        } else if key_data.starts_with(b"\xfc\x0cBITGO/ZEC/V6\x02") && val_data.len() == 4 {
            v6_vgid = Some(u32::from_le_bytes(val_data[0..4].try_into().unwrap()));
        } else if key_data.windows(12).any(|w| w == b"BITGO/ZEC/V6") {
            if key_data.contains(
                &(crate::fixed_script_wallet::bitgo_psbt::propkv::ZecV6KeySubtype::VersionGroupId
                    as u8),
            ) && val_data.len() == 4
            {
                v6_vgid = Some(u32::from_le_bytes(val_data[0..4].try_into().unwrap()));
            }
        } else if key_data.windows(5).any(|w| w == b"BITGO") {
            has_zec_branch_id = true;
        }
    }

    if let Some(vgid) = v6_vgid {
        if vgid == ZCASH_IRONWOOD_VERSION_GROUP_ID {
            return Ok(ZcashTransactionVersion::V6);
        } else {
            return Err(format!(
                "PSBT declares unrecognized Zcash v6 version_group_id: {:#010x}",
                vgid
            ));
        }
    }

    if let Some(tx_bytes) = found_tx_bytes {
        if tx_bytes.len() >= 4 {
            let header = u32::from_le_bytes(tx_bytes[0..4].try_into().unwrap());
            if header == ZCASH_V6_VERSION_HEADER {
                if tx_bytes.len() >= 8 {
                    let vgid = u32::from_le_bytes(tx_bytes[4..8].try_into().unwrap());
                    if vgid == ZCASH_IRONWOOD_VERSION_GROUP_ID {
                        return Ok(ZcashTransactionVersion::V6);
                    }
                }
                return Ok(ZcashTransactionVersion::V6);
            }
            if header == ZCASH_V4_VERSION_HEADER {
                if tx_bytes.len() >= 8 {
                    let vgid = u32::from_le_bytes(tx_bytes[4..8].try_into().unwrap());
                    if vgid == ZCASH_SAPLING_VERSION_GROUP_ID {
                        return Ok(ZcashTransactionVersion::V4);
                    }
                }
                return Ok(ZcashTransactionVersion::V4);
            }
            if (header & 0x80000000) != 0 && tx_bytes.len() >= 8 {
                let vgid = u32::from_le_bytes(tx_bytes[4..8].try_into().unwrap());
                if vgid == ZCASH_IRONWOOD_VERSION_GROUP_ID {
                    return Ok(ZcashTransactionVersion::V6);
                }
                if vgid == ZCASH_SAPLING_VERSION_GROUP_ID {
                    return Ok(ZcashTransactionVersion::V4);
                }
            }
        }

        if let Ok(parts) = decode_zcash_transaction_parts(&tx_bytes) {
            if parts.is_overwintered {
                if parts.version_group_id == Some(ZCASH_SAPLING_VERSION_GROUP_ID)
                    || parts.transaction.version.0 == 4
                    || parts.transaction.version.0 == 5
                {
                    return Ok(ZcashTransactionVersion::V4);
                }
                if parts.version_group_id == Some(ZCASH_IRONWOOD_VERSION_GROUP_ID)
                    || parts.transaction.version.0 == 6
                {
                    return Ok(ZcashTransactionVersion::V6);
                }
            } else if has_zec_branch_id
                && (parts.transaction.version.0 == 4 || parts.transaction.version.0 == 5)
            {
                return Ok(ZcashTransactionVersion::V4);
            }
        }
    }

    Err("Not a recognized Zcash PSBT (neither v4 nor v6)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt;
    use crate::fixed_script_wallet::test_utils::get_test_wallet_keys;
    use crate::fixed_script_wallet::RootWalletKeys;
    use crate::Network;

    #[test]
    fn test_detect_version_v4_psbt() {
        let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("detect-v4"));
        let psbt = ZcashBitGoPsbt::new(
            Network::Zcash,
            &wallet_keys,
            0xc2d6d0b4, // NU5 branch ID
            Some(4),
            Some(0),
            Some(ZCASH_SAPLING_VERSION_GROUP_ID),
            Some(0),
        );
        let bytes = psbt.serialize().expect("serialize v4 psbt");
        let version = detect_zcash_transaction_version(&bytes).expect("detect v4");
        assert_eq!(version, ZcashTransactionVersion::V4);
        assert_eq!(version.as_str(), "v4");
        assert_eq!(version.version_number(), 4);
    }

    #[test]
    fn test_detect_version_v6_psbt() {
        let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("detect-v6"));
        let psbt = ZcashBitGoPsbt::new_v6(
            Network::ZcashTestnet,
            &wallet_keys,
            0x37a5165b, // NU6.3 branch ID
            Some(0),
            Some(0),
        );
        let bytes = psbt.serialize_v6();
        let version = detect_zcash_transaction_version(&bytes).expect("detect v6");
        assert_eq!(version, ZcashTransactionVersion::V6);
        assert_eq!(version.as_str(), "v6");
        assert_eq!(version.version_number(), 6);
    }

    #[test]
    fn test_detect_version_v6_bare_psbt() {
        let psbt = ZcashBitGoPsbt::new_v6_bare(Network::ZcashTestnet, 0x37a5165b, Some(0), Some(0));
        let bytes = psbt.serialize_v6();
        let version = detect_zcash_transaction_version(&bytes).expect("detect v6 bare");
        assert_eq!(version, ZcashTransactionVersion::V6);
    }

    #[test]
    fn test_detect_version_rejects_non_zcash_psbt() {
        let tx = miniscript::bitcoin::Transaction {
            version: miniscript::bitcoin::transaction::Version::TWO,
            lock_time: miniscript::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let psbt = miniscript::bitcoin::Psbt::from_unsigned_tx(tx).unwrap();
        let bytes = psbt.serialize();
        let err = detect_zcash_transaction_version(&bytes).unwrap_err();
        assert!(err.contains("Not a recognized Zcash PSBT"));
    }

    #[test]
    fn test_detect_version_rejects_invalid_bytes() {
        let err = detect_zcash_transaction_version(&[0, 1, 2, 3]).unwrap_err();
        assert!(err.contains("Invalid PSBT"));
    }

    #[test]
    fn test_zcash_transaction_version_enum_display_and_parse() {
        assert_eq!(ZcashTransactionVersion::V4.to_string(), "v4");
        assert_eq!(ZcashTransactionVersion::V6.to_string(), "v6");
        assert_eq!(
            "v4".parse::<ZcashTransactionVersion>().unwrap(),
            ZcashTransactionVersion::V4
        );
        assert_eq!(
            "V4".parse::<ZcashTransactionVersion>().unwrap(),
            ZcashTransactionVersion::V4
        );
        assert_eq!(
            "4".parse::<ZcashTransactionVersion>().unwrap(),
            ZcashTransactionVersion::V4
        );
        assert_eq!(
            "v6".parse::<ZcashTransactionVersion>().unwrap(),
            ZcashTransactionVersion::V6
        );
        assert_eq!(
            "V6".parse::<ZcashTransactionVersion>().unwrap(),
            ZcashTransactionVersion::V6
        );
        assert_eq!(
            "6".parse::<ZcashTransactionVersion>().unwrap(),
            ZcashTransactionVersion::V6
        );
        assert!("v5".parse::<ZcashTransactionVersion>().is_err());
    }
}
