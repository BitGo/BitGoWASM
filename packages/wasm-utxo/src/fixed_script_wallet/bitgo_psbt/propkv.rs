//! Proprietary key-value utilities for PSBT fields
//!
//! This module provides utilities for working with proprietary key-values in PSBTs,
//! specifically for BitGo-specific extensions like MuSig2 data.
//! ```

pub use miniscript::bitcoin::psbt::raw::ProprietaryKey;

/// Find proprietary key-values in PSBT proprietary field matching the criteria
fn find_kv_iter<'a>(
    map: &'a std::collections::BTreeMap<ProprietaryKey, Vec<u8>>,
    prefix: &'a [u8],
    subtype: Option<u8>,
) -> impl Iterator<Item = (&'a ProprietaryKey, &'a Vec<u8>)> + 'a {
    map.iter().filter(move |(k, _)| {
        // Check if the prefix matches
        if k.prefix.as_slice() != prefix {
            return false;
        }

        // Check if subtype matches (if specified)
        if let Some(st) = subtype {
            if k.subtype != st {
                return false;
            }
        }

        true
    })
}

/// BitGo proprietary key identifier
pub const BITGO: &[u8] = b"BITGO";

/// Subtypes for proprietary keys that BitGo uses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProprietaryKeySubtype {
    ZecConsensusBranchId = 0x00,
    Musig2ParticipantPubKeys = 0x01,
    Musig2PubNonce = 0x02,
    Musig2PartialSig = 0x03,
    PayGoAddressAttestationProof = 0x04,
    Bip322Message = 0x05,
    WasmUtxoVersion = 0x06,
}

impl ProprietaryKeySubtype {
    pub fn from(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(ProprietaryKeySubtype::ZecConsensusBranchId),
            0x01 => Some(ProprietaryKeySubtype::Musig2ParticipantPubKeys),
            0x02 => Some(ProprietaryKeySubtype::Musig2PubNonce),
            0x03 => Some(ProprietaryKeySubtype::Musig2PartialSig),
            0x04 => Some(ProprietaryKeySubtype::PayGoAddressAttestationProof),
            0x05 => Some(ProprietaryKeySubtype::Bip322Message),
            0x06 => Some(ProprietaryKeySubtype::WasmUtxoVersion),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct BitGoKeyValueError {
    pub message: String,
}

pub struct BitGoKeyValue {
    pub subtype: ProprietaryKeySubtype,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl BitGoKeyValue {
    pub fn new(subtype: ProprietaryKeySubtype, key: Vec<u8>, value: Vec<u8>) -> Self {
        Self {
            subtype,
            key,
            value,
        }
    }

    pub fn from_key_value(key: &ProprietaryKey, value: &[u8]) -> Result<Self, BitGoKeyValueError> {
        let subtype = ProprietaryKeySubtype::from(key.subtype);
        match subtype {
            Some(subtype) => Ok(Self::new(subtype, key.key.clone(), value.to_owned())),
            None => Err(BitGoKeyValueError {
                message: format!(
                    "Unknown or unsupported BitGo proprietary key subtype: {}",
                    key.subtype
                ),
            }),
        }
    }

    pub fn to_key_value(&self) -> (ProprietaryKey, Vec<u8>) {
        let key = ProprietaryKey {
            prefix: BITGO.to_vec(),
            subtype: self.subtype as u8,
            key: self.key.clone(),
        };
        (key, self.value.clone())
    }
}

pub fn find_kv<'a>(
    subtype: ProprietaryKeySubtype,
    map: &'a std::collections::BTreeMap<ProprietaryKey, Vec<u8>>,
) -> impl Iterator<Item = BitGoKeyValue> + 'a {
    find_kv_iter(map, BITGO, Some(subtype as u8)).map(|(key, value)| {
        BitGoKeyValue::from_key_value(key, value).expect("Failed to create BitGoKeyValue")
    })
}

/// Check if a proprietary key is a BitGo key
pub fn is_bitgo_key(key: &ProprietaryKey) -> bool {
    key.prefix.as_slice() == BITGO
}

/// Check if a proprietary key is a BitGo MuSig2 key
pub fn is_musig2_key(key: &ProprietaryKey) -> bool {
    if !is_bitgo_key(key) {
        return false;
    }
    matches!(
        ProprietaryKeySubtype::from(key.subtype),
        Some(ProprietaryKeySubtype::Musig2ParticipantPubKeys)
            | Some(ProprietaryKeySubtype::Musig2PubNonce)
            | Some(ProprietaryKeySubtype::Musig2PartialSig)
    )
}

/// Version information for wasm-utxo operations on PSBTs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmUtxoVersionInfo {
    pub version: String,
    pub git_hash: String,
}

impl WasmUtxoVersionInfo {
    /// Create a new version info structure
    pub fn new(version: String, git_hash: String) -> Self {
        Self { version, git_hash }
    }

    /// Get the version info from compile-time constants
    /// Falls back to "unknown" if build.rs hasn't set the environment variables
    pub fn from_build_info() -> Self {
        Self {
            version: option_env!("WASM_UTXO_VERSION")
                .unwrap_or("unknown")
                .to_string(),
            git_hash: option_env!("WASM_UTXO_GIT_HASH")
                .unwrap_or("unknown")
                .to_string(),
        }
    }

    /// Serialize to bytes for proprietary key-value storage
    /// Format: <version_len: u8><version_bytes><git_hash_bytes (40 hex chars)>
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let version_bytes = self.version.as_bytes();
        bytes.push(version_bytes.len() as u8);
        bytes.extend_from_slice(version_bytes);
        bytes.extend_from_slice(self.git_hash.as_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("Empty version info bytes".to_string());
        }

        let version_len = bytes[0] as usize;
        if bytes.len() < 1 + version_len {
            return Err("Invalid version info: not enough bytes for version".to_string());
        }

        let version = String::from_utf8(bytes[1..1 + version_len].to_vec())
            .map_err(|e| format!("Invalid UTF-8 in version: {}", e))?;

        let git_hash = String::from_utf8(bytes[1 + version_len..].to_vec())
            .map_err(|e| format!("Invalid UTF-8 in git hash: {}", e))?;

        Ok(Self { version, git_hash })
    }

    /// Convert to proprietary key-value pair for PSBT global fields
    pub fn to_proprietary_kv(&self) -> (ProprietaryKey, Vec<u8>) {
        let key = ProprietaryKey {
            prefix: BITGO.to_vec(),
            subtype: ProprietaryKeySubtype::WasmUtxoVersion as u8,
            key: vec![], // Empty key data - only one version per PSBT
        };
        (key, self.to_bytes())
    }

    /// Create from proprietary key-value pair
    pub fn from_proprietary_kv(key: &ProprietaryKey, value: &[u8]) -> Result<Self, String> {
        if key.prefix.as_slice() != BITGO {
            return Err("Not a BITGO proprietary key".to_string());
        }
        if key.subtype != ProprietaryKeySubtype::WasmUtxoVersion as u8 {
            return Err("Not a WasmUtxoVersion proprietary key".to_string());
        }
        Self::from_bytes(value)
    }
}

/// Extract Zcash consensus branch ID from PSBT global proprietary map.
///
/// The consensus branch ID is stored as a 4-byte little-endian u32 value
/// under the BitGo proprietary key with subtype `ZecConsensusBranchId` (0x00).
///
/// # Returns
/// - `Some(u32)` if the consensus branch ID is present and valid
/// - `None` if the key is not present or the value is malformed
pub fn get_zec_consensus_branch_id(psbt: &miniscript::bitcoin::psbt::Psbt) -> Option<u32> {
    let kv = find_kv(
        ProprietaryKeySubtype::ZecConsensusBranchId,
        &psbt.proprietary,
    )
    .next()?;
    if kv.value.len() == 4 {
        let bytes: [u8; 4] = kv.value.as_slice().try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    } else {
        None
    }
}

/// Set Zcash consensus branch ID in PSBT global proprietary map.
///
/// The consensus branch ID is stored as a 4-byte little-endian u32 value
/// under the BitGo proprietary key with subtype `ZecConsensusBranchId` (0x00).
///
/// # Arguments
/// * `psbt` - The PSBT to modify
/// * `branch_id` - The Zcash consensus branch ID to store
///
/// # Example
/// ```ignore
/// use crate::zcash::NetworkUpgrade;
/// set_zec_consensus_branch_id(&mut psbt, NetworkUpgrade::Nu5.branch_id());
/// ```
///
/// See [`crate::zcash`] module for available network upgrades and their branch IDs.
pub fn set_zec_consensus_branch_id(psbt: &mut miniscript::bitcoin::psbt::Psbt, branch_id: u32) {
    let kv = BitGoKeyValue::new(
        ProprietaryKeySubtype::ZecConsensusBranchId,
        vec![], // empty key
        branch_id.to_le_bytes().to_vec(),
    );
    let (key, value) = kv.to_key_value();
    psbt.proprietary.insert(key, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proprietary_key_structure() {
        let key = ProprietaryKey {
            prefix: b"BITGO".to_vec(),
            subtype: 0x03,
            key: vec![1, 2, 3],
        };

        assert_eq!(key.prefix, b"BITGO");
        assert_eq!(key.subtype, 0x03);
        assert_eq!(key.key, vec![1, 2, 3]);
    }

    #[test]
    fn test_zec_consensus_branch_id_roundtrip() {
        use crate::zcash::NetworkUpgrade;
        use miniscript::bitcoin::psbt::Psbt;
        use miniscript::bitcoin::Transaction;

        // Create a minimal PSBT
        let tx = Transaction {
            version: miniscript::bitcoin::transaction::Version::TWO,
            lock_time: miniscript::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // Initially no branch ID
        assert_eq!(get_zec_consensus_branch_id(&psbt), None);

        // Set NU5 branch ID using generated constant
        let nu5_branch_id = NetworkUpgrade::Nu5.branch_id();
        set_zec_consensus_branch_id(&mut psbt, nu5_branch_id);

        // Should be retrievable
        assert_eq!(get_zec_consensus_branch_id(&psbt), Some(nu5_branch_id));

        // Update to Sapling branch ID using generated constant
        let sapling_branch_id = NetworkUpgrade::Sapling.branch_id();
        set_zec_consensus_branch_id(&mut psbt, sapling_branch_id);

        // Should return the updated value
        assert_eq!(get_zec_consensus_branch_id(&psbt), Some(sapling_branch_id));
    }

    #[test]
    fn test_zec_consensus_branch_id_values() {
        use crate::zcash::NetworkUpgrade;

        // Verify known Zcash branch IDs match expected values from ZIP-200
        assert_eq!(NetworkUpgrade::Overwinter.branch_id(), 0x5ba81b19);
        assert_eq!(NetworkUpgrade::Sapling.branch_id(), 0x76b809bb);
        assert_eq!(NetworkUpgrade::Blossom.branch_id(), 0x2bb40e60);
        assert_eq!(NetworkUpgrade::Heartwood.branch_id(), 0xf5b9230b);
        assert_eq!(NetworkUpgrade::Canopy.branch_id(), 0xe9ff75a6);
        assert_eq!(NetworkUpgrade::Nu5.branch_id(), 0xc2d6d0b4);
        assert_eq!(NetworkUpgrade::Nu6.branch_id(), 0xc8e71055);
    }

    #[test]
    fn test_version_info_serialization() {
        let version_info =
            WasmUtxoVersionInfo::new("0.0.2".to_string(), "abc123def456".to_string());

        let bytes = version_info.to_bytes();
        let deserialized = WasmUtxoVersionInfo::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized, version_info);
    }

    #[test]
    fn test_version_info_proprietary_kv() {
        let version_info =
            WasmUtxoVersionInfo::new("0.0.2".to_string(), "abc123def456".to_string());

        let (key, value) = version_info.to_proprietary_kv();
        assert_eq!(key.prefix, b"BITGO");
        assert_eq!(key.subtype, ProprietaryKeySubtype::WasmUtxoVersion as u8);
        let empty_vec: Vec<u8> = vec![];
        assert_eq!(key.key, empty_vec);

        let deserialized = WasmUtxoVersionInfo::from_proprietary_kv(&key, &value).unwrap();
        assert_eq!(deserialized, version_info);
    }
}
