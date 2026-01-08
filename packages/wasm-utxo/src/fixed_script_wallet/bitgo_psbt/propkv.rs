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

/// Extract Zcash consensus branch ID from PSBT global proprietary map.
///
/// The consensus branch ID is stored as a 4-byte little-endian u32 value
/// under the BitGo proprietary key with subtype `ZecConsensusBranchId` (0x00).
///
/// This function checks both the parsed `proprietary` map (where wasm-utxo stores it)
/// and the raw `unknown` map (where utxolib stores it) for compatibility.
///
/// # Temporary Compatibility Note
///
/// The fallback to the `unknown` map is a **temporary workaround** needed because
/// BitGoJS currently uses a mix of `utxo-lib` (TypeScript) and `wasm-utxo` (Rust/WASM)
/// for PSBT operations. When `utxo-lib` serializes a PSBT, it stores proprietary keys
/// in a format that ends up in the raw `unknown` map when deserialized by rust-bitcoin,
/// rather than the parsed `proprietary` map.
///
/// Once BitGoJS fully migrates to `wasm-utxo` for all Zcash PSBT operations, this
/// fallback can be removed and the function can return to only checking `proprietary`.
///
/// # Returns
/// - `Some(u32)` if the consensus branch ID is present and valid
/// - `None` if the key is not present or the value is malformed
pub fn get_zec_consensus_branch_id(psbt: &miniscript::bitcoin::psbt::Psbt) -> Option<u32> {
    // First try the proprietary map (where wasm-utxo stores it)
    if let Some(kv) = find_kv(
        ProprietaryKeySubtype::ZecConsensusBranchId,
        &psbt.proprietary,
    )
    .next()
    {
        if kv.value.len() == 4 {
            let bytes: [u8; 4] = kv.value.as_slice().try_into().ok()?;
            return Some(u32::from_le_bytes(bytes));
        }
    }

    // TEMPORARY: Also check the unknown map (where utxolib stores it as raw key-value pairs)
    // This is needed for compatibility while BitGoJS uses a mix of utxo-lib and wasm-utxo.
    // The key format from utxolib is: 0xfc + varint(5) + "BITGO" + 0x00
    // In rust-bitcoin's raw::Key struct:
    //   - type_value: u8 = 0xfc (proprietary key type)
    //   - key: Vec<u8> = [0x05, 'B', 'I', 'T', 'G', 'O', 0x00] (varint len + identifier + subtype)
    let expected_key_data: &[u8] = &[
        0x05, // length of identifier (varint)
        b'B', b'I', b'T', b'G', b'O', // "BITGO"
        0x00, // ZecConsensusBranchId subtype
    ];

    for (key, value) in &psbt.unknown {
        // Check if this is a proprietary key (0xfc) with the expected key data
        if key.type_value == 0xfc && key.key.as_slice() == expected_key_data && value.len() == 4 {
            let bytes: [u8; 4] = value.as_slice().try_into().ok()?;
            return Some(u32::from_le_bytes(bytes));
        }
    }

    None
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
    fn test_zec_consensus_branch_id_from_unknown_map() {
        use crate::zcash::NetworkUpgrade;
        use miniscript::bitcoin::psbt::raw::Key;
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

        // Simulate how utxolib stores the consensus branch ID in the unknown map
        // In rust-bitcoin's raw::Key struct:
        //   - type_value: 0xfc (proprietary key type)
        //   - key: [0x05, 'B', 'I', 'T', 'G', 'O', 0x00] (varint len + identifier + subtype)
        let utxolib_key = Key {
            type_value: 0xfc, // proprietary key type
            key: vec![
                0x05, // length of identifier (varint)
                b'B', b'I', b'T', b'G', b'O', // "BITGO"
                0x00, // ZecConsensusBranchId subtype
            ],
        };

        let nu5_branch_id = NetworkUpgrade::Nu5.branch_id();
        let value = nu5_branch_id.to_le_bytes().to_vec();
        psbt.unknown.insert(utxolib_key, value);

        // Should be retrievable from the unknown map
        assert_eq!(get_zec_consensus_branch_id(&psbt), Some(nu5_branch_id));
    }

    #[test]
    fn test_zec_consensus_branch_id_proprietary_takes_precedence() {
        use crate::zcash::NetworkUpgrade;
        use miniscript::bitcoin::psbt::raw::Key;
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

        // Set one value in the unknown map (utxolib format)
        let utxolib_key = Key {
            type_value: 0xfc,
            key: vec![0x05, b'B', b'I', b'T', b'G', b'O', 0x00],
        };
        let sapling_branch_id = NetworkUpgrade::Sapling.branch_id();
        psbt.unknown
            .insert(utxolib_key, sapling_branch_id.to_le_bytes().to_vec());

        // Set a different value in the proprietary map (wasm-utxo format)
        let nu5_branch_id = NetworkUpgrade::Nu5.branch_id();
        set_zec_consensus_branch_id(&mut psbt, nu5_branch_id);

        // The proprietary map should take precedence
        assert_eq!(get_zec_consensus_branch_id(&psbt), Some(nu5_branch_id));
    }
}
