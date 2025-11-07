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
}
