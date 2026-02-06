//! SS58 address encoding and decoding for Polkadot/Substrate chains
//!
//! Uses the official bs58 crate for base58 encoding, matching the Substrate ecosystem.
//! See: https://docs.substrate.io/reference/address-formats/

use crate::error::WasmDotError;
use crate::types::AddressFormat;
use blake2::{Blake2b512, Digest};

/// SS58 prefix for checksum calculation
const SS58_PREFIX: &[u8] = b"SS58PRE";

/// Encode a public key to SS58 address format
///
/// # Arguments
/// * `public_key` - 32-byte Ed25519 public key
/// * `prefix` - Network prefix (0 for Polkadot, 2 for Kusama, 42 for generic Substrate)
pub fn encode_ss58(public_key: &[u8], prefix: u16) -> Result<String, WasmDotError> {
    if public_key.len() != 32 {
        return Err(WasmDotError::InvalidAddress(format!(
            "Public key must be 32 bytes, got {}",
            public_key.len()
        )));
    }

    // Build payload: prefix + public key
    let mut payload = encode_prefix(prefix)?;
    payload.extend_from_slice(public_key);

    // Calculate checksum (first 2 bytes of Blake2b-512 hash)
    let checksum = ss58_checksum(&payload);
    payload.extend_from_slice(&checksum[..2]);

    // Base58 encode using bs58 crate
    Ok(bs58::encode(&payload).into_string())
}

/// Decode an SS58 address to public key and prefix
pub fn decode_ss58(address: &str) -> Result<(Vec<u8>, u16), WasmDotError> {
    // Base58 decode using bs58 crate
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|e| WasmDotError::InvalidAddress(format!("Invalid base58: {}", e)))?;

    if decoded.len() < 35 {
        return Err(WasmDotError::InvalidAddress(
            "Address too short".to_string(),
        ));
    }

    // Decode prefix
    let (prefix, prefix_len) = decode_prefix(&decoded)?;

    // Extract public key and checksum
    let checksum_start = decoded.len() - 2;
    let public_key = &decoded[prefix_len..checksum_start];
    let checksum = &decoded[checksum_start..];

    if public_key.len() != 32 {
        return Err(WasmDotError::InvalidAddress(format!(
            "Invalid public key length: {}",
            public_key.len()
        )));
    }

    // Verify checksum
    let payload = &decoded[..checksum_start];
    let expected_checksum = ss58_checksum(payload);

    if checksum != &expected_checksum[..2] {
        return Err(WasmDotError::InvalidAddress("Invalid checksum".to_string()));
    }

    Ok((public_key.to_vec(), prefix))
}

/// Validate an SS58 address
pub fn validate_address(address: &str, expected_prefix: Option<u16>) -> bool {
    match decode_ss58(address) {
        Ok((_, prefix)) => expected_prefix.map_or(true, |expected| prefix == expected),
        Err(_) => false,
    }
}

/// Get address format from address string
pub fn get_address_format(address: &str) -> Result<AddressFormat, WasmDotError> {
    let (_, prefix) = decode_ss58(address)?;
    Ok(match prefix {
        0 => AddressFormat::Polkadot,
        2 => AddressFormat::Kusama,
        _ => AddressFormat::Substrate,
    })
}

/// Encode SS58 prefix (supports single and two-byte prefixes)
fn encode_prefix(prefix: u16) -> Result<Vec<u8>, WasmDotError> {
    if prefix < 64 {
        Ok(vec![prefix as u8])
    } else if prefix < 16384 {
        // Two-byte encoding per SS58 spec
        let first = ((prefix & 0b0000_0000_1111_1100) as u8) >> 2 | 0b0100_0000;
        let second = ((prefix >> 8) as u8) | ((prefix & 0b0000_0000_0000_0011) as u8) << 6;
        Ok(vec![first, second])
    } else {
        Err(WasmDotError::InvalidAddress(format!(
            "Invalid prefix: {}",
            prefix
        )))
    }
}

/// Decode SS58 prefix from raw bytes
fn decode_prefix(data: &[u8]) -> Result<(u16, usize), WasmDotError> {
    if data[0] < 64 {
        Ok((data[0] as u16, 1))
    } else if data[0] < 128 {
        if data.len() < 2 {
            return Err(WasmDotError::InvalidAddress(
                "Address too short for two-byte prefix".to_string(),
            ));
        }
        let lower = (data[0] & 0b0011_1111) << 2 | (data[1] >> 6);
        let upper = data[1] & 0b0011_1111;
        Ok((((upper as u16) << 8) | (lower as u16), 2))
    } else {
        Err(WasmDotError::InvalidAddress(format!(
            "Invalid prefix byte: {}",
            data[0]
        )))
    }
}

/// Calculate SS58 checksum (Blake2b-512 of "SS58PRE" || payload)
fn ss58_checksum(payload: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(SS58_PREFIX);
    hasher.update(payload);
    let result = hasher.finalize();
    let mut checksum = [0u8; 64];
    checksum.copy_from_slice(&result);
    checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let pubkey =
            hex::decode("61b18c6dc02ddcabdeac56cb4f21a971cc41cc97640f6f85b073480008c53a0d")
                .unwrap();

        // Encode with Substrate prefix (42)
        let address = encode_ss58(&pubkey, 42).unwrap();
        assert_eq!(address, "5EGoFA95omzemRssELLDjVenNZ68aXyUeqtKQScXSEBvVJkr");

        // Decode and verify
        let (decoded_pubkey, prefix) = decode_ss58(&address).unwrap();
        assert_eq!(decoded_pubkey, pubkey);
        assert_eq!(prefix, 42);
    }

    #[test]
    fn test_polkadot_address() {
        let pubkey =
            hex::decode("61b18c6dc02ddcabdeac56cb4f21a971cc41cc97640f6f85b073480008c53a0d")
                .unwrap();

        // Encode with Polkadot prefix (0)
        let address = encode_ss58(&pubkey, 0).unwrap();
        assert!(address.starts_with('1'));

        let (decoded_pubkey, prefix) = decode_ss58(&address).unwrap();
        assert_eq!(decoded_pubkey, pubkey);
        assert_eq!(prefix, 0);
    }

    #[test]
    fn test_validate_address() {
        let valid = "5EGoFA95omzemRssELLDjVenNZ68aXyUeqtKQScXSEBvVJkr";
        assert!(validate_address(valid, Some(42)));
        assert!(validate_address(valid, None));
        assert!(!validate_address(valid, Some(0))); // Wrong prefix

        assert!(!validate_address("invalid", None));
    }

    #[test]
    fn test_invalid_pubkey_length() {
        let short_pubkey = vec![0u8; 16];
        assert!(encode_ss58(&short_pubkey, 42).is_err());
    }
}
