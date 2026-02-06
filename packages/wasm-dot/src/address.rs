//! SS58 address encoding and decoding for Polkadot/Substrate chains
//!
//! SS58 is a simple address format designed for Substrate based chains.
//! See: https://docs.substrate.io/reference/address-formats/

use crate::error::WasmDotError;
use crate::types::AddressFormat;
use blake2::{Blake2b512, Digest};

/// SS58 prefix for checksum calculation
const SS58_PREFIX: &[u8] = b"SS58PRE";

/// Base58 alphabet used by Substrate (same as Bitcoin)
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode a public key to SS58 address format
///
/// # Arguments
/// * `public_key` - 32-byte Ed25519 public key
/// * `prefix` - Network prefix (0 for Polkadot, 42 for generic Substrate)
///
/// # Returns
/// SS58 encoded address string
pub fn encode_ss58(public_key: &[u8], prefix: u16) -> Result<String, WasmDotError> {
    if public_key.len() != 32 {
        return Err(WasmDotError::InvalidAddress(format!(
            "Public key must be 32 bytes, got {}",
            public_key.len()
        )));
    }

    // Build the payload: prefix + public key
    let mut payload = Vec::new();

    if prefix < 64 {
        // Single byte prefix
        payload.push(prefix as u8);
    } else if prefix < 16384 {
        // Two byte prefix (encoded as per SS58 spec)
        let first = ((prefix & 0b0000_0000_1111_1100) as u8) >> 2 | 0b0100_0000;
        let second = ((prefix >> 8) as u8) | ((prefix & 0b0000_0000_0000_0011) as u8) << 6;
        payload.push(first);
        payload.push(second);
    } else {
        return Err(WasmDotError::InvalidAddress(format!(
            "Invalid prefix: {}",
            prefix
        )));
    }

    payload.extend_from_slice(public_key);

    // Calculate checksum (first 2 bytes of Blake2b hash of SS58PRE || payload)
    let checksum = ss58_checksum(&payload);
    payload.extend_from_slice(&checksum[..2]);

    // Base58 encode
    Ok(base58_encode(&payload))
}

/// Decode an SS58 address to public key and prefix
///
/// # Arguments
/// * `address` - SS58 encoded address string
///
/// # Returns
/// Tuple of (public_key, prefix)
pub fn decode_ss58(address: &str) -> Result<(Vec<u8>, u16), WasmDotError> {
    let decoded = base58_decode(address)?;

    if decoded.len() < 35 {
        // minimum: 1 byte prefix + 32 byte key + 2 byte checksum
        return Err(WasmDotError::InvalidAddress(
            "Address too short".to_string(),
        ));
    }

    // Extract prefix
    let (prefix, prefix_len) = if decoded[0] < 64 {
        (decoded[0] as u16, 1)
    } else if decoded[0] < 128 {
        if decoded.len() < 36 {
            return Err(WasmDotError::InvalidAddress(
                "Address too short for two-byte prefix".to_string(),
            ));
        }
        let lower = (decoded[0] & 0b0011_1111) << 2 | (decoded[1] >> 6);
        let upper = decoded[1] & 0b0011_1111;
        (((upper as u16) << 8) | (lower as u16), 2)
    } else {
        return Err(WasmDotError::InvalidAddress(format!(
            "Invalid prefix byte: {}",
            decoded[0]
        )));
    };

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
///
/// # Arguments
/// * `address` - SS58 encoded address string
/// * `expected_prefix` - Optional expected network prefix
///
/// # Returns
/// true if valid, false otherwise
pub fn validate_address(address: &str, expected_prefix: Option<u16>) -> bool {
    match decode_ss58(address) {
        Ok((_, prefix)) => match expected_prefix {
            Some(expected) => prefix == expected,
            None => true,
        },
        Err(_) => false,
    }
}

/// Get address format from address string by decoding and checking prefix
pub fn get_address_format(address: &str) -> Result<AddressFormat, WasmDotError> {
    let (_, prefix) = decode_ss58(address)?;
    Ok(match prefix {
        0 => AddressFormat::Polkadot,
        2 => AddressFormat::Kusama,
        _ => AddressFormat::Substrate,
    })
}

/// Calculate SS58 checksum
fn ss58_checksum(payload: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(SS58_PREFIX);
    hasher.update(payload);
    let result = hasher.finalize();
    let mut checksum = [0u8; 64];
    checksum.copy_from_slice(&result);
    checksum
}

/// Base58 encode bytes
fn base58_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    // Count leading zeros
    let zeros = data.iter().take_while(|&&b| b == 0).count();

    // Allocate enough space
    let size = data.len() * 138 / 100 + 1;
    let mut buffer = vec![0u8; size];

    let mut length = 0;
    for &byte in data {
        let mut carry = byte as u32;
        let mut i = 0;
        for j in (0..size).rev() {
            if carry == 0 && i >= length {
                break;
            }
            carry += 256 * buffer[j] as u32;
            buffer[j] = (carry % 58) as u8;
            carry /= 58;
            i += 1;
        }
        length = i;
    }

    // Skip leading zeros in buffer
    let mut start = size - length;
    while start < size && buffer[start] == 0 {
        start += 1;
    }

    // Build result
    let mut result = String::with_capacity(zeros + size - start);
    for _ in 0..zeros {
        result.push('1');
    }
    for &b in &buffer[start..] {
        result.push(ALPHABET[b as usize] as char);
    }

    result
}

/// Base58 decode string
fn base58_decode(input: &str) -> Result<Vec<u8>, WasmDotError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    // Build reverse lookup table
    let mut alphabet_map = [255u8; 128];
    for (i, &c) in ALPHABET.iter().enumerate() {
        alphabet_map[c as usize] = i as u8;
    }

    // Count leading '1's (zeros)
    let zeros = input.chars().take_while(|&c| c == '1').count();

    // Allocate space
    let size = input.len() * 733 / 1000 + 1;
    let mut buffer = vec![0u8; size];

    let mut length = 0;
    for c in input.chars() {
        if c as usize >= 128 {
            return Err(WasmDotError::InvalidAddress(format!(
                "Invalid character: {}",
                c
            )));
        }
        let digit = alphabet_map[c as usize];
        if digit == 255 {
            return Err(WasmDotError::InvalidAddress(format!(
                "Invalid character: {}",
                c
            )));
        }

        let mut carry = digit as u32;
        let mut i = 0;
        for j in (0..size).rev() {
            if carry == 0 && i >= length {
                break;
            }
            carry += 58 * buffer[j] as u32;
            buffer[j] = (carry % 256) as u8;
            carry /= 256;
            i += 1;
        }
        length = i;
    }

    // Skip leading zeros in buffer
    let mut start = size - length;
    while start < size && buffer[start] == 0 {
        start += 1;
    }

    // Build result with leading zeros
    let mut result = vec![0u8; zeros];
    result.extend_from_slice(&buffer[start..]);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        // Test with a known public key
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
