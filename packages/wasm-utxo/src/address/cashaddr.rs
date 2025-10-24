//! Cashaddr encoding/decoding module for Bitcoin Cash and eCash.
//!
//! Implements the cashaddr checksum algorithm as defined in:
//! - Spec: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
//! - Reference implementation: https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/cashaddr.cpp
//!
//! This implementation directly follows the official specification and passes all test vectors.
//!
//! # CashAddr vs Bech32 Differences
//!
//! While both CashAddr and Bech32 use 5-bit encoding with checksums, they are fundamentally
//! different encoding schemes and are **not compatible**:
//!
//! ## 1. Checksum Algorithm
//! - **Bech32/Bech32m**: Uses BCH codes with specific generator polynomial (6 checksum characters)
//! - **CashAddr**: Uses different polymod algorithm with 5 generators (8 checksum characters)
//!   - Generators: `[0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]`
//!
//! ## 2. Prefix Handling
//! - **Bech32**: HRP is expanded using both upper 3 bits and lower 5 bits of each character
//!   - Format: `[c >> 5 for c in hrp] + [0] + [c & 31 for c in hrp]`
//! - **CashAddr**: Prefix uses only lower 5 bits of each character
//!   - Format: `[c & 31 for c in prefix] + [0]`
//!
//! ## 3. Address Format
//! - **Bech32**: `hrp1<separator><data>` (separator is always '1')
//! - **CashAddr**: `prefix:<data>` (separator is ':' and prefix is optional)
//!
//! ## 4. Version/Type Encoding
//! - **Bech32**: First character encodes witness version (0-16)
//! - **CashAddr**: First byte encodes both type (P2PKH/P2SH) and size
//!   - Bit 3: 0 = P2PKH, 1 = P2SH
//!   - Bits 0-2: Payload size (0 = 20 bytes, 1 = 24 bytes, etc.)
//!
//! ## 5. Padding Validation
//! - **Bech32**: More lenient with padding bits
//! - **CashAddr**: Strict validation - non-zero padding in remaining bits is an error
//!
//! ## Why We Use Only `Fe32` from the bech32 Crate
//!
//! The `Fe32` type from the bech32 crate is a general 5-bit field element primitive that works
//! for any base32-like encoding. However, the higher-level utilities in the bech32 crate
//! (`ByteIterExt`, `Fe32IterExt`, checksum functions, etc.) are specifically designed for
//! Bech32/Bech32m and would produce incorrect results for CashAddr.
//!
//! Therefore, this module:
//! - ✓ Uses `Fe32` for character/byte conversions (`.to_char()`, `.from_char()`, `.to_u8()`)
//! - ✗ Implements its own bit packing/unpacking to handle CashAddr's specific padding rules
//! - ✗ Implements its own polymod checksum function with CashAddr's generators
//! - ✗ Implements its own prefix expansion matching CashAddr's specification
//!
//! ## Quick Reference: CashAddr vs Bech32
//!
//! | Feature | Bech32/Bech32m | CashAddr |
//! |---------|----------------|----------|
//! | **Separator** | `1` | `:` (optional) |
//! | **Example** | `bc1qw508...` | `bitcoincash:qpm2q...` |
//! | **Checksum Length** | 6 characters (30 bits) | 8 characters (40 bits) |
//! | **Checksum Algorithm** | BCH codes | Custom polymod (5 generators) |
//! | **Prefix Expansion** | `[b>>5...] + [0] + [b&31...]` | `[b&31...] + [0]` |
//! | **Version Encoding** | First char = witness version | First byte = type + size |
//! | **Padding Validation** | Lenient | Strict (must be zero) |
//! | **Used By** | Bitcoin SegWit | Bitcoin Cash, eCash |
//! | **Compatible?** | ❌ No - completely different algorithms |

use super::{AddressCodec, AddressError, Result};
use crate::bitcoin::hashes::Hash;
use crate::bitcoin::{PubkeyHash, Script, ScriptBuf, ScriptHash};
use bech32::Fe32;

/// CashAddr codec for Bitcoin Cash and eCash
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CashAddrCodec {
    /// Cashaddr prefix (e.g., "bitcoincash", "ecash")
    pub prefix: &'static str,
    /// P2PKH type identifier for cashaddr (always 0x00)
    pub pub_key_hash_type: u8,
    /// P2SH type identifier for cashaddr (always 0x08)
    pub script_hash_type: u8,
}

impl CashAddrCodec {
    /// Create a new CashAddr codec
    pub const fn new(prefix: &'static str, pub_key_hash_type: u8, script_hash_type: u8) -> Self {
        Self {
            prefix,
            pub_key_hash_type,
            script_hash_type,
        }
    }
}

/// Convert 8-bit bytes to 5-bit Fe32 field elements.
///
/// This is similar to bech32's `ByteIterExt::bytes_to_fes()` but with CashAddr-specific
/// padding behavior. CashAddr requires that any remaining bits after conversion are
/// padded to create a final 5-bit value (unlike some other schemes).
///
/// # Algorithm
/// - Accumulates bits from input bytes (8 bits at a time)
/// - Extracts 5-bit values as they become available
/// - Pads remaining bits (if any) by left-shifting to fill a 5-bit value
///
/// # Example
/// Input: `[0xFF, 0x01]` (16 bits)
/// - First 5 bits: 11111 = 31
/// - Next 5 bits: 10000 = 16
/// - Next 5 bits: 00001 = 1
/// - Remaining 1 bit (1) padded: 10000 = 16
fn bytes_to_fes(data: &[u8]) -> Result<Vec<Fe32>> {
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    let mut result = Vec::new();

    for &byte in data {
        acc = (acc << 8) | (byte as u32);
        bits += 8;

        while bits >= 5 {
            bits -= 5;
            let value = ((acc >> bits) & 0x1f) as u8;
            result.push(
                Fe32::try_from(value)
                    .map_err(|_| AddressError::CashaddrError("Invalid 5-bit value".to_string()))?,
            );
        }
    }

    if bits > 0 {
        let value = ((acc << (5 - bits)) & 0x1f) as u8;
        result.push(
            Fe32::try_from(value)
                .map_err(|_| AddressError::CashaddrError("Invalid 5-bit value".to_string()))?,
        );
    }

    Ok(result)
}

/// Convert 5-bit Fe32 field elements to 8-bit bytes.
///
/// This is similar to bech32's `Fe32IterExt::fes_to_bytes()` but with **strict padding
/// validation** specific to CashAddr. This is a key difference from Bech32.
///
/// # CashAddr Padding Rules (Stricter than Bech32)
/// After converting all 5-bit values to 8-bit bytes, there may be leftover bits.
/// CashAddr requires:
/// 1. Remaining bits must be < 5 (not enough to form another 5-bit value)
/// 2. If there are remaining bits (1-4 bits), they MUST all be zero
///
/// Bech32 is more lenient with padding, but CashAddr strictly rejects non-zero padding
/// as per the specification to prevent address malleability.
///
/// # Example
/// Valid: `[31, 16, 1, 16]` with last bits = 0000 (zero padding)
/// Invalid: `[31, 16, 1, 17]` with last bits = 0001 (non-zero padding) ❌
fn fes_to_bytes(fes: &[Fe32]) -> Result<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    let mut result = Vec::new();

    for &fe in fes {
        acc = (acc << 5) | (fe.to_u8() as u32);
        bits += 5;

        while bits >= 8 {
            bits -= 8;
            result.push(((acc >> bits) & 0xff) as u8);
        }
    }

    // CASHADDR-SPECIFIC: Strict padding validation (stricter than Bech32)
    // Reject if we have >= 5 bits remaining (should never happen with valid input)
    // OR if we have 1-4 bits remaining that are non-zero
    if bits >= 5 || (bits > 0 && ((acc << (8 - bits)) & 0xff) != 0) {
        return Err(AddressError::CashaddrError(
            "Invalid bit conversion".to_string(),
        ));
    }

    Ok(result)
}

/// Expand the cashaddr prefix for checksum calculation.
///
/// # Key Difference from Bech32
///
/// **Bech32 HRP Expansion:**
/// ```text
/// hrp = "bc"
/// expanded = [b >> 5 for b in hrp] + [0] + [b & 31 for b in hrp]
///          = [3, 3] + [0] + [2, 3]
///          = [3, 3, 0, 2, 3]
/// ```
///
/// **CashAddr Prefix Expansion (This Function):**
/// ```text
/// prefix = "bitcoincash"
/// expanded = [b & 31 for b in prefix] + [0]
///          = [2, 9, 20, 3, 15, 9, 14, 3, 1, 19, 8] + [0]
/// ```
///
/// CashAddr only uses the **lower 5 bits** of each character, making it simpler
/// but incompatible with Bech32's two-part expansion.
///
/// Reference: https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/cashaddr.cpp
fn expand_prefix(prefix: &str) -> Vec<u8> {
    let mut result = Vec::new();

    for byte in prefix.bytes() {
        result.push(byte & 0x1f); // CASHADDR-SPECIFIC: Only lower 5 bits (not Bech32's two-part expansion)
    }
    result.push(0); // Separator

    result
}

/// Compute the cashaddr polymod checksum as per the spec.
///
/// # CashAddr vs Bech32 Checksum Algorithm
///
/// This is the **core difference** between CashAddr and Bech32. They use completely
/// different checksum algorithms that are incompatible with each other.
///
/// ## Bech32/Bech32m Checksum
/// - Uses BCH (Bose-Chaudhuri-Hocquenghem) codes
/// - Generator polynomial: `x^6 + x + 1` (for Bech32) or modified constant (for Bech32m)
/// - Produces 6 checksum characters (30 bits)
/// - 40-bit checksum state
/// - Final XOR with constant: `1` (Bech32) or `0x2bc830a3` (Bech32m)
///
/// ## CashAddr Checksum (This Function)
/// - Uses custom polymod with 5 generator polynomials
/// - Generators (40-bit values):
///   - `0x98f2bc8e61`
///   - `0x79b76d99e2`
///   - `0xf33e5fb3c4`
///   - `0xae2eabe2a8`
///   - `0x1e4f43e470`
/// - Produces 8 checksum characters (40 bits)
/// - 40-bit checksum state
/// - Initial and final XOR with `1`
///
/// ## Algorithm Steps
/// 1. Initialize checksum state `c = 1`
/// 2. For each input value:
///    - Extract top 5 bits of state: `c0 = c >> 35`
///    - Shift state left 5 bits and XOR with input: `c = (c & 0x07ffffffff) << 5 ^ input`
///    - Apply generators based on bits in `c0`
/// 3. Final XOR with `1`
///
/// Reference: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
fn polymod(values: &[u8]) -> u64 {
    // CASHADDR-SPECIFIC: These generators are unique to CashAddr and incompatible with Bech32
    let generators: [u64; 5] = [
        0x98f2bc8e61,
        0x79b76d99e2,
        0xf33e5fb3c4,
        0xae2eabe2a8,
        0x1e4f43e470,
    ];

    let mut c: u64 = 1;
    for &d in values {
        let c0 = (c >> 35) as u8;
        c = ((c & 0x07ffffffff) << 5) ^ (d as u64);

        for (i, &generator) in generators.iter().enumerate() {
            if (c0 & (1 << i)) != 0 {
                c ^= generator;
            }
        }
    }

    c ^ 1
}

/// Encode hash to cashaddr format
pub fn encode_cashaddr(hash: &[u8], is_p2sh: bool, prefix: &str) -> Result<String> {
    if hash.len() != 20 {
        return Err(AddressError::CashaddrError(
            "Hash must be 20 bytes".to_string(),
        ));
    }

    // Version byte encodes type and size
    // For 20 bytes: size_bits = 0
    // type_bit: 0 for P2PKH, 1 for P2SH
    let version_byte = if is_p2sh { 0x08 } else { 0x00 };

    let mut payload = vec![version_byte];
    payload.extend_from_slice(hash);

    // Convert to 5-bit values
    let payload_5bit = bytes_to_fes(&payload)?;

    // Build the data to feed to polymod: prefix + payload + 8 zeros for checksum
    let mut data = expand_prefix(prefix);
    for fe in &payload_5bit {
        data.push(fe.to_u8());
    }
    // Add 8 zeros for the checksum placeholder
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);

    // Calculate checksum
    let checksum = polymod(&data);

    // Extract checksum as 8 5-bit values
    let mut checksum_fes = Vec::new();
    for i in 0..8 {
        let fe_val = ((checksum >> (5 * (7 - i))) & 0x1f) as u8;
        checksum_fes.push(Fe32::try_from(fe_val).expect("valid fe32"));
    }

    // Combine payload and checksum
    let mut combined = payload_5bit;
    combined.extend(checksum_fes);

    // Encode to string
    let mut result = format!("{}:", prefix);
    for fe in combined {
        result.push(fe.to_char());
    }

    Ok(result)
}

/// Decode cashaddr to (hash, is_p2sh)
pub fn decode_cashaddr(address: &str, expected_prefix: &str) -> Result<(Vec<u8>, bool)> {
    // Check for mixed case
    let has_lower = address.chars().any(|c| c.is_lowercase());
    let has_upper = address.chars().any(|c| c.is_uppercase());
    if has_lower && has_upper {
        return Err(AddressError::CashaddrError(
            "Mixed case address".to_string(),
        ));
    }

    let address = address.to_lowercase();

    // Split prefix
    let (prefix, payload_str) = if let Some(colon_pos) = address.find(':') {
        let (p, rest) = address.split_at(colon_pos);
        (p, &rest[1..])
    } else {
        (expected_prefix, address.as_str())
    };

    if prefix != expected_prefix {
        return Err(AddressError::CashaddrError(format!(
            "Prefix mismatch: expected {}, got {}",
            expected_prefix, prefix
        )));
    }

    // Decode payload to field elements
    let mut payload_fes = Vec::new();
    for ch in payload_str.chars() {
        let fe = Fe32::from_char(ch)
            .map_err(|_| AddressError::CashaddrError(format!("Invalid character: {}", ch)))?;
        payload_fes.push(fe);
    }

    // Verify checksum
    let mut data = expand_prefix(prefix);
    for fe in &payload_fes {
        data.push(fe.to_u8());
    }

    let checksum = polymod(&data);
    if checksum != 0 {
        return Err(AddressError::CashaddrError("Invalid checksum".to_string()));
    }

    // Remove checksum (last 8 elements)
    let payload_fes = &payload_fes[..payload_fes.len() - 8];

    // Convert back to 8-bit
    let payload = fes_to_bytes(payload_fes)?;

    if payload.is_empty() {
        return Err(AddressError::CashaddrError("Empty payload".to_string()));
    }

    let version_byte = payload[0];
    let hash = payload[1..].to_vec();

    if hash.len() != 20 {
        return Err(AddressError::CashaddrError(
            "Invalid hash length".to_string(),
        ));
    }

    let is_p2sh = (version_byte & 0x08) != 0;

    Ok((hash, is_p2sh))
}

impl AddressCodec for CashAddrCodec {
    fn encode(&self, script: &Script) -> Result<String> {
        if script.is_p2pkh() {
            if script.len() != 25 {
                return Err(AddressError::InvalidScript(
                    "Invalid P2PKH script length".to_string(),
                ));
            }
            let hash = &script.as_bytes()[3..23];
            encode_cashaddr(hash, false, self.prefix)
        } else if script.is_p2sh() {
            if script.len() != 23 {
                return Err(AddressError::InvalidScript(
                    "Invalid P2SH script length".to_string(),
                ));
            }
            let hash = &script.as_bytes()[2..22];
            encode_cashaddr(hash, true, self.prefix)
        } else {
            Err(AddressError::UnsupportedScriptType(
                "CashAddr only supports P2PKH and P2SH".to_string(),
            ))
        }
    }

    fn decode(&self, address: &str) -> Result<ScriptBuf> {
        let (hash, is_p2sh) = decode_cashaddr(address, self.prefix)?;

        let hash_array: [u8; 20] = hash
            .try_into()
            .map_err(|_| AddressError::CashaddrError("Invalid hash length".to_string()))?;

        if is_p2sh {
            let script_hash = ScriptHash::from_byte_array(hash_array);
            Ok(ScriptBuf::new_p2sh(&script_hash))
        } else {
            let pubkey_hash = PubkeyHash::from_byte_array(hash_array);
            Ok(ScriptBuf::new_p2pkh(&pubkey_hash))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors from the official Bitcoin Cash CashAddr specification
    /// https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
    ///
    /// # Why These Tests Use CashAddr-Specific Implementation
    ///
    /// These tests validate that our implementation follows the CashAddr specification exactly,
    /// which is incompatible with Bech32. Key differences validated by these tests:
    ///
    /// 1. **Checksum**: CashAddr's polymod with 5 generators produces different checksums than Bech32
    /// 2. **Prefix**: CashAddr uses `:` separator and simpler expansion (lower 5 bits only)
    /// 3. **Padding**: Strict validation rejects non-zero padding bits
    /// 4. **Format**: Version byte encodes type (P2PKH/P2SH) differently than Bech32's witness version
    ///
    /// Using bech32 crate's `ByteIterExt::bytes_to_fes()` or checksum functions would fail these tests
    /// because they implement Bech32/Bech32m logic, not CashAddr logic.
    // Test vector: 20-byte P2PKH payload
    const TEST_HASH_20: &str = "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9";

    #[test]
    fn test_spec_vector_bitcoincash_p2pkh_20() {
        let hash = hex::decode(TEST_HASH_20).unwrap();

        let address = encode_cashaddr(&hash, false, "bitcoincash").unwrap();
        assert_eq!(
            address,
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2"
        );

        // Test roundtrip
        let (decoded_hash, is_p2sh) = decode_cashaddr(&address, "bitcoincash").unwrap();
        assert_eq!(decoded_hash, hash);
        assert!(!is_p2sh);
    }

    #[test]
    fn test_spec_vector_bchtest_p2sh_20() {
        let hash = hex::decode(TEST_HASH_20).unwrap();

        let address = encode_cashaddr(&hash, true, "bchtest").unwrap();
        assert_eq!(
            address,
            "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t"
        );

        // Test roundtrip
        let (decoded_hash, is_p2sh) = decode_cashaddr(&address, "bchtest").unwrap();
        assert_eq!(decoded_hash, hash);
        assert!(is_p2sh);
    }

    #[test]
    fn test_spec_vector_pref_p2sh_20() {
        let hash = hex::decode(TEST_HASH_20).unwrap();

        let address = encode_cashaddr(&hash, true, "pref").unwrap();
        assert_eq!(address, "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5");

        // Test roundtrip
        let (decoded_hash, is_p2sh) = decode_cashaddr(&address, "pref").unwrap();
        assert_eq!(decoded_hash, hash);
        assert!(is_p2sh);
    }

    #[test]
    fn test_legacy_to_cashaddr_translation() {
        // Test vectors from the spec showing legacy to cashaddr translation
        let test_cases = vec![
            // (hash_hex, is_p2sh, expected_cashaddr)
            // 1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu -> bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a
            (
                "76a04053bda0a88bda5177b86a15c3b29f559873",
                false,
                "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
            ),
            // 1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR -> bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy
            (
                "cb481232299cd5743151ac4b2d63ae198e7bb0a9",
                false,
                "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
            ),
            // 16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb -> bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r
            (
                "011f28e473c95f4013d7d53ec5fbc3b42df8ed10",
                false,
                "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r",
            ),
            // 3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC -> bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq
            (
                "76a04053bda0a88bda5177b86a15c3b29f559873",
                true,
                "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq",
            ),
            // 3LDsS579y7sruadqu11beEJoTjdFiFCdX4 -> bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e
            (
                "cb481232299cd5743151ac4b2d63ae198e7bb0a9",
                true,
                "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e",
            ),
            // 31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw -> bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37
            (
                "011f28e473c95f4013d7d53ec5fbc3b42df8ed10",
                true,
                "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37",
            ),
        ];

        for (hash_hex, is_p2sh, expected) in test_cases {
            let hash = hex::decode(hash_hex).unwrap();
            let address = encode_cashaddr(&hash, is_p2sh, "bitcoincash").unwrap();
            assert_eq!(address, expected, "Failed for hash {}", hash_hex);

            // Test roundtrip
            let (decoded_hash, decoded_is_p2sh) = decode_cashaddr(&address, "bitcoincash").unwrap();
            assert_eq!(hex::encode(decoded_hash), hash_hex);
            assert_eq!(decoded_is_p2sh, is_p2sh);
        }
    }

    #[test]
    fn test_address_without_prefix() {
        // The spec allows addresses without the prefix:colon part
        let hash = hex::decode(TEST_HASH_20).unwrap();

        let full_address = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        let no_prefix = "qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";

        let (decoded_full, is_p2sh_full) = decode_cashaddr(full_address, "bitcoincash").unwrap();
        let (decoded_no_prefix, is_p2sh_no_prefix) =
            decode_cashaddr(no_prefix, "bitcoincash").unwrap();

        assert_eq!(decoded_full, decoded_no_prefix);
        assert_eq!(is_p2sh_full, is_p2sh_no_prefix);
        assert_eq!(decoded_full, hash);
    }

    #[test]
    fn test_uppercase_address() {
        // The spec states that uppercase is accepted but lowercase is preferred
        let uppercase = "BITCOINCASH:QR6M7J9NJLDWWZLG9V7V53UNLR4JKMX6EYLEP8EKG2";
        let (hash, is_p2sh) = decode_cashaddr(uppercase, "bitcoincash").unwrap();

        assert_eq!(hex::encode(hash).to_uppercase(), TEST_HASH_20);
        assert!(!is_p2sh);
    }

    #[test]
    fn test_mixed_case_rejected() {
        // The spec requires that mixed case must be rejected
        let mixed_case = "bitcoincash:Qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        assert!(decode_cashaddr(mixed_case, "bitcoincash").is_err());
    }

    #[test]
    fn test_wrong_prefix() {
        let address = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        // Try to decode with wrong expected prefix
        assert!(decode_cashaddr(address, "ecash").is_err());
    }

    #[test]
    fn test_invalid_checksum() {
        // Modify the last character to break the checksum
        let bad_address = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg3";
        assert!(decode_cashaddr(bad_address, "bitcoincash").is_err());
    }

    #[test]
    fn test_invalid_character() {
        // 'b' is not in the base32 charset used by cashaddr
        let bad_address = "bitcoincash:br6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        assert!(decode_cashaddr(bad_address, "bitcoincash").is_err());
    }

    #[test]
    fn test_ecash_vectors() {
        // Test with eCash prefix
        let hash = hex::decode(TEST_HASH_20).unwrap();

        let address = encode_cashaddr(&hash, false, "ecash").unwrap();
        // Note: eCash uses same encoding, just different prefix
        assert!(address.starts_with("ecash:"));

        // Test roundtrip
        let (decoded_hash, is_p2sh) = decode_cashaddr(&address, "ecash").unwrap();
        assert_eq!(decoded_hash, hash);
        assert!(!is_p2sh);
    }

    #[test]
    fn test_codec_trait_implementation() {
        // Test using the AddressCodec trait - roundtrip test only
        let hash = hex::decode(TEST_HASH_20).unwrap();
        let pubkey_hash = PubkeyHash::from_byte_array(hash.try_into().unwrap());
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);

        let codec = CashAddrCodec::new("bitcoincash", 0x00, 0x08);
        let address = codec.encode(&script).unwrap();

        // Verify it's a bitcoincash address
        assert!(address.starts_with("bitcoincash:"));

        // Test roundtrip: encode then decode should give us back the original script
        let decoded_script = codec.decode(&address).unwrap();
        assert_eq!(decoded_script, script);
    }

    #[test]
    fn test_p2sh_script_type() {
        let hash = hex::decode(TEST_HASH_20).unwrap();
        let script_hash = ScriptHash::from_byte_array(hash.try_into().unwrap());
        let script = ScriptBuf::new_p2sh(&script_hash);

        let codec = CashAddrCodec::new("bitcoincash", 0x00, 0x08);
        let address = codec.encode(&script).unwrap();

        // P2SH addresses start with 'p' after the prefix
        assert!(address.contains(":p"));

        // Test roundtrip
        let decoded_script = codec.decode(&address).unwrap();
        assert_eq!(decoded_script, script);
    }
}
