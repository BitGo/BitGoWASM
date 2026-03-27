//! TON address encoding, decoding, and validation
//!
//! TON addresses consist of a workchain ID (i32) and a 256-bit hash.
//! They can be represented in two formats:
//! - Raw: `workchain:hex_hash` (e.g., `0:abcdef...`)
//! - User-friendly: base64url with CRC16 checksum, bounceable/non-bounceable flags

use crate::error::WasmTonError;
use tlb_ton::MsgAddress;
use ton_contracts::wallet::{v4r2::V4R2, WalletVersion};

/// Encode a 32-byte Ed25519 public key to a TON user-friendly address.
///
/// Derives the WalletV4R2 address by computing the StateInit hash
/// (code cell + data cell containing seqno=0, wallet_id, pubkey).
///
/// # Arguments
/// * `public_key` - 32-byte Ed25519 public key
/// * `bounceable` - whether the address should be bounceable (default for smart contracts)
/// * `workchain_id` - workchain ID (0 for basechain, -1 for masterchain)
/// * `wallet_id` - wallet sub-ID (default: 0x29a9a317 for V4R2)
pub fn encode_address(
    public_key: &[u8],
    bounceable: bool,
    workchain_id: i32,
    wallet_id: Option<u32>,
) -> Result<String, WasmTonError> {
    if public_key.len() != 32 {
        return Err(WasmTonError::InvalidAddress(format!(
            "Public key must be 32 bytes, got {}",
            public_key.len()
        )));
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(public_key);

    let wallet_id = wallet_id.unwrap_or(V4R2::DEFAULT_WALLET_ID);
    let state_init = V4R2::state_init(wallet_id, pubkey);

    let addr = MsgAddress::derive(workchain_id, state_init)
        .map_err(|e| WasmTonError::InvalidAddress(format!("Failed to derive address: {}", e)))?;

    // non_bounceable flag is the inverse of bounceable
    Ok(addr.to_base64_url_flags(!bounceable, false))
}

/// Decode a TON address (user-friendly or raw) into its components.
///
/// Returns (workchain_id, hash_bytes, bounceable).
pub fn decode_address(address: &str) -> Result<(i32, [u8; 32], bool), WasmTonError> {
    // Try user-friendly format first (48 chars base64)
    if address.len() == 48 {
        let (addr, non_bounceable, _non_production) = MsgAddress::from_base64_url_flags(address)
            .or_else(|_| MsgAddress::from_base64_std_flags(address))
            .map_err(|e| {
                WasmTonError::InvalidAddress(format!("Invalid user-friendly address: {}", e))
            })?;
        return Ok((addr.workchain_id, addr.address, !non_bounceable));
    }

    // Try raw format (workchain:hex_hash)
    if address.contains(':') {
        let addr = MsgAddress::from_hex(address)
            .map_err(|e| WasmTonError::InvalidAddress(format!("Invalid raw address: {}", e)))?;
        // Raw addresses don't carry bounceable info, default to true
        return Ok((addr.workchain_id, addr.address, true));
    }

    Err(WasmTonError::InvalidAddress(format!(
        "Unrecognized address format: {}",
        address
    )))
}

/// Validate a TON address string.
///
/// Accepts both user-friendly (base64url) and raw (workchain:hex) formats.
pub fn validate_address(address: &str) -> bool {
    decode_address(address).is_ok()
}

/// Convert between address formats.
///
/// Takes any valid TON address and returns it in user-friendly base64url format.
pub fn to_user_friendly(address: &str, bounceable: bool) -> Result<String, WasmTonError> {
    let (workchain_id, hash, _) = decode_address(address)?;
    let addr = MsgAddress {
        workchain_id,
        address: hash,
    };
    Ok(addr.to_base64_url_flags(!bounceable, false))
}

/// Convert any valid TON address to raw format (workchain:hex_hash).
pub fn to_raw(address: &str) -> Result<String, WasmTonError> {
    let (workchain_id, hash, _) = decode_address(address)?;
    let addr = MsgAddress {
        workchain_id,
        address: hash,
    };
    Ok(addr.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector: known WalletV4R2 address derivation
    // Using the test from ton-contracts crate
    #[test]
    fn test_encode_address_default() {
        // This public key corresponds to the mnemonic in ton-contracts tests
        // "jewel loop vast intact snack drip fatigue lunch erode green indoor balance
        //  together scrub hen monster hour narrow banner warfare increase panel sound spell"
        // Expected address: UQA7RMTgzvcyxNNLmK2HdklOvFE8_KNMa-btKZ0dPU1UsqfC
        // (non-bounceable = UQ prefix, bounceable = EQ prefix)
        let pubkey =
            hex::decode("a26a1e5a8acab8c52e1bb9dd0e5cb8eee0ba403a7b5f3e1ec8c1cd0c1e1a3b2d")
                .unwrap();

        // Just verify it doesn't error and returns a 48-char base64url string
        let addr = encode_address(&pubkey, true, 0, None).unwrap();
        assert_eq!(addr.len(), 48);
        // Bounceable addresses start with EQ
        assert!(
            addr.starts_with("EQ"),
            "Bounceable address should start with EQ, got: {}",
            addr
        );
    }

    #[test]
    fn test_encode_non_bounceable() {
        let pubkey = [0u8; 32]; // zero pubkey
        let addr = encode_address(&pubkey, false, 0, None).unwrap();
        assert_eq!(addr.len(), 48);
        // Non-bounceable addresses start with UQ
        assert!(
            addr.starts_with("UQ"),
            "Non-bounceable address should start with UQ, got: {}",
            addr
        );
    }

    #[test]
    fn test_encode_invalid_pubkey() {
        let short_key = vec![0u8; 16];
        assert!(encode_address(&short_key, true, 0, None).is_err());
    }

    #[test]
    fn test_decode_user_friendly() {
        // Known TON address
        let address = "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e";
        let (workchain_id, hash, bounceable) = decode_address(address).unwrap();
        assert_eq!(workchain_id, 0);
        assert!(!hash.iter().all(|b| *b == 0)); // hash should not be all zeros
        assert!(bounceable); // EQ prefix = bounceable
    }

    #[test]
    fn test_decode_raw() {
        let raw = "0:465d9f5d759796ca9c7c1242627872570f972dd1ba649aed18e18a18af734cd1";
        let (workchain_id, _hash, bounceable) = decode_address(raw).unwrap();
        assert_eq!(workchain_id, 0);
        assert!(bounceable); // raw addresses default to bounceable
    }

    #[test]
    fn test_roundtrip_user_friendly() {
        let address = "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e";
        let (workchain_id, hash, bounceable) = decode_address(address).unwrap();

        // Re-encode
        let addr = MsgAddress {
            workchain_id,
            address: hash,
        };
        let re_encoded = addr.to_base64_url_flags(!bounceable, false);
        assert_eq!(re_encoded, address);
    }

    #[test]
    fn test_validate_address() {
        assert!(validate_address(
            "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e"
        ));
        assert!(validate_address(
            "0:465d9f5d759796ca9c7c1242627872570f972dd1ba649aed18e18a18af734cd1"
        ));
        assert!(!validate_address("invalid"));
        assert!(!validate_address(""));
    }

    #[test]
    fn test_to_user_friendly() {
        let raw = "0:465d9f5d759796ca9c7c1242627872570f972dd1ba649aed18e18a18af734cd1";
        let friendly = to_user_friendly(raw, true).unwrap();
        assert_eq!(friendly.len(), 48);
        assert!(friendly.starts_with("EQ"));

        // Non-bounceable
        let non_bounceable = to_user_friendly(raw, false).unwrap();
        assert!(non_bounceable.starts_with("UQ"));
    }

    #[test]
    fn test_to_raw() {
        let friendly = "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e";
        let raw = to_raw(friendly).unwrap();
        assert!(raw.starts_with("0:"));
        assert_eq!(raw.len(), 2 + 64); // "0:" + 64 hex chars
    }

    #[test]
    fn test_encode_roundtrip() {
        let pubkey = [42u8; 32]; // arbitrary pubkey
        let addr = encode_address(&pubkey, true, 0, None).unwrap();
        let (workchain_id, _hash, bounceable) = decode_address(&addr).unwrap();
        assert_eq!(workchain_id, 0);
        assert!(bounceable);
    }
}
