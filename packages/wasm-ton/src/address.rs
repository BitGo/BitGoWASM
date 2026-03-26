//! TON address encoding, decoding, and derivation
//!
//! TON addresses consist of a workchain_id (i32) and a 32-byte hash.
//! User-friendly format is base64url with flags (bounceable, testnet) and CRC16.
//! V4R2 wallet addresses are derived from Ed25519 public keys via StateInit hashing.

use crate::error::WasmTonError;
use tlb_ton::MsgAddress;
use ton_contracts::wallet::{v4r2::V4R2, WalletVersion};

/// Default wallet ID for V4R2 wallets
pub const DEFAULT_WALLET_ID: u32 = V4R2::DEFAULT_WALLET_ID;

/// Result of decoding a TON address
#[derive(Debug, Clone)]
pub struct DecodedAddress {
    /// Workchain ID (0 for basechain, -1 for masterchain)
    pub workchain_id: i32,
    /// 32-byte address hash
    pub hash: [u8; 32],
    /// Whether the address is bounceable
    pub bounceable: bool,
    /// Whether the address is for testnet
    pub testnet: bool,
}

/// Encode a V4R2 wallet address from an Ed25519 public key.
///
/// Derives the wallet StateInit, hashes it to get the address,
/// then encodes in user-friendly base64url format.
///
/// # Arguments
/// * `pubkey` - 32-byte Ed25519 public key
/// * `bounceable` - Whether the address should be bounceable
/// * `testnet` - Whether the address is for testnet
pub fn encode_address(
    pubkey: &[u8],
    bounceable: bool,
    testnet: bool,
) -> Result<String, WasmTonError> {
    let pubkey: [u8; 32] = pubkey.try_into().map_err(|_| {
        WasmTonError::InvalidPublicKey(format!("Public key must be 32 bytes, got {}", pubkey.len()))
    })?;

    let state_init = V4R2::state_init(DEFAULT_WALLET_ID, pubkey);
    let addr = MsgAddress::derive(0, state_init)?;

    // to_base64_url_flags takes (non_bounceable, non_production)
    Ok(addr.to_base64_url_flags(!bounceable, testnet))
}

/// Decode a TON address from user-friendly (base64url) or raw (workchain:hex) format.
///
/// Returns the decoded address components including flags.
pub fn decode_address(addr: &str) -> Result<DecodedAddress, WasmTonError> {
    // Try user-friendly format first (48 chars base64url/std)
    if addr.len() == 48 || (addr.len() == 46 && !addr.contains(':')) {
        // Try URL-safe base64 first, then standard base64
        let result = MsgAddress::from_base64_url_flags(addr)
            .or_else(|_| MsgAddress::from_base64_std_flags(addr))
            .map_err(|e| WasmTonError::InvalidAddress(e.to_string()))?;

        let (msg_addr, non_bounceable, non_production) = result;

        return Ok(DecodedAddress {
            workchain_id: msg_addr.workchain_id,
            hash: msg_addr.address,
            bounceable: !non_bounceable,
            testnet: non_production,
        });
    }

    // Try raw format (workchain:hex_hash)
    if addr.contains(':') {
        let msg_addr =
            MsgAddress::from_hex(addr).map_err(|e| WasmTonError::InvalidAddress(e.to_string()))?;
        return Ok(DecodedAddress {
            workchain_id: msg_addr.workchain_id,
            hash: msg_addr.address,
            bounceable: true,
            testnet: false,
        });
    }

    Err(WasmTonError::InvalidAddress(format!(
        "Unrecognized address format: {}",
        addr
    )))
}

/// Validate a TON address string.
///
/// Accepts both user-friendly (base64url) and raw (workchain:hex) formats.
pub fn validate_address(addr: &str) -> bool {
    decode_address(addr).is_ok()
}

/// Get the raw format (workchain:hex) of a decoded address
pub fn to_raw_address(decoded: &DecodedAddress) -> String {
    let msg_addr = MsgAddress {
        workchain_id: decoded.workchain_id,
        address: decoded.hash,
    };
    msg_addr.to_hex()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known V4R2 test vector from ton-contracts crate documentation:
    // Mnemonic: "jewel loop vast intact snack drip fatigue lunch erode green indoor
    //            balance together scrub hen monster hour narrow banner warfare increase
    //            panel sound spell"
    // Expected address: UQA7RMTgzvcyxNNLmK2HdklOvFE8_KNMa-btKZ0dPU1UsqfC
    // (bounceable, mainnet)

    #[test]
    fn test_encode_decode_roundtrip() {
        // Use a known public key to derive an address, then decode it
        let pubkey = [1u8; 32]; // Deterministic test key
        let addr = encode_address(&pubkey, true, false).unwrap();

        // Verify it's a valid address
        assert!(validate_address(&addr));

        // Decode and verify flags
        let decoded = decode_address(&addr).unwrap();
        assert_eq!(decoded.workchain_id, 0);
        assert!(decoded.bounceable);
        assert!(!decoded.testnet);
        assert_eq!(decoded.hash.len(), 32);

        // Re-encode with same flags should produce same address
        let msg_addr = MsgAddress {
            workchain_id: decoded.workchain_id,
            address: decoded.hash,
        };
        let re_encoded = msg_addr.to_base64_url_flags(!decoded.bounceable, decoded.testnet);
        assert_eq!(addr, re_encoded);
    }

    #[test]
    fn test_encode_non_bounceable() {
        let pubkey = [1u8; 32];
        let bounceable = encode_address(&pubkey, true, false).unwrap();
        let non_bounceable = encode_address(&pubkey, false, false).unwrap();

        // Different flag encoding should produce different strings
        assert_ne!(bounceable, non_bounceable);

        // Both should decode to the same hash
        let dec_b = decode_address(&bounceable).unwrap();
        let dec_nb = decode_address(&non_bounceable).unwrap();
        assert_eq!(dec_b.hash, dec_nb.hash);
        assert!(dec_b.bounceable);
        assert!(!dec_nb.bounceable);
    }

    #[test]
    fn test_encode_testnet() {
        let pubkey = [1u8; 32];
        let mainnet = encode_address(&pubkey, true, false).unwrap();
        let testnet = encode_address(&pubkey, true, true).unwrap();

        assert_ne!(mainnet, testnet);

        let dec_main = decode_address(&mainnet).unwrap();
        let dec_test = decode_address(&testnet).unwrap();
        assert!(!dec_main.testnet);
        assert!(dec_test.testnet);
    }

    #[test]
    fn test_raw_address_roundtrip() {
        let pubkey = [1u8; 32];
        let addr = encode_address(&pubkey, true, false).unwrap();
        let decoded = decode_address(&addr).unwrap();

        let raw = to_raw_address(&decoded);
        assert!(raw.starts_with("0:"));

        // Should be able to decode raw format
        let decoded_raw = decode_address(&raw).unwrap();
        assert_eq!(decoded.hash, decoded_raw.hash);
        assert_eq!(decoded.workchain_id, decoded_raw.workchain_id);
    }

    #[test]
    fn test_validate_address() {
        let pubkey = [1u8; 32];
        let addr = encode_address(&pubkey, true, false).unwrap();
        assert!(validate_address(&addr));

        assert!(!validate_address("invalid"));
        assert!(!validate_address(""));
    }

    #[test]
    fn test_invalid_pubkey_length() {
        let short_pubkey = vec![0u8; 16];
        assert!(encode_address(&short_pubkey, true, false).is_err());
    }

    #[test]
    fn test_known_address() {
        // Test with a well-known address format
        // EQA... addresses are bounceable, mainnet, workchain 0
        let addr = "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e";
        assert!(validate_address(addr));

        let decoded = decode_address(addr).unwrap();
        assert_eq!(decoded.workchain_id, 0);
        assert!(decoded.bounceable);
        assert!(!decoded.testnet);
    }
}
