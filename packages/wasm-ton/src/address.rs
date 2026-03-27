use tlb_ton::MsgAddress;
use ton_contracts::wallet::v4r2::V4R2;
use ton_contracts::wallet::WalletVersion;

use crate::error::WasmTonError;

/// Address format enum matching TON user-friendly formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFormat {
    /// Bounceable (EQ prefix in base64url)
    Bounceable,
    /// Non-bounceable (UQ prefix in base64url)
    NonBounceable,
    /// Raw hex format: workchain:hex_address
    RawHex,
}

/// Encode a public key hash (32 bytes) and workchain to a TON address.
///
/// The `address_hash` is the 32-byte address portion of MsgAddress,
/// NOT a public key. For wallets, this is the hash of the state init.
pub fn encode_address(
    workchain_id: i32,
    address_hash: &[u8],
    format: AddressFormat,
) -> Result<String, WasmTonError> {
    if address_hash.len() != 32 {
        return Err(WasmTonError::new("address hash must be 32 bytes"));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(address_hash);
    let addr = MsgAddress {
        workchain_id,
        address: hash,
    };
    Ok(match format {
        AddressFormat::Bounceable => addr.to_base64_url_flags(false, false),
        AddressFormat::NonBounceable => addr.to_base64_url_flags(true, false),
        AddressFormat::RawHex => addr.to_hex(),
    })
}

/// Encode a raw Ed25519 public key to a TON user-friendly address.
///
/// This computes the wallet v4r2 StateInit hash internally, using workchain 0
/// and the default wallet ID.
pub fn encode_address_from_public_key(
    public_key: &[u8],
    bounceable: bool,
) -> Result<String, WasmTonError> {
    if public_key.len() != 32 {
        return Err(WasmTonError::new("public key must be 32 bytes"));
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(public_key);

    let state_init = V4R2::state_init(V4R2::DEFAULT_WALLET_ID, pubkey);
    let msg_addr = MsgAddress::derive(0, state_init)
        .map_err(|e| WasmTonError::new(&format!("failed to derive address: {e}")))?;

    let non_bounceable = !bounceable;
    Ok(msg_addr.to_base64_url_flags(non_bounceable, false))
}

/// Decode a TON address string into its components.
///
/// Supports:
/// - User-friendly base64url (EQ/UQ prefix, 48 chars)
/// - Raw hex format (workchain:hex)
///
/// Returns (workchain_id, address_hash, is_bounceable, is_testnet)
pub fn decode_address(addr: &str) -> Result<(i32, [u8; 32], bool, bool), WasmTonError> {
    // Try raw hex first
    if addr.contains(':') {
        let parsed = MsgAddress::from_hex(addr)
            .map_err(|e| WasmTonError::new(&format!("invalid hex address: {e}")))?;
        // Raw hex doesn't carry bounce/testnet flags
        return Ok((parsed.workchain_id, parsed.address, true, false));
    }

    // Try user-friendly base64url
    let (parsed, non_bounceable, non_production) = MsgAddress::from_base64_url_flags(addr)
        .or_else(|_| MsgAddress::from_base64_std_flags(addr))
        .map_err(|e| WasmTonError::new(&format!("invalid address: {e}")))?;

    Ok((
        parsed.workchain_id,
        parsed.address,
        !non_bounceable,
        non_production,
    ))
}

/// Validate a TON address string.
pub fn validate_address(addr: &str) -> bool {
    decode_address(addr).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_bounceable() {
        let addr = "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG";
        let (wc, hash, bounceable, testnet) = decode_address(addr).unwrap();
        assert_eq!(wc, 0);
        assert!(bounceable);
        assert!(!testnet);
        let encoded = encode_address(wc, &hash, AddressFormat::Bounceable).unwrap();
        assert_eq!(encoded, addr);
    }

    #[test]
    fn test_roundtrip_non_bounceable() {
        let addr = "UQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBX1aD";
        let (wc, hash, bounceable, testnet) = decode_address(addr).unwrap();
        assert_eq!(wc, 0);
        assert!(!bounceable);
        assert!(!testnet);
        let encoded = encode_address(wc, &hash, AddressFormat::NonBounceable).unwrap();
        assert_eq!(encoded, addr);
    }

    #[test]
    fn test_raw_hex() {
        let addr = "0:348bcf82746945fc38541c77fdd91d4e347eac200f6f2d9fd62dc08885f0415f";
        let (wc, hash, _, _) = decode_address(addr).unwrap();
        assert_eq!(wc, 0);
        let encoded = encode_address(wc, &hash, AddressFormat::RawHex).unwrap();
        assert_eq!(encoded, addr);
    }

    #[test]
    fn test_invalid_addresses() {
        assert!(!validate_address("randomString"));
        assert!(!validate_address("0xc4173a804406a365e69dfb297ddfgsdcvf"));
        assert!(!validate_address(
            "5ne7phA48Jrvpn39AtupB8ZkCCAy8gLTfpGihZPuDqen"
        ));
    }

    #[test]
    fn test_encode_address_from_public_key() {
        // Known test vector from ton-contracts doctest
        let pubkey: [u8; 32] = [
            0x7d, 0x6b, 0x1a, 0x21, 0x0b, 0x18, 0x0c, 0xa1, 0x41, 0x26, 0x7c, 0xea, 0x69, 0x56,
            0x8a, 0x6a, 0x4f, 0xf2, 0xd8, 0x49, 0xda, 0x9e, 0x6f, 0x47, 0x6d, 0x04, 0x10, 0x05,
            0xd4, 0x47, 0x6c, 0x6e,
        ];
        let non_bounceable = encode_address_from_public_key(&pubkey, false).unwrap();
        assert_eq!(
            non_bounceable,
            "UQAHgNAYSdWyD3kl2RIl_oSo4lS0ECclh-FDjKETwGtSOZbW"
        );

        let bounceable = encode_address_from_public_key(&pubkey, true).unwrap();
        assert_eq!(
            bounceable,
            "EQAHgNAYSdWyD3kl2RIl_oSo4lS0ECclh-FDjKETwGtSOcsT"
        );
    }

    #[test]
    fn test_encode_address_from_public_key_invalid() {
        assert!(encode_address_from_public_key(&[0u8; 16], true).is_err());
    }
}
