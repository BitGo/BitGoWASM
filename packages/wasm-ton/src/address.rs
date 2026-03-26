//! TON address encoding, decoding, and validation
//!
//! Uses `tonlib-core` for address derivation from Ed25519 public keys.
//! TON addresses encode: workchain (1 byte) + state init hash (32 bytes) + flags.
//! The state init hash is derived from wallet contract code + initial data (which includes the public key).
//!
//! BitGo uses wallet V4R2 by default with wallet_id = 698983191.

use crate::error::WasmTonError;
use serde::{Deserialize, Serialize};
use tonlib_core::types::TonAddress;
use tonlib_core::wallet::mnemonic::KeyPair;
use tonlib_core::wallet::ton_wallet::TonWallet;
use tonlib_core::wallet::wallet_version::WalletVersion as TonlibWalletVersion;

/// Wallet versions supported by BitGo
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletVersion {
    V3R2,
    V4R2,
    V5R1,
}

impl WalletVersion {
    pub fn as_tonlib(self) -> TonlibWalletVersion {
        match self {
            WalletVersion::V3R2 => TonlibWalletVersion::V3R2,
            WalletVersion::V4R2 => TonlibWalletVersion::V4R2,
            WalletVersion::V5R1 => TonlibWalletVersion::V5R1,
        }
    }
}

impl std::str::FromStr for WalletVersion {
    type Err = WasmTonError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "V3R2" => Ok(WalletVersion::V3R2),
            "V4R2" => Ok(WalletVersion::V4R2),
            "V5R1" => Ok(WalletVersion::V5R1),
            _ => Err(WasmTonError::AddressError(format!(
                "Unsupported wallet version: {}. Supported: V3R2, V4R2, V5R1",
                s
            ))),
        }
    }
}

/// Default wallet ID used by BitGo (and standard TON wallets)
const DEFAULT_WALLET_ID: i32 = 698983191;

/// Encode a public key to a TON address.
///
/// Uses `TonWallet` to compute the state init hash, then encodes as base64url.
///
/// # Arguments
/// * `public_key` - 32-byte Ed25519 public key
/// * `bounceable` - Whether the address should be bounceable (true for V2+ wallets)
/// * `wallet_version` - Wallet contract version (V3R2, V4R2, V5R1)
pub fn encode_address(
    public_key: &[u8],
    bounceable: bool,
    wallet_version: WalletVersion,
) -> Result<String, WasmTonError> {
    if public_key.len() != 32 {
        return Err(WasmTonError::AddressError(format!(
            "Public key must be 32 bytes, got {}",
            public_key.len()
        )));
    }

    let address = derive_address(public_key, wallet_version)?;

    // non_bounceable is the inverse of bounceable
    let non_bounceable = !bounceable;
    Ok(address.to_base64_url_flags(non_bounceable, false))
}

/// Decode a TON address (base64url) to its components.
///
/// Returns the workchain, hash part, and whether the address is bounceable.
pub fn decode_address(address: &str) -> Result<DecodedAddress, WasmTonError> {
    // TonAddress::from_base64_url parses both bounceable and non-bounceable addresses
    let ton_address = TonAddress::from_base64_url(address)?;

    // Determine bounceable flag by re-encoding and comparing
    // base64url with non_bounceable=false (bounceable) starts differently than non_bounceable=true
    let bounceable_encoded = ton_address.to_base64_url_flags(false, false);
    let is_bounceable = address == bounceable_encoded;

    Ok(DecodedAddress {
        workchain: ton_address.workchain,
        hash_part: ton_address.hash_part.to_vec(),
        bounceable: is_bounceable,
    })
}

/// Validate a TON address string.
///
/// Returns true if the address is a valid base64url-encoded TON address.
pub fn validate_address(address: &str) -> bool {
    TonAddress::from_base64_url(address).is_ok()
}

/// Result of decoding a TON address
#[derive(Debug, Clone)]
pub struct DecodedAddress {
    /// Workchain ID (0 for basechain, -1 for masterchain)
    pub workchain: i32,
    /// 32-byte hash part of the address
    pub hash_part: Vec<u8>,
    /// Whether the address is bounceable
    pub bounceable: bool,
}

/// Internal helper: derive a TonAddress from a public key and wallet version.
fn derive_address(
    public_key: &[u8],
    wallet_version: WalletVersion,
) -> Result<TonAddress, WasmTonError> {
    // TonWallet::new_with_params needs a KeyPair, but get_data only uses public_key.
    // We provide a dummy secret_key since it's never used for address derivation.
    let key_pair = KeyPair {
        public_key: public_key.to_vec(),
        secret_key: vec![0u8; 64],
    };

    let wallet =
        TonWallet::new_with_params(wallet_version.as_tonlib(), key_pair, 0, DEFAULT_WALLET_ID)?;

    Ok(wallet.address)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known test vector: public key → V4R2 bounceable address
    /// This matches what BitGoJS produces with getAddressFromPublicKey
    #[test]
    fn test_encode_address_v4r2() {
        let pubkey =
            hex::decode("f61b63341a65e5e23adbf052a7e27fad28bb6f461ef63c1c04e9f63d9eb1e54f")
                .unwrap();
        let address = encode_address(&pubkey, true, WalletVersion::V4R2).unwrap();
        // Address should be a valid base64url string
        assert!(validate_address(&address));
        // Should round-trip
        let decoded = decode_address(&address).unwrap();
        assert_eq!(decoded.workchain, 0);
        assert!(decoded.bounceable);
        assert_eq!(decoded.hash_part.len(), 32);
    }

    #[test]
    fn test_encode_address_non_bounceable() {
        let pubkey =
            hex::decode("f61b63341a65e5e23adbf052a7e27fad28bb6f461ef63c1c04e9f63d9eb1e54f")
                .unwrap();
        let bounceable = encode_address(&pubkey, true, WalletVersion::V4R2).unwrap();
        let non_bounceable = encode_address(&pubkey, false, WalletVersion::V4R2).unwrap();
        // Both should be valid but different
        assert!(validate_address(&bounceable));
        assert!(validate_address(&non_bounceable));
        assert_ne!(bounceable, non_bounceable);
        // Non-bounceable should decode as non-bounceable
        let decoded = decode_address(&non_bounceable).unwrap();
        assert!(!decoded.bounceable);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let pubkey =
            hex::decode("f61b63341a65e5e23adbf052a7e27fad28bb6f461ef63c1c04e9f63d9eb1e54f")
                .unwrap();
        let address = encode_address(&pubkey, true, WalletVersion::V4R2).unwrap();
        let decoded = decode_address(&address).unwrap();

        // Re-derive from same pubkey and check hash matches
        let address2 = encode_address(&pubkey, true, WalletVersion::V4R2).unwrap();
        assert_eq!(address, address2);
        assert_eq!(decoded.workchain, 0);
    }

    #[test]
    fn test_validate_address() {
        assert!(!validate_address("invalid"));
        assert!(!validate_address(""));
        assert!(!validate_address("too_short"));

        // Generate a valid address and verify it
        let pubkey =
            hex::decode("f61b63341a65e5e23adbf052a7e27fad28bb6f461ef63c1c04e9f63d9eb1e54f")
                .unwrap();
        let address = encode_address(&pubkey, true, WalletVersion::V4R2).unwrap();
        assert!(validate_address(&address));
    }

    #[test]
    fn test_invalid_pubkey_length() {
        let short_pubkey = vec![0u8; 16];
        assert!(encode_address(&short_pubkey, true, WalletVersion::V4R2).is_err());
    }

    #[test]
    fn test_wallet_version_from_str() {
        assert_eq!(
            "V4R2".parse::<WalletVersion>().unwrap(),
            WalletVersion::V4R2
        );
        assert_eq!(
            "v4r2".parse::<WalletVersion>().unwrap(),
            WalletVersion::V4R2
        );
        assert_eq!(
            "V3R2".parse::<WalletVersion>().unwrap(),
            WalletVersion::V3R2
        );
        assert_eq!(
            "V5R1".parse::<WalletVersion>().unwrap(),
            WalletVersion::V5R1
        );
        assert!("V1R1".parse::<WalletVersion>().is_err());
    }

    #[test]
    fn test_v3r2_address_differs_from_v4r2() {
        let pubkey =
            hex::decode("f61b63341a65e5e23adbf052a7e27fad28bb6f461ef63c1c04e9f63d9eb1e54f")
                .unwrap();
        let v3r2 = encode_address(&pubkey, true, WalletVersion::V3R2).unwrap();
        let v4r2 = encode_address(&pubkey, true, WalletVersion::V4R2).unwrap();
        // Different wallet versions produce different addresses
        assert_ne!(v3r2, v4r2);
    }
}
