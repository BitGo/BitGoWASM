//! Bitcoin address encoding and decoding for multiple networks and formats.
//!
//! This module provides address format support for various cryptocurrency networks including:
//! - Bitcoin and Bitcoin-like coins (BTC, LTC, BCH, BSV, BTG, DASH, DOGE)
//! - eCash
//! - Zcash
//!
//! # Supported Address Formats
//!
//! - **Base58Check**: Traditional P2PKH and P2SH addresses
//! - **Bech32/Bech32m**: Native SegWit addresses (P2WPKH, P2WSH, P2TR)
//! - **Cashaddr**: Bitcoin Cash and eCash-specific format
//!
//! # Implementation Status
//!
//! ✅ **Working**:
//! - Base58Check encoding/decoding for all networks
//! - Bech32/Bech32m for witness programs (P2WPKH, P2WSH, P2TR)
//! - Cashaddr encoding/decoding for Bitcoin Cash and eCash (fully compliant with spec)
//! - Zcash multi-byte version support
//! - P2PKH, P2SH, P2WPKH, P2WSH, P2TR script types
//!
//! # Examples
//!
//! ```rust,ignore
//! use wasm_utxo::{BITCOIN, from_output_script, to_output_script};
//!
//! // Decode a Bitcoin address
//! let script = to_output_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", &BITCOIN)?;
//!
//! // Encode a script to address
//! let address = from_output_script(&script, &BITCOIN)?;
//! ```

mod base58check;
mod bech32;
pub mod cashaddr;
pub mod networks;
pub mod utxolib_compat;

pub use base58check::Base58CheckCodec;
pub use bech32::Bech32Codec;
pub use cashaddr::CashAddrCodec;
pub use networks::{
    from_output_script_with_coin, from_output_script_with_network, to_output_script_with_coin,
    to_output_script_with_network,
};

use crate::bitcoin::{Script, ScriptBuf};
use std::fmt;

#[derive(Debug)]
pub enum AddressError {
    InvalidScript(String),
    InvalidAddress(String),
    UnsupportedScriptType(String),
    Base58Error(String),
    Bech32Error(String),
    CashaddrError(String),
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::InvalidScript(msg) => write!(f, "Invalid script: {}", msg),
            AddressError::InvalidAddress(msg) => write!(f, "Invalid address: {}", msg),
            AddressError::UnsupportedScriptType(msg) => {
                write!(f, "Unsupported script type: {}", msg)
            }
            AddressError::Base58Error(msg) => write!(f, "Base58 error: {}", msg),
            AddressError::Bech32Error(msg) => write!(f, "Bech32 error: {}", msg),
            AddressError::CashaddrError(msg) => write!(f, "Cashaddr error: {}", msg),
        }
    }
}

impl std::error::Error for AddressError {}

type Result<T> = std::result::Result<T, AddressError>;

/// Trait for address encoding and decoding
pub trait AddressCodec {
    fn encode(&self, script: &Script) -> Result<String>;
    fn decode(&self, address: &str) -> Result<ScriptBuf>;
}

// Network-specific codec parameters (values from src/chainparams.cpp in various coin implementations):
//
// Base58CheckCodec::new(pubkey_hash_version, script_hash_version)
//   - pubkey_hash_version: base58Prefixes[PUBKEY_ADDRESS] for P2PKH addresses
//   - script_hash_version: base58Prefixes[SCRIPT_ADDRESS] for P2SH addresses
//   - Note: Zcash uses 2-byte versions (0x1cb8, 0x1cbd, etc.)
//
// Bech32Codec::new(hrp)
//   - hrp: Human-readable part for bech32/bech32m addresses (e.g., "bc", "tb", "ltc")
//
// CashAddrCodec::new(prefix, pubkey_type, script_type)
//   - prefix: Network prefix (e.g., "bitcoincash", "ecash")
//   - pubkey_type: Type byte for P2PKH (typically 0x00)
//   - script_type: Type byte for P2SH (typically 0x08)

// Bitcoin variants (Base58Check + Bech32)
// https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp
// https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp
pub const BITCOIN: Base58CheckCodec = Base58CheckCodec::new(0x00, 0x05);
pub const BITCOIN_BECH32: Bech32Codec = Bech32Codec::new("bc");

pub const TESTNET: Base58CheckCodec = Base58CheckCodec::new(0x6f, 0xc4);
pub const TESTNET_BECH32: Bech32Codec = Bech32Codec::new("tb");

// Bitcoin Cash (Base58Check)
// https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/master/src/validation.cpp
// https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/master/src/chainparams.cpp
pub const BITCOIN_CASH: Base58CheckCodec = Base58CheckCodec::new(0x00, 0x05);
pub const BITCOIN_CASH_TESTNET: Base58CheckCodec = Base58CheckCodec::new(0x6f, 0xc4);

// Bitcoin Cash (Cashaddr)
// https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
pub const BITCOIN_CASH_CASHADDR: CashAddrCodec = CashAddrCodec::new("bitcoincash", 0x00, 0x08);
pub const BITCOIN_CASH_TESTNET_CASHADDR: CashAddrCodec = CashAddrCodec::new("bchtest", 0x00, 0x08);

// eCash (Base58Check)
// https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/validation.cpp
// https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/chainparams.cpp
pub const ECASH: Base58CheckCodec = Base58CheckCodec::new(0x00, 0x05);
pub const ECASH_TEST: Base58CheckCodec = Base58CheckCodec::new(0x6f, 0xc4);

// eCash (Cashaddr)
pub const ECASH_CASHADDR: CashAddrCodec = CashAddrCodec::new("ecash", 0x00, 0x08);
pub const ECASH_TEST_CASHADDR: CashAddrCodec = CashAddrCodec::new("ectest", 0x00, 0x08);

// Bitcoin Gold
// https://github.com/BTCGPU/BTCGPU/blob/master/src/validation.cpp
// https://github.com/BTCGPU/BTCGPU/blob/master/src/chainparams.cpp
pub const BITCOIN_GOLD: Base58CheckCodec = Base58CheckCodec::new(0x26, 0x17);
pub const BITCOIN_GOLD_BECH32: Bech32Codec = Bech32Codec::new("btg");

pub const BITCOIN_GOLD_TESTNET: Base58CheckCodec = Base58CheckCodec::new(0x6f, 0xc4);
pub const BITCOIN_GOLD_TESTNET_BECH32: Bech32Codec = Bech32Codec::new("tbtg");

// Bitcoin SV
// https://github.com/bitcoin-sv/bitcoin-sv/blob/master/src/validation.cpp
// https://github.com/bitcoin-sv/bitcoin-sv/blob/master/src/chainparams.cpp
pub const BITCOIN_SV: Base58CheckCodec = Base58CheckCodec::new(0x00, 0x05);
pub const BITCOIN_SV_TESTNET: Base58CheckCodec = Base58CheckCodec::new(0x6f, 0xc4);

// Litecoin
// https://github.com/litecoin-project/litecoin/blob/master/src/validation.cpp
// https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp
pub const LITECOIN: Base58CheckCodec = Base58CheckCodec::new(0x30, 0x32);
pub const LITECOIN_BECH32: Bech32Codec = Bech32Codec::new("ltc");

pub const LITECOIN_TEST: Base58CheckCodec = Base58CheckCodec::new(0x6f, 0x3a);
pub const LITECOIN_TEST_BECH32: Bech32Codec = Bech32Codec::new("tltc");

// Dogecoin
// https://github.com/dogecoin/dogecoin/blob/master/src/validation.cpp
// https://github.com/dogecoin/dogecoin/blob/master/src/chainparams.cpp
// Mainnet bip32 does not match dogecoin core (see BG-53241)
pub const DOGECOIN: Base58CheckCodec = Base58CheckCodec::new(0x1e, 0x16);
pub const DOGECOIN_TEST: Base58CheckCodec = Base58CheckCodec::new(0x71, 0xc4);

// Dash
// https://github.com/dashpay/dash/blob/master/src/validation.cpp
// https://github.com/dashpay/dash/blob/master/src/chainparams.cpp
pub const DASH: Base58CheckCodec = Base58CheckCodec::new(0x4c, 0x10);
pub const DASH_TEST: Base58CheckCodec = Base58CheckCodec::new(0x8c, 0x13);

// Zcash (uses 2-byte version prefixes)
// https://github.com/zcash/zcash/blob/master/src/validation.cpp
// https://github.com/zcash/zcash/blob/master/src/chainparams.cpp
pub const ZCASH: Base58CheckCodec = Base58CheckCodec::new(0x1cb8, 0x1cbd);
pub const ZCASH_TEST: Base58CheckCodec = Base58CheckCodec::new(0x1d25, 0x1cba);

/// Convert output script to address string (convenience wrapper)
pub fn from_output_script(script: &Script, codec: &dyn AddressCodec) -> Result<String> {
    codec.encode(script)
}

/// Try multiple codecs to decode an address
pub fn to_output_script_try_codecs(
    address: &str,
    codecs: &[&dyn AddressCodec],
) -> Result<ScriptBuf> {
    for &codec in codecs {
        if let Ok(script) = codec.decode(address) {
            return Ok(script);
        }
    }

    Err(AddressError::InvalidAddress(format!(
        "Could not decode address with any provided codec: {}",
        address
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::hashes::Hash;
    use crate::bitcoin::PubkeyHash;

    /// Convert address string to output script (convenience wrapper)
    pub fn to_output_script(address: &str, codec: &dyn AddressCodec) -> Result<ScriptBuf> {
        codec.decode(address)
    }

    #[test]
    fn test_base58_roundtrip() {
        let hash = hex::decode("1e231c7f9b3415daaa53ee5a7e12e120f00ec212").unwrap();
        let pubkey_hash = PubkeyHash::from_byte_array(hash.try_into().unwrap());
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);

        let encoded = from_output_script(&script, &BITCOIN).unwrap();
        let decoded_script = to_output_script(&encoded, &BITCOIN).unwrap();

        assert_eq!(script, decoded_script);
    }

    #[test]
    fn test_zcash_base58() {
        // Zcash uses 2-byte version prefixes
        let hash = [0; 20];
        let pubkey_hash = PubkeyHash::from_byte_array(hash);
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);

        let encoded = from_output_script(&script, &ZCASH).unwrap();
        let decoded_script = to_output_script(&encoded, &ZCASH).unwrap();

        assert_eq!(script, decoded_script);
    }

    #[test]
    fn test_cashaddr_roundtrip() {
        // Test that our cashaddr implementation is internally consistent (encode/decode roundtrip)
        let hash = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let pubkey_hash = PubkeyHash::from_byte_array(hash.try_into().unwrap());
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);

        let encoded = from_output_script(&script, &BITCOIN_CASH_CASHADDR).unwrap();
        eprintln!("Encoded cashaddr: {}", encoded);

        // Ensure we can decode what we encoded
        let decoded_script = to_output_script(&encoded, &BITCOIN_CASH_CASHADDR).unwrap();
        assert_eq!(script, decoded_script);
    }

    #[test]
    fn test_cashaddr_encode_decode() {
        let hash = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let pubkey_hash = PubkeyHash::from_byte_array(hash.try_into().unwrap());
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);

        let encoded = from_output_script(&script, &BITCOIN_CASH_CASHADDR).unwrap();
        // Correct checksum according to the official spec
        assert_eq!(
            encoded,
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2"
        );

        let decoded_script = to_output_script(&encoded, &BITCOIN_CASH_CASHADDR).unwrap();
        assert_eq!(script, decoded_script);
    }

    #[test]
    fn test_cashaddr_no_prefix() {
        let hash = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let pubkey_hash = PubkeyHash::from_byte_array(hash.try_into().unwrap());
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);
        let encoded = "qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";

        let decoded_script = to_output_script(encoded, &BITCOIN_CASH_CASHADDR).unwrap();
        assert_eq!(script, decoded_script);
    }

    #[test]
    fn test_cashaddr_uppercase() {
        let encoded = "BITCOINCASH:QR6M7J9NJLDWWZLG9V7V53UNLR4JKMX6EYLEP8EKG2";
        let _ = to_output_script(encoded, &BITCOIN_CASH_CASHADDR).unwrap();
    }

    #[test]
    fn test_cashaddr_mixed_case_rejected() {
        let encoded = "bitcoincash:Qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        assert!(to_output_script(encoded, &BITCOIN_CASH_CASHADDR).is_err());
    }

    // Helper to encode Bitcoin addresses (tries both base58 and bech32)
    fn bitcoin_encode(script: &[u8]) -> Result<String> {
        let script_obj = Script::from_bytes(script);
        if script_obj.is_p2pkh() || script_obj.is_p2sh() {
            from_output_script(script_obj, &BITCOIN)
        } else if script_obj.is_p2wpkh()
            || script_obj.is_p2wsh()
            || script_obj.is_p2tr()
            || bech32::is_p2mr(script_obj)
        {
            from_output_script(script_obj, &BITCOIN_BECH32)
        } else {
            Err(AddressError::UnsupportedScriptType(format!(
                "Unknown script type, length: {}",
                script.len()
            )))
        }
    }

    // Helper to decode Bitcoin addresses (tries both base58 and bech32)
    fn bitcoin_decode(address: &str) -> Result<ScriptBuf> {
        to_output_script_try_codecs(address, &[&BITCOIN, &BITCOIN_BECH32])
    }

    // Helper for testnet
    fn testnet_encode(script: &[u8]) -> Result<String> {
        let script_obj = Script::from_bytes(script);
        if script_obj.is_p2pkh() || script_obj.is_p2sh() {
            from_output_script(script_obj, &TESTNET)
        } else if script_obj.is_p2wpkh()
            || script_obj.is_p2wsh()
            || script_obj.is_p2tr()
            || bech32::is_p2mr(script_obj)
        {
            from_output_script(script_obj, &TESTNET_BECH32)
        } else {
            Err(AddressError::UnsupportedScriptType(format!(
                "Unknown script type, length: {}",
                script.len()
            )))
        }
    }

    // Helper for Litecoin
    fn litecoin_encode(script: &[u8]) -> Result<String> {
        let script_obj = Script::from_bytes(script);
        if script_obj.is_p2pkh() || script_obj.is_p2sh() {
            from_output_script(script_obj, &LITECOIN)
        } else if script_obj.is_p2wpkh()
            || script_obj.is_p2wsh()
            || script_obj.is_p2tr()
            || bech32::is_p2mr(script_obj)
        {
            from_output_script(script_obj, &LITECOIN_BECH32)
        } else {
            Err(AddressError::UnsupportedScriptType(format!(
                "Unknown script type, length: {}",
                script.len()
            )))
        }
    }

    fn load_fixture(network: &str) -> Vec<(String, String, String)> {
        let fixture_path = format!("test/fixtures/address/{}.json", network);
        let content = std::fs::read_to_string(&fixture_path)
            .unwrap_or_else(|_| panic!("Failed to load fixture: {}", fixture_path));

        let parsed: Vec<serde_json::Value> = serde_json::from_str(&content)
            .unwrap_or_else(|_| panic!("Failed to parse fixture: {}", fixture_path));

        parsed
            .iter()
            .map(|item| {
                let arr = item.as_array().unwrap();
                (
                    arr[0].as_str().unwrap().to_string(),
                    arr[1].as_str().unwrap().to_string(),
                    arr[2].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn test_bitcoin_addresses() {
        let vectors = load_fixture("bitcoin");

        for (script_type, script_hex, expected_address) in vectors {
            let script = hex::decode(&script_hex).unwrap();
            let address = bitcoin_encode(&script).unwrap();
            assert_eq!(
                address, expected_address,
                "Failed for script type: {}",
                script_type
            );

            // Round trip
            let decoded_script = bitcoin_decode(&address).unwrap();
            assert_eq!(
                hex::encode(decoded_script.as_bytes()),
                script_hex,
                "Round trip failed for: {}",
                script_type
            );
        }
    }

    #[test]
    fn test_testnet_addresses() {
        let vectors = load_fixture("testnet");

        for (script_type, script_hex, expected_address) in vectors {
            let script = hex::decode(&script_hex).unwrap();
            let address = testnet_encode(&script).unwrap();
            assert_eq!(
                address, expected_address,
                "Failed for script type: {}",
                script_type
            );
        }
    }

    #[test]
    fn test_bitcoincash_cashaddr() {
        let vectors = load_fixture("bitcoincash-cashaddr");

        for (_script_type, script_hex, expected_address) in vectors {
            let script = hex::decode(&script_hex).unwrap();
            let script_obj = Script::from_bytes(&script);
            let address = from_output_script(script_obj, &BITCOIN_CASH_CASHADDR).unwrap();
            assert_eq!(address, expected_address);

            // Round trip
            let decoded_script = to_output_script(&address, &BITCOIN_CASH_CASHADDR).unwrap();
            assert_eq!(hex::encode(decoded_script.as_bytes()), script_hex);
        }
    }

    #[test]
    fn test_ecash_cashaddr() {
        let vectors = load_fixture("ecash-cashaddr");

        for (_script_type, script_hex, expected_address) in vectors {
            let script = hex::decode(&script_hex).unwrap();
            let script_obj = Script::from_bytes(&script);
            let address = from_output_script(script_obj, &ECASH_CASHADDR).unwrap();
            assert_eq!(address, expected_address);
        }
    }

    #[test]
    fn test_litecoin_addresses() {
        let vectors = load_fixture("litecoin");

        for (_script_type, script_hex, expected_address) in vectors {
            let script = hex::decode(&script_hex).unwrap();
            let address = litecoin_encode(&script).unwrap();
            assert_eq!(address, expected_address);
        }
    }

    #[test]
    fn test_try_codecs() {
        let codecs: &[&dyn AddressCodec] = &[&BITCOIN_CASH, &BITCOIN_CASH_CASHADDR];

        // Test with cashaddr address
        let address = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        let _script = to_output_script_try_codecs(address, codecs).unwrap();
        // Successfully decoded with one of the codecs
    }

    /// Maps fixture filename to appropriate codec(s) for encoding
    fn get_codecs_for_fixture(filename: &str) -> Vec<&'static dyn AddressCodec> {
        match filename {
            "bitcoin.json" => vec![&BITCOIN as &dyn AddressCodec, &BITCOIN_BECH32],
            "testnet.json" => vec![&TESTNET, &TESTNET_BECH32],
            "bitcoinPublicSignet.json" => vec![&TESTNET, &TESTNET_BECH32],
            "bitcoincash.json" => vec![&BITCOIN_CASH],
            "bitcoincash-cashaddr.json" => vec![&BITCOIN_CASH_CASHADDR],
            "bitcoincashTestnet.json" => vec![&BITCOIN_CASH_TESTNET],
            "bitcoincashTestnet-cashaddr.json" => vec![&BITCOIN_CASH_TESTNET_CASHADDR],
            "bitcoingold.json" => vec![&BITCOIN_GOLD, &BITCOIN_GOLD_BECH32],
            "bitcoingoldTestnet.json" => vec![&BITCOIN_GOLD_TESTNET, &BITCOIN_GOLD_TESTNET_BECH32],
            "bitcoinsv.json" => vec![&BITCOIN_SV],
            "bitcoinsvTestnet.json" => vec![&BITCOIN_SV_TESTNET],
            "dash.json" => vec![&DASH],
            "dashTest.json" => vec![&DASH_TEST],
            "dogecoin.json" => vec![&DOGECOIN],
            "dogecoinTest.json" => vec![&DOGECOIN_TEST],
            "ecash.json" => vec![&ECASH],
            "ecash-cashaddr.json" => vec![&ECASH_CASHADDR],
            "ecashTest.json" => vec![&ECASH_TEST],
            "ecashTest-cashaddr.json" => vec![&ECASH_TEST_CASHADDR],
            "ecashTestnet.json" => vec![&ECASH_TEST],
            "ecashTestnet-cashaddr.json" => vec![&ECASH_TEST_CASHADDR],
            "litecoin.json" => vec![&LITECOIN, &LITECOIN_BECH32],
            "litecoinTest.json" => vec![&LITECOIN_TEST, &LITECOIN_TEST_BECH32],
            "zcash.json" => vec![&ZCASH],
            "zcashTest.json" => vec![&ZCASH_TEST],
            _ => panic!("Unknown fixture file: {}", filename),
        }
    }

    /// Helper to encode an address using the appropriate codec based on script type
    fn encode_with_codecs(script: &[u8], codecs: &[&dyn AddressCodec]) -> Result<String> {
        let script_obj = Script::from_bytes(script);

        // For networks with both base58 and bech32, choose based on script type
        let codec = if script_obj.is_p2pkh() || script_obj.is_p2sh() {
            codecs[0]
        } else if script_obj.is_p2wpkh()
            || script_obj.is_p2wsh()
            || script_obj.is_p2tr()
            || bech32::is_p2mr(script_obj)
        {
            // Use bech32 codec if available (index 1), otherwise fall back to base58
            if codecs.len() > 1 {
                codecs[1]
            } else {
                codecs[0]
            }
        } else {
            return Err(AddressError::UnsupportedScriptType(format!(
                "Unknown script type, length: {}",
                script.len()
            )));
        };

        codec.encode(script_obj)
    }

    #[test]
    fn test_all_fixtures() {
        let fixtures_dir = "test/fixtures/address";

        // Read all JSON files in the fixtures directory
        let entries = std::fs::read_dir(fixtures_dir)
            .unwrap_or_else(|_| panic!("Failed to read fixtures directory: {}", fixtures_dir));

        let mut fixture_files: Vec<_> = entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension()? == "json" {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();

        // Sort for deterministic test order
        fixture_files.sort();

        assert!(
            !fixture_files.is_empty(),
            "No fixture files found in {}",
            fixtures_dir
        );

        for fixture_path in fixture_files {
            let filename = fixture_path.file_name().unwrap().to_str().unwrap();
            eprintln!("\nTesting fixture: {}", filename);

            // Get the appropriate codecs for this fixture
            let codecs = get_codecs_for_fixture(filename);

            // Load and parse the fixture
            let content = std::fs::read_to_string(&fixture_path)
                .unwrap_or_else(|_| panic!("Failed to read fixture: {:?}", fixture_path));

            let parsed: Vec<serde_json::Value> = serde_json::from_str(&content)
                .unwrap_or_else(|_| panic!("Failed to parse fixture: {:?}", fixture_path));

            // Test each vector in the fixture
            for (idx, item) in parsed.iter().enumerate() {
                let arr = item.as_array().unwrap();
                let script_type = arr[0].as_str().unwrap();
                let script_hex = arr[1].as_str().unwrap();
                let expected_address = arr[2].as_str().unwrap();

                let script = hex::decode(script_hex).unwrap_or_else(|_| {
                    panic!(
                        "Failed to decode script hex in {}[{}]: {}",
                        filename, idx, script_hex
                    )
                });

                // Test encoding
                let encoded_address = encode_with_codecs(&script, &codecs).unwrap_or_else(|e| {
                    panic!(
                        "Failed to encode {}[{}] ({}): {:?}",
                        filename, idx, script_type, e
                    )
                });

                assert_eq!(
                    encoded_address, expected_address,
                    "Encoding mismatch in {}[{}] ({})",
                    filename, idx, script_type
                );

                // Test decoding (round trip)
                let decoded_script = to_output_script_try_codecs(&encoded_address, &codecs)
                    .unwrap_or_else(|e| {
                        panic!(
                            "Failed to decode {}[{}] ({}): {:?}",
                            filename, idx, script_type, e
                        )
                    });

                assert_eq!(
                    hex::encode(decoded_script.as_bytes()),
                    script_hex,
                    "Decoding mismatch in {}[{}] ({})",
                    filename,
                    idx,
                    script_type
                );
            }

            eprintln!("✓ {} passed ({} vectors)", filename, parsed.len());
        }
    }
}
