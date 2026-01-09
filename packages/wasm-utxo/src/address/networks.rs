//! Network-aware address encoding and decoding.
//!
//! This module bridges the Network enum with address codecs, providing
//! convenient functions to encode/decode addresses using network identifiers.

use super::{
    from_output_script, to_output_script_try_codecs, AddressCodec, AddressError, Result, ScriptBuf,
    BITCOIN, BITCOIN_BECH32, BITCOIN_CASH, BITCOIN_CASH_CASHADDR, BITCOIN_CASH_TESTNET,
    BITCOIN_CASH_TESTNET_CASHADDR, BITCOIN_GOLD, BITCOIN_GOLD_BECH32, BITCOIN_GOLD_TESTNET,
    BITCOIN_GOLD_TESTNET_BECH32, BITCOIN_SV, BITCOIN_SV_TESTNET, DASH, DASH_TEST, DOGECOIN,
    DOGECOIN_TEST, ECASH, ECASH_CASHADDR, ECASH_TEST, ECASH_TEST_CASHADDR, LITECOIN,
    LITECOIN_BECH32, LITECOIN_TEST, LITECOIN_TEST_BECH32, TESTNET, TESTNET_BECH32, ZCASH,
    ZCASH_TEST,
};
use crate::bitcoin::Script;
use crate::fixed_script_wallet::wallet_scripts::OutputScriptType;
use crate::networks::Network;
use miniscript::bitcoin::WitnessVersion;

/// Get codecs for decoding addresses for a given network.
/// Returns multiple codecs to try in order (Base58Check, Bech32, CashAddr, etc.)
fn get_decode_codecs(network: Network) -> Vec<&'static dyn AddressCodec> {
    match network {
        Network::Bitcoin => vec![&BITCOIN, &BITCOIN_BECH32],
        Network::BitcoinTestnet3
        | Network::BitcoinTestnet4
        | Network::BitcoinPublicSignet
        | Network::BitcoinBitGoSignet => {
            vec![&TESTNET, &TESTNET_BECH32]
        }
        Network::BitcoinCash => vec![&BITCOIN_CASH, &BITCOIN_CASH_CASHADDR],
        Network::BitcoinCashTestnet => vec![&BITCOIN_CASH_TESTNET, &BITCOIN_CASH_TESTNET_CASHADDR],
        Network::Ecash => vec![&ECASH, &ECASH_CASHADDR],
        Network::EcashTestnet => vec![&ECASH_TEST, &ECASH_TEST_CASHADDR],
        Network::BitcoinGold => vec![&BITCOIN_GOLD, &BITCOIN_GOLD_BECH32],
        Network::BitcoinGoldTestnet => vec![&BITCOIN_GOLD_TESTNET, &BITCOIN_GOLD_TESTNET_BECH32],
        Network::BitcoinSV => vec![&BITCOIN_SV],
        Network::BitcoinSVTestnet => vec![&BITCOIN_SV_TESTNET],
        Network::Dash => vec![&DASH],
        Network::DashTestnet => vec![&DASH_TEST],
        Network::Dogecoin => vec![&DOGECOIN],
        Network::DogecoinTestnet => vec![&DOGECOIN_TEST],
        Network::Litecoin => vec![&LITECOIN, &LITECOIN_BECH32],
        Network::LitecoinTestnet => vec![&LITECOIN_TEST, &LITECOIN_TEST_BECH32],
        Network::Zcash => vec![&ZCASH],
        Network::ZcashTestnet => vec![&ZCASH_TEST],
    }
}

/// Address encoding format selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFormat {
    /// Use default address encoding
    /// In most cases, there is one unambiguous address encoding for a given network and script type.
    /// For Bitcoin Cash, Base58Check is the default.
    Default,
    /// For Bitcoin Cash and eCash, there is a choice of address formats: base58check or cashaddr.
    Cashaddr,
}

impl AddressFormat {
    /// Parse an AddressFormat from an optional string.
    /// Returns Default if None or if the string is empty.
    pub fn from_optional_str(s: Option<&str>) -> Result<Self> {
        match s {
            None | Some("") | Some("default") => Ok(Self::Default),
            Some("cashaddr") => Ok(Self::Cashaddr),
            Some(other) => Err(AddressError::InvalidAddress(format!(
                "Unknown address format: {}. Valid formats are: 'default', 'cashaddr'",
                other
            ))),
        }
    }
}

pub struct OutputScriptSupport {
    pub segwit: bool,
    pub taproot: bool,
}

impl OutputScriptSupport {
    pub(crate) fn assert_legacy(&self) -> Result<()> {
        // all coins support legacy scripts
        Ok(())
    }

    pub(crate) fn assert_segwit(&self) -> Result<()> {
        if !self.segwit {
            return Err(AddressError::UnsupportedScriptType(
                "Network does not support segwit".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn assert_taproot(&self) -> Result<()> {
        if !self.taproot {
            return Err(AddressError::UnsupportedScriptType(
                "Network does not support taproot".to_string(),
            ));
        }
        Ok(())
    }

    pub fn assert_support(&self, script: &Script) -> Result<()> {
        match script.witness_version() {
            None => {
                // all coins support legacy scripts
            }
            Some(WitnessVersion::V0) => {
                self.assert_segwit()?;
            }
            Some(WitnessVersion::V1) => {
                self.assert_taproot()?;
            }
            _ => {
                return Err(AddressError::UnsupportedScriptType(
                    "Unsupported witness version".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Check if the network supports a given fixed-script wallet script type
    pub fn supports_script_type(&self, script_type: OutputScriptType) -> bool {
        match script_type {
            OutputScriptType::P2sh => true, // all networks support legacy scripts
            OutputScriptType::P2shP2wsh | OutputScriptType::P2wsh => self.segwit,
            OutputScriptType::P2trLegacy | OutputScriptType::P2trMusig2 => self.taproot,
        }
    }
}

impl Network {
    pub fn output_script_support(&self) -> OutputScriptSupport {
        // SegWit support:
        // Bitcoin: SegWit activated August 24, 2017 at block 481,824
        // - Consensus rules: https://github.com/bitcoin/bitcoin/blob/v28.0/src/consensus/tx_verify.cpp
        // - Witness validation: https://github.com/bitcoin/bitcoin/blob/v28.0/src/script/interpreter.cpp
        // - BIP141 (SegWit): https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
        // - BIP143 (Signature verification): https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
        // - BIP144 (P2P changes): https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
        //
        // Litecoin: SegWit activated May 10, 2017 at block 1,201,536
        // - Consensus implementation: https://github.com/litecoin-project/litecoin/blob/v0.21.4/src/consensus/tx_verify.cpp
        // - Script interpreter: https://github.com/litecoin-project/litecoin/blob/v0.21.4/src/script/interpreter.cpp
        //
        // Bitcoin Gold: Launched with SegWit support in October 2017
        // - Implementation: https://github.com/BTCGPU/BTCGPU/blob/v0.17.3/src/consensus/tx_verify.cpp
        let segwit = matches!(
            self.mainnet(),
            Network::Bitcoin | Network::Litecoin | Network::BitcoinGold
        );

        // Taproot support:
        // Bitcoin: Taproot activated November 14, 2021 at block 709,632
        // - Taproot validation: https://github.com/bitcoin/bitcoin/blob/v28.0/src/script/interpreter.cpp
        //   (see VerifyWitnessProgram, WITNESS_V1_TAPROOT)
        // - Schnorr signature verification: https://github.com/bitcoin/bitcoin/blob/v28.0/src/pubkey.cpp
        //   (see XOnlyPubKey::VerifySchnorr)
        // - Deployment params: https://github.com/bitcoin/bitcoin/blob/v28.0/src/kernel/chainparams.cpp
        //   (see Consensus::DeploymentPos::DEPLOYMENT_TAPROOT)
        // - BIP340 (Schnorr signatures): https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
        // - BIP341 (Taproot): https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
        // - BIP342 (Tapscript): https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki
        //
        // Litecoin: has apparent taproot support, but we have not enabled it in this library yet.
        // - https://github.com/litecoin-project/litecoin/blob/v0.21.4/src/chainparams.cpp#L89-L92
        // - https://github.com/litecoin-project/litecoin/blob/v0.21.4/src/script/interpreter.h#L129-L131
        let taproot = segwit && matches!(self.mainnet(), Network::Bitcoin);

        OutputScriptSupport { segwit, taproot }
    }
}

/// Get codec for encoding an address for a given network and script type.
fn get_encode_codec(
    network: Network,
    script: &Script,
    format: AddressFormat,
) -> Result<&'static dyn AddressCodec> {
    network.output_script_support().assert_support(script)?;

    let is_witness = script.is_p2wpkh() || script.is_p2wsh() || script.is_p2tr();
    let is_legacy = script.is_p2pkh() || script.is_p2sh();

    if !is_witness && !is_legacy {
        return Err(AddressError::UnsupportedScriptType(
            "Script is not a standard address type (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)".to_string(),
        ));
    }

    // Handle Cashaddr format request
    if matches!(format, AddressFormat::Cashaddr) {
        return match network {
            Network::BitcoinCash => Ok(&BITCOIN_CASH_CASHADDR),
            Network::BitcoinCashTestnet => Ok(&BITCOIN_CASH_TESTNET_CASHADDR),
            Network::Ecash => Ok(&ECASH_CASHADDR),
            Network::EcashTestnet => Ok(&ECASH_TEST_CASHADDR),
            _ => Err(AddressError::UnsupportedScriptType(
                format!("Cashaddr format is only supported for Bitcoin Cash and eCash networks, not for {:?}", network),
            )),
        };
    }

    match network {
        Network::Bitcoin => {
            if is_witness {
                Ok(&BITCOIN_BECH32)
            } else {
                Ok(&BITCOIN)
            }
        }
        Network::BitcoinTestnet3
        | Network::BitcoinTestnet4
        | Network::BitcoinPublicSignet
        | Network::BitcoinBitGoSignet => {
            if is_witness {
                Ok(&TESTNET_BECH32)
            } else {
                Ok(&TESTNET)
            }
        }
        Network::BitcoinCash => Ok(&BITCOIN_CASH),
        Network::BitcoinCashTestnet => Ok(&BITCOIN_CASH_TESTNET),
        Network::Ecash => Ok(&ECASH),
        Network::EcashTestnet => Ok(&ECASH_TEST),
        Network::BitcoinGold => {
            if is_witness {
                Ok(&BITCOIN_GOLD_BECH32)
            } else {
                Ok(&BITCOIN_GOLD)
            }
        }
        Network::BitcoinGoldTestnet => {
            if is_witness {
                Ok(&BITCOIN_GOLD_TESTNET_BECH32)
            } else {
                Ok(&BITCOIN_GOLD_TESTNET)
            }
        }
        Network::BitcoinSV => Ok(&BITCOIN_SV),
        Network::BitcoinSVTestnet => Ok(&BITCOIN_SV_TESTNET),
        Network::Dash => Ok(&DASH),
        Network::DashTestnet => Ok(&DASH_TEST),
        Network::Dogecoin => Ok(&DOGECOIN),
        Network::DogecoinTestnet => Ok(&DOGECOIN_TEST),
        Network::Litecoin => {
            if is_witness {
                Ok(&LITECOIN_BECH32)
            } else {
                Ok(&LITECOIN)
            }
        }
        Network::LitecoinTestnet => {
            if is_witness {
                Ok(&LITECOIN_TEST_BECH32)
            } else {
                Ok(&LITECOIN_TEST)
            }
        }
        Network::Zcash => Ok(&ZCASH),
        Network::ZcashTestnet => Ok(&ZCASH_TEST),
    }
}

/// Convert an address string to an output script using a Network.
/// Tries multiple address formats for the given network (Base58, Bech32, CashAddr, etc.)
pub fn to_output_script_with_network(address: &str, network: Network) -> Result<ScriptBuf> {
    let codecs = get_decode_codecs(network);
    to_output_script_try_codecs(address, &codecs)
}

/// Convert an output script to an address string using a Network.
/// Automatically selects the appropriate format based on the script type.
pub fn from_output_script_with_network(script: &Script, network: Network) -> Result<String> {
    from_output_script_with_network_and_format(script, network, AddressFormat::Default)
}

/// Convert an output script to an address string using a Network and format.
pub fn from_output_script_with_network_and_format(
    script: &Script,
    network: Network,
    format: AddressFormat,
) -> Result<String> {
    let codec = get_encode_codec(network, script, format)?;
    from_output_script(script, codec)
}

/// Convert an address string to an output script using a BitGo coin name.
/// The coin name is first converted to a Network using `Network::from_coin_name()`.
pub fn to_output_script_with_coin(address: &str, coin: &str) -> Result<ScriptBuf> {
    let network = Network::from_coin_name(coin)
        .ok_or_else(|| AddressError::InvalidAddress(format!("Unknown coin: {}", coin)))?;
    to_output_script_with_network(address, network)
}

/// Convert an output script to an address string using a BitGo coin name.
/// The coin name is first converted to a Network using `Network::from_coin_name()`.
pub fn from_output_script_with_coin(script: &Script, coin: &str) -> Result<String> {
    from_output_script_with_coin_and_format(script, coin, AddressFormat::Default)
}

/// Convert an output script to an address string using a BitGo coin name and format.
pub fn from_output_script_with_coin_and_format(
    script: &Script,
    coin: &str,
    format: AddressFormat,
) -> Result<String> {
    let network = Network::from_coin_name(coin)
        .ok_or_else(|| AddressError::InvalidAddress(format!("Unknown coin: {}", coin)))?;
    from_output_script_with_network_and_format(script, network, format)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::hashes::Hash;
    use crate::bitcoin::{PubkeyHash, ScriptBuf};

    #[test]
    fn test_to_output_script_with_network() {
        // Bitcoin mainnet P2PKH
        let addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let script = to_output_script_with_network(addr, Network::Bitcoin).unwrap();
        assert!(script.is_p2pkh());

        // Bitcoin mainnet bech32
        let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let script = to_output_script_with_network(addr, Network::Bitcoin).unwrap();
        assert!(script.is_p2wpkh());

        // Bitcoin testnet
        let addr = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";
        let script = to_output_script_with_network(addr, Network::BitcoinTestnet3).unwrap();
        assert!(script.is_p2pkh());
    }

    #[test]
    fn test_from_output_script_with_network() {
        // Create a P2PKH script
        let hash = hex::decode("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").unwrap();
        let pubkey_hash = PubkeyHash::from_byte_array(hash.try_into().unwrap());
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);

        // Encode for Bitcoin mainnet
        let addr = from_output_script_with_network(&script, Network::Bitcoin).unwrap();
        assert_eq!(addr, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");

        // Encode for Bitcoin testnet
        let addr = from_output_script_with_network(&script, Network::BitcoinTestnet3).unwrap();
        assert_eq!(addr, "mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt");
    }

    #[test]
    fn test_to_output_script_with_coin() {
        // BTC
        let addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let script = to_output_script_with_coin(addr, "btc").unwrap();
        assert!(script.is_p2pkh());

        // tbtc
        let addr = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";
        let script = to_output_script_with_coin(addr, "tbtc").unwrap();
        assert!(script.is_p2pkh());
    }

    #[test]
    fn test_from_output_script_with_coin() {
        let hash = hex::decode("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").unwrap();
        let pubkey_hash = PubkeyHash::from_byte_array(hash.try_into().unwrap());
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);

        // btc
        let addr = from_output_script_with_coin(&script, "btc").unwrap();
        assert_eq!(addr, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");

        // tbtc
        let addr = from_output_script_with_coin(&script, "tbtc").unwrap();
        assert_eq!(addr, "mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt");
    }

    #[test]
    fn test_invalid_coin() {
        let addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let result = to_output_script_with_coin(addr, "invalid_coin");
        assert!(result.is_err());
    }

    #[test]
    fn test_base58_bitcoin_cash() {
        // Bitcoin Cash should prefer base58 format for encoding
        let hash = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let pubkey_hash = PubkeyHash::from_byte_array(hash.try_into().unwrap());
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);

        let addr = from_output_script_with_network(&script, Network::BitcoinCash).unwrap();
        assert_eq!(addr, "1PQPheJQSauxRPTxzNMUco1XmoCyPoEJCp");

        // Should be able to decode it back
        let decoded = to_output_script_with_network(&addr, Network::BitcoinCash).unwrap();
        assert_eq!(script, decoded);
    }

    #[test]
    fn test_witness_addresses() {
        // Create a P2WPKH script
        let hash = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let wpkh = crate::bitcoin::WPubkeyHash::from_byte_array(hash.try_into().unwrap());
        let script = ScriptBuf::new_p2wpkh(&wpkh);

        // Should encode to bech32 for Bitcoin
        let addr = from_output_script_with_network(&script, Network::Bitcoin).unwrap();
        assert!(addr.starts_with("bc1"));

        // Should encode to bech32 for Litecoin
        let addr = from_output_script_with_network(&script, Network::Litecoin).unwrap();
        assert!(addr.starts_with("ltc1"));
    }

    #[test]
    fn test_cashaddr_format() {
        // Test that Cashaddr format works for Bitcoin Cash
        let hash = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let pubkey_hash = PubkeyHash::from_byte_array(hash.try_into().unwrap());
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);

        // Cashaddr format for Bitcoin Cash mainnet
        let codec =
            get_encode_codec(Network::BitcoinCash, &script, AddressFormat::Cashaddr).unwrap();
        let addr = from_output_script(&script, codec).unwrap();
        assert!(addr.starts_with("bitcoincash:"));

        // Cashaddr format for Bitcoin Cash testnet
        let codec = get_encode_codec(
            Network::BitcoinCashTestnet,
            &script,
            AddressFormat::Cashaddr,
        )
        .unwrap();
        let addr = from_output_script(&script, codec).unwrap();
        assert!(
            addr.starts_with("bchtest:") || addr.starts_with("bitcoincash:"),
            "Expected bchtest: or bitcoincash: prefix but got: {}",
            addr
        );

        // Cashaddr format for eCash mainnet
        let codec = get_encode_codec(Network::Ecash, &script, AddressFormat::Cashaddr).unwrap();
        let addr = from_output_script(&script, codec).unwrap();
        assert!(addr.starts_with("ecash:"));

        // Cashaddr format for eCash testnet
        let codec =
            get_encode_codec(Network::EcashTestnet, &script, AddressFormat::Cashaddr).unwrap();
        let addr = from_output_script(&script, codec).unwrap();
        assert!(
            addr.starts_with("ectest:") || addr.starts_with("ecash:"),
            "Expected ectest: or ecash: prefix but got: {}",
            addr
        );
    }

    #[test]
    fn test_cashaddr_format_error_for_non_bch_ecash() {
        // Test that Cashaddr format returns error for non-BCH/eCash networks
        let hash = hex::decode("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").unwrap();
        let pubkey_hash = PubkeyHash::from_byte_array(hash.try_into().unwrap());
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);

        // Should error for Bitcoin
        let result = get_encode_codec(Network::Bitcoin, &script, AddressFormat::Cashaddr);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Cashaddr format is only supported"));
        }

        // Should error for Litecoin
        let result = get_encode_codec(Network::Litecoin, &script, AddressFormat::Cashaddr);
        assert!(result.is_err());

        // Should error for Dogecoin
        let result = get_encode_codec(Network::Dogecoin, &script, AddressFormat::Cashaddr);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_output_script_with_coin_and_format() {
        // Test with Bitcoin Cash using default format (base58)
        let hash = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let pubkey_hash = PubkeyHash::from_byte_array(hash.try_into().unwrap());
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);

        // Default format for bch should be base58
        let addr = from_output_script_with_coin_and_format(&script, "bch", AddressFormat::Default)
            .unwrap();
        assert_eq!(addr, "1PQPheJQSauxRPTxzNMUco1XmoCyPoEJCp");

        // Cashaddr format for bch should be cashaddr
        let addr = from_output_script_with_coin_and_format(&script, "bch", AddressFormat::Cashaddr)
            .unwrap();
        assert!(addr.starts_with("bitcoincash:"));

        // Default format for tbch should be base58
        let addr = from_output_script_with_coin_and_format(&script, "tbch", AddressFormat::Default)
            .unwrap();
        assert!(!addr.starts_with("bchtest:"));

        // Cashaddr format for tbch should be cashaddr
        let addr =
            from_output_script_with_coin_and_format(&script, "tbch", AddressFormat::Cashaddr)
                .unwrap();
        assert!(addr.starts_with("bchtest:") || addr.starts_with("bitcoincash:"));

        // Cashaddr format should error for non-BCH/eCash coins
        let result =
            from_output_script_with_coin_and_format(&script, "btc", AddressFormat::Cashaddr);
        assert!(result.is_err());
    }

    #[test]
    fn test_address_format_from_optional_str() {
        // Test valid formats
        assert!(matches!(
            AddressFormat::from_optional_str(None),
            Ok(AddressFormat::Default)
        ));
        assert!(matches!(
            AddressFormat::from_optional_str(Some("")),
            Ok(AddressFormat::Default)
        ));
        assert!(matches!(
            AddressFormat::from_optional_str(Some("default")),
            Ok(AddressFormat::Default)
        ));
        assert!(matches!(
            AddressFormat::from_optional_str(Some("cashaddr")),
            Ok(AddressFormat::Cashaddr)
        ));

        // Test invalid format
        let result = AddressFormat::from_optional_str(Some("invalid"));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unknown address format"));
    }

    #[test]
    fn test_output_script_support_assert_legacy() {
        // Legacy should always succeed regardless of support flags
        let support_none = OutputScriptSupport {
            segwit: false,
            taproot: false,
        };
        assert!(support_none.assert_legacy().is_ok());

        let support_all = OutputScriptSupport {
            segwit: true,
            taproot: true,
        };
        assert!(support_all.assert_legacy().is_ok());
    }

    #[test]
    fn test_output_script_support_assert_segwit() {
        // Should succeed when segwit is supported
        let support_segwit = OutputScriptSupport {
            segwit: true,
            taproot: false,
        };
        assert!(support_segwit.assert_segwit().is_ok());

        // Should fail when segwit is not supported
        let no_support = OutputScriptSupport {
            segwit: false,
            taproot: false,
        };
        let result = no_support.assert_segwit();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support segwit"));
    }

    #[test]
    fn test_output_script_support_assert_taproot() {
        // Should succeed when taproot is supported
        let support_taproot = OutputScriptSupport {
            segwit: true,
            taproot: true,
        };
        assert!(support_taproot.assert_taproot().is_ok());

        // Should fail when taproot is not supported
        let no_support = OutputScriptSupport {
            segwit: true,
            taproot: false,
        };
        let result = no_support.assert_taproot();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support taproot"));
    }

    #[test]
    fn test_output_script_support_assert_support_legacy() {
        // Test with legacy P2PKH script
        let hash = hex::decode("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").unwrap();
        let pubkey_hash = PubkeyHash::from_byte_array(hash.try_into().unwrap());
        let p2pkh_script = ScriptBuf::new_p2pkh(&pubkey_hash);

        // Legacy scripts should work even without segwit/taproot support
        let no_support = OutputScriptSupport {
            segwit: false,
            taproot: false,
        };
        assert!(no_support.assert_support(&p2pkh_script).is_ok());

        // Test with legacy P2SH script
        let hash2 = hex::decode("89abcdef89abcdef89abcdef89abcdef89abcdef").unwrap();
        let script_hash = crate::bitcoin::ScriptHash::from_byte_array(hash2.try_into().unwrap());
        let p2sh_script = ScriptBuf::new_p2sh(&script_hash);
        assert!(no_support.assert_support(&p2sh_script).is_ok());
    }

    #[test]
    fn test_output_script_support_assert_support_segwit() {
        // Test with P2WPKH script (witness v0)
        let hash = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let wpkh = crate::bitcoin::WPubkeyHash::from_byte_array(hash.try_into().unwrap());
        let p2wpkh_script = ScriptBuf::new_p2wpkh(&wpkh);

        // Should succeed with segwit support
        let support_segwit = OutputScriptSupport {
            segwit: true,
            taproot: false,
        };
        assert!(support_segwit.assert_support(&p2wpkh_script).is_ok());

        // Should fail without segwit support
        let no_support = OutputScriptSupport {
            segwit: false,
            taproot: false,
        };
        let result = no_support.assert_support(&p2wpkh_script);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support segwit"));

        // Test with P2WSH script (witness v0)
        let wsh = crate::bitcoin::WScriptHash::from_byte_array(
            hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let p2wsh_script = ScriptBuf::new_p2wsh(&wsh);
        assert!(support_segwit.assert_support(&p2wsh_script).is_ok());
        assert!(no_support.assert_support(&p2wsh_script).is_err());
    }

    #[test]
    fn test_output_script_support_assert_support_taproot() {
        // Test with P2TR script (witness v1)
        use crate::bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};

        let secp = Secp256k1::verification_only();
        // Use a fixed x-only public key for testing
        let xonly_pk = XOnlyPublicKey::from_slice(
            &hex::decode("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115")
                .unwrap(),
        )
        .unwrap();
        let p2tr_script = ScriptBuf::new_p2tr(&secp, xonly_pk, None);

        // Should succeed with taproot support
        let support_taproot = OutputScriptSupport {
            segwit: true,
            taproot: true,
        };
        assert!(support_taproot.assert_support(&p2tr_script).is_ok());

        // Should fail without taproot support (but with segwit)
        let no_taproot = OutputScriptSupport {
            segwit: true,
            taproot: false,
        };
        let result = no_taproot.assert_support(&p2tr_script);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support taproot"));

        // Should also fail without segwit or taproot
        let no_support = OutputScriptSupport {
            segwit: false,
            taproot: false,
        };
        let result = no_support.assert_support(&p2tr_script);
        assert!(result.is_err());
    }

    #[test]
    fn test_output_script_support_network_specific() {
        // Test Bitcoin - should support segwit and taproot
        let btc_support = Network::Bitcoin.output_script_support();
        assert!(btc_support.segwit);
        assert!(btc_support.taproot);

        // Test Bitcoin testnet - should support segwit and taproot
        let tbtc_support = Network::BitcoinTestnet3.output_script_support();
        assert!(tbtc_support.segwit);
        assert!(tbtc_support.taproot);

        // Test Litecoin - should support segwit but not taproot
        let ltc_support = Network::Litecoin.output_script_support();
        assert!(ltc_support.segwit);
        assert!(!ltc_support.taproot);

        // Test Bitcoin Gold - should support segwit but not taproot
        let btg_support = Network::BitcoinGold.output_script_support();
        assert!(btg_support.segwit);
        assert!(!btg_support.taproot);

        // Test Dogecoin - should not support segwit or taproot
        let doge_support = Network::Dogecoin.output_script_support();
        assert!(!doge_support.segwit);
        assert!(!doge_support.taproot);

        // Test Bitcoin Cash - should not support segwit or taproot
        let bch_support = Network::BitcoinCash.output_script_support();
        assert!(!bch_support.segwit);
        assert!(!bch_support.taproot);
    }

    #[test]
    fn test_get_encode_codec_enforces_script_support() {
        // Test that get_encode_codec enforces script support via assert_support

        // P2WPKH on Bitcoin should work
        let hash = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let wpkh = crate::bitcoin::WPubkeyHash::from_byte_array(hash.try_into().unwrap());
        let p2wpkh_script = ScriptBuf::new_p2wpkh(&wpkh);
        assert!(get_encode_codec(Network::Bitcoin, &p2wpkh_script, AddressFormat::Default).is_ok());

        // P2WPKH on Bitcoin Cash should fail (no segwit support)
        let result = get_encode_codec(Network::BitcoinCash, &p2wpkh_script, AddressFormat::Default);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Network does not support segwit"));
        }

        // P2TR on Bitcoin should work
        use crate::bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
        let secp = Secp256k1::verification_only();
        let xonly_pk = XOnlyPublicKey::from_slice(
            &hex::decode("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115")
                .unwrap(),
        )
        .unwrap();
        let p2tr_script = ScriptBuf::new_p2tr(&secp, xonly_pk, None);
        assert!(get_encode_codec(Network::Bitcoin, &p2tr_script, AddressFormat::Default).is_ok());

        // P2TR on Litecoin should fail (no taproot support)
        let result = get_encode_codec(Network::Litecoin, &p2tr_script, AddressFormat::Default);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Network does not support taproot"));
        }
    }
}
