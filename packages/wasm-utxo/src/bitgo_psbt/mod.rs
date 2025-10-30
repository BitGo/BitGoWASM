//! BitGo-specific PSBT parsing that handles multiple network formats
//!
//! This module provides PSBT deserialization that works across different
//! bitcoin-like networks, including those with non-standard transaction formats.

mod sighash;
mod zcash_psbt;

pub use sighash::validate_sighash_type;

use crate::{bitgo_psbt::zcash_psbt::ZcashPsbt, networks::Network};
use miniscript::bitcoin::psbt::Psbt;

#[derive(Debug)]
pub enum DeserializeError {
    /// Standard bitcoin consensus decoding error
    Consensus(miniscript::bitcoin::consensus::encode::Error),
    /// PSBT-specific error
    Psbt(miniscript::bitcoin::psbt::Error),
    /// Network-specific error message
    Network(String),
}

impl std::fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeserializeError::Consensus(e) => write!(f, "{}", e),
            DeserializeError::Psbt(e) => write!(f, "{}", e),
            DeserializeError::Network(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DeserializeError {}

impl From<miniscript::bitcoin::consensus::encode::Error> for DeserializeError {
    fn from(e: miniscript::bitcoin::consensus::encode::Error) -> Self {
        DeserializeError::Consensus(e)
    }
}

impl From<miniscript::bitcoin::psbt::Error> for DeserializeError {
    fn from(e: miniscript::bitcoin::psbt::Error) -> Self {
        DeserializeError::Psbt(e)
    }
}

#[derive(Debug)]
pub enum SerializeError {
    /// Standard bitcoin consensus encoding error
    Consensus(std::io::Error),
    /// Network-specific error message
    Network(String),
}

impl std::fmt::Display for SerializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SerializeError::Consensus(e) => write!(f, "{}", e),
            SerializeError::Network(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for SerializeError {}

impl From<std::io::Error> for SerializeError {
    fn from(e: std::io::Error) -> Self {
        SerializeError::Consensus(e)
    }
}

impl From<DeserializeError> for SerializeError {
    fn from(e: DeserializeError) -> Self {
        match e {
            DeserializeError::Consensus(ce) => {
                // Convert consensus encode error to io error
                SerializeError::Network(format!("Consensus error: {}", ce))
            }
            DeserializeError::Psbt(pe) => SerializeError::Network(format!("PSBT error: {}", pe)),
            DeserializeError::Network(msg) => SerializeError::Network(msg),
        }
    }
}

#[derive(Debug, Clone)]
pub enum BitGoPsbt {
    BitcoinLike(Psbt, Network),
    Zcash(ZcashPsbt, Network),
}

impl BitGoPsbt {
    /// Deserialize a PSBT from bytes, using network-specific logic
    pub fn deserialize(psbt_bytes: &[u8], network: Network) -> Result<BitGoPsbt, DeserializeError> {
        match network {
            Network::Zcash | Network::ZcashTestnet => {
                // Zcash uses overwintered transaction format which is not compatible
                // with standard Bitcoin transaction deserialization
                let zcash_psbt = ZcashPsbt::deserialize(psbt_bytes)?;
                Ok(BitGoPsbt::Zcash(zcash_psbt, network))
            }

            // All other networks use standard Bitcoin transaction format
            Network::Bitcoin
            | Network::BitcoinTestnet3
            | Network::BitcoinTestnet4
            | Network::BitcoinPublicSignet
            | Network::BitcoinBitGoSignet
            | Network::BitcoinCash
            | Network::BitcoinCashTestnet
            | Network::Ecash
            | Network::EcashTestnet
            | Network::BitcoinGold
            | Network::BitcoinGoldTestnet
            | Network::BitcoinSV
            | Network::BitcoinSVTestnet
            | Network::Dash
            | Network::DashTestnet
            | Network::Dogecoin
            | Network::DogecoinTestnet
            | Network::Litecoin
            | Network::LitecoinTestnet => Ok(BitGoPsbt::BitcoinLike(
                Psbt::deserialize(psbt_bytes)?,
                network,
            )),
        }
    }

    /// Serialize the PSBT to bytes, using network-specific logic
    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        match self {
            BitGoPsbt::BitcoinLike(psbt, _network) => Ok(psbt.serialize()),
            BitGoPsbt::Zcash(zcash_psbt, _network) => Ok(zcash_psbt.serialize()?),
        }
    }

    pub fn into_psbt(self) -> Psbt {
        match self {
            BitGoPsbt::BitcoinLike(psbt, _network) => psbt,
            BitGoPsbt::Zcash(zcash_psbt, _network) => zcash_psbt.into_bitcoin_psbt(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_script_wallet::Chain;
    use crate::fixed_script_wallet::{RootWalletKeys, WalletScripts};
    use crate::test_utils::fixtures;
    use base64::engine::{general_purpose::STANDARD as BASE64_STANDARD, Engine};
    use miniscript::bitcoin::bip32::Xpub;
    use miniscript::bitcoin::consensus::Decodable;
    use miniscript::bitcoin::Transaction;
    
    use std::str::FromStr;

    crate::test_all_networks!(test_deserialize_invalid_bytes, network, {
        // Invalid PSBT bytes should fail with either consensus, PSBT, or network error
        let result = BitGoPsbt::deserialize(&[0x00], network);
        assert!(
            matches!(
                result,
                Err(DeserializeError::Consensus(_)
                    | DeserializeError::Psbt(_)
                    | DeserializeError::Network(_))
            ),
            "Expected error for network {:?}, got {:?}",
            network,
            result
        );
    });

    fn test_parse_with_format(format: fixtures::TxFormat, network: Network) {
        let fixture = fixtures::load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            fixtures::SignatureState::Unsigned,
            format,
        )
        .unwrap();
        match fixture.to_bitgo_psbt(network) {
            Ok(_) => {}
            Err(e) => panic!("Failed on network: {:?} with error: {:?}", network, e),
        }
    }

    crate::test_psbt_fixtures!(test_parse_network_mainnet_only, network, {
        test_parse_with_format(fixtures::TxFormat::Psbt, network);
        test_parse_with_format(fixtures::TxFormat::PsbtLite, network);
    });

    #[test]
    fn test_zcash_deserialize_error() {
        // Invalid bytes should return an error (not panic)
        let result = BitGoPsbt::deserialize(&[0x00], Network::Zcash);
        assert!(result.is_err());
    }

    #[test]
    fn test_zcash_testnet_deserialize_error() {
        // Invalid bytes should return an error (not panic)
        let result = BitGoPsbt::deserialize(&[0x00], Network::ZcashTestnet);
        assert!(result.is_err());
    }

    fn test_round_trip_with_format(format: fixtures::TxFormat, network: Network) {
        let fixture = fixtures::load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            fixtures::SignatureState::Unsigned,
            format,
        )
        .unwrap();

        // Deserialize from fixture
        let original_bytes = BASE64_STANDARD
            .decode(&fixture.psbt_base64)
            .expect("Failed to decode base64");
        let psbt =
            BitGoPsbt::deserialize(&original_bytes, network).expect("Failed to deserialize PSBT");

        // Serialize back
        let serialized = psbt.serialize().expect("Failed to serialize PSBT");

        // Deserialize again
        let round_trip =
            BitGoPsbt::deserialize(&serialized, network).expect("Failed to deserialize round-trip");

        // Verify the data matches by comparing the underlying PSBTs
        match (&psbt, &round_trip) {
            (BitGoPsbt::BitcoinLike(psbt1, net1), BitGoPsbt::BitcoinLike(psbt2, net2)) => {
                assert_eq!(net1, net2, "Networks should match");
                assert_eq!(psbt1, psbt2);
            }
            (BitGoPsbt::Zcash(zpsbt1, net1), BitGoPsbt::Zcash(zpsbt2, net2)) => {
                assert_eq!(net1, net2, "Networks should match");
                assert_eq!(zpsbt1, zpsbt2);
            }
            _ => panic!(
                "PSBT type mismatch after round-trip: {:?} vs {:?}",
                psbt, round_trip
            ),
        }
    }

    crate::test_psbt_fixtures!(test_round_trip_mainnet_only, network, {
        test_round_trip_with_format(fixtures::TxFormat::Psbt, network);
        test_round_trip_with_format(fixtures::TxFormat::PsbtLite, network);
    });

    fn parse_derivation_path(path: &str) -> Result<(u32, u32), String> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != 4 {
            return Err(format!("Invalid path length: {}", path));
        }
        let chain = u32::from_str(parts[2]).map_err(|e| e.to_string())?;
        let index = u32::from_str(parts[3]).map_err(|e| e.to_string())?;
        Ok((chain, index))
    }

    fn parse_fixture_paths(
        fixture_input: &fixtures::PsbtInputFixture,
    ) -> Result<(Chain, u32), String> {
        let bip32_path = match fixture_input {
            fixtures::PsbtInputFixture::P2sh(i) => i.bip32_derivation[0].path.to_string(),
            fixtures::PsbtInputFixture::P2shP2pk(_) => {
                // P2shP2pk doesn't have derivation paths in the fixture, use a dummy path
                return Err("P2shP2pk does not use chain-based derivation".to_string());
            }
            fixtures::PsbtInputFixture::P2shP2wsh(i) => i.bip32_derivation[0].path.to_string(),
            fixtures::PsbtInputFixture::P2wsh(i) => i.bip32_derivation[0].path.to_string(),
            fixtures::PsbtInputFixture::P2trLegacy(i) => i.tap_bip32_derivation[0].path.to_string(),
            fixtures::PsbtInputFixture::P2trMusig2ScriptPath(i) => {
                i.tap_bip32_derivation[0].path.to_string()
            }
            fixtures::PsbtInputFixture::P2trMusig2KeyPath(i) => {
                i.tap_bip32_derivation[0].path.to_string()
            }
        };
        let (chain_num, index) = parse_derivation_path(&bip32_path).expect("Failed to parse path");
        let chain = Chain::try_from(chain_num).expect("Invalid chain");
        Ok((chain, index))
    }

    fn find_input_with_script_type(
        fixture: &fixtures::PsbtFixture,
        script_type: fixtures::ScriptType,
    ) -> Result<(usize, &fixtures::PsbtInputFixture), String> {
        let result = fixture
            .psbt_inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| script_type.matches_fixture(input))
            .collect::<Vec<_>>();
        if result.len() != 1 {
            return Err(format!(
                "Expected 1 input with script type {}, got {}",
                script_type.as_str(),
                result.len()
            ));
        }
        Ok(result[0])
    }

    fn get_output_script_from_non_witness_utxo(
        input: &fixtures::P2shInput,
        index: usize,
    ) -> String {
        use miniscript::bitcoin::hashes::hex::FromHex;
        let tx_bytes = Vec::<u8>::from_hex(
            input
                .non_witness_utxo
                .as_ref()
                .expect("expected non-witness utxo for legacy inputs"),
        )
        .expect("Failed to decode hex");
        let prev_tx: Transaction = Decodable::consensus_decode(&mut tx_bytes.as_slice())
            .expect("Failed to decode non-witness utxo");
        let output = &prev_tx.output[index];
        output.script_pubkey.to_hex_string()
    }

    fn test_wallet_script_type(
        script_type: fixtures::ScriptType,
        network: Network,
        tx_format: fixtures::TxFormat,
    ) -> Result<(), String> {
        let fixture = fixtures::load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            fixtures::SignatureState::Fullsigned,
            tx_format,
        )
        .expect("Failed to load fixture");
        let xprvs = fixtures::parse_wallet_keys(&fixture).expect("Failed to parse wallet keys");
        let secp = crate::bitcoin::secp256k1::Secp256k1::new();
        let wallet_keys = RootWalletKeys::new(
            xprvs
                .iter()
                .map(|x| Xpub::from_priv(&secp, x))
                .collect::<Vec<_>>()
                .try_into()
                .expect("Failed to convert to XpubTriple"),
        );

        // Check if the script type is supported by the network
        let output_script_support = network.output_script_support();
        let input_fixture = find_input_with_script_type(&fixture, script_type);
        if !script_type.is_supported_by(&output_script_support) {
            // Script type not supported by network - skip test (no fixture expected)
            assert!(
                input_fixture.is_err(),
                "Expected error for unsupported script type"
            );
            return Ok(());
        }

        let (input_index, input_fixture) = input_fixture.unwrap();

        let (chain, index) =
            parse_fixture_paths(input_fixture).expect("Failed to parse fixture paths");
        let scripts = WalletScripts::from_wallet_keys(
            &wallet_keys,
            chain,
            index,
            &network.output_script_support(),
        )
        .expect("Failed to create wallet scripts");

        // Use the new helper methods for validation
        match (scripts, input_fixture) {
            (WalletScripts::P2sh(scripts), fixtures::PsbtInputFixture::P2sh(fixture_input)) => {
                let vout = fixture.inputs[input_index].index as usize;
                let output_script =
                    if tx_format == fixtures::TxFormat::PsbtLite || network == Network::Zcash {
                        // Zcash only supports PSBT-lite
                        fixture_input
                            .witness_utxo
                            .as_ref()
                            .expect("expected witness utxo for zcash")
                            .script
                            .clone()
                    } else {
                        get_output_script_from_non_witness_utxo(fixture_input, vout)
                    };
                fixture_input
                    .assert_matches_wallet_scripts(&scripts, &output_script, network)
                    .expect("P2sh validation failed");
            }
            (
                WalletScripts::P2shP2wsh(scripts),
                fixtures::PsbtInputFixture::P2shP2wsh(fixture_input),
            ) => {
                fixture_input
                    .assert_matches_wallet_scripts(
                        &scripts,
                        &fixture_input.witness_utxo.script,
                        network,
                    )
                    .expect("P2shP2wsh validation failed");
            }
            (WalletScripts::P2wsh(scripts), fixtures::PsbtInputFixture::P2wsh(fixture_input)) => {
                fixture_input
                    .assert_matches_wallet_scripts(
                        &scripts,
                        &fixture_input.witness_utxo.script,
                        network,
                    )
                    .expect("P2wsh validation failed");
            }
            (
                WalletScripts::P2trLegacy(scripts),
                fixtures::PsbtInputFixture::P2trLegacy(fixture_input),
            ) => {
                fixture_input
                    .assert_matches_wallet_scripts(&scripts, network)
                    .expect("P2trLegacy validation failed");
            }
            (
                WalletScripts::P2trMusig2(scripts),
                fixtures::PsbtInputFixture::P2trMusig2ScriptPath(fixture_input),
            ) => {
                fixture_input
                    .assert_matches_wallet_scripts(&scripts, network)
                    .expect("P2trMusig2ScriptPath validation failed");
            }
            (
                WalletScripts::P2trMusig2(scripts),
                fixtures::PsbtInputFixture::P2trMusig2KeyPath(fixture_input),
            ) => {
                fixture_input
                    .assert_matches_wallet_scripts(&scripts, network)
                    .expect("P2trMusig2KeyPath validation failed");
            }
            (scripts, input_fixture) => {
                return Err(format!(
                    "Mismatched input and scripts: {:?} and {:?}",
                    scripts, input_fixture
                ));
            }
        }

        Ok(())
    }

    crate::test_psbt_fixtures!(test_p2sh_script_generation_from_fixture, network, {
        test_wallet_script_type(
            fixtures::ScriptType::P2sh,
            network,
            fixtures::TxFormat::Psbt,
        )
        .unwrap();
        test_wallet_script_type(
            fixtures::ScriptType::P2sh,
            network,
            fixtures::TxFormat::PsbtLite,
        )
        .unwrap();
    });

    crate::test_psbt_fixtures!(test_p2sh_p2wsh_script_generation_from_fixture, network, {
        test_wallet_script_type(
            fixtures::ScriptType::P2shP2wsh,
            network,
            fixtures::TxFormat::Psbt,
        )
        .unwrap();
        test_wallet_script_type(
            fixtures::ScriptType::P2shP2wsh,
            network,
            fixtures::TxFormat::PsbtLite,
        )
        .unwrap();
    });

    crate::test_psbt_fixtures!(test_p2wsh_script_generation_from_fixture, network, {
        test_wallet_script_type(
            fixtures::ScriptType::P2wsh,
            network,
            fixtures::TxFormat::Psbt,
        )
        .unwrap();
        test_wallet_script_type(
            fixtures::ScriptType::P2wsh,
            network,
            fixtures::TxFormat::PsbtLite,
        )
        .unwrap();
    });

    crate::test_psbt_fixtures!(test_p2tr_script_generation_from_fixture, network, {
        test_wallet_script_type(
            fixtures::ScriptType::P2tr,
            network,
            fixtures::TxFormat::Psbt,
        )
        .unwrap();
        test_wallet_script_type(
            fixtures::ScriptType::P2tr,
            network,
            fixtures::TxFormat::PsbtLite,
        )
        .unwrap();
    });

    crate::test_psbt_fixtures!(
        test_p2tr_musig2_script_path_generation_from_fixture,
        network,
        {
            test_wallet_script_type(
                fixtures::ScriptType::P2trMusig2,
                network,
                fixtures::TxFormat::Psbt,
            )
            .unwrap();
            test_wallet_script_type(
                fixtures::ScriptType::P2trMusig2,
                network,
                fixtures::TxFormat::PsbtLite,
            )
            .unwrap();
        }
    );

    crate::test_psbt_fixtures!(
        test_p2tr_musig2_key_path_spend_script_generation_from_fixture,
        network,
        {
            test_wallet_script_type(
                fixtures::ScriptType::TaprootKeypath,
                network,
                fixtures::TxFormat::Psbt,
            )
            .unwrap();
            test_wallet_script_type(
                fixtures::ScriptType::TaprootKeypath,
                network,
                fixtures::TxFormat::PsbtLite,
            )
            .unwrap();
        }
    );

    crate::test_psbt_fixtures!(test_extract_transaction, network, {
        let fixture = fixtures::load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            fixtures::SignatureState::Fullsigned,
            fixtures::TxFormat::Psbt,
        )
        .expect("Failed to load fixture");
        let psbt = fixture
            .to_bitgo_psbt(network)
            .expect("Failed to convert to BitGo PSBT");
        let fixture_extracted_transaction = fixture
            .extracted_transaction
            .expect("Failed to extract transaction");
        let extracted_transaction = psbt
            .into_psbt()
            .finalize(&crate::bitcoin::secp256k1::Secp256k1::verification_only())
            .expect("Failed to finalize PSBT")
            .extract_tx()
            .expect("Failed to extract transaction");
        let extracted_transaction_hex = hex::encode(serialize(&extracted_transaction));
        assert_eq!(
            extracted_transaction_hex, fixture_extracted_transaction,
            "Extracted transaction should match"
        );
    });

    #[test]
    fn test_serialize_bitcoin_psbt() {
        // Test that Bitcoin-like PSBTs can be serialized
        let fixture = fixtures::load_psbt_fixture_with_network(
            Network::Bitcoin,
            fixtures::SignatureState::Unsigned,
        )
        .unwrap();
        let psbt = fixture
            .to_bitgo_psbt(Network::Bitcoin)
            .expect("Failed to convert to BitGo PSBT");

        // Serialize should succeed
        let serialized = psbt.serialize();
        assert!(serialized.is_ok(), "Serialization should succeed");
    }

    #[test]
    fn test_serialize_zcash_psbt() {
        // Test that Zcash PSBTs can be serialized
        let fixture = fixtures::load_psbt_fixture_with_network(
            Network::Zcash,
            fixtures::SignatureState::Unsigned,
        )
        .unwrap();
        let original_bytes = BASE64_STANDARD
            .decode(&fixture.psbt_base64)
            .expect("Failed to decode base64");
        let psbt = BitGoPsbt::deserialize(&original_bytes, Network::Zcash)
            .expect("Failed to deserialize PSBT");

        // Serialize should succeed
        let serialized = psbt.serialize();
        assert!(serialized.is_ok(), "Serialization should succeed");
    }
}
