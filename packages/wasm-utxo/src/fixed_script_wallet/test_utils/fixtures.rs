//! Fixture parsing utilities for fixed script wallet tests
//!
//! This module provides utilities for parsing JSON fixture files containing PSBT test data.
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use wasm_miniscript::fixed_script_wallet::test_utils::fixtures::*;
//!
//! // Load a fixture by network and signature state
//! let fixture = load_psbt_fixture("bitcoin", SignatureState::Fullsigned)
//!     .expect("Failed to load fixture");
//!
//! // Parse the PSBT from base64
//! let psbt = decode_psbt_from_fixture(&fixture)
//!     .expect("Failed to decode PSBT");
//!
//! // Parse wallet keys (xprv)
//! let xprvs = fixture.get_wallet_xprvs()
//!     .expect("Failed to parse wallet keys");
//!
//! // Access fixture data
//! assert_eq!(fixture.wallet_keys.len(), 3);
//! assert_eq!(fixture.inputs.len(), 7);
//! assert_eq!(fixture.psbt_inputs.len(), 7);
//! assert_eq!(fixture.outputs.len(), 5);
//! assert_eq!(fixture.psbt_outputs.len(), 5);
//!
//! // Check input types
//! match &fixture.psbt_inputs[0] {
//!     PsbtInputFixture::P2sh(input) => {
//!         println!("P2SH input with {} derivations", input.bip32_derivation.len());
//!     }
//!     PsbtInputFixture::P2trLegacy(input) => {
//!         println!("P2TR input with {} tap leaf scripts", input.tap_leaf_script.len());
//!     }
//!     _ => {}
//! }
//! ```

use std::str::FromStr;

use crate::{
    bitcoin::bip32::Xpriv, bitgo_psbt::p2tr_musig2_input, fixed_script_wallet::RootWalletKeys,
};
use miniscript::bitcoin::bip32::Xpub;
use serde::{Deserialize, Serialize};

use crate::Network;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XprvTriple([Xpriv; 3]);

impl XprvTriple {
    pub fn new(xprvs: [Xpriv; 3]) -> Self {
        Self(xprvs)
    }

    pub fn from_strings(strings: Vec<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let xprvs = strings
            .iter()
            .map(|s| Xpriv::from_str(s).map_err(|e| Box::new(e) as Box<dyn std::error::Error>))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(
            xprvs.try_into().expect("Expected exactly 3 xprvs"),
        ))
    }

    pub fn user_key(&self) -> &Xpriv {
        &self.0[0]
    }

    pub fn backup_key(&self) -> &Xpriv {
        &self.0[1]
    }

    pub fn bitgo_key(&self) -> &Xpriv {
        &self.0[2]
    }

    pub fn to_root_wallet_keys(&self) -> RootWalletKeys {
        let secp = crate::bitcoin::secp256k1::Secp256k1::new();
        RootWalletKeys::new(self.0.map(|x| Xpub::from_priv(&secp, &x)))
    }
}

// Basic helper types (no dependencies on other types in this file)

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnknownKeyVal {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TxInput {
    pub hash: String,
    pub index: u32,
    pub sequence: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TxOutput {
    pub script: String,
    pub value: String,
    pub address: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessUtxo {
    pub script: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bip32Derivation {
    pub pubkey: String,
    pub path: String,
    pub master_fingerprint: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PartialSig {
    pub pubkey: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TapLeafScript {
    pub control_block: String,
    pub script: String,
    pub leaf_version: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TapBip32Derivation {
    pub leaf_hashes: Vec<String>,
    pub pubkey: String,
    pub path: String,
    pub master_fingerprint: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TapScriptSig {
    pub pubkey: String,
    pub signature: String,
    pub leaf_hash: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TapTreeLeaf {
    pub script: String,
    pub leaf_version: u8,
    pub depth: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TapTree {
    pub leaves: Vec<TapTreeLeaf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Musig2Participants {
    pub tap_output_key: String,
    pub tap_internal_key: String,
    pub participant_pub_keys: Vec<String>,
}

impl Musig2Participants {
    /// Validates that the parsed Musig2Participants matches this fixture
    pub fn assert_matches_parsed(
        &self,
        parsed: &p2tr_musig2_input::Musig2Participants,
    ) -> Result<(), String> {
        // Compare tap_output_key
        let parsed_output_key_hex = hex::encode(parsed.tap_output_key.serialize());
        assert_hex_eq(
            &parsed_output_key_hex,
            &self.tap_output_key,
            "Tap output key",
        )?;

        // Compare tap_internal_key
        let parsed_internal_key_hex = hex::encode(parsed.tap_internal_key.serialize());
        assert_hex_eq(
            &parsed_internal_key_hex,
            &self.tap_internal_key,
            "Tap internal key",
        )?;

        // Compare participant pub keys
        if parsed.participant_pub_keys.len() != self.participant_pub_keys.len() {
            return Err(format!(
                "Participant pub keys count mismatch: expected {}, got {}",
                self.participant_pub_keys.len(),
                parsed.participant_pub_keys.len()
            ));
        }

        for (i, parsed_key) in parsed.participant_pub_keys.iter().enumerate() {
            let parsed_key_hex = hex::encode(parsed_key.to_bytes());
            assert_hex_eq(
                &parsed_key_hex,
                &self.participant_pub_keys[i],
                &format!("Participant pub key {}", i),
            )?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Musig2Nonce {
    pub participant_pub_key: String,
    pub tap_output_key: String,
    pub pub_nonce: String,
}

impl Musig2Nonce {
    /// Validates that the parsed Musig2PubNonce matches this fixture
    pub fn assert_matches_parsed(
        &self,
        parsed: &p2tr_musig2_input::Musig2PubNonce,
    ) -> Result<(), String> {
        // Compare participant pub key
        let parsed_participant_key_hex = hex::encode(parsed.participant_pub_key.to_bytes());
        assert_hex_eq(
            &parsed_participant_key_hex,
            &self.participant_pub_key,
            "Participant pub key",
        )?;

        // Compare tap_output_key
        let parsed_output_key_hex = hex::encode(parsed.tap_output_key.serialize());
        assert_hex_eq(
            &parsed_output_key_hex,
            &self.tap_output_key,
            "Tap output key",
        )?;

        // Compare pub_nonce
        let parsed_nonce_hex = hex::encode(parsed.pub_nonce.serialize());
        assert_hex_eq(&parsed_nonce_hex, &self.pub_nonce, "Public nonce")?;

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Musig2PartialSig {
    pub participant_pub_key: String,
    pub tap_output_key: String,
    pub partial_sig: String,
}

impl Musig2PartialSig {
    /// Validates that the parsed Musig2PartialSig matches this fixture
    pub fn assert_matches_parsed(
        &self,
        parsed: &p2tr_musig2_input::Musig2PartialSig,
    ) -> Result<(), String> {
        // Compare participant pub key
        let parsed_participant_key_hex = hex::encode(parsed.participant_pub_key.to_bytes());
        assert_hex_eq(
            &parsed_participant_key_hex,
            &self.participant_pub_key,
            "Participant pub key",
        )?;

        // Compare tap_output_key
        let parsed_output_key_hex = hex::encode(parsed.tap_output_key.serialize());
        assert_hex_eq(
            &parsed_output_key_hex,
            &self.tap_output_key,
            "Tap output key",
        )?;

        // Compare partial_sig
        let parsed_sig_hex = hex::encode(&parsed.partial_sig);
        assert_hex_eq(&parsed_sig_hex, &self.partial_sig, "Partial signature")?;

        Ok(())
    }
}

// Input type structs (depend on helper types above)

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2shInput {
    pub unknown_key_vals: Option<Vec<UnknownKeyVal>>,
    /// Absent for PSBT-LITE format
    pub non_witness_utxo: Option<String>,
    /// Present for PSBT-LITE format
    pub witness_utxo: Option<WitnessUtxo>,
    pub sighash_type: u32,
    pub bip32_derivation: Vec<Bip32Derivation>,
    pub redeem_script: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partial_sig: Vec<PartialSig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2shP2wshInput {
    pub unknown_key_vals: Option<Vec<UnknownKeyVal>>,
    pub witness_utxo: WitnessUtxo,
    pub sighash_type: u32,
    pub bip32_derivation: Vec<Bip32Derivation>,
    pub witness_script: String,
    pub redeem_script: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partial_sig: Vec<PartialSig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2wshInput {
    pub unknown_key_vals: Option<Vec<UnknownKeyVal>>,
    pub witness_utxo: WitnessUtxo,
    pub sighash_type: u32,
    pub bip32_derivation: Vec<Bip32Derivation>,
    pub witness_script: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partial_sig: Vec<PartialSig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2trScriptPathInput {
    pub unknown_key_vals: Option<Vec<UnknownKeyVal>>,
    pub witness_utxo: WitnessUtxo,
    pub sighash_type: u32,
    pub tap_leaf_script: Vec<TapLeafScript>,
    pub tap_bip32_derivation: Vec<TapBip32Derivation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tap_script_sig: Vec<TapScriptSig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2trMusig2KeyPathInput {
    pub unknown_key_vals: Option<Vec<UnknownKeyVal>>,
    pub witness_utxo: WitnessUtxo,
    pub sighash_type: u32,
    pub tap_internal_key: String,
    pub tap_merkle_root: String,
    pub tap_bip32_derivation: Vec<TapBip32Derivation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub musig2_participants: Option<Musig2Participants>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub musig2_nonces: Vec<Musig2Nonce>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub musig2_partial_sigs: Vec<Musig2PartialSig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2shP2pkInput {
    pub unknown_key_vals: Option<Vec<UnknownKeyVal>>,
    pub redeem_script: String,
    /// Skipped for PSBT-LITE format
    pub non_witness_utxo: Option<String>,
    /// Present for PSBT-LITE format
    pub witness_utxo: Option<WitnessUtxo>,
    pub sighash_type: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partial_sig: Vec<PartialSig>,
}

// Input enum (depends on input type structs)

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum PsbtInputFixture {
    #[serde(rename = "p2sh")]
    P2sh(P2shInput),
    #[serde(rename = "p2shP2wsh")]
    P2shP2wsh(P2shP2wshInput),
    #[serde(rename = "p2wsh")]
    P2wsh(P2wshInput),
    #[serde(rename = "p2tr")]
    P2trLegacy(P2trScriptPathInput),
    #[serde(rename = "p2trMusig2")]
    P2trMusig2ScriptPath(P2trScriptPathInput),
    #[serde(rename = "taprootKeyPathSpend")]
    P2trMusig2KeyPath(P2trMusig2KeyPathInput),
    #[serde(rename = "p2shP2pk")]
    P2shP2pk(P2shP2pkInput),
}

impl PsbtInputFixture {
    /// Get partial signatures from PSBT input fixtures that support them.
    /// Returns None for input types that don't use ECDSA partial signatures (e.g., Taproot).
    pub fn partial_sigs(&self) -> Option<&Vec<PartialSig>> {
        match self {
            PsbtInputFixture::P2sh(fixture) => Some(&fixture.partial_sig),
            PsbtInputFixture::P2shP2wsh(fixture) => Some(&fixture.partial_sig),
            PsbtInputFixture::P2wsh(fixture) => Some(&fixture.partial_sig),
            PsbtInputFixture::P2shP2pk(fixture) => Some(&fixture.partial_sig),
            PsbtInputFixture::P2trLegacy(_)
            | PsbtInputFixture::P2trMusig2ScriptPath(_)
            | PsbtInputFixture::P2trMusig2KeyPath(_) => None,
        }
    }
}

// Finalized input type structs (depend on helper types above)

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2shFinalInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_key_vals: Option<Vec<UnknownKeyVal>>,
    pub final_script_sig: String,
    /// Present for non-PSBT-LITE format (legacy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub non_witness_utxo: Option<String>,
    /// Present for PSBT-LITE format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_utxo: Option<WitnessUtxo>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2shP2wshFinalInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_key_vals: Option<Vec<UnknownKeyVal>>,
    pub witness_utxo: WitnessUtxo,
    pub final_script_sig: String,
    pub final_script_witness: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2wshFinalInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_key_vals: Option<Vec<UnknownKeyVal>>,
    pub witness_utxo: WitnessUtxo,
    pub final_script_witness: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2trScriptPathFinalInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_key_vals: Option<Vec<UnknownKeyVal>>,
    pub witness_utxo: WitnessUtxo,
    pub final_script_witness: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2trMusig2KeyPathFinalInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_key_vals: Option<Vec<UnknownKeyVal>>,
    pub witness_utxo: WitnessUtxo,
    pub final_script_witness: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2shP2pkFinalInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_key_vals: Option<Vec<UnknownKeyVal>>,
    pub final_script_sig: String,
    /// Present for non-PSBT-LITE format (legacy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub non_witness_utxo: Option<String>,
    /// Present for PSBT-LITE format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_utxo: Option<WitnessUtxo>,
}

// Final input enum (depends on final input type structs)

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum PsbtFinalInputFixture {
    #[serde(rename = "p2sh")]
    P2sh(P2shFinalInput),
    #[serde(rename = "p2shP2wsh")]
    P2shP2wsh(P2shP2wshFinalInput),
    #[serde(rename = "p2wsh")]
    P2wsh(P2wshFinalInput),
    #[serde(rename = "p2tr")]
    P2trLegacy(P2trScriptPathFinalInput),
    #[serde(rename = "p2trMusig2")]
    P2trMusig2ScriptPath(P2trScriptPathFinalInput),
    #[serde(rename = "taprootKeyPathSpend")]
    P2trMusig2KeyPath(P2trMusig2KeyPathFinalInput),
    #[serde(rename = "p2shP2pk")]
    P2shP2pk(P2shP2pkFinalInput),
}

// Output types (depend on helper types)

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PsbtOutputFixture {
    pub unknown_key_vals: Option<Vec<UnknownKeyVal>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bip32_derivation: Option<Vec<Bip32Derivation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_script: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tap_tree: Option<TapTree>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tap_internal_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tap_bip32_derivation: Option<Vec<TapBip32Derivation>>,
}

// Top-level fixture type (depends on input and output types)

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PsbtFixture {
    pub wallet_keys: Vec<String>,
    pub psbt_base64: String,
    pub inputs: Vec<TxInput>,
    pub psbt_inputs: Vec<PsbtInputFixture>,
    pub psbt_inputs_finalized: Option<Vec<PsbtFinalInputFixture>>,
    pub outputs: Vec<TxOutput>,
    pub psbt_outputs: Vec<PsbtOutputFixture>,
    pub extracted_transaction: Option<String>,
}

// Test helper types for multi-stage PSBT testing

pub struct PsbtStages {
    pub network: Network,
    pub tx_format: TxFormat,
    pub wallet_keys: XprvTriple,
    pub unsigned: PsbtFixture,
    pub halfsigned: PsbtFixture,
    pub fullsigned: PsbtFixture,
}

impl PsbtStages {
    pub fn load(network: Network, tx_format: TxFormat) -> Result<Self, String> {
        let unsigned = load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            SignatureState::Unsigned,
            tx_format,
        )
        .expect("Failed to load unsigned fixture");
        let halfsigned = load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            SignatureState::Halfsigned,
            tx_format,
        )
        .expect("Failed to load halfsigned fixture");
        let fullsigned = load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            SignatureState::Fullsigned,
            tx_format,
        )
        .expect("Failed to load fullsigned fixture");
        let wallet_keys_unsigned = unsigned
            .get_wallet_xprvs()
            .expect("Failed to parse wallet keys");
        let wallet_keys_halfsigned = halfsigned
            .get_wallet_xprvs()
            .expect("Failed to parse wallet keys");
        let wallet_keys_fullsigned = fullsigned
            .get_wallet_xprvs()
            .expect("Failed to parse wallet keys");
        assert_eq!(wallet_keys_unsigned, wallet_keys_halfsigned);
        assert_eq!(wallet_keys_unsigned, wallet_keys_fullsigned);

        Ok(Self {
            network,
            tx_format,
            wallet_keys: wallet_keys_unsigned.clone(),
            unsigned,
            halfsigned,
            fullsigned,
        })
    }
}

pub struct PsbtInputStages {
    pub network: Network,
    pub tx_format: TxFormat,
    pub wallet_keys: XprvTriple,
    pub wallet_script_type: ScriptType,
    pub input_index: usize,
    pub input_fixture_unsigned: PsbtInputFixture,
    pub input_fixture_halfsigned: PsbtInputFixture,
    pub input_fixture_fullsigned: PsbtInputFixture,
}

impl PsbtInputStages {
    pub fn from_psbt_stages(
        psbt_stages: &PsbtStages,
        wallet_script_type: ScriptType,
    ) -> Result<Self, String> {
        let input_fixture_unsigned = psbt_stages
            .unsigned
            .find_input_with_script_type(wallet_script_type)?;
        let input_fixture_halfsigned = psbt_stages
            .halfsigned
            .find_input_with_script_type(wallet_script_type)?;
        let input_fixture_fullsigned = psbt_stages
            .fullsigned
            .find_input_with_script_type(wallet_script_type)?;
        assert_eq!(input_fixture_unsigned.0, input_fixture_halfsigned.0);
        assert_eq!(input_fixture_unsigned.0, input_fixture_fullsigned.0);
        Ok(Self {
            network: psbt_stages.network,
            tx_format: psbt_stages.tx_format,
            wallet_keys: psbt_stages.wallet_keys.clone(),
            wallet_script_type,
            input_index: input_fixture_unsigned.0,
            input_fixture_unsigned: input_fixture_unsigned.1.clone(),
            input_fixture_halfsigned: input_fixture_halfsigned.1.clone(),
            input_fixture_fullsigned: input_fixture_fullsigned.1.clone(),
        })
    }
}

/// Helper function to find a unique input matching a predicate
fn find_unique_input<'a, T, I, F>(
    iter: I,
    predicate: F,
    script_type: ScriptType,
) -> Result<(usize, &'a T), String>
where
    I: Iterator<Item = (usize, &'a T)>,
    F: FnMut(&(usize, &'a T)) -> bool,
{
    let result = iter.filter(predicate).collect::<Vec<_>>();
    if result.len() != 1 {
        return Err(format!(
            "Expected 1 input with script type {}, got {}",
            script_type.as_str(),
            result.len()
        ));
    }
    Ok(result[0])
}

impl PsbtFixture {
    pub fn to_psbt_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use base64::engine::{general_purpose::STANDARD as BASE64_STANDARD, Engine};
        Ok(BASE64_STANDARD.decode(&self.psbt_base64)?)
    }

    pub fn to_bitgo_psbt(
        &self,
        network: Network,
    ) -> Result<crate::bitgo_psbt::BitGoPsbt, Box<dyn std::error::Error>> {
        let psbt = crate::bitgo_psbt::BitGoPsbt::deserialize(&self.to_psbt_bytes()?, network)?;
        Ok(psbt)
    }

    /// Parse wallet keys from fixture (xprv strings)
    pub fn get_wallet_xprvs(&self) -> Result<XprvTriple, Box<dyn std::error::Error>> {
        XprvTriple::from_strings(self.wallet_keys.clone())
    }

    pub fn find_input_with_script_type(
        &self,
        script_type: ScriptType,
    ) -> Result<(usize, &PsbtInputFixture), String> {
        find_unique_input(
            self.psbt_inputs.iter().enumerate(),
            |(_, input)| script_type.matches_fixture(input),
            script_type,
        )
    }

    pub fn find_finalized_input_with_script_type(
        &self,
        script_type: ScriptType,
    ) -> Result<(usize, &PsbtFinalInputFixture), String> {
        let finalized_inputs = self
            .psbt_inputs_finalized
            .as_ref()
            .ok_or_else(|| "No finalized inputs available in fixture".to_string())?;

        find_unique_input(
            finalized_inputs.iter().enumerate(),
            |(_, input)| script_type.matches_finalized_fixture(input),
            script_type,
        )
    }
}

// Output script fixture types
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlBlockEntry {
    pub redeem_index: u32,
    pub control_block: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputScriptFixture {
    pub script_type: String,
    pub pubkeys: Vec<String>,
    pub internal_pubkey: String,
    pub control_blocks: Vec<ControlBlockEntry>,
    pub tap_tree: TapTree,
    pub taptree_root: String,
    pub output: String,
}

// Functions (depend on types above)

/// Load a fixture file from the test/fixtures directory and return its contents as a String
///
/// # Arguments
/// * `path` - Path relative to test/fixtures/ (e.g., "fixed-script/psbt.bitcoin.fullsigned.json")
///
/// # Example
/// ```rust,no_run
/// use wasm_miniscript::fixed_script_wallet::test_utils::fixtures::*;
///
/// let contents = load_fixture("fixed-script/psbt.bitcoin.fullsigned.json")
///     .expect("Failed to load fixture");
/// ```
pub fn load_fixture(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let full_path = format!("{}/test/fixtures/{}", env!("CARGO_MANIFEST_DIR"), path);
    let contents = std::fs::read_to_string(&full_path)?;
    Ok(contents)
}

/// Signature state for PSBT fixtures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureState {
    Unsigned,
    Halfsigned,
    Fullsigned,
}

impl SignatureState {
    fn as_str(&self) -> &'static str {
        match self {
            SignatureState::Unsigned => "unsigned",
            SignatureState::Halfsigned => "halfsigned",
            SignatureState::Fullsigned => "fullsigned",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxFormat {
    Psbt,
    PsbtLite,
}

impl TxFormat {
    fn as_str(&self) -> &'static str {
        match self {
            TxFormat::Psbt => "psbt",
            TxFormat::PsbtLite => "psbt-lite",
        }
    }
}

/// Load a PSBT fixture from a JSON file
///
/// # Arguments
/// * `network_name` - The network name (e.g., "bitcoin", "litecoin", "dogecoin")
/// * `signature_state` - The signature state of the PSBT
///
/// # Example
/// ```rust,no_run
/// use wasm_miniscript::fixed_script_wallet::test_utils::fixtures::*;
///
/// let fixture = load_psbt_fixture("bitcoin", SignatureState::Fullsigned)
///     .expect("Failed to load fixture");
/// ```
pub fn load_psbt_fixture_with_format(
    network_name: &str,
    signature_state: SignatureState,
    tx_format: TxFormat,
) -> Result<PsbtFixture, Box<dyn std::error::Error>> {
    let filename = format!(
        "{}.{}.{}.json",
        tx_format.as_str(),
        network_name,
        signature_state.as_str()
    );
    let path = format!("fixed-script/{}", filename);
    let contents =
        load_fixture(&path).unwrap_or_else(|_| panic!("Failed to load fixture: {}", filename));
    let fixture: PsbtFixture = serde_json::from_str(&contents)?;
    Ok(fixture)
}

pub fn load_psbt_fixture(
    network_name: &str,
    signature_state: SignatureState,
) -> Result<PsbtFixture, Box<dyn std::error::Error>> {
    load_psbt_fixture_with_format(network_name, signature_state, TxFormat::Psbt)
}

pub fn load_psbt_lite_fixture(
    network_name: &str,
    signature_state: SignatureState,
) -> Result<PsbtFixture, Box<dyn std::error::Error>> {
    load_psbt_fixture_with_format(network_name, signature_state, TxFormat::PsbtLite)
}

pub fn load_psbt_fixture_with_network(
    network: Network,
    signature_state: SignatureState,
) -> Result<PsbtFixture, Box<dyn std::error::Error>> {
    load_psbt_fixture(network.to_utxolib_name(), signature_state)
}

/// Load a PSBT fixture from JSON string
pub(crate) fn parse_psbt_fixture_json(
    json: &str,
) -> Result<PsbtFixture, Box<dyn std::error::Error>> {
    let fixture: PsbtFixture = serde_json::from_str(json)?;
    Ok(fixture)
}

/// Load output script fixtures for P2TR or P2TR-MuSig2 scripts
///
/// # Arguments
/// * `script_type` - The script type ("p2tr" or "p2trMusig2")
///
/// # Example
/// ```rust,no_run
/// use wasm_miniscript::fixed_script_wallet::test_utils::fixtures::*;
///
/// let fixtures = load_fixture_p2tr_output_scripts("p2tr")
///     .expect("Failed to load p2tr fixtures");
/// ```
pub fn load_fixture_p2tr_output_scripts(
    script_type: &str,
) -> Result<Vec<OutputScriptFixture>, Box<dyn std::error::Error>> {
    let path = format!("fixed-script/output-scripts/{}.json", script_type);
    let contents = load_fixture(&path)?;
    let fixtures: Vec<OutputScriptFixture> = serde_json::from_str(&contents)?;
    Ok(fixtures)
}

/// Decode the PSBT from base64
pub fn decode_psbt_from_fixture(
    fixture: &PsbtFixture,
) -> Result<crate::bitcoin::psbt::Psbt, Box<dyn std::error::Error>> {
    use base64::Engine;

    let psbt_bytes = base64::prelude::BASE64_STANDARD.decode(&fixture.psbt_base64)?;
    let psbt = crate::bitcoin::psbt::Psbt::deserialize(&psbt_bytes)?;
    Ok(psbt)
}

// Helper functions for validation

/// Compares a generated hex string with an expected hex string
pub fn assert_hex_eq(generated: &str, expected: &str, field_name: &str) -> Result<(), String> {
    if generated != expected {
        Err(format!(
            "{} mismatch\nExpected: {}\nGot: {}",
            field_name, expected, generated
        ))
    } else {
        Ok(())
    }
}

/// Validates sighash type for the given network
fn validate_sighash_type(sighash_type: u32, network: Network) -> Result<(), String> {
    crate::bitgo_psbt::validate_sighash_type(sighash_type, network)
}

/// Validates output script from witness UTXO against generated script
fn validate_witness_output_script(
    witness_utxo_script: &str,
    generated_script: &str,
) -> Result<(), String> {
    assert_hex_eq(generated_script, witness_utxo_script, "Output script")
}

/// Common validation for P2TR variants that includes output script and delegates to spend_info validation
fn validate_p2tr_wallet_scripts<F>(
    witness_utxo_script: &str,
    scripts: &crate::fixed_script_wallet::wallet_scripts::ScriptP2tr,
    validate_spend_info: F,
) -> Result<(), String>
where
    F: FnOnce(&crate::bitcoin::taproot::TaprootSpendInfo) -> Result<(), String>,
{
    validate_witness_output_script(
        witness_utxo_script,
        &scripts.output_script().to_hex_string(),
    )?;
    validate_spend_info(&scripts.spend_info)
}

// Implementation methods for validation

impl P2shInput {
    /// Validates that the generated WalletScripts matches this fixture
    pub fn assert_matches_wallet_scripts(
        &self,
        scripts: &crate::fixed_script_wallet::wallet_scripts::ScriptP2sh,
        output_script: &str,
        network: Network,
    ) -> Result<(), String> {
        // Compare output script
        let generated_output = scripts.redeem_script.to_p2sh().to_hex_string();
        assert_hex_eq(&generated_output, output_script, "Output script")?;

        // Compare redeem script
        let redeem_script_hex = scripts.redeem_script.to_hex_string();
        assert_hex_eq(&redeem_script_hex, &self.redeem_script, "Redeem script")?;

        validate_sighash_type(self.sighash_type, network)
    }
}

impl P2shP2wshInput {
    /// Validates that the generated WalletScripts matches this fixture
    pub fn assert_matches_wallet_scripts(
        &self,
        scripts: &crate::fixed_script_wallet::wallet_scripts::ScriptP2shP2wsh,
        output_script: &str,
        network: Network,
    ) -> Result<(), String> {
        // Compare output script
        let generated_output = scripts.redeem_script.to_p2sh().to_hex_string();
        assert_hex_eq(&generated_output, output_script, "Output script")?;

        // Compare redeem script
        let redeem_script_hex = scripts.redeem_script.to_hex_string();
        assert_hex_eq(&redeem_script_hex, &self.redeem_script, "Redeem script")?;

        // Compare witness script
        let witness_script_hex = scripts.witness_script.to_hex_string();
        assert_hex_eq(&witness_script_hex, &self.witness_script, "Witness script")?;

        validate_sighash_type(self.sighash_type, network)
    }
}

impl P2wshInput {
    /// Validates that the generated WalletScripts matches this fixture
    pub fn assert_matches_wallet_scripts(
        &self,
        scripts: &crate::fixed_script_wallet::wallet_scripts::ScriptP2wsh,
        output_script: &str,
        network: Network,
    ) -> Result<(), String> {
        // Compare output script
        let generated_output = scripts.witness_script.to_p2wsh().to_hex_string();
        assert_hex_eq(&generated_output, output_script, "Output script")?;

        // Compare witness script
        let witness_script_hex = scripts.witness_script.to_hex_string();
        assert_hex_eq(&witness_script_hex, &self.witness_script, "Witness script")?;

        validate_sighash_type(self.sighash_type, network)
    }
}

impl P2trScriptPathInput {
    /// Validates that the generated TaprootSpendInfo matches this fixture
    pub fn assert_matches_spend_info(
        &self,
        spend_info: &crate::bitcoin::taproot::TaprootSpendInfo,
        network: Network,
    ) -> Result<(), String> {
        use crate::bitcoin::hashes::hex::FromHex;
        use crate::bitcoin::ScriptBuf;

        // Compare tap leaf scripts and control blocks
        for fixture_leaf in &self.tap_leaf_script {
            let script_bytes = Vec::<u8>::from_hex(&fixture_leaf.script)
                .map_err(|e| format!("Failed to decode leaf script hex: {}", e))?;
            let script = ScriptBuf::from_bytes(script_bytes);

            let control_block = spend_info
                .control_block(&(
                    script.clone(),
                    crate::bitcoin::taproot::LeafVersion::TapScript,
                ))
                .ok_or_else(|| {
                    format!(
                        "Failed to generate control block for script: {}",
                        fixture_leaf.script
                    )
                })?;

            let control_block_hex = hex::encode(control_block.serialize());
            assert_hex_eq(
                &control_block_hex,
                &fixture_leaf.control_block,
                &format!("Control block for script {}", fixture_leaf.script),
            )?;

            if fixture_leaf.leaf_version != 0xc0 {
                return Err(format!(
                    "Expected leaf version 0xc0, got: {}",
                    fixture_leaf.leaf_version
                ));
            }
        }

        validate_sighash_type(self.sighash_type, network)
    }

    /// Validates that the generated WalletScripts matches this fixture
    /// This is a higher-level method that includes output script validation
    pub fn assert_matches_wallet_scripts(
        &self,
        scripts: &crate::fixed_script_wallet::wallet_scripts::ScriptP2tr,
        network: Network,
    ) -> Result<(), String> {
        validate_p2tr_wallet_scripts(&self.witness_utxo.script, scripts, |spend_info| {
            self.assert_matches_spend_info(spend_info, network)
        })
    }
}

impl P2trMusig2KeyPathInput {
    /// Validates that the generated TaprootSpendInfo matches this fixture
    pub fn assert_matches_spend_info(
        &self,
        spend_info: &crate::bitcoin::taproot::TaprootSpendInfo,
        network: Network,
    ) -> Result<(), String> {
        // Compare internal key
        let internal_key_hex = hex::encode(spend_info.internal_key().serialize());
        assert_hex_eq(&internal_key_hex, &self.tap_internal_key, "Internal key")?;

        // Compare merkle root
        let merkle_root = spend_info
            .merkle_root()
            .ok_or_else(|| "Expected merkle root to exist".to_string())?;
        let merkle_root_bytes: &[u8] = merkle_root.as_ref();
        let merkle_root_hex = hex::encode(merkle_root_bytes);
        assert_hex_eq(&merkle_root_hex, &self.tap_merkle_root, "Merkle root")?;

        validate_sighash_type(self.sighash_type, network)
    }

    /// Validates that the generated WalletScripts matches this fixture
    /// This is a higher-level method that includes output script validation
    pub fn assert_matches_wallet_scripts(
        &self,
        scripts: &crate::fixed_script_wallet::wallet_scripts::ScriptP2tr,
        network: Network,
    ) -> Result<(), String> {
        validate_p2tr_wallet_scripts(&self.witness_utxo.script, scripts, |spend_info| {
            self.assert_matches_spend_info(spend_info, network)
        })
    }

    /// Validates that the parsed Musig2 input data matches this fixture
    pub fn assert_matches_musig2_input(
        &self,
        musig2_input: &p2tr_musig2_input::Musig2Input,
    ) -> Result<(), String> {
        // Validate participants
        let fixture_participants = self
            .musig2_participants
            .as_ref()
            .ok_or_else(|| "Expected fixture participants".to_string())?;

        fixture_participants
            .assert_matches_parsed(&musig2_input.participants)
            .map_err(|e| format!("Participants mismatch: {}", e))?;

        // Validate nonces
        if musig2_input.nonces.len() != self.musig2_nonces.len() {
            return Err(format!(
                "Nonce count mismatch: expected {}, got {}",
                self.musig2_nonces.len(),
                musig2_input.nonces.len()
            ));
        }

        for fixture_nonce in &self.musig2_nonces {
            // Find matching parsed nonce by participant key
            let matching_parsed = musig2_input.nonces.iter().find(|pn| {
                hex::encode(pn.participant_pub_key.to_bytes()) == fixture_nonce.participant_pub_key
            });

            let parsed_nonce = matching_parsed.ok_or_else(|| {
                format!(
                    "No matching nonce found for participant key: {}",
                    fixture_nonce.participant_pub_key
                )
            })?;

            fixture_nonce
                .assert_matches_parsed(parsed_nonce)
                .map_err(|e| format!("Nonce mismatch: {}", e))?;
        }

        // Validate partial signatures
        if musig2_input.partial_sigs.len() != self.musig2_partial_sigs.len() {
            return Err(format!(
                "Partial signature count mismatch: expected {}, got {}",
                self.musig2_partial_sigs.len(),
                musig2_input.partial_sigs.len()
            ));
        }

        for fixture_sig in &self.musig2_partial_sigs {
            // Find matching parsed sig by participant key
            let matching_parsed = musig2_input.partial_sigs.iter().find(|ps| {
                hex::encode(ps.participant_pub_key.to_bytes()) == fixture_sig.participant_pub_key
            });

            let parsed_sig = matching_parsed.ok_or_else(|| {
                format!(
                    "No matching partial sig found for participant key: {}",
                    fixture_sig.participant_pub_key
                )
            })?;

            fixture_sig
                .assert_matches_parsed(parsed_sig)
                .map_err(|e| format!("Partial signature mismatch: {}", e))?;
        }

        Ok(())
    }
}

/// Script type for PSBT input validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptType {
    P2sh,
    P2shP2wsh,
    P2wsh,
    P2trLegacyScriptPath,
    P2trMusig2ScriptPath,
    P2trMusig2TaprootKeypath,
}

impl ScriptType {
    /// Returns the string representation used in fixtures
    pub fn as_str(&self) -> &'static str {
        match self {
            ScriptType::P2sh => "p2sh",
            ScriptType::P2shP2wsh => "p2shP2wsh",
            ScriptType::P2wsh => "p2wsh",
            ScriptType::P2trLegacyScriptPath => "p2tr",
            ScriptType::P2trMusig2ScriptPath => "p2trMusig2",
            ScriptType::P2trMusig2TaprootKeypath => "taprootKeypath",
        }
    }

    /// Checks if the given fixture input matches this script type
    pub fn matches_fixture(&self, fixture: &PsbtInputFixture) -> bool {
        matches!(
            (self, fixture),
            (ScriptType::P2sh, PsbtInputFixture::P2sh(_))
                | (ScriptType::P2shP2wsh, PsbtInputFixture::P2shP2wsh(_))
                | (ScriptType::P2wsh, PsbtInputFixture::P2wsh(_))
                | (
                    ScriptType::P2trLegacyScriptPath,
                    PsbtInputFixture::P2trLegacy(_)
                )
                | (
                    ScriptType::P2trMusig2ScriptPath,
                    PsbtInputFixture::P2trMusig2ScriptPath(_)
                )
                | (
                    ScriptType::P2trMusig2TaprootKeypath,
                    PsbtInputFixture::P2trMusig2KeyPath(_)
                )
        )
    }

    /// Checks if the given finalized fixture input matches this script type
    pub fn matches_finalized_fixture(&self, fixture: &PsbtFinalInputFixture) -> bool {
        matches!(
            (self, fixture),
            (ScriptType::P2sh, PsbtFinalInputFixture::P2sh(_))
                | (ScriptType::P2shP2wsh, PsbtFinalInputFixture::P2shP2wsh(_))
                | (ScriptType::P2wsh, PsbtFinalInputFixture::P2wsh(_))
                | (
                    ScriptType::P2trLegacyScriptPath,
                    PsbtFinalInputFixture::P2trLegacy(_)
                )
                | (
                    ScriptType::P2trMusig2ScriptPath,
                    PsbtFinalInputFixture::P2trMusig2ScriptPath(_)
                )
                | (
                    ScriptType::P2trMusig2TaprootKeypath,
                    PsbtFinalInputFixture::P2trMusig2KeyPath(_)
                )
        )
    }

    pub fn is_segwit(&self) -> bool {
        matches!(self, ScriptType::P2shP2wsh | ScriptType::P2wsh)
    }

    pub fn is_taproot(&self) -> bool {
        matches!(
            self,
            ScriptType::P2trLegacyScriptPath
                | ScriptType::P2trMusig2ScriptPath
                | ScriptType::P2trMusig2TaprootKeypath
        )
    }

    /// Checks if this script type is supported by the given network's output script support
    pub fn is_supported_by(&self, support: &crate::address::networks::OutputScriptSupport) -> bool {
        // P2sh is always supported (legacy)
        if matches!(self, ScriptType::P2sh) {
            return true;
        }

        // SegWit scripts require segwit support
        if self.is_segwit() {
            return support.segwit;
        }

        // Taproot scripts require taproot support (which implies segwit)
        if self.is_taproot() {
            return support.taproot;
        }

        // Default to supported for any other types
        true
    }
}

/// Macro for testing PSBT fixtures across all mainnet networks (excluding testnets and BSV)
/// and both transaction formats (Psbt and PsbtLite)
///
/// This macro generates test cases for mainnet networks only: Bitcoin, BitcoinCash, Ecash,
/// BitcoinGold, Dash, Dogecoin, Litecoin, and Zcash, combined with both TxFormat variants.
/// This creates a cartesian product of 8 networks × 2 formats = 16 test cases.
///
/// # Example
/// ```rust,no_run
/// test_psbt_fixtures!(test_my_feature, network, format, {
///     let fixture = load_psbt_fixture_with_network(network, SignatureState::Fullsigned).unwrap();
///     // ... test logic using both network and format
/// });
///
/// // With ignored networks:
/// test_psbt_fixtures!(test_my_feature, network, format, {
///     // test body
/// }, ignore: [BitcoinGold, Zcash]);
/// ```
///
/// This macro generates separate test functions for each network to enable proper
/// `#[ignore]` support. For a test named `test_foo`, it generates:
/// - `test_foo_bitcoin`
/// - `test_foo_bitcoin_cash`
/// - `test_foo_zcash` (with #[ignore] if in ignore list)
/// - etc.
#[macro_export]
macro_rules! test_psbt_fixtures {
    // Pattern without ignored networks - delegates to the pattern with ignore (backward compatible)
    ($test_name:ident, $network:ident, $format:ident, $body:block) => {
        $crate::test_psbt_fixtures!($test_name, $network, $format, $body, ignore: []);
    };

    // Pattern with ignored networks
    ($test_name:ident, $network:ident, $format:ident, $body:block, ignore: [$($ignore_net:ident),* $(,)?]) => {
        $crate::test_psbt_fixtures!(@generate_test $test_name, bitcoin, Bitcoin, $crate::Network::Bitcoin, $network, $format, $body, [$($ignore_net),*]);
        $crate::test_psbt_fixtures!(@generate_test $test_name, bitcoin_cash, BitcoinCash, $crate::Network::BitcoinCash, $network, $format, $body, [$($ignore_net),*]);
        $crate::test_psbt_fixtures!(@generate_test $test_name, ecash, Ecash, $crate::Network::Ecash, $network, $format, $body, [$($ignore_net),*]);
        $crate::test_psbt_fixtures!(@generate_test $test_name, bitcoin_gold, BitcoinGold, $crate::Network::BitcoinGold, $network, $format, $body, [$($ignore_net),*]);
        $crate::test_psbt_fixtures!(@generate_test $test_name, dash, Dash, $crate::Network::Dash, $network, $format, $body, [$($ignore_net),*]);
        $crate::test_psbt_fixtures!(@generate_test $test_name, dogecoin, Dogecoin, $crate::Network::Dogecoin, $network, $format, $body, [$($ignore_net),*]);
        $crate::test_psbt_fixtures!(@generate_test $test_name, litecoin, Litecoin, $crate::Network::Litecoin, $network, $format, $body, [$($ignore_net),*]);
        $crate::test_psbt_fixtures!(@generate_test $test_name, zcash, Zcash, $crate::Network::Zcash, $network, $format, $body, [$($ignore_net),*]);
    };

    // Internal: Generate a test function for a specific network
    (@generate_test $test_name:ident, $net_suffix:ident, $net_id:ident, $net_value:path, $network:ident, $format:ident, $body:block, []) => {
        ::pastey::paste! {
            #[::rstest::rstest]
            fn [<$test_name _ $net_suffix>](
                #[values(
                    $crate::fixed_script_wallet::test_utils::fixtures::TxFormat::Psbt,
                    $crate::fixed_script_wallet::test_utils::fixtures::TxFormat::PsbtLite
                )]
                $format: $crate::fixed_script_wallet::test_utils::fixtures::TxFormat
            ) {
                let $network = $net_value;
                $body
            }
        }
    };

    (@generate_test $test_name:ident, $net_suffix:ident, $net_id:ident, $net_value:path, $network:ident, $format:ident, $body:block, [$($ignore_net:ident),+]) => {
        $crate::test_psbt_fixtures!(@check_ignore_and_generate $test_name, $net_suffix, $net_id, $net_value, $network, $format, $body, $($ignore_net),+);
    };

    // Check if this network should be ignored and generate accordingly
    (@check_ignore_and_generate $test_name:ident, $net_suffix:ident, $net_id:ident, $net_value:path, $network:ident, $format:ident, $body:block, $($ignore_net:ident),+) => {
        $crate::test_psbt_fixtures!(@is_ignored $test_name, $net_suffix, $net_id, $net_value, $network, $format, $body, false, $($ignore_net),+);
    };

    // Check if current network matches any in the ignore list
    (@is_ignored $test_name:ident, $net_suffix:ident, Bitcoin, $net_value:path, $network:ident, $format:ident, $body:block, $ignored:tt, Bitcoin $(, $rest:ident)*) => {
        $crate::test_psbt_fixtures!(@emit_test $test_name, $net_suffix, $net_value, $network, $format, $body, true);
    };
    (@is_ignored $test_name:ident, $net_suffix:ident, BitcoinCash, $net_value:path, $network:ident, $format:ident, $body:block, $ignored:tt, BitcoinCash $(, $rest:ident)*) => {
        $crate::test_psbt_fixtures!(@emit_test $test_name, $net_suffix, $net_value, $network, $format, $body, true);
    };
    (@is_ignored $test_name:ident, $net_suffix:ident, Ecash, $net_value:path, $network:ident, $format:ident, $body:block, $ignored:tt, Ecash $(, $rest:ident)*) => {
        $crate::test_psbt_fixtures!(@emit_test $test_name, $net_suffix, $net_value, $network, $format, $body, true);
    };
    (@is_ignored $test_name:ident, $net_suffix:ident, BitcoinGold, $net_value:path, $network:ident, $format:ident, $body:block, $ignored:tt, BitcoinGold $(, $rest:ident)*) => {
        $crate::test_psbt_fixtures!(@emit_test $test_name, $net_suffix, $net_value, $network, $format, $body, true);
    };
    (@is_ignored $test_name:ident, $net_suffix:ident, Dash, $net_value:path, $network:ident, $format:ident, $body:block, $ignored:tt, Dash $(, $rest:ident)*) => {
        $crate::test_psbt_fixtures!(@emit_test $test_name, $net_suffix, $net_value, $network, $format, $body, true);
    };
    (@is_ignored $test_name:ident, $net_suffix:ident, Dogecoin, $net_value:path, $network:ident, $format:ident, $body:block, $ignored:tt, Dogecoin $(, $rest:ident)*) => {
        $crate::test_psbt_fixtures!(@emit_test $test_name, $net_suffix, $net_value, $network, $format, $body, true);
    };
    (@is_ignored $test_name:ident, $net_suffix:ident, Litecoin, $net_value:path, $network:ident, $format:ident, $body:block, $ignored:tt, Litecoin $(, $rest:ident)*) => {
        $crate::test_psbt_fixtures!(@emit_test $test_name, $net_suffix, $net_value, $network, $format, $body, true);
    };
    (@is_ignored $test_name:ident, $net_suffix:ident, Zcash, $net_value:path, $network:ident, $format:ident, $body:block, $ignored:tt, Zcash $(, $rest:ident)*) => {
        $crate::test_psbt_fixtures!(@emit_test $test_name, $net_suffix, $net_value, $network, $format, $body, true);
    };

    // No match - try next
    (@is_ignored $test_name:ident, $net_suffix:ident, $net_id:ident, $net_value:path, $network:ident, $format:ident, $body:block, $ignored:tt, $other:ident $(, $rest:ident)*) => {
        $crate::test_psbt_fixtures!(@is_ignored $test_name, $net_suffix, $net_id, $net_value, $network, $format, $body, $ignored $(, $rest)*);
    };

    // Exhausted list without match - not ignored
    (@is_ignored $test_name:ident, $net_suffix:ident, $net_id:ident, $net_value:path, $network:ident, $format:ident, $body:block, $ignored:tt) => {
        $crate::test_psbt_fixtures!(@emit_test $test_name, $net_suffix, $net_value, $network, $format, $body, false);
    };

    // Emit test function - not ignored
    (@emit_test $test_name:ident, $net_suffix:ident, $net_value:path, $network:ident, $format:ident, $body:block, false) => {
        ::pastey::paste! {
            #[::rstest::rstest]
            fn [<$test_name _ $net_suffix>](
                #[values(
                    $crate::fixed_script_wallet::test_utils::fixtures::TxFormat::Psbt,
                    $crate::fixed_script_wallet::test_utils::fixtures::TxFormat::PsbtLite
                )]
                $format: $crate::fixed_script_wallet::test_utils::fixtures::TxFormat
            ) {
                let $network = $net_value;
                $body
            }
        }
    };

    // Emit test function - ignored
    (@emit_test $test_name:ident, $net_suffix:ident, $net_value:path, $network:ident, $format:ident, $body:block, true) => {
        ::pastey::paste! {
            #[ignore]
            #[::rstest::rstest]
            fn [<$test_name _ $net_suffix>](
                #[values(
                    $crate::fixed_script_wallet::test_utils::fixtures::TxFormat::Psbt,
                    $crate::fixed_script_wallet::test_utils::fixtures::TxFormat::PsbtLite
                )]
                $format: $crate::fixed_script_wallet::test_utils::fixtures::TxFormat
            ) {
                let $network = $net_value;
                $body
            }
        }
    };
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_fixture_helper() {
        // Test loading a fixture file
        let contents = load_fixture("fixed-script/psbt.bitcoin.fullsigned.json")
            .expect("Failed to load fixture");
        assert!(!contents.is_empty());
        assert!(contents.contains("walletKeys"));
        assert!(contents.contains("psbtBase64"));
    }

    #[test]
    fn test_parse_fixture() {
        let json = r#"{
            "walletKeys": ["xprv..."],
            "psbtBase64": "cHNidP8BAP3q...",
            "inputs": [],
            "psbtInputs": [],
            "outputs": [],
            "psbtOutputs": []
        }"#;

        let result = parse_psbt_fixture_json(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_bitcoin_fullsigned_fixture() {
        // Example of loading a fixture file
        let fixture = load_psbt_fixture("bitcoin", SignatureState::Fullsigned)
            .expect("Failed to load fixture");

        // Verify structure
        assert_eq!(fixture.wallet_keys.len(), 3);
        assert!(!fixture.psbt_base64.is_empty());
        assert_eq!(fixture.inputs.len(), 7);
        assert_eq!(fixture.psbt_inputs.len(), 7);
        assert_eq!(fixture.outputs.len(), 5);
        assert_eq!(fixture.psbt_outputs.len(), 5);

        // Decode PSBT
        let psbt = decode_psbt_from_fixture(&fixture).expect("Failed to decode PSBT");
        assert_eq!(psbt.inputs.len(), 7);
        assert_eq!(psbt.outputs.len(), 5);
    }

    #[test]
    fn test_load_different_signature_states() {
        // Test unsigned
        let unsigned = load_psbt_fixture("bitcoin", SignatureState::Unsigned)
            .expect("Failed to load unsigned fixture");
        assert_eq!(unsigned.inputs.len(), 7);
        assert_eq!(unsigned.psbt_inputs.len(), 7);

        // Test halfsigned
        let halfsigned = load_psbt_fixture("bitcoin", SignatureState::Halfsigned)
            .expect("Failed to load halfsigned fixture");
        assert_eq!(halfsigned.inputs.len(), 7);
        assert_eq!(halfsigned.psbt_inputs.len(), 7);

        // Test fullsigned
        let fullsigned = load_psbt_fixture("bitcoin", SignatureState::Fullsigned)
            .expect("Failed to load fullsigned fixture");
        assert_eq!(fullsigned.inputs.len(), 7);
        assert_eq!(fullsigned.psbt_inputs.len(), 7);
    }

    #[test]
    fn test_load_different_networks() {
        // Test various networks
        for network in &[
            "bitcoin",
            "litecoin",
            "dogecoin",
            "bitcoincash",
            "ecash",
            "dash",
            "bitcoingold",
        ] {
            let fixture = load_psbt_fixture(network, SignatureState::Fullsigned)
                .unwrap_or_else(|_| panic!("Failed to load {} fixture", network));
            assert_eq!(fixture.wallet_keys.len(), 3);
        }
    }

    #[test]
    fn test_load_p2tr_output_scripts() {
        // Test p2tr
        let p2tr_fixtures =
            load_fixture_p2tr_output_scripts("p2tr").expect("Failed to load p2tr output scripts");
        assert_eq!(p2tr_fixtures.len(), 2);
        assert_eq!(p2tr_fixtures[0].script_type, "p2tr");
        assert_eq!(p2tr_fixtures[0].pubkeys.len(), 3);
        assert_eq!(p2tr_fixtures[0].control_blocks.len(), 3);
        assert_eq!(p2tr_fixtures[0].tap_tree.leaves.len(), 3);

        // Test p2trMusig2
        let p2tr_musig2_fixtures = load_fixture_p2tr_output_scripts("p2trMusig2")
            .expect("Failed to load p2trMusig2 output scripts");
        assert_eq!(p2tr_musig2_fixtures.len(), 2);
        assert_eq!(p2tr_musig2_fixtures[0].script_type, "p2trMusig2");
        assert_eq!(p2tr_musig2_fixtures[0].pubkeys.len(), 3);
        assert_eq!(p2tr_musig2_fixtures[0].control_blocks.len(), 2);
        assert_eq!(p2tr_musig2_fixtures[0].tap_tree.leaves.len(), 2);
    }

    #[test]
    fn test_find_input_with_script_type() {
        let fixture = load_psbt_fixture("bitcoin", SignatureState::Fullsigned)
            .expect("Failed to load fixture");

        // Test finding P2SH input
        let (index, input) = fixture
            .find_input_with_script_type(ScriptType::P2sh)
            .expect("Failed to find P2SH input");
        assert_eq!(index, 0);
        assert!(matches!(input, PsbtInputFixture::P2sh(_)));

        // Test finding P2WSH input
        let (index, input) = fixture
            .find_input_with_script_type(ScriptType::P2wsh)
            .expect("Failed to find P2WSH input");
        assert_eq!(index, 2);
        assert!(matches!(input, PsbtInputFixture::P2wsh(_)));
    }

    #[test]
    fn test_find_finalized_input_with_script_type() {
        let fixture = load_psbt_fixture("bitcoin", SignatureState::Fullsigned)
            .expect("Failed to load fixture");

        // Test finding P2SH finalized input
        let (index, input) = fixture
            .find_finalized_input_with_script_type(ScriptType::P2sh)
            .expect("Failed to find P2SH finalized input");
        assert_eq!(index, 0);
        assert!(matches!(input, PsbtFinalInputFixture::P2sh(_)));

        // Test finding taproot key path finalized input
        let (index, input) = fixture
            .find_finalized_input_with_script_type(ScriptType::P2trMusig2TaprootKeypath)
            .expect("Failed to find taproot key path finalized input");
        assert_eq!(index, 5);
        assert!(matches!(input, PsbtFinalInputFixture::P2trMusig2KeyPath(_)));

        // Test with unsigned fixture (should return error)
        let unsigned_fixture = load_psbt_fixture("bitcoin", SignatureState::Unsigned)
            .expect("Failed to load unsigned fixture");
        let result = unsigned_fixture.find_finalized_input_with_script_type(ScriptType::P2sh);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "No finalized inputs available in fixture"
        );
    }
}
