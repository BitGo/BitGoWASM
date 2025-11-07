//! BitGo-specific PSBT parsing that handles multiple network formats
//!
//! This module provides PSBT deserialization that works across different
//! bitcoin-like networks, including those with non-standard transaction formats.

pub mod p2tr_musig2_input;
#[cfg(test)]
mod p2tr_musig2_input_utxolib;
mod propkv;
mod psbt_wallet_input;
mod sighash;
mod zcash_psbt;

use crate::Network;
use miniscript::bitcoin::{psbt::Psbt, secp256k1, CompressedPublicKey};
pub use propkv::{BitGoKeyValue, ProprietaryKeySubtype, BITGO};
pub use sighash::validate_sighash_type;
use zcash_psbt::ZcashPsbt;

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

    pub fn network(&self) -> Network {
        match self {
            BitGoPsbt::BitcoinLike(_, network) => *network,
            BitGoPsbt::Zcash(_, network) => *network,
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

    /// Get a reference to the underlying PSBT
    ///
    /// This works for both BitcoinLike and Zcash PSBTs, returning a reference
    /// to the inner Bitcoin-compatible PSBT structure.
    pub fn psbt(&self) -> &Psbt {
        match self {
            BitGoPsbt::BitcoinLike(ref psbt, _network) => psbt,
            BitGoPsbt::Zcash(ref zcash_psbt, _network) => &zcash_psbt.psbt,
        }
    }

    /// Get a mutable reference to the underlying PSBT
    ///
    /// This works for both BitcoinLike and Zcash PSBTs, returning a reference
    /// to the inner Bitcoin-compatible PSBT structure.
    pub fn psbt_mut(&mut self) -> &mut Psbt {
        match self {
            BitGoPsbt::BitcoinLike(ref mut psbt, _network) => psbt,
            BitGoPsbt::Zcash(ref mut zcash_psbt, _network) => &mut zcash_psbt.psbt,
        }
    }

    pub fn finalize_input<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
    ) -> Result<(), String> {
        use miniscript::psbt::PsbtExt;

        match self {
            BitGoPsbt::BitcoinLike(ref mut psbt, _network) => {
                // Use custom bitgo p2trMusig2 input finalization for MuSig2 inputs
                if p2tr_musig2_input::Musig2Input::is_musig2_input(&psbt.inputs[input_index]) {
                    let mut ctx = p2tr_musig2_input::Musig2Context::new(psbt, input_index)
                        .map_err(|e| e.to_string())?;
                    ctx.finalize_input(secp).map_err(|e| e.to_string())?;
                    return Ok(());
                }
                // other inputs can be finalized using the standard miniscript::psbt::finalize_input
                psbt.finalize_inp_mut(secp, input_index)
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            BitGoPsbt::Zcash(_zcash_psbt, _network) => {
                todo!("Zcash PSBT finalization not yet implemented");
            }
        }
    }

    /// Finalize all inputs in the PSBT, attempting each input even if some fail.
    /// Similar to miniscript::psbt::PsbtExt::finalize_mut.
    ///
    /// # Returns
    /// - `Ok(())` if all inputs were successfully finalized
    /// - `Err(Vec<String>)` containing error messages for each failed input
    ///
    /// # Note
    /// This method will attempt to finalize ALL inputs, collecting errors for any that fail.
    /// It does not stop at the first error.
    pub fn finalize_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<(), Vec<String>> {
        let num_inputs = self.psbt().inputs.len();

        let mut errors = vec![];
        for index in 0..num_inputs {
            match self.finalize_input(secp, index) {
                Ok(()) => {}
                Err(e) => {
                    errors.push(format!("Input {}: {}", index, e));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Finalize all inputs and consume the PSBT, returning the finalized PSBT.
    /// Similar to miniscript::psbt::PsbtExt::finalize.
    ///
    /// # Returns
    /// - `Ok(Psbt)` if all inputs were successfully finalized
    /// - `Err(String)` containing a formatted error message if any input failed
    pub fn finalize<C: secp256k1::Verification>(
        mut self,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<Psbt, String> {
        match self.finalize_mut(secp) {
            Ok(()) => Ok(self.into_psbt()),
            Err(errors) => Err(format!(
                "Failed to finalize {} input(s): {}",
                errors.len(),
                errors.join("; ")
            )),
        }
    }

    /// Helper function to create a MuSig2 context for an input
    ///
    /// This validates that:
    /// 1. The PSBT is BitcoinLike (not Zcash)
    /// 2. The input index is valid
    /// 3. The input is a MuSig2 input
    ///
    /// Returns a Musig2Context for the specified input
    fn musig2_context<'a>(
        &'a mut self,
        input_index: usize,
    ) -> Result<p2tr_musig2_input::Musig2Context<'a>, String> {
        if self.network().mainnet() != Network::Bitcoin {
            return Err("MuSig2 not supported for non-Bitcoin networks".to_string());
        }

        if matches!(self, BitGoPsbt::Zcash(_, _)) {
            return Err("MuSig2 not supported for Zcash".to_string());
        }

        let psbt = self.psbt_mut();
        if input_index >= psbt.inputs.len() {
            return Err(format!("Input index {} out of bounds", input_index));
        }

        // Validate this is a MuSig2 input
        if !p2tr_musig2_input::Musig2Input::is_musig2_input(&psbt.inputs[input_index]) {
            return Err(format!("Input {} is not a MuSig2 input", input_index));
        }

        // Create and return the context
        p2tr_musig2_input::Musig2Context::new(psbt, input_index).map_err(|e| e.to_string())
    }

    /// Set the counterparty's (BitGo's) nonce in the PSBT
    ///
    /// # Arguments
    /// * `input_index` - The index of the MuSig2 input
    /// * `participant_pub_key` - The counterparty's public key
    /// * `pub_nonce` - The counterparty's public nonce
    pub fn set_counterparty_nonce(
        &mut self,
        input_index: usize,
        participant_pub_key: CompressedPublicKey,
        pub_nonce: musig2::PubNonce,
    ) -> Result<(), String> {
        let mut ctx = self.musig2_context(input_index)?;
        let tap_output_key = ctx.musig2_input().participants.tap_output_key;

        // Set the nonce
        ctx.set_nonce(participant_pub_key, tap_output_key, pub_nonce)
            .map_err(|e| e.to_string())
    }

    /// Generate and set a user nonce for a MuSig2 input using State-Machine API
    ///
    /// This method uses the State-Machine API from the musig2 crate, which encapsulates
    /// the SecNonce internally to prevent accidental reuse. This is the recommended
    /// production API.
    ///
    /// # Arguments
    /// * `input_index` - The index of the MuSig2 input
    /// * `xpriv` - The user's extended private key (will be derived for the input)
    /// * `session_id` - 32-byte session ID (use rand::thread_rng().gen() in production)
    ///
    /// # Returns
    /// A tuple of (FirstRound, PubNonce) - keep FirstRound secret for signing later,
    /// send PubNonce to the counterparty
    pub fn generate_nonce_first_round(
        &mut self,
        input_index: usize,
        xpriv: &miniscript::bitcoin::bip32::Xpriv,
        session_id: [u8; 32],
    ) -> Result<(musig2::FirstRound, musig2::PubNonce), String> {
        let mut ctx = self.musig2_context(input_index)?;
        ctx.generate_nonce_first_round(xpriv, session_id)
            .map_err(|e| e.to_string())
    }

    /// Sign a MuSig2 input using State-Machine API
    ///
    /// This method uses the State-Machine API from the musig2 crate. The FirstRound
    /// from nonce generation encapsulates the secret nonce, preventing reuse.
    ///
    /// # Arguments
    /// * `input_index` - The index of the MuSig2 input
    /// * `first_round` - The FirstRound from generate_nonce_first_round()
    /// * `xpriv` - The user's extended private key
    ///
    /// # Returns
    /// Ok(()) if the signature was successfully created and added to the PSBT
    pub fn sign_with_first_round(
        &mut self,
        input_index: usize,
        first_round: musig2::FirstRound,
        xpriv: &miniscript::bitcoin::bip32::Xpriv,
    ) -> Result<(), String> {
        let mut ctx = self.musig2_context(input_index)?;
        ctx.sign_with_first_round(first_round, xpriv)
            .map_err(|e| e.to_string())
    }

    /// Sign the PSBT with the provided key.
    /// Wraps the underlying PSBT's sign method from miniscript::psbt::PsbtExt.
    ///
    /// # Type Parameters
    /// - `C`: Signing context from secp256k1
    /// - `K`: Key type that implements `psbt::GetKey` trait
    ///
    /// # Returns
    /// - `Ok(SigningKeysMap)` on success, mapping input index to keys used for signing
    /// - `Err((SigningKeysMap, SigningErrors))` on failure, containing both partial success info and errors
    pub fn sign<C, K>(
        &mut self,
        k: &K,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<
        miniscript::bitcoin::psbt::SigningKeysMap,
        (
            miniscript::bitcoin::psbt::SigningKeysMap,
            miniscript::bitcoin::psbt::SigningErrors,
        ),
    >
    where
        C: secp256k1::Signing + secp256k1::Verification,
        K: miniscript::bitcoin::psbt::GetKey,
    {
        match self {
            BitGoPsbt::BitcoinLike(ref mut psbt, _network) => psbt.sign(k, secp),
            BitGoPsbt::Zcash(_zcash_psbt, _network) => {
                // Return an error indicating Zcash signing is not implemented
                Err((
                    Default::default(),
                    std::collections::BTreeMap::from_iter([(
                        0,
                        miniscript::bitcoin::psbt::SignError::KeyNotFound,
                    )]),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_script_wallet::Chain;
    use crate::fixed_script_wallet::WalletScripts;
    use crate::test_utils::fixtures;
    use crate::test_utils::fixtures::assert_hex_eq;
    use base64::engine::{general_purpose::STANDARD as BASE64_STANDARD, Engine};
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

    crate::test_psbt_fixtures!(test_parse_network_mainnet_only, network, format, {
        test_parse_with_format(format, network);
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

    crate::test_psbt_fixtures!(test_round_trip_mainnet_only, network, format, {
        test_round_trip_with_format(format, network);
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

    type PartialSignatures =
        std::collections::BTreeMap<crate::bitcoin::PublicKey, crate::bitcoin::ecdsa::Signature>;

    fn assert_eq_partial_signatures(
        actual: &PartialSignatures,
        expected: &PartialSignatures,
    ) -> Result<(), String> {
        assert_eq!(
            actual.len(),
            expected.len(),
            "Partial signatures should match"
        );
        for (actual_sig, expected_sig) in actual.iter().zip(expected.iter()) {
            assert_eq!(actual_sig.0, expected_sig.0, "Public key should match");
            assert_hex_eq(
                &hex::encode(actual_sig.1.serialize()),
                &hex::encode(expected_sig.1.serialize()),
                "Signature",
            )?;
        }
        Ok(())
    }

    // ensure we can put the first signature (user signature) on an unsigned PSBT
    fn assert_half_sign(
        script_type: fixtures::ScriptType,
        unsigned_bitgo_psbt: &BitGoPsbt,
        halfsigned_bitgo_psbt: &BitGoPsbt,
        xpriv_triple: &fixtures::XprvTriple,
        input_index: usize,
    ) -> Result<(), String> {
        let user_xpriv = xpriv_triple.user_key();

        // Clone the unsigned PSBT and sign with user key
        let mut unsigned_bitgo_psbt = unsigned_bitgo_psbt.clone();
        let secp = secp256k1::Secp256k1::new();

        if script_type == fixtures::ScriptType::P2trMusig2TaprootKeypath {
            // MuSig2 keypath: set nonces and sign with user key
            p2tr_musig2_input::assert_set_nonce_and_sign_musig2_keypath(
                xpriv_triple,
                &mut unsigned_bitgo_psbt,
                halfsigned_bitgo_psbt,
                input_index,
            )?;

            // MuSig2 inputs use proprietary key values for partial signatures,
            // not standard PSBT partial_sigs, so we're done
            return Ok(());
        }

        // Sign with user key using the new sign method
        unsigned_bitgo_psbt
            .sign(user_xpriv, &secp)
            .map_err(|(_num_keys, errors)| format!("Failed to sign PSBT: {:?}", errors))?;

        // Extract partial signatures from the signed input
        let signed_input = match &unsigned_bitgo_psbt {
            BitGoPsbt::BitcoinLike(psbt, _) => &psbt.inputs[input_index],
            BitGoPsbt::Zcash(_, _) => {
                return Err("Zcash signing not yet implemented".to_string());
            }
        };

        match script_type {
            fixtures::ScriptType::P2trLegacyScriptPath
            | fixtures::ScriptType::P2trMusig2ScriptPath => {
                assert_eq!(signed_input.tap_script_sigs.len(), 1);
                // Get expected tap script sig from halfsigned fixture
                let expected_tap_script_sig = halfsigned_bitgo_psbt.clone().into_psbt().inputs
                    [input_index]
                    .tap_script_sigs
                    .clone();
                assert_eq!(signed_input.tap_script_sigs, expected_tap_script_sig);
            }
            _ => {
                let actual_partial_sigs = signed_input.partial_sigs.clone();
                // Get expected partial signatures from halfsigned fixture
                let expected_partial_sigs = halfsigned_bitgo_psbt.clone().into_psbt().inputs
                    [input_index]
                    .partial_sigs
                    .clone();

                assert_eq!(actual_partial_sigs.len(), 1);
                assert_eq_partial_signatures(&actual_partial_sigs, &expected_partial_sigs)?;
            }
        }

        Ok(())
    }

    fn assert_full_signed_matches_wallet_scripts(
        network: Network,
        tx_format: fixtures::TxFormat,
        fixture: &fixtures::PsbtFixture,
        wallet_keys: &fixtures::XprvTriple,
        input_index: usize,
        input_fixture: &fixtures::PsbtInputFixture,
    ) -> Result<(), String> {
        let (chain, index) =
            parse_fixture_paths(input_fixture).expect("Failed to parse fixture paths");
        let scripts = WalletScripts::from_wallet_keys(
            &wallet_keys.to_root_wallet_keys(),
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

    fn assert_finalize_input(
        mut bitgo_psbt: BitGoPsbt,
        input_index: usize,
        _network: Network,
        _tx_format: fixtures::TxFormat,
    ) -> Result<(), String> {
        let secp = crate::bitcoin::secp256k1::Secp256k1::new();
        bitgo_psbt
            .finalize_input(&secp, input_index)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn test_wallet_script_type(
        script_type: fixtures::ScriptType,
        network: Network,
        tx_format: fixtures::TxFormat,
    ) -> Result<(), String> {
        let psbt_stages = fixtures::PsbtStages::load(network, tx_format)?;
        let psbt_input_stages =
            fixtures::PsbtInputStages::from_psbt_stages(&psbt_stages, script_type);

        // Check if the script type is supported by the network
        let output_script_support = network.output_script_support();
        if !script_type.is_supported_by(&output_script_support) {
            // Script type not supported by network - skip test (no fixture expected)
            assert!(
                psbt_input_stages.is_err(),
                "Expected error for unsupported script type"
            );
            return Ok(());
        }

        let psbt_input_stages = psbt_input_stages.unwrap();

        assert_half_sign(
            script_type,
            &psbt_stages
                .unsigned
                .to_bitgo_psbt(network)
                .expect("Failed to convert to BitGo PSBT"),
            &psbt_stages
                .halfsigned
                .to_bitgo_psbt(network)
                .expect("Failed to convert to BitGo PSBT"),
            &psbt_input_stages.wallet_keys,
            psbt_input_stages.input_index,
        )?;

        assert_full_signed_matches_wallet_scripts(
            network,
            tx_format,
            &psbt_stages.fullsigned,
            &psbt_input_stages.wallet_keys,
            psbt_input_stages.input_index,
            &psbt_input_stages.input_fixture_fullsigned,
        )?;

        assert_finalize_input(
            psbt_stages.fullsigned.to_bitgo_psbt(network).unwrap(),
            psbt_input_stages.input_index,
            network,
            tx_format,
        )?;

        Ok(())
    }

    crate::test_psbt_fixtures!(test_p2sh_suite, network, format, {
        test_wallet_script_type(fixtures::ScriptType::P2sh, network, format).unwrap();
    }, ignore: [
        // TODO: sighash support
        BitcoinCash, Ecash, BitcoinGold,
        // TODO: zec support
        Zcash,
        ]);

    crate::test_psbt_fixtures!(
        test_p2sh_p2wsh_suite,
        network,
        format,
        {
            test_wallet_script_type(fixtures::ScriptType::P2shP2wsh, network, format).unwrap();
        },
        // TODO: sighash support
        ignore: [BitcoinGold]
    );

    crate::test_psbt_fixtures!(
        test_p2wsh_suite,
        network,
        format,
        {
            test_wallet_script_type(fixtures::ScriptType::P2wsh, network, format).unwrap();
        },
        // TODO: sighash support
        ignore: [BitcoinGold]
    );

    crate::test_psbt_fixtures!(test_p2tr_legacy_script_path_suite, network, format, {
        test_wallet_script_type(fixtures::ScriptType::P2trLegacyScriptPath, network, format)
            .unwrap();
    });

    crate::test_psbt_fixtures!(test_p2tr_musig2_script_path_suite, network, format, {
        test_wallet_script_type(fixtures::ScriptType::P2trMusig2ScriptPath, network, format)
            .unwrap();
    });

    crate::test_psbt_fixtures!(test_p2tr_musig2_key_path_suite, network, format, {
        test_wallet_script_type(
            fixtures::ScriptType::P2trMusig2TaprootKeypath,
            network,
            format,
        )
        .unwrap();
    });

    crate::test_psbt_fixtures!(test_extract_transaction, network, format, {
        let fixture = fixtures::load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            fixtures::SignatureState::Fullsigned,
            format,
        )
        .expect("Failed to load fixture");
        let bitgo_psbt = fixture
            .to_bitgo_psbt(network)
            .expect("Failed to convert to BitGo PSBT");
        let fixture_extracted_transaction = fixture
            .extracted_transaction
            .expect("Failed to extract transaction");

        // // Use BitGoPsbt::finalize() which handles MuSig2 inputs
        let secp = crate::bitcoin::secp256k1::Secp256k1::new();
        let finalized_psbt = bitgo_psbt.finalize(&secp).expect("Failed to finalize PSBT");
        let extracted_transaction = finalized_psbt
            .extract_tx()
            .expect("Failed to extract transaction");
        use miniscript::bitcoin::consensus::serialize;
        let extracted_transaction_hex = hex::encode(serialize(&extracted_transaction));
        assert_eq!(
            extracted_transaction_hex, fixture_extracted_transaction,
            "Extracted transaction should match"
        );
    }, ignore: [BitcoinGold, BitcoinCash, Ecash, Zcash]);

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
