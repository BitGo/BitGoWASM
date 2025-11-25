//! BitGo-specific PSBT parsing that handles multiple network formats
//!
//! This module provides PSBT deserialization that works across different
//! bitcoin-like networks, including those with non-standard transaction formats.

pub mod p2tr_musig2_input;
#[cfg(test)]
mod p2tr_musig2_input_utxolib;
mod propkv;
pub mod psbt_wallet_input;
pub mod psbt_wallet_output;
mod sighash;
mod zcash_psbt;

use crate::Network;
use miniscript::bitcoin::{psbt::Psbt, secp256k1, CompressedPublicKey, Txid};
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

// Re-export types from submodules for convenience
pub use psbt_wallet_input::{InputScriptType, ParsedInput, ScriptId};
pub use psbt_wallet_output::ParsedOutput;

/// Parsed transaction with wallet information
#[derive(Debug, Clone)]
pub struct ParsedTransaction {
    pub inputs: Vec<ParsedInput>,
    pub outputs: Vec<ParsedOutput>,
    pub spend_amount: u64,
    pub miner_fee: u64,
    pub virtual_size: u32,
}

/// Error type for transaction parsing
#[derive(Debug)]
pub enum ParseTransactionError {
    /// Failed to parse input
    Input {
        index: usize,
        error: psbt_wallet_input::ParseInputError,
    },
    /// Input value overflow when adding to total
    InputValueOverflow { index: usize },
    /// Failed to parse output
    Output {
        index: usize,
        error: psbt_wallet_output::ParseOutputError,
    },
    /// Output value overflow when adding to total
    OutputValueOverflow { index: usize },
    /// Spend amount overflow
    SpendAmountOverflow { index: usize },
    /// Fee calculation error (outputs exceed inputs)
    FeeCalculation,
}

impl std::fmt::Display for ParseTransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseTransactionError::Input { index, error } => {
                write!(f, "Input {}: {}", index, error)
            }
            ParseTransactionError::InputValueOverflow { index } => {
                write!(f, "Input {}: value overflow", index)
            }
            ParseTransactionError::Output { index, error } => {
                write!(f, "Output {}: {}", index, error)
            }
            ParseTransactionError::OutputValueOverflow { index } => {
                write!(f, "Output {}: value overflow", index)
            }
            ParseTransactionError::SpendAmountOverflow { index } => {
                write!(f, "Output {}: spend amount overflow", index)
            }
            ParseTransactionError::FeeCalculation => {
                write!(f, "Fee calculation error: outputs exceed inputs")
            }
        }
    }
}

impl std::error::Error for ParseTransactionError {}

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

        let errors: Vec<String> = (0..num_inputs)
            .filter_map(|index| {
                self.finalize_input(secp, index)
                    .err()
                    .map(|e| format!("Input {}: {}", index, e))
            })
            .collect();

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

    /// Get the unsigned transaction ID
    pub fn unsigned_txid(&self) -> Txid {
        self.psbt().unsigned_tx.compute_txid()
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

    /// Parse inputs with wallet keys and replay protection
    ///
    /// # Arguments
    /// - `wallet_keys`: The wallet's root keys for deriving scripts
    /// - `replay_protection`: Scripts that are allowed as inputs without wallet validation
    ///
    /// # Returns
    /// - `Ok(Vec<ParsedInput>)` with parsed inputs
    /// - `Err(ParseTransactionError)` if input parsing fails
    fn parse_inputs(
        &self,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        replay_protection: &psbt_wallet_input::ReplayProtection,
    ) -> Result<Vec<ParsedInput>, ParseTransactionError> {
        let psbt = self.psbt();
        let network = self.network();

        psbt.unsigned_tx
            .input
            .iter()
            .zip(psbt.inputs.iter())
            .enumerate()
            .map(|(input_index, (tx_input, psbt_input))| {
                ParsedInput::parse(
                    psbt_input,
                    tx_input,
                    wallet_keys,
                    replay_protection,
                    network,
                )
                .map_err(|error| ParseTransactionError::Input {
                    index: input_index,
                    error,
                })
            })
            .collect()
    }

    /// Parse outputs with wallet keys to identify which outputs belong to the wallet
    ///
    /// # Arguments
    /// - `wallet_keys`: The wallet's root keys for deriving scripts
    ///
    /// # Returns
    /// - `Ok(Vec<ParsedOutput>)` with parsed outputs
    /// - `Err(ParseTransactionError)` if output parsing fails
    ///
    /// # Note
    /// This method does NOT validate wallet inputs. It only parses outputs to identify
    /// which ones belong to the provided wallet keys.
    fn parse_outputs(
        &self,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
    ) -> Result<Vec<ParsedOutput>, ParseTransactionError> {
        let psbt = self.psbt();
        let network = self.network();

        psbt.unsigned_tx
            .output
            .iter()
            .zip(psbt.outputs.iter())
            .enumerate()
            .map(|(output_index, (tx_output, psbt_output))| {
                ParsedOutput::parse(psbt_output, tx_output, wallet_keys, network).map_err(|error| {
                    ParseTransactionError::Output {
                        index: output_index,
                        error,
                    }
                })
            })
            .collect()
    }

    /// Calculate total input value from parsed inputs
    ///
    /// # Returns
    /// - `Ok(u64)` with total input value
    /// - `Err(ParseTransactionError)` if overflow occurs
    fn sum_input_values(parsed_inputs: &[ParsedInput]) -> Result<u64, ParseTransactionError> {
        parsed_inputs
            .iter()
            .enumerate()
            .try_fold(0u64, |total, (index, input)| {
                total
                    .checked_add(input.value)
                    .ok_or(ParseTransactionError::InputValueOverflow { index })
            })
    }

    /// Calculate total output value and spend amount from transaction outputs and parsed outputs
    ///
    /// # Returns
    /// - `Ok((total_value, spend_amount))` with total output value and external spend amount
    /// - `Err(ParseTransactionError)` if overflow occurs
    fn sum_output_values(
        tx_outputs: &[miniscript::bitcoin::TxOut],
        parsed_outputs: &[ParsedOutput],
    ) -> Result<(u64, u64), ParseTransactionError> {
        tx_outputs
            .iter()
            .zip(parsed_outputs.iter())
            .enumerate()
            .try_fold(
                (0u64, 0u64),
                |(total_value, spend), (index, (tx_output, parsed_output))| {
                    let new_total = total_value
                        .checked_add(tx_output.value.to_sat())
                        .ok_or(ParseTransactionError::OutputValueOverflow { index })?;

                    let new_spend = if parsed_output.is_external() {
                        spend
                            .checked_add(tx_output.value.to_sat())
                            .ok_or(ParseTransactionError::SpendAmountOverflow { index })?
                    } else {
                        spend
                    };

                    Ok((new_total, new_spend))
                },
            )
    }

    /// Helper function to extract public key from a P2PK redeem script
    ///
    /// # Arguments
    /// - `redeem_script`: The redeem script to parse (expected format: <pubkey> OP_CHECKSIG)
    ///
    /// # Returns
    /// - `Ok(PublicKey)` if parsing succeeds
    /// - `Err(String)` if the script format is invalid
    fn extract_pubkey_from_p2pk_redeem_script(
        redeem_script: &miniscript::bitcoin::ScriptBuf,
    ) -> Result<miniscript::bitcoin::PublicKey, String> {
        use miniscript::bitcoin::{opcodes::all::OP_CHECKSIG, script::Instruction, PublicKey};

        // Extract public key from redeem script
        // For P2SH(P2PK), redeem_script is: <pubkey> OP_CHECKSIG
        let mut redeem_instructions = redeem_script.instructions();
        let public_key_bytes = match redeem_instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes(),
            _ => return Err("Invalid redeem script format: missing public key".to_string()),
        };

        // Verify the script ends with OP_CHECKSIG
        match redeem_instructions.next() {
            Some(Ok(Instruction::Op(op))) if op == OP_CHECKSIG => {}
            _ => return Err("Redeem script does not end with OP_CHECKSIG".to_string()),
        }

        PublicKey::from_slice(public_key_bytes).map_err(|e| format!("Invalid public key: {}", e))
    }

    /// Helper function to parse an ECDSA signature from final_script_sig
    ///
    /// # Returns
    /// - `Ok(bitcoin::ecdsa::Signature)` if parsing succeeds
    /// - `Err(String)` if parsing fails
    fn parse_signature_from_script_sig(
        final_script_sig: &miniscript::bitcoin::ScriptBuf,
    ) -> Result<miniscript::bitcoin::ecdsa::Signature, String> {
        use miniscript::bitcoin::{ecdsa::Signature, script::Instruction};

        // Extract signature from final_script_sig
        // For P2SH(P2PK), the scriptSig is: <signature> <redeemScript>
        let mut instructions = final_script_sig.instructions();
        let signature_bytes = match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes(),
            _ => return Err("Invalid final_script_sig format".to_string()),
        };

        if signature_bytes.is_empty() {
            return Err("Empty signature in final_script_sig".to_string());
        }

        Signature::from_slice(signature_bytes)
            .map_err(|e| format!("Invalid signature in final_script_sig: {}", e))
    }

    /// Verify if a replay protection input has a valid signature
    ///
    /// This method checks if a given input is a replay protection input and verifies the signature.
    /// Replay protection inputs (like P2shP2pk) don't use standard derivation paths,
    /// so this method verifies signatures without deriving from xpub.
    ///
    /// For P2PK replay protection inputs:
    /// - Extracts public key from `redeem_script`
    /// - Checks for signature in `partial_sigs` (non-finalized) or `final_script_sig` (finalized)
    /// - Computes the legacy P2SH sighash using the redeem script
    /// - Verifies the ECDSA signature
    ///
    /// # Arguments
    /// - `secp`: Secp256k1 context for signature verification
    /// - `input_index`: The index of the input to check
    /// - `replay_protection`: Replay protection configuration
    ///
    /// # Returns
    /// - `Ok(true)` if the input is a replay protection input and has a valid signature
    /// - `Ok(false)` if the input is a replay protection input but has no valid signature
    /// - `Err(String)` if the input is not a replay protection input, index is out of bounds, or verification fails
    pub fn verify_replay_protection_signature<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
        replay_protection: &psbt_wallet_input::ReplayProtection,
    ) -> Result<bool, String> {
        use miniscript::bitcoin::{hashes::Hash, sighash::SighashCache};

        let psbt = self.psbt();

        // Check input index bounds
        if input_index >= psbt.inputs.len() {
            return Err(format!("Input index {} out of bounds", input_index));
        }

        let input = &psbt.inputs[input_index];
        let prevout = psbt.unsigned_tx.input[input_index].previous_output;

        // Get output script from input
        let (output_script, _value) =
            psbt_wallet_input::get_output_script_and_value(input, prevout)
                .map_err(|e| format!("Failed to get output script: {}", e))?;

        // Verify this is a replay protection input
        if !replay_protection.is_replay_protection_input(output_script) {
            return Err(format!(
                "Input {} is not a replay protection input",
                input_index
            ));
        }

        // Get redeem script and extract public key
        let redeem_script = input
            .redeem_script
            .as_ref()
            .ok_or_else(|| "Missing redeem_script for replay protection input".to_string())?;
        let public_key = Self::extract_pubkey_from_p2pk_redeem_script(redeem_script)?;

        // Get signature from partial_sigs (non-finalized) or final_script_sig (finalized)
        // The bitcoin crate's ecdsa::Signature type contains both .signature and .sighash_type
        let ecdsa_sig = if let Some(&partial_sig) = input.partial_sigs.get(&public_key) {
            partial_sig
        } else if let Some(final_script_sig) = &input.final_script_sig {
            Self::parse_signature_from_script_sig(final_script_sig)?
        } else {
            // No signature present (neither partial nor final)
            return Ok(false);
        };

        // Compute legacy P2SH sighash
        let cache = SighashCache::new(&psbt.unsigned_tx);
        let sighash = cache
            .legacy_signature_hash(input_index, redeem_script, ecdsa_sig.sighash_type.to_u32())
            .map_err(|e| format!("Failed to compute sighash: {}", e))?;

        // Verify the signature using the bitcoin crate's built-in verification
        let message = secp256k1::Message::from_digest(sighash.to_byte_array());
        match secp.verify_ecdsa(&message, &ecdsa_sig.signature, &public_key.inner) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Helper method to verify signature with a compressed public key
    ///
    /// This method checks if a signature exists for the given public key.
    /// It handles both ECDSA and Taproot script path signatures.
    ///
    /// # Arguments
    /// - `secp`: Secp256k1 context for signature verification
    /// - `input_index`: The index of the input to check
    /// - `public_key`: The compressed public key to verify the signature for
    ///
    /// # Returns
    /// - `Ok(true)` if a valid signature exists for the public key
    /// - `Ok(false)` if no signature exists for the public key
    /// - `Err(String)` if verification fails
    fn verify_signature_with_pubkey<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
        public_key: CompressedPublicKey,
    ) -> Result<bool, String> {
        let psbt = self.psbt();

        let input = &psbt.inputs[input_index];

        // Check for Taproot script path signatures first
        if !input.tap_script_sigs.is_empty() {
            return psbt_wallet_input::verify_taproot_script_signature(
                secp,
                psbt,
                input_index,
                public_key,
            );
        }

        // Fall back to ECDSA signature verification for legacy/SegWit inputs
        psbt_wallet_input::verify_ecdsa_signature(secp, psbt, input_index, public_key)
    }

    /// Verify if a valid signature exists for a given extended public key at the specified input index
    ///
    /// This method derives the public key from the xpub using the derivation path found in the
    /// PSBT input, then verifies the signature. It supports:
    /// - ECDSA signatures (for legacy/SegWit inputs)
    /// - Schnorr signatures (for Taproot script path inputs)
    /// - MuSig2 partial signatures (for Taproot keypath MuSig2 inputs)
    ///
    /// # Arguments
    /// - `secp`: Secp256k1 context for signature verification and key derivation
    /// - `input_index`: The index of the input to check
    /// - `xpub`: The extended public key to derive from and verify the signature for
    ///
    /// # Returns
    /// - `Ok(true)` if a valid signature exists for the derived public key
    /// - `Ok(false)` if no signature exists for the derived public key
    /// - `Err(String)` if the input index is out of bounds, derivation fails, or verification fails
    pub fn verify_signature_with_xpub<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
        xpub: &miniscript::bitcoin::bip32::Xpub,
    ) -> Result<bool, String> {
        let psbt = self.psbt();

        // Check input index bounds
        if input_index >= psbt.inputs.len() {
            return Err(format!("Input index {} out of bounds", input_index));
        }

        let input = &psbt.inputs[input_index];

        // Handle MuSig2 inputs early - they use proprietary fields for partial signatures
        if p2tr_musig2_input::Musig2Input::is_musig2_input(input) {
            // Parse MuSig2 data from input
            let musig2_input = p2tr_musig2_input::Musig2Input::from_input(input)
                .map_err(|e| format!("Failed to parse MuSig2 input: {}", e))?;

            // Derive the public key for this input using tap_key_origins
            // If this xpub doesn't match any tap_key_origins, return false (e.g., backup key)
            let derived_xpub =
                match p2tr_musig2_input::derive_xpub_for_input_tap(xpub, &input.tap_key_origins) {
                    Ok(xpub) => xpub,
                    Err(_) => return Ok(false), // This xpub doesn't match
                };
            let derived_pubkey = derived_xpub.to_pub();

            // Check if this public key has a partial signature in the MuSig2 proprietary fields
            let has_partial_sig = musig2_input
                .partial_sigs
                .iter()
                .any(|sig| sig.participant_pub_key == derived_pubkey);

            return Ok(has_partial_sig);
        }

        // For non-MuSig2 inputs, use standard derivation
        // Derive the public key from xpub using derivation path in PSBT
        let derived_pubkey = match psbt_wallet_input::derive_pubkey_from_input(secp, xpub, input)? {
            Some(pubkey) => pubkey,
            None => return Ok(false), // No matching derivation path for this xpub
        };

        // Convert to CompressedPublicKey for verification
        let public_key = CompressedPublicKey::from_slice(&derived_pubkey.serialize())
            .map_err(|e| format!("Failed to convert derived key: {}", e))?;

        // Verify signature with the derived public key
        self.verify_signature_with_pubkey(secp, input_index, public_key)
    }

    /// Verify if a valid signature exists for a given public key at the specified input index
    ///
    /// This method verifies the signature directly with the provided public key. It supports:
    /// - ECDSA signatures (for legacy/SegWit inputs)
    /// - Schnorr signatures (for Taproot script path inputs)
    ///
    /// Note: This method does NOT support MuSig2 inputs, as MuSig2 requires derivation from xpubs.
    /// Use `verify_signature_with_xpub` for MuSig2 inputs.
    ///
    /// # Arguments
    /// - `secp`: Secp256k1 context for signature verification
    /// - `input_index`: The index of the input to check
    /// - `pubkey`: The secp256k1 public key
    ///
    /// # Returns
    /// - `Ok(true)` if a valid signature exists for the public key
    /// - `Ok(false)` if no signature exists for the public key
    /// - `Err(String)` if the input index is out of bounds or verification fails
    pub fn verify_signature_with_pub<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
        pubkey: &secp256k1::PublicKey,
    ) -> Result<bool, String> {
        let psbt = self.psbt();

        // Check input index bounds
        if input_index >= psbt.inputs.len() {
            return Err(format!("Input index {} out of bounds", input_index));
        }

        // Convert secp256k1::PublicKey to CompressedPublicKey
        let public_key = CompressedPublicKey::from_slice(&pubkey.serialize())
            .map_err(|e| format!("Failed to convert public key: {}", e))?;

        // Verify signature with the public key
        self.verify_signature_with_pubkey(secp, input_index, public_key)
    }

    /// Parse outputs with wallet keys to identify which outputs belong to a particular wallet.
    ///
    /// This is useful in cases where we want to identify outputs that belong to a different
    /// wallet than the inputs.
    ///
    /// If you only want to identify change outputs, use `parse_transaction_with_wallet_keys` instead.
    ///
    /// # Arguments
    /// - `wallet_keys`: A wallet's root keys for deriving scripts (can be different wallet than the inputs)
    ///
    /// # Returns
    /// - `Ok(Vec<ParsedOutput>)` with parsed outputs
    /// - `Err(ParseTransactionError)` if output parsing fails
    ///
    /// # Note
    /// This method does NOT validate wallet inputs. It only parses outputs to identify
    /// which ones belong to the provided wallet keys.
    pub fn parse_outputs_with_wallet_keys(
        &self,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
    ) -> Result<Vec<ParsedOutput>, ParseTransactionError> {
        self.parse_outputs(wallet_keys)
    }

    /// Parse transaction with wallet keys to identify wallet inputs/outputs and calculate metrics
    ///
    /// # Arguments
    /// - `wallet_keys`: The wallet's root keys for deriving scripts
    /// - `replay_protection`: Scripts that are allowed as inputs without wallet validation
    ///
    /// # Returns
    /// - `Ok(ParsedTransaction)` with parsed inputs, outputs, spend amount, fee, and size
    /// - `Err(ParseTransactionError)` if input validation fails or required data is missing
    pub fn parse_transaction_with_wallet_keys(
        &self,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        replay_protection: &psbt_wallet_input::ReplayProtection,
    ) -> Result<ParsedTransaction, ParseTransactionError> {
        let psbt = self.psbt();

        // Parse inputs and outputs
        let parsed_inputs = self.parse_inputs(wallet_keys, replay_protection)?;
        let parsed_outputs = self.parse_outputs(wallet_keys)?;

        // Calculate totals
        let total_input_value = Self::sum_input_values(&parsed_inputs)?;
        let (total_output_value, spend_amount) =
            Self::sum_output_values(&psbt.unsigned_tx.output, &parsed_outputs)?;

        // Calculate miner fee
        let miner_fee = total_input_value
            .checked_sub(total_output_value)
            .ok_or(ParseTransactionError::FeeCalculation)?;

        // Calculate virtual size from unsigned transaction weight
        // TODO: Consider using finalized transaction size estimate for more accurate fee calculation
        let weight = psbt.unsigned_tx.weight();
        let virtual_size = weight.to_vbytes_ceil();

        Ok(ParsedTransaction {
            inputs: parsed_inputs,
            outputs: parsed_outputs,
            spend_amount,
            miner_fee,
            virtual_size: virtual_size as u32,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_script_wallet::Chain;
    use crate::fixed_script_wallet::RootWalletKeys;
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
            fixtures::ScriptType::P2shP2pk => {
                // In production, these will be signed by BitGo
                assert_eq!(signed_input.partial_sigs.len(), 0);
            }
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

    fn assert_replay_protection_signature(
        bitgo_psbt: &BitGoPsbt,
        _wallet_keys: &fixtures::XprvTriple,
        input_index: usize,
    ) -> Result<(), String> {
        let secp = secp256k1::Secp256k1::new();
        let psbt = bitgo_psbt.psbt();

        if input_index >= psbt.inputs.len() {
            return Err(format!("Input index {} out of bounds", input_index));
        }

        let input = &psbt.inputs[input_index];
        let prevout = psbt.unsigned_tx.input[input_index].previous_output;

        // Get the output script from the input
        let (output_script, _value) =
            psbt_wallet_input::get_output_script_and_value(input, prevout)
                .map_err(|e| format!("Failed to get output script: {}", e))?;

        // Create replay protection with this output script
        let replay_protection =
            psbt_wallet_input::ReplayProtection::new(vec![output_script.clone()]);

        // Verify the signature exists and is valid
        let has_valid_signature = bitgo_psbt.verify_replay_protection_signature(
            &secp,
            input_index,
            &replay_protection,
        )?;

        if !has_valid_signature {
            return Err(format!(
                "Replay protection input {} does not have a valid signature",
                input_index
            ));
        }

        Ok(())
    }

    fn assert_signature_count(
        bitgo_psbt: &BitGoPsbt,
        wallet_keys: &RootWalletKeys,
        input_index: usize,
        expected_count: usize,
        stage_name: &str,
    ) -> Result<(), String> {
        // Use verify_signature_with_xpub to count valid signatures for all input types
        // This now handles MuSig2, ECDSA, and Schnorr signatures uniformly
        let secp = secp256k1::Secp256k1::new();
        let mut signature_count = 0;
        for xpub in &wallet_keys.xpubs {
            match bitgo_psbt.verify_signature_with_xpub(&secp, input_index, xpub) {
                Ok(true) => signature_count += 1,
                Ok(false) => {}          // No signature for this key
                Err(e) => return Err(e), // Propagate other errors
            }
        }

        if signature_count != expected_count {
            return Err(format!(
                "{} input {} should have {} signature(s), found {}",
                stage_name, input_index, expected_count, signature_count
            ));
        }

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

        let halfsigned_bitgo_psbt = psbt_stages
            .halfsigned
            .to_bitgo_psbt(network)
            .expect("Failed to convert to BitGo PSBT");

        let fullsigned_bitgo_psbt = psbt_stages
            .fullsigned
            .to_bitgo_psbt(network)
            .expect("Failed to convert to BitGo PSBT");

        assert_half_sign(
            script_type,
            &psbt_stages
                .unsigned
                .to_bitgo_psbt(network)
                .expect("Failed to convert to BitGo PSBT"),
            &halfsigned_bitgo_psbt,
            &psbt_input_stages.wallet_keys,
            psbt_input_stages.input_index,
        )?;

        let wallet_keys = psbt_input_stages.wallet_keys.to_root_wallet_keys();

        // Verify halfsigned PSBT has exactly 1 signature
        assert_signature_count(
            &halfsigned_bitgo_psbt,
            &wallet_keys,
            psbt_input_stages.input_index,
            if matches!(script_type, fixtures::ScriptType::P2shP2pk) {
                // p2shP2pk inputs are signed at the halfsigned stage with replay protection
                0
            } else {
                1
            },
            "Halfsigned",
        )?;

        if matches!(script_type, fixtures::ScriptType::P2shP2pk) {
            // Replay protection inputs are signed at the halfsigned stage
            assert_replay_protection_signature(
                &halfsigned_bitgo_psbt,
                &psbt_input_stages.wallet_keys,
                psbt_input_stages.input_index,
            )?;
            // They remain signed at the fullsigned stage
            assert_replay_protection_signature(
                &fullsigned_bitgo_psbt,
                &psbt_input_stages.wallet_keys,
                psbt_input_stages.input_index,
            )?;
        } else {
            assert_full_signed_matches_wallet_scripts(
                network,
                tx_format,
                &psbt_stages.fullsigned,
                &psbt_input_stages.wallet_keys,
                psbt_input_stages.input_index,
                &psbt_input_stages.input_fixture_fullsigned,
            )?;
        }

        // Verify fullsigned PSBT has exactly 2 signatures
        assert_signature_count(
            &fullsigned_bitgo_psbt,
            &wallet_keys,
            psbt_input_stages.input_index,
            if matches!(script_type, fixtures::ScriptType::P2shP2pk) {
                0
            } else {
                2
            },
            "Fullsigned",
        )?;

        assert_finalize_input(
            fullsigned_bitgo_psbt,
            psbt_input_stages.input_index,
            network,
            tx_format,
        )?;

        Ok(())
    }

    crate::test_psbt_fixtures!(test_p2sh_p2pk_suite, network, format, {
        test_wallet_script_type(fixtures::ScriptType::P2shP2pk, network, format).unwrap();
    }, ignore: [
        // TODO: sighash support
        BitcoinCash, Ecash, BitcoinGold,
        // TODO: zec support
        Zcash,
        ]);

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

    crate::test_psbt_fixtures!(
        test_p2tr_legacy_script_path_suite,
        network,
        format,
        {
            test_wallet_script_type(fixtures::ScriptType::P2trLegacyScriptPath, network, format)
                .unwrap();
        },
        ignore: [BitcoinCash, Ecash, BitcoinGold, Dash, Dogecoin, Litecoin, Zcash]
    );

    crate::test_psbt_fixtures!(
        test_p2tr_musig2_script_path_suite,
        network,
        format,
        {
            test_wallet_script_type(fixtures::ScriptType::P2trMusig2ScriptPath, network, format)
                .unwrap();
        },
        ignore: [BitcoinCash, Ecash, BitcoinGold, Dash, Dogecoin, Litecoin, Zcash]
    );

    crate::test_psbt_fixtures!(
        test_p2tr_musig2_key_path_suite,
        network,
        format,
        {
            test_wallet_script_type(
                fixtures::ScriptType::P2trMusig2TaprootKeypath,
                network,
                format,
            )
            .unwrap();
        },
        ignore: [BitcoinCash, Ecash, BitcoinGold, Dash, Dogecoin, Litecoin, Zcash]
    );

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

    crate::test_psbt_fixtures!(test_parse_transaction_with_wallet_keys, network, format, {
        // Load fixture and get PSBT
        let fixture = fixtures::load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            fixtures::SignatureState::Unsigned,
            format,
        )
        .expect("Failed to load fixture");
        
        let bitgo_psbt = fixture
            .to_bitgo_psbt(network)
            .expect("Failed to convert to BitGo PSBT");
        
        // Get wallet keys from fixture
        let wallet_xprv = fixture
            .get_wallet_xprvs()
            .expect("Failed to get wallet keys");
        let wallet_keys = wallet_xprv.to_root_wallet_keys();
        
        // Create replay protection with the replay protection script from fixture
        let replay_protection = psbt_wallet_input::ReplayProtection::new(vec![
            miniscript::bitcoin::ScriptBuf::from_hex("a91420b37094d82a513451ff0ccd9db23aba05bc5ef387")
                .expect("Failed to parse replay protection output script"),
        ]);
        
        // Parse the transaction
        let parsed = bitgo_psbt
            .parse_transaction_with_wallet_keys(&wallet_keys, &replay_protection)
            .expect("Failed to parse transaction");
        
        // Basic validations
        assert!(!parsed.inputs.is_empty(), "Should have at least one input");
        assert!(!parsed.outputs.is_empty(), "Should have at least one output");
        
        // Verify at least one replay protection input exists
        let replay_protection_inputs = parsed
            .inputs
            .iter()
            .filter(|i| i.script_id.is_none())
            .count();
        assert!(
            replay_protection_inputs > 0,
            "Should have at least one replay protection input"
        );
        
        // Verify at least one wallet input exists
        let wallet_inputs = parsed
            .inputs
            .iter()
            .filter(|i| i.script_id.is_some())
            .count();
        assert!(
            wallet_inputs > 0,
            "Should have at least one wallet input"
        );
        
        // Count internal (wallet) and external outputs
        let internal_outputs = parsed
            .outputs
            .iter()
            .filter(|o| o.script_id.is_some())
            .count();
        let external_outputs = parsed
            .outputs
            .iter()
            .filter(|o| o.script_id.is_none())
            .count();
        
        assert_eq!(
            internal_outputs + external_outputs,
            parsed.outputs.len(),
            "All outputs should be either internal or external"
        );
        
        // Verify spend amount only includes external outputs
        let calculated_spend_amount: u64 = parsed
            .outputs
            .iter()
            .filter(|o| o.script_id.is_none())
            .map(|o| o.value)
            .sum();
        assert_eq!(
            parsed.spend_amount, calculated_spend_amount,
            "Spend amount should equal sum of external output values"
        );
        
        // Verify total values
        let total_input_value: u64 = parsed.inputs.iter().map(|i| i.value).sum();
        let total_output_value: u64 = parsed.outputs.iter().map(|o| o.value).sum();
        
        assert_eq!(
            parsed.miner_fee,
            total_input_value - total_output_value,
            "Miner fee should equal inputs minus outputs"
        );
        
        // Verify virtual size is reasonable
        assert!(
            parsed.virtual_size > 0,
            "Virtual size should be greater than 0"
        );
        
        // Verify outputs (fixtures now have 3 external outputs)
        assert_eq!(
            external_outputs, 3,
            "Test fixtures should have 3 external outputs"
        );
        assert_eq!(
            internal_outputs + external_outputs,
            parsed.outputs.len(),
            "Internal + external should equal total outputs"
        );
        assert!(
            parsed.spend_amount > 0,
            "Spend amount should be greater than 0 when there are external outputs"
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
