//! Legacy transaction format extraction for half-signed transactions.
//!
//! This module provides functionality to extract half-signed transactions in the
//! legacy format used by utxo-lib and bitcoinjs-lib, where signatures are placed
//! in scriptSig/witness with OP_0 placeholders for missing signatures.

use crate::fixed_script_wallet::wallet_scripts::{parse_multisig_script_2_of_3, parse_p2pk_script};
use miniscript::bitcoin::blockdata::opcodes::all::OP_PUSHBYTES_0;
use miniscript::bitcoin::blockdata::script::Builder;
use miniscript::bitcoin::ecdsa::Signature as EcdsaSig;
use miniscript::bitcoin::psbt::Psbt;
use miniscript::bitcoin::script::PushBytesBuf;
use miniscript::bitcoin::{CompressedPublicKey, ScriptBuf, Transaction, TxIn, Witness};

/// Build a half-signed transaction in legacy format from a PSBT.
///
/// Returns the Transaction with signatures placed in scriptSig/witness.
/// Use `extract_half_signed_legacy_tx` for serialized bytes.
pub fn build_half_signed_legacy_tx(psbt: &Psbt) -> Result<Transaction, String> {
    // Validate we have inputs and outputs
    if psbt.inputs.is_empty() || psbt.unsigned_tx.output.is_empty() {
        return Err("empty inputs or outputs".to_string());
    }

    // Clone the unsigned transaction - we'll set scriptSig/witness on this
    let mut tx = psbt.unsigned_tx.clone();

    for (input_index, psbt_input) in psbt.inputs.iter().enumerate() {
        // Determine script type and get the redeem/multisig script
        let (is_p2sh, is_p2wsh, redeem_or_multisig_script) =
            if let Some(ref witness_script) = psbt_input.witness_script {
                // p2wsh or p2shP2wsh - witness_script contains the multisig script
                let is_p2sh = psbt_input.redeem_script.is_some();
                (is_p2sh, true, witness_script.clone())
            } else if let Some(ref redeem_script) = psbt_input.redeem_script {
                // p2sh only - redeem_script may be multisig or P2PK (replay protection)
                (true, false, redeem_script.clone())
            } else {
                return Err(format!(
                "Input {}: unsupported script type (no witness_script or redeem_script found). \
                 Only p2ms-based types (p2sh, p2shP2wsh, p2wsh) and P2SH-P2PK are supported.",
                input_index
            ));
            };

        // Check for taproot inputs (not supported)
        if !psbt_input.tap_script_sigs.is_empty() || !psbt_input.tap_key_origins.is_empty() {
            return Err(format!(
                "Input {}: Taproot inputs are not supported in legacy half-signed format",
                input_index
            ));
        }

        // Try to parse as 2-of-3 multisig first
        if let Ok(pubkeys) = parse_multisig_script_2_of_3(&redeem_or_multisig_script) {
            // Multisig wallet input: require exactly 1 partial signature
            let sig_count = psbt_input.partial_sigs.len();
            if sig_count != 1 {
                return Err(format!(
                    "Input {}: expected exactly 1 partial signature, got {}",
                    input_index, sig_count
                ));
            }

            let (sig_pubkey, ecdsa_sig) = psbt_input.partial_sigs.iter().next().unwrap();

            // Find which key index (0, 1, 2) matches the signature's pubkey
            let sig_key_index = pubkeys
                .iter()
                .position(|pk| pk.to_bytes() == sig_pubkey.to_bytes()[..])
                .ok_or_else(|| {
                    format!(
                        "Input {}: signature pubkey not found in multisig script",
                        input_index
                    )
                })?;

            let sig_bytes = ecdsa_sig.to_vec();

            // Build the signatures array with the signature in the correct position
            // Format: [OP_0, sig_or_empty, sig_or_empty, sig_or_empty]
            let mut sig_stack: Vec<Vec<u8>> = vec![vec![]]; // Start with OP_0 (empty)
            for i in 0..3 {
                if i == sig_key_index {
                    sig_stack.push(sig_bytes.clone());
                } else {
                    sig_stack.push(vec![]); // OP_0 placeholder
                }
            }

            // Build scriptSig and/or witness based on script type
            if is_p2wsh {
                // p2wsh or p2shP2wsh: witness = [empty, sigs..., witnessScript]
                let mut witness_items = sig_stack;
                witness_items.push(redeem_or_multisig_script.to_bytes());
                tx.input[input_index].witness = Witness::from_slice(&witness_items);

                if is_p2sh {
                    // p2shP2wsh: also need scriptSig = [redeemScript]
                    let redeem_script = psbt_input.redeem_script.as_ref().unwrap();
                    let redeem_script_bytes = PushBytesBuf::try_from(redeem_script.to_bytes())
                        .map_err(|e| {
                            format!(
                                "Input {}: failed to convert redeem script to push bytes: {}",
                                input_index, e
                            )
                        })?;
                    let script_sig = Builder::new().push_slice(redeem_script_bytes).into_script();
                    tx.input[input_index].script_sig = script_sig;
                }
            } else {
                // p2sh only: scriptSig = [OP_0, sigs..., redeemScript]
                let mut builder = Builder::new().push_opcode(OP_PUSHBYTES_0);
                for i in 0..3 {
                    if i == sig_key_index {
                        let sig_push_bytes =
                            PushBytesBuf::try_from(sig_bytes.clone()).map_err(|e| {
                                format!(
                                    "Input {}: failed to convert signature to push bytes: {}",
                                    input_index, e
                                )
                            })?;
                        builder = builder.push_slice(sig_push_bytes);
                    } else {
                        builder = builder.push_opcode(OP_PUSHBYTES_0);
                    }
                }
                let multisig_push_bytes =
                    PushBytesBuf::try_from(redeem_or_multisig_script.to_bytes()).map_err(|e| {
                        format!(
                            "Input {}: failed to convert multisig script to push bytes: {}",
                            input_index, e
                        )
                    })?;
                builder = builder.push_slice(multisig_push_bytes);
                tx.input[input_index].script_sig = builder.into_script();
            }
        } else if parse_p2pk_script(&redeem_or_multisig_script).is_some() {
            // P2SH-P2PK replay protection input: 0 or 1 partial sigs allowed
            let sig_count = psbt_input.partial_sigs.len();
            if sig_count > 1 {
                return Err(format!(
                    "Input {}: P2SH-P2PK replay protection input has {} signatures, expected 0 or 1",
                    input_index, sig_count
                ));
            }

            let redeem_push_bytes = PushBytesBuf::try_from(redeem_or_multisig_script.to_bytes())
                .map_err(|e| {
                    format!(
                        "Input {}: failed to convert P2PK redeem script to push bytes: {}",
                        input_index, e
                    )
                })?;

            let script_sig = if sig_count == 1 {
                // Signed: scriptSig = <sig> <redeemScript>
                let (_, ecdsa_sig) = psbt_input.partial_sigs.iter().next().unwrap();
                let sig_bytes = ecdsa_sig.to_vec();
                let sig_push_bytes = PushBytesBuf::try_from(sig_bytes).map_err(|e| {
                    format!(
                        "Input {}: failed to convert RP signature to push bytes: {}",
                        input_index, e
                    )
                })?;
                Builder::new()
                    .push_slice(sig_push_bytes)
                    .push_slice(redeem_push_bytes)
                    .into_script()
            } else {
                // Unsigned: scriptSig = OP_0 <redeemScript>
                Builder::new()
                    .push_opcode(OP_PUSHBYTES_0)
                    .push_slice(redeem_push_bytes)
                    .into_script()
            };
            tx.input[input_index].script_sig = script_sig;
        } else {
            return Err(format!(
                "Input {}: redeem_script is neither a valid 2-of-3 multisig nor a P2PK script",
                input_index
            ));
        }
    }

    Ok(tx)
}

/// A partial signature extracted from a legacy half-signed input.
pub struct LegacyPartialSig {
    pub pubkey: CompressedPublicKey,
    pub sig: EcdsaSig,
}

/// The result of parsing a legacy input — either a multisig wallet input or a
/// P2SH-P2PK replay protection input.
pub enum LegacyInputResult {
    /// Standard p2ms wallet input (p2sh, p2shP2wsh, p2wsh) with exactly 1 sig.
    Multisig(LegacyPartialSig),
    /// P2SH-P2PK replay protection input with the pubkey and an optional signature
    /// (None when the input was serialized unsigned with an OP_0 placeholder).
    ReplayProtection {
        pubkey: CompressedPublicKey,
        sig: Option<EcdsaSig>,
    },
}

/// Determines whether a legacy input uses segwit (witness data) and whether it
/// has a p2sh wrapper (scriptSig pushing a redeem script).
///
/// Returns `(is_p2sh, is_segwit, multisig_script)`.
fn classify_legacy_input(tx_in: &TxIn) -> Result<(bool, bool, ScriptBuf), String> {
    let has_witness = !tx_in.witness.is_empty();
    let has_script_sig = !tx_in.script_sig.is_empty();

    if has_witness {
        // Segwit: witness contains [empty, sig0?, sig1?, sig2?, witnessScript]
        let witness_items: Vec<&[u8]> = tx_in.witness.iter().collect();
        if witness_items.len() < 5 {
            return Err(format!(
                "Expected at least 5 witness items, got {}",
                witness_items.len()
            ));
        }
        let multisig_script = ScriptBuf::from(witness_items.last().unwrap().to_vec());
        let is_p2sh = has_script_sig; // p2shP2wsh has scriptSig, p2wsh does not
        Ok((is_p2sh, true, multisig_script))
    } else if has_script_sig {
        // p2sh: scriptSig items vary by type (multisig: ≥5 items, P2PK: 2 items)
        let instructions: Vec<_> = tx_in
            .script_sig
            .instructions()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse scriptSig: {}", e))?;
        if instructions.len() < 2 {
            return Err(format!(
                "Expected at least 2 scriptSig items, got {}",
                instructions.len()
            ));
        }
        let last = instructions.last().unwrap();
        let redeem_bytes = match last {
            miniscript::bitcoin::script::Instruction::PushBytes(bytes) => bytes.as_bytes(),
            _ => return Err("Last scriptSig item is not a push".to_string()),
        };
        Ok((true, false, ScriptBuf::from(redeem_bytes.to_vec())))
    } else {
        Err("Input has neither witness nor scriptSig".to_string())
    }
}

/// Parse a legacy half-signed input and return either a multisig or replay protection result.
///
/// This is the inverse of the signature placement in `build_half_signed_legacy_tx`.
pub fn parse_legacy_input(tx_in: &TxIn) -> Result<LegacyInputResult, String> {
    let (_, is_segwit, redeem_or_multisig_script) = classify_legacy_input(tx_in)?;

    // Try to parse as multisig first
    if let Ok(pubkeys) = parse_multisig_script_2_of_3(&redeem_or_multisig_script) {
        // Extract the 3 signature slots (index 1..=3, skipping the leading OP_0/empty)
        let sig_slots: Vec<Vec<u8>> = if is_segwit {
            let items: Vec<&[u8]> = tx_in.witness.iter().collect();
            if items.len() < 5 {
                return Err(format!(
                    "Expected at least 5 witness items for multisig, got {}",
                    items.len()
                ));
            }
            // witness = [empty, sig0?, sig1?, sig2?, witnessScript]
            items[1..=3].iter().map(|s| s.to_vec()).collect()
        } else {
            // scriptSig = [OP_0, sig0?, sig1?, sig2?, redeemScript]
            let instructions: Vec<_> = tx_in
                .script_sig
                .instructions()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("Failed to parse scriptSig: {}", e))?;
            if instructions.len() < 5 {
                return Err(format!(
                    "Expected at least 5 scriptSig items for multisig, got {}",
                    instructions.len()
                ));
            }
            // instructions[0] = OP_0, [1..=3] = sigs, [4] = redeemScript
            instructions[1..=3]
                .iter()
                .map(|inst| match inst {
                    miniscript::bitcoin::script::Instruction::PushBytes(bytes) => {
                        bytes.as_bytes().to_vec()
                    }
                    miniscript::bitcoin::script::Instruction::Op(_) => vec![],
                })
                .collect()
        };

        // Find the non-empty signature slot
        let mut found_sig = None;
        for (i, slot) in sig_slots.iter().enumerate() {
            if !slot.is_empty() {
                if found_sig.is_some() {
                    return Err("Expected exactly 1 signature, found multiple".to_string());
                }
                let sig = EcdsaSig::from_slice(slot)
                    .map_err(|e| format!("Failed to parse signature at position {}: {}", i, e))?;
                let pubkey = CompressedPublicKey::from_slice(&pubkeys[i].to_bytes())
                    .map_err(|e| format!("Failed to convert pubkey: {}", e))?;
                found_sig = Some(LegacyPartialSig { pubkey, sig });
            }
        }

        let sig = found_sig.ok_or_else(|| "No signature found in multisig input".to_string())?;
        Ok(LegacyInputResult::Multisig(sig))
    } else if let Some(pubkey) = parse_p2pk_script(&redeem_or_multisig_script) {
        // P2SH-P2PK replay protection input
        // scriptSig = [<sig_or_OP_0> <redeemScript>]
        let instructions: Vec<_> = tx_in
            .script_sig
            .instructions()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse P2PK scriptSig: {}", e))?;

        // instructions[0] = sig or OP_0 placeholder, instructions[1] = redeemScript
        let sig = match instructions.first() {
            Some(miniscript::bitcoin::script::Instruction::PushBytes(bytes))
                if !bytes.is_empty() =>
            {
                let ecdsa_sig = EcdsaSig::from_slice(bytes.as_bytes())
                    .map_err(|e| format!("Failed to parse P2PK signature: {}", e))?;
                Some(ecdsa_sig)
            }
            _ => None, // OP_0 or empty push = unsigned placeholder
        };

        Ok(LegacyInputResult::ReplayProtection { pubkey, sig })
    } else {
        Err(
            "scriptSig/witness does not correspond to a known script type \
             (multisig 2-of-3 or P2SH-P2PK)"
                .to_string(),
        )
    }
}
