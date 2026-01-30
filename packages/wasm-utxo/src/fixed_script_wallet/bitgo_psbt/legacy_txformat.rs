//! Legacy transaction format extraction for half-signed transactions.
//!
//! This module provides functionality to extract half-signed transactions in the
//! legacy format used by utxo-lib and bitcoinjs-lib, where signatures are placed
//! in scriptSig/witness with OP_0 placeholders for missing signatures.

use crate::fixed_script_wallet::wallet_scripts::parse_multisig_script_2_of_3;
use miniscript::bitcoin::blockdata::opcodes::all::OP_PUSHBYTES_0;
use miniscript::bitcoin::blockdata::script::Builder;
use miniscript::bitcoin::psbt::Psbt;
use miniscript::bitcoin::script::PushBytesBuf;
use miniscript::bitcoin::{Transaction, Witness};

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
        // Determine script type and get the multisig script
        let (is_p2sh, is_p2wsh, multisig_script) =
            if let Some(ref witness_script) = psbt_input.witness_script {
                // p2wsh or p2shP2wsh - witness_script contains the multisig script
                let is_p2sh = psbt_input.redeem_script.is_some();
                (is_p2sh, true, witness_script.clone())
            } else if let Some(ref redeem_script) = psbt_input.redeem_script {
                // p2sh only - redeem_script contains the multisig script
                (true, false, redeem_script.clone())
            } else {
                return Err(format!(
                "Input {}: unsupported script type (no witness_script or redeem_script found). \
                 Only p2ms-based types (p2sh, p2shP2wsh, p2wsh) are supported.",
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

        // Validate exactly 1 partial signature
        let sig_count = psbt_input.partial_sigs.len();
        if sig_count != 1 {
            return Err(format!(
                "Input {}: expected exactly 1 partial signature, got {}",
                input_index, sig_count
            ));
        }

        // Get the single partial signature
        let (sig_pubkey, ecdsa_sig) = psbt_input.partial_sigs.iter().next().unwrap();

        // Parse the multisig script to get the 3 public keys
        let pubkeys = parse_multisig_script_2_of_3(&multisig_script).map_err(|e| {
            format!(
                "Input {}: failed to parse multisig script: {}",
                input_index, e
            )
        })?;

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

        // Serialize the signature
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
            witness_items.push(multisig_script.to_bytes());
            tx.input[input_index].witness = Witness::from_slice(&witness_items);

            if is_p2sh {
                // p2shP2wsh: also need scriptSig = [redeemScript]
                // The redeemScript is the p2wsh script (hash of witness script)
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
                PushBytesBuf::try_from(multisig_script.to_bytes()).map_err(|e| {
                    format!(
                        "Input {}: failed to convert multisig script to push bytes: {}",
                        input_index, e
                    )
                })?;
            builder = builder.push_slice(multisig_push_bytes);
            tx.input[input_index].script_sig = builder.into_script();
        }
    }

    Ok(tx)
}
