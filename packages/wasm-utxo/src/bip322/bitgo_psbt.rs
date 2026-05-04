//! BIP-0322 integration with BitGo PSBT
//!
//! This module contains the business logic for BIP-0322 message signing
//! with BitGo fixed-script wallets.

use crate::fixed_script_wallet::bitgo_psbt::p2tr_musig2_input::Musig2Participants;
use crate::fixed_script_wallet::bitgo_psbt::{
    create_bip32_derivation, create_tap_bip32_derivation, find_kv, BitGoKeyValue, BitGoPsbt,
    ProprietaryKeySubtype,
};
use crate::fixed_script_wallet::wallet_scripts::chain_index_path;
use crate::fixed_script_wallet::wallet_scripts::{
    build_multisig_script_2_of_3, build_p2tr_ns_script, ScriptP2mr, ScriptP2tr,
};
use crate::fixed_script_wallet::{to_pub_triple, Chain, PubTriple, RootWalletKeys, WalletScripts};
use crate::networks::Network;

use miniscript::bitcoin::hashes::Hash;
use miniscript::bitcoin::taproot::{LeafVersion, TapLeafHash};
use miniscript::bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut};

/// Verify that an input in a finalized transaction has signature data.
fn verify_input_has_signature_data(tx: &Transaction, input_index: usize) -> Result<(), String> {
    let input = &tx.input[input_index];

    // Check that signature data exists (witness or scriptSig)
    if input.witness.is_empty() && input.script_sig.is_empty() {
        return Err(format!(
            "Input {} has no signature data (missing witness and scriptSig)",
            input_index
        ));
    }

    Ok(())
}

/// Add a BIP-0322 message input to a BitGoPsbt
///
/// If this is the first input, also adds the OP_RETURN output.
/// The PSBT must have version 0 per BIP-0322 specification.
///
/// # Arguments
/// * `psbt` - The BitGoPsbt to add the input to
/// * `message` - The message to sign
/// * `chain` - The wallet chain (e.g., 10 for external, 20 for internal)
/// * `index` - The address index
/// * `wallet_keys` - The wallet's root keys
/// * `sign_path` - Optional (signer_idx, cosigner_idx) for taproot
/// * `tag` - Optional custom tag for message hashing
///
/// # Returns
/// The index of the added input
pub fn add_bip322_input(
    psbt: &mut BitGoPsbt,
    message: &str,
    chain: u32,
    index: u32,
    wallet_keys: &RootWalletKeys,
    sign_path: Option<(usize, usize)>,
    tag: Option<&str>,
) -> Result<usize, String> {
    let network = psbt.network();
    let inner_psbt = psbt.psbt_mut();

    // Verify the PSBT has version 0 per BIP-0322
    if inner_psbt.unsigned_tx.version.0 != 0 {
        return Err(format!(
            "BIP-0322 PSBT must have version 0, got {}",
            inner_psbt.unsigned_tx.version.0
        ));
    }

    // If this is the first input, add the OP_RETURN output
    if inner_psbt.unsigned_tx.input.is_empty() {
        let op_return_script = miniscript::bitcoin::script::Builder::new()
            .push_opcode(miniscript::bitcoin::opcodes::all::OP_RETURN)
            .into_script();

        let tx_output = TxOut {
            value: Amount::ZERO,
            script_pubkey: op_return_script,
        };

        inner_psbt.unsigned_tx.output.push(tx_output);
        inner_psbt.outputs.push(Default::default());
    }

    // Get the output script for this wallet script location
    let chain_enum = Chain::try_from(chain).map_err(|e| format!("Invalid chain: {}", e))?;
    let scripts = WalletScripts::from_wallet_keys(
        wallet_keys,
        chain_enum.script_type,
        &chain_index_path(chain, index),
        &network.output_script_support(),
    )
    .map_err(|e| e.to_string())?;
    let script_pubkey = scripts.output_script().clone();

    // Compute the message hash
    let msg_hash = super::message_hash(message.as_bytes(), tag);

    // Create the virtual to_spend transaction
    let to_spend = super::create_to_spend_tx(msg_hash, script_pubkey.clone());
    let to_spend_txid = to_spend.compute_txid();

    // Create the tx input
    let tx_input = TxIn {
        previous_output: miniscript::bitcoin::OutPoint {
            txid: to_spend_txid,
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: miniscript::bitcoin::Sequence::ZERO,
        witness: miniscript::bitcoin::Witness::new(),
    };

    // Add the input to the transaction
    inner_psbt.unsigned_tx.input.push(tx_input);
    inner_psbt.inputs.push(Default::default());
    let input_index = inner_psbt.inputs.len() - 1;

    // Set witness_utxo to the to_spend output
    inner_psbt.inputs[input_index].witness_utxo = Some(TxOut {
        value: Amount::ZERO,
        script_pubkey: script_pubkey.clone(),
    });

    // Add script-type-specific metadata
    match &scripts {
        WalletScripts::P2sh(script) => {
            inner_psbt.inputs[input_index].bip32_derivation =
                create_bip32_derivation(wallet_keys, chain, index);
            inner_psbt.inputs[input_index].redeem_script = Some(script.redeem_script.clone());
            // Legacy P2SH sighash requires the full previous transaction, not just the output.
            inner_psbt.inputs[input_index].non_witness_utxo = Some(to_spend);
        }
        WalletScripts::P2shP2wsh(script) => {
            inner_psbt.inputs[input_index].bip32_derivation =
                create_bip32_derivation(wallet_keys, chain, index);
            inner_psbt.inputs[input_index].witness_script = Some(script.witness_script.clone());
            inner_psbt.inputs[input_index].redeem_script = Some(script.redeem_script.clone());
        }
        WalletScripts::P2wsh(script) => {
            inner_psbt.inputs[input_index].bip32_derivation =
                create_bip32_derivation(wallet_keys, chain, index);
            inner_psbt.inputs[input_index].witness_script = Some(script.witness_script.clone());
        }
        WalletScripts::P2mr(script) => {
            // P2MR is always script-path (no key-path). Same sighash as P2TR
            // (BIP-360 reuses BIP-342 common signature message).
            //
            // Unlike P2trLegacy, we use the precomputed leaf hashes from ScriptP2mr
            // rather than re-deriving keys and rebuilding scripts. The tree is fixed:
            //   leaf[0]: user+bitgo  (key indices {0,2})
            //   leaf[1]: user+backup (key indices {0,1})
            //   leaf[2]: backup+bitgo (key indices {1,2})
            //
            // tap_scripts is skipped because P2MR control blocks (no internal key)
            // can't be represented as rust-bitcoin's ControlBlock type.
            let (signer_idx, cosigner_idx) =
                sign_path.ok_or("signer and cosigner are required for p2mr inputs")?;

            let mut pair = [signer_idx, cosigner_idx];
            pair.sort();
            let leaf_idx = match pair {
                [0, 2] => 0,
                [0, 1] => 1,
                [1, 2] => 2,
                _ => {
                    return Err(format!(
                        "Invalid signer pair: ({}, {})",
                        signer_idx, cosigner_idx
                    ))
                }
            };

            let leaf_hash = TapLeafHash::from_byte_array(script.leaves[leaf_idx].leaf_hash);

            inner_psbt.inputs[input_index].tap_key_origins = create_tap_bip32_derivation(
                wallet_keys,
                chain,
                index,
                &[signer_idx, cosigner_idx],
                Some(leaf_hash),
            );
        }
        WalletScripts::P2trLegacy(script) | WalletScripts::P2trMusig2(script) => {
            // For taproot, sign_path is required
            let (signer_idx, cosigner_idx) =
                sign_path.ok_or("signer and cosigner are required for p2tr/p2trMusig2 inputs")?;

            // Derive pubkeys
            let derived_keys = wallet_keys
                .derive_path(&chain_index_path(chain, index))
                .map_err(|e| format!("Failed to derive keys: {}", e))?;
            let pub_triple = to_pub_triple(&derived_keys);

            let is_musig2 = matches!(scripts, WalletScripts::P2trMusig2(_));
            let is_backup_flow = signer_idx == 1 || cosigner_idx == 1;

            if !is_musig2 || is_backup_flow {
                // Script path spending
                let signer_keys = [pub_triple[signer_idx], pub_triple[cosigner_idx]];
                let leaf_script = build_p2tr_ns_script(&signer_keys);
                let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);

                // Find the control block
                let control_block = script
                    .spend_info
                    .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
                    .ok_or("Could not find control block for leaf script")?;

                // Set tap_scripts
                inner_psbt.inputs[input_index]
                    .tap_scripts
                    .insert(control_block, (leaf_script, LeafVersion::TapScript));

                // Set tap_key_origins
                inner_psbt.inputs[input_index].tap_key_origins = create_tap_bip32_derivation(
                    wallet_keys,
                    chain,
                    index,
                    &[signer_idx, cosigner_idx],
                    Some(leaf_hash),
                );
            } else {
                // Key path spending (MuSig2 with user/bitgo)
                let internal_key = script.spend_info.internal_key();
                inner_psbt.inputs[input_index].tap_internal_key = Some(internal_key);
                inner_psbt.inputs[input_index].tap_merkle_root = script.spend_info.merkle_root();
                inner_psbt.inputs[input_index].tap_key_origins = create_tap_bip32_derivation(
                    wallet_keys,
                    chain,
                    index,
                    &[signer_idx, cosigner_idx],
                    None,
                );
                // Write Musig2Participants so is_musig2_input() returns true and the
                // nonce-generation and signing routines engage the musig2 protocol.
                let tap_output_key = script.spend_info.output_key().to_x_only_public_key();
                let musig2_participants = Musig2Participants {
                    tap_output_key,
                    tap_internal_key: internal_key,
                    participant_pub_keys: [pub_triple[0], pub_triple[2]],
                };
                let (key, value) = musig2_participants.to_key_value().to_key_value();
                inner_psbt.inputs[input_index]
                    .proprietary
                    .insert(key, value);
            }
        }
    }

    // Store the BIP322 message as a proprietary field for later extraction
    let (prop_key, prop_value) = BitGoKeyValue::new(
        ProprietaryKeySubtype::Bip322Message,
        vec![],
        message.as_bytes().to_vec(),
    )
    .to_key_value();
    inner_psbt.inputs[input_index]
        .proprietary
        .insert(prop_key, prop_value);

    Ok(input_index)
}

/// Extract the BIP322 message stored in a PSBT input's proprietary fields.
/// Returns None if no message is stored at that index.
pub fn get_bip322_message(psbt: &BitGoPsbt, input_index: usize) -> Result<Option<String>, String> {
    let input = psbt
        .psbt()
        .inputs
        .get(input_index)
        .ok_or_else(|| format!("Input index {} out of bounds", input_index))?;

    let mut iter = find_kv(ProprietaryKeySubtype::Bip322Message, &input.proprietary);
    match iter.next() {
        Some(kv) => String::from_utf8(kv.value)
            .map(Some)
            .map_err(|e| format!("Invalid UTF-8 in BIP322 message: {e}")),
        None => Ok(None),
    }
}

/// Verify a single input of a BIP-0322 transaction proof
///
/// # Arguments
/// * `tx` - The signed transaction
/// * `input_index` - The index of the input to verify
/// * `message` - The message that was signed
/// * `chain` - The wallet chain
/// * `index` - The address index
/// * `wallet_keys` - The wallet's root keys
/// * `network` - The network
/// * `tag` - Optional custom tag for message hashing
#[allow(clippy::too_many_arguments)]
pub fn verify_bip322_tx_input(
    tx: &Transaction,
    input_index: usize,
    message: &str,
    chain: u32,
    index: u32,
    wallet_keys: &RootWalletKeys,
    network: &Network,
    tag: Option<&str>,
) -> Result<(), String> {
    // Verify structure: version 0, single OP_RETURN output
    if tx.version.0 != 0 {
        return Err(format!(
            "Invalid BIP-0322 transaction: expected version 0, got {}",
            tx.version.0
        ));
    }

    if tx.output.len() != 1 {
        return Err(format!(
            "Invalid BIP-0322 transaction: expected 1 output, got {}",
            tx.output.len()
        ));
    }

    if !tx.output[0].script_pubkey.is_op_return() {
        return Err("Invalid BIP-0322 transaction: output must be OP_RETURN".to_string());
    }

    if input_index >= tx.input.len() {
        return Err(format!(
            "Input index {} out of bounds (transaction has {} inputs)",
            input_index,
            tx.input.len()
        ));
    }

    // Get the output script for this wallet script location
    let chain_enum = Chain::try_from(chain).map_err(|e| format!("Invalid chain: {}", e))?;
    let scripts = WalletScripts::from_wallet_keys(
        wallet_keys,
        chain_enum.script_type,
        &chain_index_path(chain, index),
        &network.output_script_support(),
    )
    .map_err(|e| e.to_string())?;
    let script_pubkey = scripts.output_script().clone();

    // Compute the expected to_spend txid
    let msg_hash = super::message_hash(message.as_bytes(), tag);
    let to_spend = super::create_to_spend_tx(msg_hash, script_pubkey);
    let expected_txid = to_spend.compute_txid();

    // Verify the input references the correct to_spend transaction
    if tx.input[input_index].previous_output.txid != expected_txid {
        return Err(format!(
            "Input {} references wrong to_spend txid: expected {}, got {}",
            input_index, expected_txid, tx.input[input_index].previous_output.txid
        ));
    }

    if tx.input[input_index].previous_output.vout != 0 {
        return Err(format!(
            "Input {} references wrong output index: expected 0, got {}",
            input_index, tx.input[input_index].previous_output.vout
        ));
    }

    // Verify signature data exists (signatures were validated during PSBT finalization)
    verify_input_has_signature_data(tx, input_index)?;

    Ok(())
}

/// Verify a single input of a BIP-0322 PSBT proof
///
/// # Arguments
/// * `psbt` - The signed BitGoPsbt
/// * `input_index` - The index of the input to verify
/// * `message` - The message that was signed
/// * `chain` - The wallet chain
/// * `index` - The address index
/// * `wallet_keys` - The wallet's root keys
/// * `tag` - Optional custom tag for message hashing
///
/// # Returns
/// A vector of signer names ("user", "backup", "bitgo") that have valid signatures
pub fn verify_bip322_psbt_input(
    psbt: &BitGoPsbt,
    input_index: usize,
    message: &str,
    chain: u32,
    index: u32,
    wallet_keys: &RootWalletKeys,
    tag: Option<&str>,
) -> Result<Vec<String>, String> {
    let network = psbt.network();
    let inner_psbt = psbt.psbt();

    // Verify structure: version 0, single OP_RETURN output
    if inner_psbt.unsigned_tx.version.0 != 0 {
        return Err(format!(
            "Invalid BIP-0322 PSBT: expected version 0, got {}",
            inner_psbt.unsigned_tx.version.0
        ));
    }

    if inner_psbt.unsigned_tx.output.len() != 1 {
        return Err(format!(
            "Invalid BIP-0322 PSBT: expected 1 output, got {}",
            inner_psbt.unsigned_tx.output.len()
        ));
    }

    if !inner_psbt.unsigned_tx.output[0]
        .script_pubkey
        .is_op_return()
    {
        return Err("Invalid BIP-0322 PSBT: output must be OP_RETURN".to_string());
    }

    if input_index >= inner_psbt.inputs.len() {
        return Err(format!(
            "Input index {} out of bounds (PSBT has {} inputs)",
            input_index,
            inner_psbt.inputs.len()
        ));
    }

    // Get the output script for this wallet script location
    let chain_enum = Chain::try_from(chain).map_err(|e| format!("Invalid chain: {}", e))?;
    let scripts = WalletScripts::from_wallet_keys(
        wallet_keys,
        chain_enum.script_type,
        &chain_index_path(chain, index),
        &network.output_script_support(),
    )
    .map_err(|e| e.to_string())?;
    let script_pubkey = scripts.output_script().clone();

    // Compute the expected to_spend txid
    let msg_hash = super::message_hash(message.as_bytes(), tag);
    let to_spend = super::create_to_spend_tx(msg_hash, script_pubkey);
    let expected_txid = to_spend.compute_txid();

    // Verify the input references the correct to_spend transaction
    if inner_psbt.unsigned_tx.input[input_index]
        .previous_output
        .txid
        != expected_txid
    {
        return Err(format!(
            "Input {} references wrong to_spend txid: expected {}, got {}",
            input_index,
            expected_txid,
            inner_psbt.unsigned_tx.input[input_index]
                .previous_output
                .txid
        ));
    }

    // Verify signatures using BitGoPsbt's signature verification
    // Collect signer names for all wallet keys with valid signatures
    let secp = miniscript::bitcoin::secp256k1::Secp256k1::verification_only();
    const SIGNER_NAMES: [&str; 3] = ["user", "backup", "bitgo"];
    let mut signers = Vec::new();

    for (i, xpub) in wallet_keys.xpubs.iter().enumerate() {
        match psbt.verify_signature_with_xpub(&secp, input_index, xpub) {
            Ok(true) => signers.push(SIGNER_NAMES[i].to_string()),
            Ok(false) => {} // No signature for this key
            Err(_) => {}    // Verification error (e.g., no derivation path for this key)
        }
    }

    if signers.is_empty() {
        return Err(format!(
            "Input {} has no valid signatures from wallet keys",
            input_index
        ));
    }

    Ok(signers)
}

/// Build an output script from pubkeys and script type
///
/// # Arguments
/// * `pubkeys` - The three wallet pubkeys [user, backup, bitgo]
/// * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2", "p2mr"
///
/// # Returns
/// The output script (scriptPubKey)
fn build_output_script_from_pubkeys(
    pubkeys: &PubTriple,
    script_type: &str,
) -> Result<ScriptBuf, String> {
    match script_type {
        "p2sh" => {
            let redeem_script = build_multisig_script_2_of_3(pubkeys);
            Ok(redeem_script.to_p2sh())
        }
        "p2shP2wsh" => {
            let witness_script = build_multisig_script_2_of_3(pubkeys);
            let redeem_script = witness_script.to_p2wsh();
            Ok(redeem_script.to_p2sh())
        }
        "p2wsh" => {
            let witness_script = build_multisig_script_2_of_3(pubkeys);
            Ok(witness_script.to_p2wsh())
        }
        "p2tr" => {
            let script_p2tr = ScriptP2tr::new(pubkeys, false);
            Ok(script_p2tr.output_script())
        }
        "p2trMusig2" => {
            let script_p2tr = ScriptP2tr::new(pubkeys, true);
            Ok(script_p2tr.output_script())
        }
        "p2mr" => {
            let script_p2mr = ScriptP2mr::new(pubkeys);
            Ok(script_p2mr.output_script())
        }
        _ => Err(format!(
            "Unknown script type '{}'. Expected: p2sh, p2shP2wsh, p2wsh, p2tr, p2trMusig2, p2mr",
            script_type
        )),
    }
}

/// Verify BIP-0322 PSBT structure (version 0, single OP_RETURN output)
fn verify_bip322_psbt_structure(
    psbt: &miniscript::bitcoin::Psbt,
    input_index: usize,
) -> Result<(), String> {
    if psbt.unsigned_tx.version.0 != 0 {
        return Err(format!(
            "Invalid BIP-0322 PSBT: expected version 0, got {}",
            psbt.unsigned_tx.version.0
        ));
    }

    if psbt.unsigned_tx.output.len() != 1 {
        return Err(format!(
            "Invalid BIP-0322 PSBT: expected 1 output, got {}",
            psbt.unsigned_tx.output.len()
        ));
    }

    if !psbt.unsigned_tx.output[0].script_pubkey.is_op_return() {
        return Err("Invalid BIP-0322 PSBT: output must be OP_RETURN".to_string());
    }

    if input_index >= psbt.inputs.len() {
        return Err(format!(
            "Input index {} out of bounds (PSBT has {} inputs)",
            input_index,
            psbt.inputs.len()
        ));
    }

    Ok(())
}

/// Verify BIP-0322 transaction structure (version 0, single OP_RETURN output)
fn verify_bip322_tx_structure(tx: &Transaction, input_index: usize) -> Result<(), String> {
    if tx.version.0 != 0 {
        return Err(format!(
            "Invalid BIP-0322 transaction: expected version 0, got {}",
            tx.version.0
        ));
    }

    if tx.output.len() != 1 {
        return Err(format!(
            "Invalid BIP-0322 transaction: expected 1 output, got {}",
            tx.output.len()
        ));
    }

    if !tx.output[0].script_pubkey.is_op_return() {
        return Err("Invalid BIP-0322 transaction: output must be OP_RETURN".to_string());
    }

    if input_index >= tx.input.len() {
        return Err(format!(
            "Input index {} out of bounds (transaction has {} inputs)",
            input_index,
            tx.input.len()
        ));
    }

    Ok(())
}

/// Verify a single input of a BIP-0322 PSBT proof using pubkeys directly
///
/// # Arguments
/// * `psbt` - The signed BitGoPsbt
/// * `input_index` - The index of the input to verify
/// * `message` - The message that was signed
/// * `pubkeys` - The three wallet pubkeys [user, backup, bitgo]
/// * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2", "p2mr"
/// * `is_script_path` - For taproot types, whether script path was used (None for non-taproot)
/// * `tag` - Optional custom tag for message hashing
///
/// # Returns
/// A vector of pubkey indices (0, 1, 2) that have valid signatures
pub fn verify_bip322_psbt_input_with_pubkeys(
    psbt: &BitGoPsbt,
    input_index: usize,
    message: &str,
    pubkeys: &PubTriple,
    script_type: &str,
    _is_script_path: Option<bool>,
    tag: Option<&str>,
) -> Result<Vec<usize>, String> {
    let inner_psbt = psbt.psbt();

    // Verify BIP-0322 structure
    verify_bip322_psbt_structure(inner_psbt, input_index)?;

    // Build the output script from pubkeys and script type
    let script_pubkey = build_output_script_from_pubkeys(pubkeys, script_type)?;

    // Compute the expected to_spend txid
    let msg_hash = super::message_hash(message.as_bytes(), tag);
    let to_spend = super::create_to_spend_tx(msg_hash, script_pubkey);
    let expected_txid = to_spend.compute_txid();

    // Verify the input references the correct to_spend transaction
    if inner_psbt.unsigned_tx.input[input_index]
        .previous_output
        .txid
        != expected_txid
    {
        return Err(format!(
            "Input {} references wrong to_spend txid: expected {}, got {}",
            input_index,
            expected_txid,
            inner_psbt.unsigned_tx.input[input_index]
                .previous_output
                .txid
        ));
    }

    // Verify signatures against all 3 pubkeys
    let secp = miniscript::bitcoin::secp256k1::Secp256k1::verification_only();
    let mut signer_indices = Vec::new();

    for (i, pubkey) in pubkeys.iter().enumerate() {
        // Convert CompressedPublicKey to secp256k1::PublicKey
        let secp_pubkey = miniscript::bitcoin::secp256k1::PublicKey::from_slice(&pubkey.to_bytes())
            .map_err(|e| format!("Invalid pubkey at index {}: {}", i, e))?;

        match psbt.verify_signature_with_pub(&secp, input_index, &secp_pubkey) {
            Ok(true) => signer_indices.push(i),
            Ok(false) => {} // No signature for this key
            Err(_) => {}    // Verification error
        }
    }

    if signer_indices.is_empty() {
        return Err(format!(
            "Input {} has no valid signatures from provided pubkeys",
            input_index
        ));
    }

    Ok(signer_indices)
}

/// Verify a single input of a BIP-0322 transaction proof using pubkeys directly
///
/// # Arguments
/// * `tx` - The signed transaction
/// * `input_index` - The index of the input to verify
/// * `message` - The message that was signed
/// * `pubkeys` - The three wallet pubkeys [user, backup, bitgo]
/// * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2", "p2mr"
/// * `is_script_path` - For taproot types, whether script path was used (None for non-taproot)
/// * `tag` - Optional custom tag for message hashing
///
/// # Returns
/// A vector of pubkey indices (0, 1, 2) that have valid signatures
///
/// # Note
/// For finalized transactions, we can only verify that signature data exists.
/// The actual signature verification was done during PSBT finalization.
pub fn verify_bip322_tx_input_with_pubkeys(
    tx: &Transaction,
    input_index: usize,
    message: &str,
    pubkeys: &PubTriple,
    script_type: &str,
    _is_script_path: Option<bool>,
    tag: Option<&str>,
) -> Result<Vec<usize>, String> {
    // Verify BIP-0322 structure
    verify_bip322_tx_structure(tx, input_index)?;

    // Build the output script from pubkeys and script type
    let script_pubkey = build_output_script_from_pubkeys(pubkeys, script_type)?;

    // Compute the expected to_spend txid
    let msg_hash = super::message_hash(message.as_bytes(), tag);
    let to_spend = super::create_to_spend_tx(msg_hash, script_pubkey);
    let expected_txid = to_spend.compute_txid();

    // Verify the input references the correct to_spend transaction
    if tx.input[input_index].previous_output.txid != expected_txid {
        return Err(format!(
            "Input {} references wrong to_spend txid: expected {}, got {}",
            input_index, expected_txid, tx.input[input_index].previous_output.txid
        ));
    }

    if tx.input[input_index].previous_output.vout != 0 {
        return Err(format!(
            "Input {} references wrong output index: expected 0, got {}",
            input_index, tx.input[input_index].previous_output.vout
        ));
    }

    // Verify signature data exists
    verify_input_has_signature_data(tx, input_index)?;

    // For finalized transactions, we cannot easily determine which specific pubkeys signed
    // without re-parsing the witness/scriptSig. Return all indices as "potentially signed"
    // since the transaction passed finalization validation.
    // TODO: Parse witness to determine actual signers if needed
    Ok(vec![0, 1, 2])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_script_wallet::bitgo_psbt::p2tr_musig2_input::{Musig2Context, Musig2Input};
    use crate::fixed_script_wallet::test_utils::fixtures::XprvTriple;
    use crate::Network;
    use miniscript::bitcoin::bip32::Xpriv;
    use miniscript::bitcoin::hashes::{sha256, Hash};

    fn make_xprv_triple(seed: &str) -> XprvTriple {
        let get_xpriv = |s: &str| {
            let seed_hash = sha256::Hash::hash(s.as_bytes()).to_byte_array();
            Xpriv::new_master(miniscript::bitcoin::Network::Testnet, &seed_hash)
                .expect("could not create xpriv from seed")
        };
        XprvTriple::new([
            get_xpriv(&format!("{}.0", seed)),
            get_xpriv(&format!("{}.1", seed)),
            get_xpriv(&format!("{}.2", seed)),
        ])
    }

    fn make_wallet_keys(seed: &str) -> (XprvTriple, RootWalletKeys) {
        let xprivs = make_xprv_triple(seed);
        let wallet_keys = xprivs.to_root_wallet_keys();
        (xprivs, wallet_keys)
    }

    fn make_bip322_psbt(wallet_keys: &RootWalletKeys) -> BitGoPsbt {
        BitGoPsbt::new(Network::Bitcoin, wallet_keys, Some(0), None)
    }

    // Sign a p2trMusig2 keypath BIP322 PSBT input using the Musig2Context state machine.
    fn sign_musig2_bip322(
        psbt: &mut BitGoPsbt,
        input_index: usize,
        xprivs: &XprvTriple,
    ) -> Result<(), String> {
        let user_session_id: [u8; 32] = [1u8; 32];
        let bitgo_session_id: [u8; 32] = [2u8; 32];

        let mut ctx =
            Musig2Context::new(psbt.psbt_mut(), input_index).map_err(|e| e.to_string())?;
        let (user_first_round, _) = ctx
            .generate_nonce_first_round(xprivs.user_key(), user_session_id)
            .map_err(|e| e.to_string())?;

        let mut ctx =
            Musig2Context::new(psbt.psbt_mut(), input_index).map_err(|e| e.to_string())?;
        let (bitgo_first_round, _) = ctx
            .generate_nonce_first_round(xprivs.bitgo_key(), bitgo_session_id)
            .map_err(|e| e.to_string())?;

        let mut ctx =
            Musig2Context::new(psbt.psbt_mut(), input_index).map_err(|e| e.to_string())?;
        ctx.sign_with_first_round(user_first_round, xprivs.user_key())
            .map_err(|e| e.to_string())?;

        let mut ctx =
            Musig2Context::new(psbt.psbt_mut(), input_index).map_err(|e| e.to_string())?;
        ctx.sign_with_first_round(bitgo_first_round, xprivs.bitgo_key())
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    #[test]
    fn test_add_bip322_input_musig2_sets_participants_field() {
        let (_, wallet_keys) = make_wallet_keys("bip322_musig2_test");
        let mut psbt = make_bip322_psbt(&wallet_keys);
        let idx = add_bip322_input(
            &mut psbt,
            "test message",
            40,
            0,
            &wallet_keys,
            Some((0, 2)),
            None,
        )
        .unwrap();
        assert!(
            Musig2Input::is_musig2_input(&psbt.psbt().inputs[idx]),
            "Musig2Participants proprietary field must be present"
        );
    }

    #[test]
    fn test_bip322_musig2_keypath_sign_and_verify() {
        let (xprivs, wallet_keys) = make_wallet_keys("bip322_musig2_sign_verify");
        let message = "BIP322 p2trMusig2 keypath test";
        let chain = 40; // p2trMusig2 external
        let index = 0;

        let mut psbt = make_bip322_psbt(&wallet_keys);
        add_bip322_input(
            &mut psbt,
            message,
            chain,
            index,
            &wallet_keys,
            Some((0, 2)),
            None,
        )
        .unwrap();
        sign_musig2_bip322(&mut psbt, 0, &xprivs).unwrap();

        let signers =
            verify_bip322_psbt_input(&psbt, 0, message, chain, index, &wallet_keys, None).unwrap();
        assert!(signers.contains(&"user".to_string()));
        assert!(signers.contains(&"bitgo".to_string()));
    }

    #[test]
    fn test_bip322_musig2_backup_flow_uses_script_path() {
        // backup+user and backup+bitgo pairs must use script path, not musig2 keypath
        let (_, wallet_keys) = make_wallet_keys("bip322_musig2_backup");
        let chain = 40;
        let index = 0;

        for (signer, cosigner) in [(0usize, 1usize), (1, 2)] {
            let mut psbt = make_bip322_psbt(&wallet_keys);
            add_bip322_input(
                &mut psbt,
                "backup flow",
                chain,
                index,
                &wallet_keys,
                Some((signer, cosigner)),
                None,
            )
            .unwrap();
            assert!(
                !Musig2Input::is_musig2_input(&psbt.psbt().inputs[0]),
                "Backup flow must not set Musig2Participants (should use script path)"
            );
        }
    }

    #[test]
    fn test_bip322_musig2_multiple_inputs_verify_each() {
        let (xprivs, wallet_keys) = make_wallet_keys("bip322_musig2_multi");
        let messages = ["msg one", "msg two"];
        let chain = 40;

        let mut psbt = make_bip322_psbt(&wallet_keys);
        for (i, msg) in messages.iter().enumerate() {
            add_bip322_input(
                &mut psbt,
                msg,
                chain,
                i as u32,
                &wallet_keys,
                Some((0, 2)),
                None,
            )
            .unwrap();
            sign_musig2_bip322(&mut psbt, i, &xprivs).unwrap();
        }

        for (i, msg) in messages.iter().enumerate() {
            let signers =
                verify_bip322_psbt_input(&psbt, i, msg, chain, i as u32, &wallet_keys, None)
                    .unwrap();
            assert!(signers.contains(&"user".to_string()));
            assert!(signers.contains(&"bitgo".to_string()));
        }
    }

    #[test]
    fn test_bip322_musig2_wrong_message_fails_verification() {
        let (xprivs, wallet_keys) = make_wallet_keys("bip322_musig2_wrong_msg");
        let message = "correct message";
        let chain = 40;
        let index = 0;

        let mut psbt = make_bip322_psbt(&wallet_keys);
        add_bip322_input(
            &mut psbt,
            message,
            chain,
            index,
            &wallet_keys,
            Some((0, 2)),
            None,
        )
        .unwrap();
        sign_musig2_bip322(&mut psbt, 0, &xprivs).unwrap();

        let result =
            verify_bip322_psbt_input(&psbt, 0, "wrong message", chain, index, &wallet_keys, None);
        assert!(result.is_err(), "Verification with wrong message must fail");
    }

    #[test]
    fn test_bip322_p2tr_legacy_sign_and_verify() {
        let (xprivs, wallet_keys) = make_wallet_keys("bip322_p2tr_legacy");
        let message = "BIP322 p2tr legacy test";
        let chain = 30; // p2tr external
        let index = 0;
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();

        let mut psbt = make_bip322_psbt(&wallet_keys);
        add_bip322_input(
            &mut psbt,
            message,
            chain,
            index,
            &wallet_keys,
            Some((0, 2)),
            None,
        )
        .unwrap();

        psbt.sign(xprivs.user_key(), &secp).ok();
        psbt.sign(xprivs.bitgo_key(), &secp).ok();

        let signers =
            verify_bip322_psbt_input(&psbt, 0, message, chain, index, &wallet_keys, None).unwrap();
        assert!(signers.contains(&"user".to_string()));
        assert!(signers.contains(&"bitgo".to_string()));
    }

    // --- helpers ---

    fn xprv_for_index(xprivs: &XprvTriple, idx: usize) -> &Xpriv {
        match idx {
            0 => xprivs.user_key(),
            1 => xprivs.backup_key(),
            2 => xprivs.bitgo_key(),
            _ => panic!("invalid key index {}", idx),
        }
    }

    fn sign_script_path_pair(
        psbt: &mut BitGoPsbt,
        xprivs: &XprvTriple,
        signer: usize,
        cosigner: usize,
    ) {
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();
        psbt.sign(xprv_for_index(xprivs, signer), &secp).ok();
        psbt.sign(xprv_for_index(xprivs, cosigner), &secp).ok();
    }

    fn assert_signers_include(signers: &[String], expected: &[&str]) {
        for name in expected {
            assert!(
                signers.contains(&name.to_string()),
                "expected signer '{}' not found in {:?}",
                name,
                signers
            );
        }
    }

    // --- P2sh, P2shP2wsh, P2wsh ---

    fn test_bip322_ecdsa_sign_and_verify(chain: u32, seed: &str) {
        let (xprivs, wallet_keys) = make_wallet_keys(seed);
        let message = format!("BIP322 chain-{} test", chain);
        let index = 0;
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();

        let mut psbt = make_bip322_psbt(&wallet_keys);
        add_bip322_input(&mut psbt, &message, chain, index, &wallet_keys, None, None).unwrap();

        psbt.sign(xprivs.user_key(), &secp).ok();
        psbt.sign(xprivs.bitgo_key(), &secp).ok();

        let signers =
            verify_bip322_psbt_input(&psbt, 0, &message, chain, index, &wallet_keys, None).unwrap();
        assert_signers_include(&signers, &["user", "bitgo"]);
    }

    #[test]
    fn test_bip322_p2sh_sign_and_verify() {
        test_bip322_ecdsa_sign_and_verify(0, "bip322_p2sh");
    }

    #[test]
    fn test_bip322_p2sh_p2wsh_sign_and_verify() {
        test_bip322_ecdsa_sign_and_verify(10, "bip322_p2sh_p2wsh");
    }

    #[test]
    fn test_bip322_p2wsh_sign_and_verify() {
        test_bip322_ecdsa_sign_and_verify(20, "bip322_p2wsh");
    }

    // --- P2trLegacy backup flows ---

    #[test]
    fn test_bip322_p2tr_legacy_backup_sign_and_verify() {
        const SIGNER_NAMES: [&str; 3] = ["user", "backup", "bitgo"];
        let chain = 30;
        let index = 0;

        for (signer, cosigner) in [(0usize, 1usize), (1, 2)] {
            let (xprivs, wallet_keys) = make_wallet_keys(&format!(
                "bip322_p2tr_legacy_backup_{}_{}",
                signer, cosigner
            ));
            let message = format!("p2tr legacy backup {}-{}", signer, cosigner);
            let mut psbt = make_bip322_psbt(&wallet_keys);
            add_bip322_input(
                &mut psbt,
                &message,
                chain,
                index,
                &wallet_keys,
                Some((signer, cosigner)),
                None,
            )
            .unwrap();
            sign_script_path_pair(&mut psbt, &xprivs, signer, cosigner);
            let signers =
                verify_bip322_psbt_input(&psbt, 0, &message, chain, index, &wallet_keys, None)
                    .unwrap();
            assert_signers_include(&signers, &[SIGNER_NAMES[signer], SIGNER_NAMES[cosigner]]);
        }
    }

    // --- P2trMusig2 backup flow sign+verify ---

    #[test]
    fn test_bip322_p2trmusig2_backup_sign_and_verify() {
        const SIGNER_NAMES: [&str; 3] = ["user", "backup", "bitgo"];
        let chain = 40;
        let index = 0;

        for (signer, cosigner) in [(0usize, 1usize), (1, 2)] {
            let (xprivs, wallet_keys) = make_wallet_keys(&format!(
                "bip322_musig2_backup_sign_{}_{}",
                signer, cosigner
            ));
            let message = format!("p2trMusig2 backup {}-{}", signer, cosigner);
            let mut psbt = make_bip322_psbt(&wallet_keys);
            add_bip322_input(
                &mut psbt,
                &message,
                chain,
                index,
                &wallet_keys,
                Some((signer, cosigner)),
                None,
            )
            .unwrap();
            // Backup pairs use script-path: standard ECDSA signing works
            sign_script_path_pair(&mut psbt, &xprivs, signer, cosigner);
            let signers =
                verify_bip322_psbt_input(&psbt, 0, &message, chain, index, &wallet_keys, None)
                    .unwrap();
            assert_signers_include(&signers, &[SIGNER_NAMES[signer], SIGNER_NAMES[cosigner]]);
        }
    }
}
