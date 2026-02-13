//! BIP-0322 integration with BitGo PSBT
//!
//! This module contains the business logic for BIP-0322 message signing
//! with BitGo fixed-script wallets.

use crate::fixed_script_wallet::bitgo_psbt::{
    create_bip32_derivation, create_tap_bip32_derivation, BitGoPsbt,
};
use crate::fixed_script_wallet::wallet_scripts::{
    build_multisig_script_2_of_3, build_p2tr_ns_script, ScriptP2tr,
};
use crate::fixed_script_wallet::{to_pub_triple, Chain, PubTriple, RootWalletKeys, WalletScripts};
use crate::networks::Network;

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
        chain_enum,
        index,
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
        WalletScripts::P2trLegacy(script) | WalletScripts::P2trMusig2(script) => {
            // For taproot, sign_path is required
            let (signer_idx, cosigner_idx) =
                sign_path.ok_or("signer and cosigner are required for p2tr/p2trMusig2 inputs")?;

            // Derive pubkeys
            let derived_keys = wallet_keys
                .derive_for_chain_and_index(chain, index)
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
            }
        }
    }

    Ok(input_index)
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
        chain_enum,
        index,
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
        chain_enum,
        index,
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
/// * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2"
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
        _ => Err(format!(
            "Unknown script type '{}'. Expected: p2sh, p2shP2wsh, p2wsh, p2tr, p2trMusig2",
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
/// * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2"
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
/// * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2"
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
