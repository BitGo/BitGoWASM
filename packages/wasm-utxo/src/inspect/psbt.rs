/// This contains low-level parsing of PSBT into a node structure suitable for display
use crate::address::from_output_script_with_network;
use crate::bitcoin::consensus::Decodable;
use crate::bitcoin::psbt::Psbt;
use crate::bitcoin::{ScriptBuf, Transaction};
use crate::fixed_script_wallet::bitgo_psbt::{
    p2tr_musig2_input::{Musig2PartialSig, Musig2Participants, Musig2PubNonce},
    BitGoKeyValue, ProprietaryKeySubtype, ZcashBitGoPsbt, BITGO,
};
use crate::networks::Network;
use crate::zcash::transaction::{decode_zcash_transaction_parts, ZcashTransactionParts};

pub use super::node::{Node, Primitive};

fn script_buf_to_node(label: &str, script_buf: &ScriptBuf) -> Node {
    let mut node = Node::new(label, Primitive::Buffer(script_buf.to_bytes()));
    node.add_child(Node::new(
        "asm",
        Primitive::String(script_buf.to_asm_string()),
    ));
    node
}

fn bip32_derivations_to_nodes(
    bip32_derivation: &std::collections::BTreeMap<
        crate::bitcoin::secp256k1::PublicKey,
        (
            crate::bitcoin::bip32::Fingerprint,
            crate::bitcoin::bip32::DerivationPath,
        ),
    >,
) -> Vec<Node> {
    bip32_derivation
        .iter()
        .map(|(pubkey, (fingerprint, path))| {
            let mut derivation_node = Node::new("bip32_derivation", Primitive::None);
            derivation_node.add_child(Node::new(
                "pubkey",
                Primitive::Buffer(pubkey.serialize().to_vec()),
            ));
            derivation_node.add_child(Node::new(
                "fingerprint",
                Primitive::Buffer(fingerprint.to_bytes().to_vec()),
            ));
            derivation_node.add_child(Node::new("path", Primitive::String(path.to_string())));
            derivation_node
        })
        .collect()
}

fn musig2_participants_to_node(participants: &Musig2Participants) -> Node {
    let mut node = Node::new("musig2_participants", Primitive::None);
    node.add_child(Node::new(
        "tap_output_key",
        Primitive::Buffer(participants.tap_output_key.serialize().to_vec()),
    ));
    node.add_child(Node::new(
        "tap_internal_key",
        Primitive::Buffer(participants.tap_internal_key.serialize().to_vec()),
    ));

    let mut participants_node = Node::new("participant_pub_keys", Primitive::U64(2));
    for (i, pub_key) in participants.participant_pub_keys.iter().enumerate() {
        let pub_key_vec: Vec<u8> = pub_key.to_bytes().as_slice().to_vec();
        participants_node.add_child(Node::new(
            format!("participant_{}", i),
            Primitive::Buffer(pub_key_vec),
        ));
    }
    node.add_child(participants_node);
    node
}

fn musig2_pub_nonce_to_node(nonce: &Musig2PubNonce) -> Node {
    let mut node = Node::new("musig2_pub_nonce", Primitive::None);
    node.add_child(Node::new(
        "participant_pub_key",
        Primitive::Buffer(nonce.participant_pub_key.to_bytes().to_vec()),
    ));
    node.add_child(Node::new(
        "tap_output_key",
        Primitive::Buffer(nonce.tap_output_key.serialize().to_vec()),
    ));
    node.add_child(Node::new(
        "pub_nonce",
        Primitive::Buffer(nonce.pub_nonce.serialize().to_vec()),
    ));
    node
}

fn musig2_partial_sig_to_node(sig: &Musig2PartialSig) -> Node {
    let mut node = Node::new("musig2_partial_sig", Primitive::None);
    node.add_child(Node::new(
        "participant_pub_key",
        Primitive::Buffer(sig.participant_pub_key.to_bytes().to_vec()),
    ));
    node.add_child(Node::new(
        "tap_output_key",
        Primitive::Buffer(sig.tap_output_key.serialize().to_vec()),
    ));
    node.add_child(Node::new(
        "partial_sig",
        Primitive::Buffer(sig.partial_sig.clone()),
    ));
    node
}

fn bitgo_proprietary_to_node(
    prop_key: &crate::bitcoin::psbt::raw::ProprietaryKey,
    v: &[u8],
) -> Node {
    // Try to parse as BitGo key-value
    let v_vec = v.to_vec();
    let bitgo_kv_result = BitGoKeyValue::from_key_value(prop_key, &v_vec);

    match bitgo_kv_result {
        Ok(bitgo_kv) => {
            // Parse based on subtype
            match bitgo_kv.subtype {
                ProprietaryKeySubtype::Musig2ParticipantPubKeys => {
                    match Musig2Participants::from_key_value(&bitgo_kv) {
                        Ok(participants) => musig2_participants_to_node(&participants),
                        Err(_) => {
                            // Fall back to raw display
                            raw_proprietary_to_node("musig2_participants_error", prop_key, v)
                        }
                    }
                }
                ProprietaryKeySubtype::Musig2PubNonce => {
                    match Musig2PubNonce::from_key_value(&bitgo_kv) {
                        Ok(nonce) => musig2_pub_nonce_to_node(&nonce),
                        Err(_) => {
                            // Fall back to raw display
                            raw_proprietary_to_node("musig2_pub_nonce_error", prop_key, v)
                        }
                    }
                }
                ProprietaryKeySubtype::Musig2PartialSig => {
                    match Musig2PartialSig::from_key_value(&bitgo_kv) {
                        Ok(sig) => musig2_partial_sig_to_node(&sig),
                        Err(_) => {
                            // Fall back to raw display
                            raw_proprietary_to_node("musig2_partial_sig_error", prop_key, v)
                        }
                    }
                }
                _ => {
                    // Other BitGo subtypes - show with name
                    let subtype_name = match bitgo_kv.subtype {
                        ProprietaryKeySubtype::ZecConsensusBranchId => "zec_consensus_branch_id",
                        ProprietaryKeySubtype::PayGoAddressAttestationProof => {
                            "paygo_address_attestation_proof"
                        }
                        ProprietaryKeySubtype::Bip322Message => "bip322_message",
                        _ => "unknown",
                    };
                    raw_proprietary_to_node(subtype_name, prop_key, v)
                }
            }
        }
        Err(_) => {
            // Not a valid BitGo key-value, show raw
            raw_proprietary_to_node("unknown", prop_key, v)
        }
    }
}

fn raw_proprietary_to_node(
    label: &str,
    prop_key: &crate::bitcoin::psbt::raw::ProprietaryKey,
    v: &[u8],
) -> Node {
    let mut prop_node = Node::new(label, Primitive::None);
    prop_node.add_child(Node::new(
        "prefix",
        Primitive::String(String::from_utf8_lossy(&prop_key.prefix).to_string()),
    ));
    prop_node.add_child(Node::new("subtype", Primitive::U8(prop_key.subtype)));
    prop_node.add_child(Node::new(
        "key_data",
        Primitive::Buffer(prop_key.key.to_vec()),
    ));
    prop_node.add_child(Node::new("value", Primitive::Buffer(v.to_vec())));
    prop_node
}

fn proprietary_to_nodes(
    proprietary: &std::collections::BTreeMap<crate::bitcoin::psbt::raw::ProprietaryKey, Vec<u8>>,
) -> Vec<Node> {
    proprietary
        .iter()
        .map(|(prop_key, v)| {
            // Check if this is a BITGO proprietary key
            if prop_key.prefix.as_slice() == BITGO {
                bitgo_proprietary_to_node(prop_key, v)
            } else {
                raw_proprietary_to_node("key", prop_key, v)
            }
        })
        .collect()
}

fn xpubs_to_nodes(
    xpubs: &std::collections::BTreeMap<
        crate::bitcoin::bip32::Xpub,
        (
            crate::bitcoin::bip32::Fingerprint,
            crate::bitcoin::bip32::DerivationPath,
        ),
    >,
) -> Vec<Node> {
    xpubs
        .iter()
        .map(|(xpub, (fingerprint, path))| {
            let mut xpub_node = Node::new("xpub", Primitive::None);
            xpub_node.add_child(Node::new("xpub", Primitive::String(xpub.to_string())));
            xpub_node.add_child(Node::new(
                "fingerprint",
                Primitive::Buffer(fingerprint.to_bytes().to_vec()),
            ));
            xpub_node.add_child(Node::new("path", Primitive::String(path.to_string())));
            xpub_node
        })
        .collect()
}

pub fn xpubs_to_node(
    xpubs: &std::collections::BTreeMap<
        crate::bitcoin::bip32::Xpub,
        (
            crate::bitcoin::bip32::Fingerprint,
            crate::bitcoin::bip32::DerivationPath,
        ),
    >,
) -> Node {
    let mut xpubs_node = Node::new("xpubs", Primitive::U64(xpubs.len() as u64));
    for node in xpubs_to_nodes(xpubs) {
        xpubs_node.add_child(node);
    }
    xpubs_node
}

// ============================================================================
// Transaction Input/Output Helpers (shared between Bitcoin and Zcash)
// ============================================================================

fn tx_input_to_node(input: &crate::bitcoin::TxIn, index: usize) -> Node {
    let mut input_node = Node::new(format!("input_{}", index), Primitive::None);

    input_node.add_child(Node::new(
        "prev_txid",
        Primitive::String(input.previous_output.txid.to_string()),
    ));
    input_node.add_child(Node::new(
        "prev_vout",
        Primitive::U32(input.previous_output.vout),
    ));
    input_node.add_child(Node::new(
        "sequence",
        Primitive::U32(input.sequence.to_consensus_u32()),
    ));

    input_node.add_child(Node::new(
        "script_sig",
        Primitive::Buffer(input.script_sig.as_bytes().to_vec()),
    ));

    if !input.witness.is_empty() {
        let mut witness_node = Node::new("witness", Primitive::U64(input.witness.len() as u64));

        for (j, item) in input.witness.iter().enumerate() {
            witness_node.add_child(Node::new(
                format!("item_{}", j),
                Primitive::Buffer(item.to_vec()),
            ));
        }

        input_node.add_child(witness_node);
    }

    input_node
}

fn tx_inputs_to_node(inputs: &[crate::bitcoin::TxIn]) -> Node {
    let mut inputs_node = Node::new("inputs", Primitive::U64(inputs.len() as u64));
    for (i, input) in inputs.iter().enumerate() {
        inputs_node.add_child(tx_input_to_node(input, i));
    }
    inputs_node
}

fn tx_output_to_node(output: &crate::bitcoin::TxOut, index: usize, network: Network) -> Node {
    let mut output_node = Node::new(format!("output_{}", index), Primitive::None);

    output_node.add_child(Node::new("value", Primitive::U64(output.value.to_sat())));

    output_node.add_child(Node::new(
        "script_pubkey",
        Primitive::Buffer(output.script_pubkey.as_bytes().to_vec()),
    ));

    if let Ok(address) = from_output_script_with_network(&output.script_pubkey, network) {
        output_node.add_child(Node::new("address", Primitive::String(address)));
    }

    output_node
}

fn tx_outputs_to_node(outputs: &[crate::bitcoin::TxOut], network: Network) -> Node {
    let mut outputs_node = Node::new("outputs", Primitive::U64(outputs.len() as u64));
    for (i, output) in outputs.iter().enumerate() {
        outputs_node.add_child(tx_output_to_node(output, i, network));
    }
    outputs_node
}

// ============================================================================
// PSBT Input/Output Helpers (shared between Bitcoin and Zcash PSBTs)
// ============================================================================

fn psbt_input_to_node(input: &crate::bitcoin::psbt::Input, index: usize, network: Network) -> Node {
    let mut input_node = Node::new(format!("input_{}", index), Primitive::None);

    if let Some(utxo) = &input.non_witness_utxo {
        input_node.add_child(Node::new(
            "non_witness_utxo",
            Primitive::String(utxo.compute_txid().to_string()),
        ));
    }

    if let Some(witness_utxo) = &input.witness_utxo {
        let mut witness_node = Node::new("witness_utxo", Primitive::None);
        witness_node.add_child(Node::new(
            "value",
            Primitive::U64(witness_utxo.value.to_sat()),
        ));
        witness_node.add_child(Node::new(
            "script_pubkey",
            Primitive::Buffer(witness_utxo.script_pubkey.as_bytes().to_vec()),
        ));
        witness_node.add_child(Node::new(
            "address",
            Primitive::String(
                from_output_script_with_network(&witness_utxo.script_pubkey, network)
                    .unwrap_or_else(|_| "<invalid address>".to_string()),
            ),
        ));
        input_node.add_child(witness_node);
    }

    if let Some(redeem_script) = &input.redeem_script {
        input_node.add_child(script_buf_to_node("redeem_script", redeem_script));
    }

    if let Some(witness_script) = &input.witness_script {
        input_node.add_child(script_buf_to_node("witness_script", witness_script))
    }

    if let Some(final_script_sig) = &input.final_script_sig {
        input_node.add_child(script_buf_to_node("final_script_sig", final_script_sig));
    }

    if let Some(final_script_witness) = &input.final_script_witness {
        let mut witness_node = Node::new(
            "final_script_witness",
            Primitive::U64(final_script_witness.len() as u64),
        );
        for (i, item) in final_script_witness.iter().enumerate() {
            witness_node.add_child(Node::new(
                format!("item_{}", i),
                Primitive::Buffer(item.to_vec()),
            ));
        }
        input_node.add_child(witness_node);
    }

    let mut sigs_node = Node::new(
        "signatures",
        Primitive::U64(input.partial_sigs.len() as u64),
    );
    for (i, (pubkey, sig)) in input.partial_sigs.iter().enumerate() {
        let mut sig_node = Node::new(format!("{}", i), Primitive::None);
        sig_node.add_child(Node::new("pubkey", Primitive::Buffer(pubkey.to_bytes())));
        sig_node.add_child(Node::new("signature", Primitive::Buffer(sig.to_vec())));
        sigs_node.add_child(sig_node);
    }

    if !input.partial_sigs.is_empty() {
        input_node.add_child(sigs_node);
    }

    if let Some(sighash) = &input.sighash_type {
        input_node.add_child(Node::new("sighash_type", Primitive::U32(sighash.to_u32())));
        input_node.add_child(Node::new(
            "sighash_type",
            Primitive::String(sighash.to_string()),
        ));
    }

    input_node.extend(bip32_derivations_to_nodes(&input.bip32_derivation));

    if !input.proprietary.is_empty() {
        let mut prop_node = Node::new(
            "proprietary",
            Primitive::U64(input.proprietary.len() as u64),
        );
        prop_node.extend(proprietary_to_nodes(&input.proprietary));
        input_node.add_child(prop_node);
    }

    input_node
}

fn psbt_inputs_to_node(inputs: &[crate::bitcoin::psbt::Input], network: Network) -> Node {
    let mut inputs_node = Node::new("inputs", Primitive::U64(inputs.len() as u64));
    for (i, input) in inputs.iter().enumerate() {
        inputs_node.add_child(psbt_input_to_node(input, i, network));
    }
    inputs_node
}

fn psbt_output_to_node(output: &crate::bitcoin::psbt::Output, index: usize) -> Node {
    let mut output_node = Node::new(format!("{}", index), Primitive::None);

    if let Some(script) = &output.redeem_script {
        output_node.add_child(script_buf_to_node("redeem_script", script));
    }

    if let Some(script) = &output.witness_script {
        output_node.add_child(script_buf_to_node("witness_script", script));
    }

    if !output.proprietary.is_empty() {
        let mut prop_node = Node::new(
            "proprietary",
            Primitive::U64(output.proprietary.len() as u64),
        );
        prop_node.extend(proprietary_to_nodes(&output.proprietary));
        output_node.add_child(prop_node);
    }

    output_node.extend(bip32_derivations_to_nodes(&output.bip32_derivation));

    output_node
}

fn psbt_outputs_to_node(outputs: &[crate::bitcoin::psbt::Output]) -> Node {
    let mut outputs_node = Node::new("outputs", Primitive::U64(outputs.len() as u64));
    for (i, output) in outputs.iter().enumerate() {
        outputs_node.add_child(psbt_output_to_node(output, i));
    }
    outputs_node
}

pub fn psbt_to_node(psbt: &Psbt, network: Network) -> Node {
    let mut psbt_node = Node::new("psbt", Primitive::None);

    psbt_node.add_child(tx_to_node(&psbt.unsigned_tx, network));
    psbt_node.add_child(xpubs_to_node(&psbt.xpub));

    if !psbt.proprietary.is_empty() {
        let mut proprietary_node =
            Node::new("proprietary", Primitive::U64(psbt.proprietary.len() as u64));
        proprietary_node.extend(proprietary_to_nodes(&psbt.proprietary));
        psbt_node.add_child(proprietary_node);
    }

    psbt_node.add_child(Node::new("version", Primitive::U32(psbt.version)));
    psbt_node.add_child(psbt_inputs_to_node(&psbt.inputs, network));
    psbt_node.add_child(psbt_outputs_to_node(&psbt.outputs));

    psbt_node
}

pub fn tx_to_node(tx: &Transaction, network: Network) -> Node {
    let mut tx_node = Node::new("tx", Primitive::None);

    tx_node.add_child(Node::new("version", Primitive::I32(tx.version.0)));
    tx_node.add_child(Node::new(
        "lock_time",
        Primitive::U32(tx.lock_time.to_consensus_u32()),
    ));
    tx_node.add_child(Node::new(
        "txid",
        Primitive::String(tx.compute_txid().to_string()),
    ));
    tx_node.add_child(Node::new(
        "ntxid",
        Primitive::String(tx.compute_ntxid().to_string()),
    ));
    tx_node.add_child(Node::new(
        "wtxid",
        Primitive::String(tx.compute_wtxid().to_string()),
    ));
    tx_node.add_child(tx_inputs_to_node(&tx.input));
    tx_node.add_child(tx_outputs_to_node(&tx.output, network));

    tx_node
}

/// Convert a Zcash transaction (ZcashTransactionParts) to a Node tree
pub fn zcash_tx_to_node(parts: &ZcashTransactionParts, network: Network) -> Node {
    let tx = &parts.transaction;
    let mut tx_node = Node::new("tx", Primitive::None);

    // Zcash-specific fields first
    if parts.is_overwintered {
        tx_node.add_child(Node::new("is_overwintered", Primitive::Boolean(true)));
    }
    if let Some(vgid) = parts.version_group_id {
        tx_node.add_child(Node::new("version_group_id", Primitive::U32(vgid)));
    }
    if let Some(expiry) = parts.expiry_height {
        tx_node.add_child(Node::new("expiry_height", Primitive::U32(expiry)));
    }
    if !parts.sapling_fields.is_empty() {
        tx_node.add_child(Node::new(
            "sapling_fields",
            Primitive::Buffer(parts.sapling_fields.clone()),
        ));
    }

    // Standard transaction fields (reuse helpers)
    tx_node.add_child(Node::new("version", Primitive::I32(tx.version.0)));
    tx_node.add_child(Node::new(
        "lock_time",
        Primitive::U32(tx.lock_time.to_consensus_u32()),
    ));
    tx_node.add_child(Node::new(
        "txid",
        Primitive::String(tx.compute_txid().to_string()),
    ));
    tx_node.add_child(Node::new(
        "ntxid",
        Primitive::String(tx.compute_ntxid().to_string()),
    ));
    tx_node.add_child(Node::new(
        "wtxid",
        Primitive::String(tx.compute_wtxid().to_string()),
    ));
    tx_node.add_child(tx_inputs_to_node(&tx.input));
    tx_node.add_child(tx_outputs_to_node(&tx.output, network));

    tx_node
}

/// Convert a ZcashBitGoPsbt to a Node tree
pub fn zcash_psbt_to_node(zcash_psbt: &ZcashBitGoPsbt, network: Network) -> Node {
    if zcash_psbt.is_ironwood_v6() {
        return ironwood_v6_psbt_to_node(zcash_psbt, network);
    }

    let psbt = &zcash_psbt.psbt;
    let mut psbt_node = Node::new("psbt", Primitive::None);

    // Zcash-specific fields at PSBT level
    if let Some(vgid) = zcash_psbt.version_group_id {
        psbt_node.add_child(Node::new("version_group_id", Primitive::U32(vgid)));
    }
    if let Some(expiry) = zcash_psbt.expiry_height {
        psbt_node.add_child(Node::new("expiry_height", Primitive::U32(expiry)));
    }
    if !zcash_psbt.sapling_fields.is_empty() {
        psbt_node.add_child(Node::new(
            "sapling_fields_len",
            Primitive::U64(zcash_psbt.sapling_fields.len() as u64),
        ));
    }

    // Create ZcashTransactionParts from the PSBT's unsigned_tx
    let parts = ZcashTransactionParts {
        transaction: psbt.unsigned_tx.clone(),
        is_overwintered: zcash_psbt.version_group_id.is_some(),
        version_group_id: zcash_psbt.version_group_id,
        expiry_height: zcash_psbt.expiry_height,
        sapling_fields: zcash_psbt.sapling_fields.clone(),
    };
    psbt_node.add_child(zcash_tx_to_node(&parts, network));

    psbt_node.add_child(xpubs_to_node(&psbt.xpub));

    if !psbt.proprietary.is_empty() {
        let mut proprietary_node =
            Node::new("proprietary", Primitive::U64(psbt.proprietary.len() as u64));
        proprietary_node.extend(proprietary_to_nodes(&psbt.proprietary));
        psbt_node.add_child(proprietary_node);
    }

    psbt_node.add_child(Node::new("version", Primitive::U32(psbt.version)));
    psbt_node.add_child(psbt_inputs_to_node(&psbt.inputs, network));
    psbt_node.add_child(psbt_outputs_to_node(&psbt.outputs));

    psbt_node
}

/// The minimum partial signatures a fixed-script (2-of-3 P2SH multisig) transparent input needs
/// before it can be finalized — see `ZcashBitGoPsbt::finalized_transparent_tx`'s `REQUIRED_SIGS`.
const V6_TRANSPARENT_REQUIRED_SIGS: usize = 2;

/// Convert an Ironwood (v6) `ZcashBitGoPsbt` to a Node tree.
///
/// Unlike the v4/Sapling-shaped path, the transparent skeleton in `unsigned_tx` is rendered
/// directly (a v6 PSBT is a plain PSBT, not an embedded overwintered transaction), and a
/// dedicated `ironwood` node surfaces the shielded output data that lives out-of-band in the
/// proprietary-map PCZT — invisible to `unsigned_tx.output` and so absent from the generic
/// transparent-output accounting above. This handles unsigned, half-signed, and fully-signed
/// (transparent-side) PSBTs uniformly: the shielded action data is read from the PCZT's
/// plaintext fields, which do not depend on transparent signing state.
fn ironwood_v6_psbt_to_node(zcash_psbt: &ZcashBitGoPsbt, network: Network) -> Node {
    let psbt = &zcash_psbt.psbt;
    let mut psbt_node = Node::new("psbt", Primitive::None);

    psbt_node.add_child(Node::new("is_ironwood_v6", Primitive::Boolean(true)));
    if let Some(vgid) = zcash_psbt.version_group_id {
        psbt_node.add_child(Node::new("version_group_id", Primitive::U32(vgid)));
    }
    if let Some(expiry) = zcash_psbt.expiry_height {
        psbt_node.add_child(Node::new("expiry_height", Primitive::U32(expiry)));
    }

    // The transparent skeleton: a v6 PSBT's `unsigned_tx` is a plain rust-bitcoin transaction, so
    // the shared (non-Zcash-specific) renderer applies directly.
    psbt_node.add_child(tx_to_node(&psbt.unsigned_tx, network));

    psbt_node.add_child(ironwood_shielded_state_to_node(zcash_psbt));

    psbt_node.add_child(xpubs_to_node(&psbt.xpub));

    if !psbt.proprietary.is_empty() {
        let mut proprietary_node =
            Node::new("proprietary", Primitive::U64(psbt.proprietary.len() as u64));
        proprietary_node.extend(proprietary_to_nodes(&psbt.proprietary));
        psbt_node.add_child(proprietary_node);
    }

    psbt_node.add_child(Node::new("version", Primitive::U32(psbt.version)));
    psbt_node.add_child(psbt_inputs_to_node(&psbt.inputs, network));
    psbt_node.add_child(psbt_outputs_to_node(&psbt.outputs));

    // Overall signing state of the transparent side, since a v6 PSBT is never "fully signed" on
    // the shielded side until the external proof service and `combine_ironwood_proof` run (that
    // step produces a broadcast-ready transaction, not another PSBT).
    psbt_node.add_child(Node::new(
        "transparent_signing_state",
        Primitive::String(transparent_signing_state(&psbt.inputs).to_string()),
    ));

    psbt_node
}

/// "unsigned" (no input has any partial signature), "fully_signed" (every input has at least
/// [`V6_TRANSPARENT_REQUIRED_SIGS`] partial signatures), or "half_signed" (anything in between,
/// including a PSBT with no transparent inputs at all treated as unsigned).
fn transparent_signing_state(inputs: &[crate::bitcoin::psbt::Input]) -> &'static str {
    if inputs.is_empty() || inputs.iter().all(|i| i.partial_sigs.is_empty()) {
        return "unsigned";
    }
    if inputs
        .iter()
        .all(|i| i.partial_sigs.len() >= V6_TRANSPARENT_REQUIRED_SIGS)
    {
        return "fully_signed";
    }
    "half_signed"
}

/// The `ironwood` node: every shielded output's value/recipient (one per action) and the bundle's
/// action-data (commitments, ciphertexts, flags, value balance, anchor) read from the PCZT stored
/// in the proprietary map. Reports an error message inline rather than aborting the whole parse if
/// the PCZT is malformed or missing (e.g. a v6 PSBT that had `add_ironwood_output`/
/// `add_ironwood_outputs` never called, or was already extracted via `combine_ironwood_proof`).
fn ironwood_shielded_state_to_node(zcash_psbt: &ZcashBitGoPsbt) -> Node {
    let mut node = Node::new("ironwood", Primitive::None);

    match zcash_psbt.ironwood_shielded_outputs_info() {
        Ok(outputs) if outputs.is_empty() => {
            node.add_child(Node::new(
                "shielded_outputs",
                Primitive::String("none".to_string()),
            ));
        }
        Ok(outputs) => {
            let mut outputs_node = Node::new("shielded_outputs", Primitive::None);
            for (action_index, value, recipient) in outputs {
                let mut output_node = Node::new("shielded_output", Primitive::None);
                output_node.add_child(Node::new(
                    "action_index",
                    Primitive::U64(action_index as u64),
                ));
                output_node.add_child(Node::new("value", Primitive::U64(value)));
                output_node.add_child(Node::new(
                    "recipient",
                    Primitive::Buffer(recipient.to_vec()),
                ));
                outputs_node.add_child(output_node);
            }
            node.add_child(outputs_node);
        }
        Err(e) => {
            node.add_child(Node::new("shielded_output_error", Primitive::String(e)));
        }
    }

    match zcash_psbt.ironwood_action_data() {
        Ok(bundle) => {
            node.add_child(Node::new(
                "action_count",
                Primitive::U64(bundle.actions.len() as u64),
            ));
            node.add_child(Node::new("flags", Primitive::U8(bundle.flags)));
            node.add_child(Node::new(
                "value_balance",
                Primitive::String(bundle.value_balance.to_string()),
            ));
            node.add_child(Node::new(
                "anchor",
                Primitive::Buffer(bundle.anchor.to_vec()),
            ));
            // `pczt_action_data` always returns these empty — see its doc comment — so their
            // presence would only ever indicate a bug, not a later pipeline stage; not rendered.
        }
        Err(e) => {
            node.add_child(Node::new("action_data_error", Primitive::String(e)));
        }
    }

    node
}

pub fn parse_psbt_bytes_with_network(
    bytes: &[u8],
    network: crate::networks::Network,
) -> Result<Node, String> {
    use crate::networks::Network as NetEnum;

    // Use Zcash-specific parser for Zcash networks
    if matches!(network, NetEnum::Zcash | NetEnum::ZcashTestnet) {
        let zcash_psbt = ZcashBitGoPsbt::deserialize(bytes, network)
            .map_err(|e| format!("Zcash PSBT parse error: {}", e))?;
        return Ok(zcash_psbt_to_node(&zcash_psbt, network));
    }

    // Standard Bitcoin-compatible PSBT parsing
    Psbt::deserialize(bytes)
        .map(|psbt| psbt_to_node(&psbt, network))
        .map_err(|e| e.to_string())
}

pub fn parse_tx_bytes_with_network(
    bytes: &[u8],
    network: crate::networks::Network,
) -> Result<Node, String> {
    use crate::networks::Network as NetEnum;

    // Use Zcash-specific parser for Zcash networks
    if matches!(network, NetEnum::Zcash | NetEnum::ZcashTestnet) {
        let parts = decode_zcash_transaction_parts(bytes)
            .map_err(|e| format!("Zcash transaction parse error: {}", e))?;
        return Ok(zcash_tx_to_node(&parts, network));
    }

    // Standard Bitcoin-compatible transaction parsing
    Transaction::consensus_decode(&mut &bytes[..])
        .map(|tx| tx_to_node(&tx, network))
        .map_err(|e| e.to_string())
}

/// Parsing of v6 (Ironwood) shielding PSBTs at unsigned/half-signed/fully-signed transparent
/// signing states. Native-only (orchard + zebra), matching
/// `bitgo_psbt::zcash_psbt::ironwood_v6_tests`.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod ironwood_v6_tests {
    use super::*;
    use crate::bitcoin::bip32::DerivationPath;
    use crate::bitcoin::hashes::{sha256, Hash};
    use crate::bitcoin::secp256k1::{Message, Secp256k1};
    use crate::bitcoin::{CompressedPublicKey, Network as BtcNetwork, PublicKey, Txid};
    use crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::WalletInputOptions;
    use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt;
    use crate::fixed_script_wallet::script_id::ScriptId;
    use crate::fixed_script_wallet::test_utils::get_test_wallet_keys;
    use crate::fixed_script_wallet::wallet_scripts::chain_index_path;
    use crate::fixed_script_wallet::RootWalletKeys;
    use crate::networks::Network as NetEnum;
    use crate::zcash::NetworkUpgrade;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use orchard::tree::Anchor;
    use rand::rngs::OsRng;
    use std::str::FromStr;

    fn test_recipient() -> [u8; 43] {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([9u8; 32])).unwrap();
        FullViewingKey::from(&sk)
            .address_at(0u32, Scope::External)
            .to_raw_address_bytes()
    }

    /// Builds an unsigned v6 shielding PSBT (one 2-of-3 P2SH transparent input, a transparent
    /// change output, one shielded Ironwood output) and its bytes.
    fn build_shield_psbt(
        seed: &str,
    ) -> (
        crate::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt,
        [SecretKeyTriple; 1],
    ) {
        let wallet_keys = RootWalletKeys::new(get_test_wallet_keys(seed));
        let mut psbt = BitGoPsbt::new_zcash_v6_at_height(
            NetEnum::ZcashTestnet,
            &wallet_keys,
            NetworkUpgrade::Nu6_3.testnet_activation_height(),
            None,
            None,
        )
        .unwrap();
        psbt.add_wallet_input(
            Txid::from_byte_array([0x55u8; 32]),
            0,
            200_000_000,
            &wallet_keys,
            ScriptId { chain: 0, index: 0 },
            WalletInputOptions::default(),
        )
        .unwrap();
        psbt.add_wallet_output(0, 1, 99_900_000, &wallet_keys)
            .unwrap();
        let BitGoPsbt::Zcash(mut z, _) = psbt else {
            panic!("expected Zcash PSBT");
        };
        z.add_ironwood_output(
            &test_recipient(),
            100_000_000,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            None, // unified_address
            OsRng,
        )
        .unwrap();

        let prefix = DerivationPath::from_str("m/0/0").unwrap();
        let path = prefix.extend(chain_index_path(0, 0));
        let secp = Secp256k1::new();
        let mut keys = Vec::with_capacity(3);
        for i in 0..3u8 {
            let hash = sha256::Hash::hash(format!("{seed}.{i}").as_bytes()).to_byte_array();
            let master =
                crate::bitcoin::bip32::Xpriv::new_master(BtcNetwork::Testnet, &hash).unwrap();
            keys.push(master.derive_priv(&secp, &path).unwrap().private_key);
        }
        (z, [keys.try_into().unwrap()])
    }

    type SecretKeyTriple = [crate::bitcoin::secp256k1::SecretKey; 3];

    fn sign_input(
        z: &mut crate::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt,
        keys: &SecretKeyTriple,
        which: &[usize],
    ) {
        let secp = Secp256k1::new();
        let sighash = z.v6_transparent_sighash(0).unwrap();
        let msg = Message::from_digest(sighash);
        for &i in which {
            let sk = keys[i];
            let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
            let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
            let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
            der.push(0x01);
            z.add_v6_transparent_signature(0, pubkey, &der).unwrap();
        }
    }

    fn parse(z: &crate::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt) -> Node {
        let bytes = z.serialize().unwrap();
        parse_psbt_bytes_with_network(&bytes, NetEnum::ZcashTestnet).unwrap()
    }

    fn find<'a>(node: &'a Node, label: &str) -> Option<&'a Node> {
        node.children.iter().find(|c| c.label == label)
    }

    fn assert_shielded_output(node: &Node, expected_value: u64, expected_recipient: &[u8; 43]) {
        let ironwood = find(node, "ironwood").expect("ironwood node present");
        let outputs = find(ironwood, "shielded_outputs").expect("shielded_outputs node present");
        let output = find(outputs, "shielded_output").expect("shielded_output node present");
        let value = find(output, "value").expect("value present");
        match &value.value {
            Primitive::U64(v) => assert_eq!(*v, expected_value),
            other => panic!("unexpected primitive: {other:?}"),
        }
        let recipient = find(output, "recipient").expect("recipient present");
        match &recipient.value {
            Primitive::Buffer(b) => assert_eq!(b.as_slice(), expected_recipient.as_slice()),
            other => panic!("unexpected primitive: {other:?}"),
        }
    }

    fn signing_state(node: &Node) -> String {
        match &find(node, "transparent_signing_state").unwrap().value {
            Primitive::String(s) => s.clone(),
            other => panic!("unexpected primitive: {other:?}"),
        }
    }

    #[test]
    fn parses_unsigned_v6_shielding_psbt() {
        let (z, _keys) = build_shield_psbt("inspect_v6_unsigned");
        let node = parse(&z);
        match &find(&node, "is_ironwood_v6").unwrap().value {
            Primitive::Boolean(b) => assert!(*b),
            other => panic!("unexpected primitive: {other:?}"),
        }
        assert_shielded_output(&node, 100_000_000, &test_recipient());
        assert_eq!(signing_state(&node), "unsigned");
    }

    #[test]
    fn parses_half_signed_v6_shielding_psbt() {
        let (mut z, keys) = build_shield_psbt("inspect_v6_half_signed");
        sign_input(&mut z, &keys[0], &[0]);
        let node = parse(&z);
        assert_shielded_output(&node, 100_000_000, &test_recipient());
        assert_eq!(signing_state(&node), "half_signed");
    }

    #[test]
    fn parses_fully_signed_v6_shielding_psbt() {
        let (mut z, keys) = build_shield_psbt("inspect_v6_fully_signed");
        sign_input(&mut z, &keys[0], &[0, 2]);
        let node = parse(&z);
        assert_shielded_output(&node, 100_000_000, &test_recipient());
        assert_eq!(signing_state(&node), "fully_signed");
    }
}
