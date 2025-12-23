/// This contains low-level parsing of PSBT into a node structure suitable for display
use crate::bitcoin::consensus::Decodable;
use crate::bitcoin::hashes::Hash;
use crate::bitcoin::psbt::Psbt;
use crate::bitcoin::{Network, ScriptBuf, Transaction};
use crate::fixed_script_wallet::bitgo_psbt::{
    p2tr_musig2_input::{Musig2PartialSig, Musig2Participants, Musig2PubNonce},
    BitGoKeyValue, ProprietaryKeySubtype, ZcashBitGoPsbt, BITGO,
};
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
        Primitive::Buffer(input.previous_output.txid.to_byte_array().to_vec()),
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

    if let Ok(address) = crate::bitcoin::Address::from_script(&output.script_pubkey, network) {
        output_node.add_child(Node::new("address", Primitive::String(address.to_string())));
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
            Primitive::Buffer(utxo.compute_txid().to_byte_array().to_vec()),
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
                crate::bitcoin::Address::from_script(&witness_utxo.script_pubkey, network)
                    .map(|a| a.to_string())
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

pub fn tx_to_node(tx: &Transaction, network: crate::bitcoin::Network) -> Node {
    let mut tx_node = Node::new("tx", Primitive::None);

    tx_node.add_child(Node::new("version", Primitive::I32(tx.version.0)));
    tx_node.add_child(Node::new(
        "lock_time",
        Primitive::U32(tx.lock_time.to_consensus_u32()),
    ));
    tx_node.add_child(Node::new(
        "txid",
        Primitive::Buffer(tx.compute_txid().to_byte_array().to_vec()),
    ));
    tx_node.add_child(Node::new(
        "ntxid",
        Primitive::Buffer(tx.compute_ntxid().to_byte_array().to_vec()),
    ));
    tx_node.add_child(Node::new(
        "wtxid",
        Primitive::Buffer(tx.compute_wtxid().to_byte_array().to_vec()),
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
        Primitive::Buffer(tx.compute_txid().to_byte_array().to_vec()),
    ));
    tx_node.add_child(Node::new(
        "ntxid",
        Primitive::Buffer(tx.compute_ntxid().to_byte_array().to_vec()),
    ));
    tx_node.add_child(Node::new(
        "wtxid",
        Primitive::Buffer(tx.compute_wtxid().to_byte_array().to_vec()),
    ));
    tx_node.add_child(tx_inputs_to_node(&tx.input));
    tx_node.add_child(tx_outputs_to_node(&tx.output, network));

    tx_node
}

/// Convert a ZcashBitGoPsbt to a Node tree
pub fn zcash_psbt_to_node(zcash_psbt: &ZcashBitGoPsbt, network: Network) -> Node {
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

pub fn parse_psbt_bytes_internal(bytes: &[u8]) -> Result<Node, String> {
    parse_psbt_bytes_with_network(bytes, crate::networks::Network::Bitcoin)
}

pub fn parse_psbt_bytes_with_network(
    bytes: &[u8],
    network: crate::networks::Network,
) -> Result<Node, String> {
    use crate::networks::Network as NetEnum;

    let bitcoin_network = network.to_bitcoin_network();

    // Use Zcash-specific parser for Zcash networks
    if matches!(network, NetEnum::Zcash | NetEnum::ZcashTestnet) {
        let zcash_psbt = ZcashBitGoPsbt::deserialize(bytes, network)
            .map_err(|e| format!("Zcash PSBT parse error: {}", e))?;
        return Ok(zcash_psbt_to_node(&zcash_psbt, bitcoin_network));
    }

    // Standard Bitcoin-compatible PSBT parsing
    Psbt::deserialize(bytes)
        .map(|psbt| psbt_to_node(&psbt, bitcoin_network))
        .map_err(|e| e.to_string())
}

pub fn parse_tx_bytes_internal(bytes: &[u8]) -> Result<Node, String> {
    parse_tx_bytes_with_network(bytes, crate::networks::Network::Bitcoin)
}

pub fn parse_tx_bytes_with_network(
    bytes: &[u8],
    network: crate::networks::Network,
) -> Result<Node, String> {
    use crate::networks::Network as NetEnum;

    let bitcoin_network = network.to_bitcoin_network();

    // Use Zcash-specific parser for Zcash networks
    if matches!(network, NetEnum::Zcash | NetEnum::ZcashTestnet) {
        let parts = decode_zcash_transaction_parts(bytes)
            .map_err(|e| format!("Zcash transaction parse error: {}", e))?;
        return Ok(zcash_tx_to_node(&parts, bitcoin_network));
    }

    // Standard Bitcoin-compatible transaction parsing
    Transaction::consensus_decode(&mut &bytes[..])
        .map(|tx| tx_to_node(&tx, bitcoin_network))
        .map_err(|e| e.to_string())
}
