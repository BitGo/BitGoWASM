/// This contains low-level parsing of PSBT into a node structure suitable for display
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::{Network, ScriptBuf, Transaction};

pub use crate::node::{Node, Primitive};

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
        bitcoin::secp256k1::PublicKey,
        (bitcoin::bip32::Fingerprint, bitcoin::bip32::DerivationPath),
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

fn proprietary_to_nodes(
    proprietary: &std::collections::BTreeMap<bitcoin::psbt::raw::ProprietaryKey, Vec<u8>>,
) -> Vec<Node> {
    proprietary
        .iter()
        .map(|(prop_key, v)| {
            let mut prop_node = Node::new("key", Primitive::None);
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
        })
        .collect()
}

fn xpubs_to_nodes(
    xpubs: &std::collections::BTreeMap<
        bitcoin::bip32::Xpub,
        (bitcoin::bip32::Fingerprint, bitcoin::bip32::DerivationPath),
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
        bitcoin::bip32::Xpub,
        (bitcoin::bip32::Fingerprint, bitcoin::bip32::DerivationPath),
    >,
) -> Node {
    let mut xpubs_node = Node::new("xpubs", Primitive::U64(xpubs.len() as u64));
    for node in xpubs_to_nodes(xpubs) {
        xpubs_node.add_child(node);
    }
    xpubs_node
}

pub fn psbt_to_node(psbt: &Psbt, network: Network) -> Node {
    let mut psbt_node = Node::new("psbt", Primitive::None);

    let tx = &psbt.unsigned_tx;
    psbt_node.add_child(tx_to_node(tx, network));

    psbt_node.add_child(xpubs_to_node(&psbt.xpub));

    if psbt.proprietary.len() > 0 {
        let mut proprietary_node =
            Node::new("proprietary", Primitive::U64(psbt.proprietary.len() as u64));
        proprietary_node.extend(proprietary_to_nodes(&psbt.proprietary));
        psbt_node.add_child(proprietary_node);
    }

    psbt_node.add_child(Node::new("version", Primitive::U32(psbt.version)));

    let mut inputs_node = Node::new("inputs", Primitive::U64(psbt.inputs.len() as u64));
    for (i, input) in psbt.inputs.iter().enumerate() {
        let mut input_node = Node::new(format!("input_{}", i), Primitive::None);

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
                    bitcoin::Address::from_script(&witness_utxo.script_pubkey, network)
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

        if input.proprietary.len() > 0 {
            let mut prop_node = Node::new(
                "proprietary",
                Primitive::U64(input.proprietary.len() as u64),
            );
            prop_node.extend(proprietary_to_nodes(&input.proprietary));
            input_node.add_child(prop_node);
        }

        inputs_node.add_child(input_node);
    }

    psbt_node.add_child(inputs_node);

    let mut outputs_node = Node::new("outputs", Primitive::U64(psbt.outputs.len() as u64));
    for (i, output) in psbt.outputs.iter().enumerate() {
        let mut output_node = Node::new(format!("{}", i), Primitive::None);

        if let Some(script) = &output.redeem_script {
            output_node.add_child(script_buf_to_node("redeem_script", script));
        }

        if let Some(script) = &output.witness_script {
            output_node.add_child(script_buf_to_node("witness_script", script));
        }

        if output.proprietary.len() > 0 {
            let mut prop_node = Node::new(
                "proprietary",
                Primitive::U64(output.proprietary.len() as u64),
            );
            prop_node.extend(proprietary_to_nodes(&output.proprietary));
            output_node.add_child(prop_node);
        }

        output_node.extend(bip32_derivations_to_nodes(&output.bip32_derivation));

        outputs_node.add_child(output_node);
    }

    psbt_node.add_child(outputs_node);

    psbt_node
}

pub fn tx_to_node(tx: &Transaction, network: bitcoin::Network) -> Node {
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

    let mut inputs_node = Node::new("inputs", Primitive::U64(tx.input.len() as u64));
    for (i, input) in tx.input.iter().enumerate() {
        let mut input_node = Node::new(format!("input_{}", i), Primitive::None);

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

        inputs_node.add_child(input_node);
    }

    tx_node.add_child(inputs_node);

    let mut outputs_node = Node::new("outputs", Primitive::U64(tx.output.len() as u64));
    for (i, output) in tx.output.iter().enumerate() {
        let mut output_node = Node::new(format!("output_{}", i), Primitive::None);

        output_node.add_child(Node::new("value", Primitive::U64(output.value.to_sat())));

        output_node.add_child(Node::new(
            "script_pubkey",
            Primitive::Buffer(output.script_pubkey.as_bytes().to_vec()),
        ));

        if let Ok(address) = bitcoin::Address::from_script(&output.script_pubkey, network) {
            output_node.add_child(Node::new("address", Primitive::String(address.to_string())));
        }

        outputs_node.add_child(output_node);
    }

    tx_node.add_child(outputs_node);

    tx_node
}

pub fn parse_psbt_bytes_internal(bytes: &[u8]) -> Result<Node, String> {
    Psbt::deserialize(bytes)
        .map(|psbt| psbt_to_node(&psbt, Network::Bitcoin))
        .map_err(|e| e.to_string())
}

pub fn parse_tx_bytes_internal(bytes: &[u8]) -> Result<Node, String> {
    Transaction::consensus_decode(&mut &bytes[..])
        .map(|tx| tx_to_node(&tx, Network::Bitcoin))
        .map_err(|e| e.to_string())
}
