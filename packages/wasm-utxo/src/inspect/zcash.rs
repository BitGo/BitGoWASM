//! Node-tree rendering for Zcash PSBTs and transactions.
//!
//! Split out of `inspect/psbt.rs`; the coin-neutral dispatch in [`super::psbt`] routes
//! Zcash networks here.

use super::node::{Node, Primitive};
use super::psbt::{
    proprietary_to_nodes, psbt_inputs_to_node, psbt_outputs_to_node, tx_inputs_to_node,
    tx_outputs_to_node, tx_to_node, xpubs_to_node,
};
use crate::fixed_script_wallet::bitgo_psbt::zcash::ironwood_spend::IronwoodInputKind;
use crate::fixed_script_wallet::bitgo_psbt::zcash::IronwoodPsbtError;
use crate::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt;
use crate::networks::Network;
use crate::zcash::transaction::ZcashTransactionParts;

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
    // the shielded side until the external prover and `combine_ironwood_proof` run (that
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

/// The `ironwood` node: the shielded workflow's state and the key-free verifier's verdict.
///
/// - **Workflow state** (from [`ZcashBitGoPsbt::shielded_status`]): the `input_kind`, what is
///   still pending (out-ciphertexts, randomizers, spend signatures) and whether the bundle is
///   ready for its proof.
/// - **Verification** (from [`ZcashBitGoPsbt::verify_shielded_bundle`], with no caller key
///   material — the inspector is unauthenticated): the real spends with their randomizer /
///   signature state and Unified Addresses, and the real outputs. `failed` names the failing
///   check; `not_applicable` when no PCZT is stored (a transparent-only v6 PSBT, or one
///   already extracted).
/// - The action-data view (action count, flags, value balance, anchor) the ZIP-244 txid
///   commits to.
///
/// Reports errors inline rather than aborting the whole parse.
fn ironwood_shielded_state_to_node(zcash_psbt: &ZcashBitGoPsbt) -> Node {
    let mut node = Node::new("ironwood", Primitive::None);

    // The workflow state: where this PSBT stands in the build → ciphertexts → sign → prove
    // sequence.
    match zcash_psbt.shielded_status() {
        Ok(status) => {
            node.add_child(Node::new(
                "input_kind",
                Primitive::String(
                    match status.input_kind {
                        IronwoodInputKind::Transparent => "transparent",
                        IronwoodInputKind::Shielded => "shielded",
                    }
                    .to_string(),
                ),
            ));
            add_pending(
                &mut node,
                "pending_out_ciphertexts",
                &status.pending_out_ciphertexts,
            );
            add_pending(
                &mut node,
                "pending_randomizers",
                &status.pending_randomizers,
            );
            add_pending(
                &mut node,
                "pending_spend_signatures",
                &status.pending_spend_signatures,
            );
            node.add_child(Node::new(
                "ready_for_proof",
                Primitive::Boolean(status.ready_for_proof),
            ));
        }
        Err(e) => node.add_child(Node::new("status_error", Primitive::String(e.to_string()))),
    }

    // The key-free verifier's verdict. No caller key material: an inspector can see what the
    // bundle commits to, not whose wallet it spends from.
    match zcash_psbt.verify_shielded_bundle(None, &[]) {
        Ok(report) => {
            let mut verification = Node::new("verification", Primitive::String("ok".to_string()));
            if !report.spends.is_empty() {
                let mut spends = Node::new("spends", Primitive::None);
                for spend in &report.spends {
                    let mut spend_node = Node::new("spend", Primitive::None);
                    spend_node.add_child(Node::new(
                        "action_index",
                        Primitive::U64(spend.action_index as u64),
                    ));
                    spend_node.add_child(Node::new("value", Primitive::U64(spend.value)));
                    spend_node.add_child(Node::new(
                        "address",
                        Primitive::String(spend.address.clone()),
                    ));
                    spend_node.add_child(Node::new(
                        "randomizer",
                        Primitive::String(
                            if spend.rk_replaced {
                                "installed"
                            } else {
                                "placeholder"
                            }
                            .to_string(),
                        ),
                    ));
                    spend_node.add_child(Node::new("signed", Primitive::Boolean(spend.signed)));
                    spends.add_child(spend_node);
                }
                verification.add_child(spends);
            }
            if !report.outputs.is_empty() {
                let mut outputs = Node::new("outputs", Primitive::None);
                for output in &report.outputs {
                    let mut output_node = Node::new("output", Primitive::None);
                    output_node.add_child(Node::new(
                        "action_index",
                        Primitive::U64(output.action_index as u64),
                    ));
                    output_node.add_child(Node::new("value", Primitive::U64(output.value)));
                    output_node.add_child(Node::new(
                        "recipient",
                        Primitive::Buffer(output.recipient.to_vec()),
                    ));
                    outputs.add_child(output_node);
                }
                verification.add_child(outputs);
            }
            node.add_child(verification);
        }
        Err(IronwoodPsbtError::NotSpendBundle) => {
            node.add_child(Node::new(
                "verification",
                Primitive::String("not_applicable".to_string()),
            ));
        }
        Err(e) => {
            let mut verification =
                Node::new("verification", Primitive::String("failed".to_string()));
            verification.add_child(Node::new("error", Primitive::String(e.to_string())));
            node.add_child(verification);
        }
    }

    // The action-data view: what the ZIP-244 txid commits to.
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

/// Attach a pending-index list: a "none" marker when empty, otherwise one `index` child per
/// action.
fn add_pending(node: &mut Node, label: &str, indices: &[usize]) {
    if indices.is_empty() {
        node.add_child(Node::new(label, Primitive::String("none".to_string())));
        return;
    }
    let mut list = Node::new(label, Primitive::None);
    for index in indices {
        list.add_child(Node::new("index", Primitive::U64(*index as u64)));
    }
    node.add_child(list);
}

/// Parsing of v6 (Ironwood) shielding PSBTs at unsigned/half-signed/fully-signed transparent
/// signing states. Native-only (orchard + zebra), matching
/// `bitgo_psbt::zcash::tests::ironwood`.
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
    use crate::inspect::psbt::parse_psbt_bytes_with_network;
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
        let verification = find(ironwood, "verification").expect("verification node present");
        assert!(matches!(
            &verification.value,
            Primitive::String(s) if s == "ok"
        ));
        let outputs = find(verification, "outputs").expect("outputs node present");
        let output = find(outputs, "output").expect("output node present");
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
    /// A keyless shielded→shielded spend PSBT: two wallet notes into two wallet outputs, with
    /// its action map and the wallet's spending key.
    fn build_spend_psbt(
        seed: &str,
    ) -> (
        ZcashBitGoPsbt,
        crate::zcash::ironwood_build::IronwoodActionMap,
        SpendingKey,
    ) {
        use crate::fixed_script_wallet::bitgo_psbt::zcash::IronwoodOutputRequest;
        use crate::zcash::ironwood_construct::test_util::keyless_fixture;

        let (specs, anchor, fvk, _ak) = keyless_fixture();
        let wallet_keys = RootWalletKeys::new(get_test_wallet_keys(seed));
        let psbt = BitGoPsbt::new_zcash_v6_at_height(
            NetEnum::ZcashTestnet,
            &wallet_keys,
            NetworkUpgrade::Nu6_3.testnet_activation_height(),
            None,
            None,
        )
        .unwrap();
        let BitGoPsbt::Zcash(mut z, _) = psbt else {
            panic!("expected Zcash PSBT");
        };
        let outputs: Vec<IronwoodOutputRequest> = [100u32, 101]
            .iter()
            .map(|&diversifier| IronwoodOutputRequest {
                recipient: fvk
                    .address_at(diversifier, Scope::External)
                    .to_raw_address_bytes(),
                amount: 90_000_000,
                ovk: None,
                memo: [0u8; 512],
                unified_address: None,
            })
            .collect();
        let map = z
            .add_shielded_spends(&specs, &outputs, &anchor, OsRng)
            .unwrap();
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        (z, map, sk)
    }

    fn string_value<'a>(node: &'a Node, label: &str) -> &'a str {
        match &find(node, label)
            .unwrap_or_else(|| panic!("{label} present"))
            .value
        {
            Primitive::String(s) => s,
            other => panic!("unexpected primitive for {label}: {other:?}"),
        }
    }

    /// The action indices listed under a pending node, or empty for its "none" marker.
    fn pending(ironwood: &Node, label: &str) -> Vec<usize> {
        let node = find(ironwood, label).unwrap_or_else(|| panic!("{label} present"));
        if matches!(&node.value, Primitive::String(s) if s == "none") {
            return Vec::new();
        }
        node.children
            .iter()
            .map(|child| match child.value {
                Primitive::U64(index) => index as usize,
                ref other => panic!("unexpected primitive: {other:?}"),
            })
            .collect()
    }

    fn ready_for_proof(ironwood: &Node) -> bool {
        match find(ironwood, "ready_for_proof").unwrap().value {
            Primitive::Boolean(b) => b,
            ref other => panic!("unexpected primitive: {other:?}"),
        }
    }

    /// Every verified spend's `(randomizer, signed)` state.
    fn spend_states(ironwood: &Node) -> Vec<(String, bool)> {
        let verification = find(ironwood, "verification").expect("verification node present");
        assert_eq!(string_value(ironwood, "verification"), "ok");
        find(verification, "spends")
            .expect("spends node present")
            .children
            .iter()
            .map(|spend| {
                let signed = match find(spend, "signed").unwrap().value {
                    Primitive::Boolean(b) => b,
                    ref other => panic!("unexpected primitive: {other:?}"),
                };
                (string_value(spend, "randomizer").to_string(), signed)
            })
            .collect()
    }

    fn sorted(indices: &[usize]) -> Vec<usize> {
        let mut indices = indices.to_vec();
        indices.sort_unstable();
        indices
    }

    /// The `ironwood` node tracks a spend PSBT through ciphertexts → randomizers → signatures.
    #[test]
    fn parses_shielded_spend_psbt_at_every_stage() {
        use crate::zcash::ironwood_build::compute_out_ciphertext;
        use ff::{Field, PrimeField};
        use orchard::keys::SpendAuthorizingKey;
        use orchard::primitives::redpallas::{SpendAuth, VerificationKey};

        let (mut z, map, sk) = build_spend_psbt("inspect_v6_spend");
        let spends = sorted(map.spend_action_indices());
        let outputs = sorted(map.output_action_indices());

        let node = parse(&z);
        let ironwood = find(&node, "ironwood").expect("ironwood node present");
        assert_eq!(string_value(ironwood, "input_kind"), "shielded");
        assert_eq!(pending(ironwood, "pending_out_ciphertexts"), outputs);
        assert_eq!(pending(ironwood, "pending_randomizers"), spends);
        assert_eq!(pending(ironwood, "pending_spend_signatures"), spends);
        assert!(!ready_for_proof(ironwood));
        assert!(spend_states(ironwood)
            .iter()
            .all(|(randomizer, signed)| randomizer == "placeholder" && !signed));

        let ovk = *FullViewingKey::from(&sk).to_ovk(Scope::External).as_ref();
        let pczt = z.ironwood_pczt().unwrap();
        let ciphertexts: Vec<_> = outputs
            .iter()
            .map(|&i| {
                (
                    i,
                    compute_out_ciphertext(&pczt, i, ovk, &mut OsRng).unwrap(),
                )
            })
            .collect();
        z.add_out_ciphertexts(&ciphertexts).unwrap();
        let node = parse(&z);
        let ironwood = find(&node, "ironwood").unwrap();
        assert!(pending(ironwood, "pending_out_ciphertexts").is_empty());
        assert_eq!(pending(ironwood, "pending_randomizers"), spends);

        let ask = SpendAuthorizingKey::from(&sk);
        let alphas: Vec<(usize, pasta_curves::pallas::Scalar)> = spends
            .iter()
            .map(|&i| (i, pasta_curves::pallas::Scalar::random(&mut OsRng)))
            .collect();
        let triples: Vec<(usize, [u8; 32], [u8; 32])> = alphas
            .iter()
            .map(|(i, alpha)| {
                let rk = VerificationKey::<SpendAuth>::from(&ask.randomize(alpha));
                (*i, alpha.to_repr(), <[u8; 32]>::from(rk))
            })
            .collect();
        z.add_spend_randomizers(&triples, None).unwrap();
        let node = parse(&z);
        let ironwood = find(&node, "ironwood").unwrap();
        assert!(pending(ironwood, "pending_randomizers").is_empty());
        assert_eq!(pending(ironwood, "pending_spend_signatures"), spends);
        assert!(!ready_for_proof(ironwood));
        assert!(spend_states(ironwood)
            .iter()
            .all(|(randomizer, signed)| randomizer == "installed" && !signed));

        let sighash = z.spend_sighash().unwrap();
        let signatures: Vec<(usize, [u8; 64])> = alphas
            .iter()
            .map(|(i, alpha)| {
                (
                    *i,
                    <[u8; 64]>::from(&ask.randomize(alpha).sign(OsRng, &sighash)),
                )
            })
            .collect();
        z.add_spend_signatures(&signatures).unwrap();
        let node = parse(&z);
        let ironwood = find(&node, "ironwood").unwrap();
        assert!(pending(ironwood, "pending_spend_signatures").is_empty());
        assert!(ready_for_proof(ironwood));
        let states = spend_states(ironwood);
        assert_eq!(states.len(), spends.len());
        assert!(states
            .iter()
            .all(|(randomizer, signed)| randomizer == "installed" && *signed));
    }

    /// A transparent-only v6 PSBT has no bundle to verify.
    #[test]
    fn parses_transparent_only_v6_psbt_as_not_applicable() {
        let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("inspect_v6_transparent"));
        let mut psbt = BitGoPsbt::new_zcash_v6_at_height(
            NetEnum::ZcashTestnet,
            &wallet_keys,
            NetworkUpgrade::Nu6_3.testnet_activation_height(),
            None,
            None,
        )
        .unwrap();
        psbt.add_wallet_input(
            Txid::from_byte_array([0x66u8; 32]),
            0,
            200_000_000,
            &wallet_keys,
            ScriptId { chain: 0, index: 0 },
            WalletInputOptions::default(),
        )
        .unwrap();
        psbt.add_wallet_output(0, 1, 199_900_000, &wallet_keys)
            .unwrap();
        let BitGoPsbt::Zcash(z, _) = psbt else {
            panic!("expected Zcash PSBT");
        };
        let node = parse(&z);
        let ironwood = find(&node, "ironwood").expect("ironwood node present");
        assert_eq!(string_value(ironwood, "input_kind"), "transparent");
        assert_eq!(string_value(ironwood, "verification"), "not_applicable");
        assert!(!ready_for_proof(ironwood));
    }
}
