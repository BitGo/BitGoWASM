//! Tests for the keyless Ironwood spend flow (plan PR 5): `add_shielded_spends`, the
//! one-input-kind rule (rule 0), and the deshield / shielded→shielded lifecycles the build
//! service drives. Native-only (orchard + zebra).

use super::*;
use crate::bitcoin::hashes::Hash;
use crate::bitcoin::Txid;
use crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::WalletInputOptions;
use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt;
use crate::fixed_script_wallet::script_id::ScriptId;
use crate::networks::Network;
use crate::zcash::ironwood_build::{compute_out_ciphertext, IronwoodActionMap};
use crate::zcash::ironwood_construct::test_util::keyless_fixture;
use crate::zcash::ironwood_pczt::with_out_ciphertext;
use crate::zcash::NetworkUpgrade;
use ff::{Field, PrimeField};
use orchard::keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey};
use orchard::primitives::redpallas::{SpendAuth, VerificationKey};
use orchard::Proof;
use rand::rngs::OsRng;

fn test_spending_key() -> SpendingKey {
    Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap()
}

/// A shielded output request back to the wallet itself, at the given diversifier and amount.
fn wallet_output(fvk: &FullViewingKey, diversifier: u32, amount: u64) -> IronwoodOutputRequest {
    IronwoodOutputRequest {
        recipient: fvk
            .address_at(diversifier, Scope::External)
            .to_raw_address_bytes(),
        amount,
        ovk: None,
        memo: [0u8; 512],
        unified_address: None,
    }
}

/// A deshield PSBT: one real note (100M zatoshi) spent with no shielded outputs, paying a
/// transparent output of 99_999_000 — a 1_000-zatoshi fee, no transparent inputs.
fn keyless_deshield_psbt(
    seed: &str,
) -> (
    ZcashBitGoPsbt,
    IronwoodActionMap,
    [u8; 32],
    FullViewingKey,
    SpendAuthorizingKey,
) {
    let (specs, anchor, fvk, ak) = keyless_fixture();
    let wallet_keys = root_wallet_keys(seed);
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    z.add_transparent_output(
        miniscript::bitcoin::ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac]),
        99_999_000,
        None,
    )
    .unwrap();
    let map = z
        .add_shielded_spends(&specs[..1], &[], &anchor, &ak, OsRng)
        .unwrap();
    (
        z,
        map,
        ak,
        fvk,
        SpendAuthorizingKey::from(&test_spending_key()),
    )
}

/// A shielded→shielded transfer: two real notes (100M + 80M) spent into two shielded outputs
/// (90M each, back to the wallet's own addresses) — value balance 0, no transparent side.
fn keyless_transfer_psbt(
    seed: &str,
) -> (
    ZcashBitGoPsbt,
    IronwoodActionMap,
    [u8; 32],
    FullViewingKey,
    SpendAuthorizingKey,
) {
    let (specs, anchor, fvk, ak) = keyless_fixture();
    let wallet_keys = root_wallet_keys(seed);
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    let outputs = [
        wallet_output(&fvk, 100, 90_000_000),
        wallet_output(&fvk, 101, 90_000_000),
    ];
    let map = z
        .add_shielded_spends(&specs, &outputs, &anchor, &ak, OsRng)
        .unwrap();
    (
        z,
        map,
        ak,
        fvk,
        SpendAuthorizingKey::from(&test_spending_key()),
    )
}

/// KMS's out-ciphertext round (plan §2 step 3): re-encrypt every requested output's
/// `out_ciphertext` under the FVK's external `ovk` and splice it into the stored PCZT.
fn kms_out_ciphertexts(z: &mut ZcashBitGoPsbt, map: &IronwoodActionMap, fvk: &FullViewingKey) {
    let ovk = *fvk.to_ovk(Scope::External).as_ref();
    let pczt = z.ironwood_pczt().unwrap();
    let mut bytes = z.raw_ironwood_pczt_bytes().unwrap();
    for &action_index in map.output_action_indices() {
        let expected = compute_out_ciphertext(&pczt, action_index, ovk, &mut OsRng).unwrap();
        bytes = with_out_ciphertext(&bytes, action_index, expected).unwrap();
    }
    crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::set_ironwood_pczt(&mut z.psbt, bytes);
}

/// The FROST stand-in round: install `(alpha, rk = ak.randomize(alpha))` on every real spend
/// and return the `(action_index, alpha)` pairs the local prover needs.
///
/// PR 7's `add_spend_randomizers` batch method does this atomically; until it lands, the
/// alpha goes through the wire patcher and the matching `rk` through the existing
/// `replace_ironwood_spend_rk` — the same two writes, in the same order.
fn install_randomizers(
    z: &mut ZcashBitGoPsbt,
    map: &IronwoodActionMap,
    ask: &SpendAuthorizingKey,
) -> Vec<(usize, [u8; 32])> {
    use crate::zcash::ironwood_pczt::with_spend_alpha;

    let mut pairs = Vec::new();
    for &action_index in map.spend_action_indices() {
        let alpha = pasta_curves::pallas::Scalar::random(&mut OsRng);
        let rk = <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&ask.randomize(&alpha)));
        // Alpha first, so the stored ak already justifies the rk the verifier checks.
        let bytes = z.raw_ironwood_pczt_bytes().unwrap();
        let bytes = with_spend_alpha(&bytes, action_index, Some(alpha.to_repr())).unwrap();
        crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::set_ironwood_pczt(
            &mut z.psbt,
            bytes,
        );
        z.replace_ironwood_spend_rk(action_index, rk).unwrap();
        pairs.push((action_index, alpha.to_repr()));
    }
    pairs
}

/// The FROST stand-in signatures: RedPallas over the PSBT's ZIP-244 sig digest.
fn install_spend_signatures(
    z: &mut ZcashBitGoPsbt,
    pairs: &[(usize, [u8; 32])],
    ask: &SpendAuthorizingKey,
) {
    let sighash = z.v6_sig_digest().unwrap();
    for (action_index, alpha_repr) in pairs {
        let alpha = pasta_curves::pallas::Scalar::from_repr(*alpha_repr).unwrap();
        let sig = ask.randomize(&alpha).sign(OsRng, &sighash);
        z.apply_ironwood_spend_signature(*action_index, <[u8; 64]>::from(&sig))
            .unwrap();
    }
}

/// The full keyless deshield lifecycle (plan §2, no transparent inputs): build → FROST
/// randomizers → signatures → combine. Each step survives a serialize/deserialize round-trip,
/// and zebra independently decodes the result.
#[test]
fn keyless_deshield_lifecycle_round_trips() {
    let seed = "ironwood_v6_keyless_deshield";
    let (mut z, map, _ak, fvk, ask) = keyless_deshield_psbt(seed);

    // The stored key is the wallet's spend-validating key (the verifier's `Rk` input).
    assert_eq!(
        crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::get_ironwood_spend_validating_key(
            &z.psbt
        ),
        Some(fvk.to_bytes()[..32].try_into().unwrap()),
    );

    // The accounting view: one real spend, no shielded outputs, +100M value balance.
    let info = z.ironwood_bundle_info().unwrap();
    assert_eq!(info.spends.len(), 1);
    assert_eq!(info.spends[0].value, 100_000_000);
    assert!(info.outputs.is_empty());
    assert_eq!(info.value_balance, 100_000_000);
    assert_eq!(info.fee, 1_000);

    // Round-trip before randomizing: the placeholder state survives the PSBT wire.
    let bytes = z.serialize_v6();
    z = ZcashBitGoPsbt::deserialize_v6(&bytes, Network::ZcashTestnet).unwrap();

    let pairs = install_randomizers(&mut z, &map, &ask);
    let bytes = z.serialize_v6();
    z = ZcashBitGoPsbt::deserialize_v6(&bytes, Network::ZcashTestnet).unwrap();

    install_spend_signatures(&mut z, &pairs, &ask);
    let bytes = z.serialize_v6();
    let z = ZcashBitGoPsbt::deserialize_v6(&bytes, Network::ZcashTestnet).unwrap();

    // No shielded outputs ⇒ no KMS out-ciphertext round for this shape.
    let raw = z
        .combine_ironwood_proof(vec![0u8; Proof::expected_proof_size(1)], OsRng)
        .unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    let bundle = tx.ironwood_bundle.as_ref().unwrap();
    assert_eq!(bundle.actions.len(), 1);
    assert_eq!(bundle.value_balance, 100_000_000, "a deshield pays out");

    use zebra_chain::serialization::ZcashDeserialize;
    use zebra_chain::transaction::Transaction as ZebraTx;
    let zebra = ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes the deshield");
    assert_eq!(zebra.version(), 6);
    assert_eq!(zebra.ironwood_actions().count(), 1);
    assert!(
        zebra.has_transparent_outputs(),
        "the transparent payout is on the wire"
    );
}

/// The shielded→shielded lifecycle: two spends into two outputs, with the KMS out-ciphertext
/// round — the patched ciphertexts are exactly what the FVK's `ovk` recovers, and they
/// survive to the broadcast transaction.
#[test]
fn keyless_shielded_transfer_lifecycle_round_trips() {
    use orchard::note_encryption::IronwoodDomain;
    use zcash_note_encryption::try_output_recovery_with_ovk;

    let seed = "ironwood_v6_keyless_transfer";
    let (mut z, map, _ak, fvk, ask) = keyless_transfer_psbt(seed);

    assert_eq!(z.ironwood_bundle_info().unwrap().value_balance, 0);

    // KMS round: every output's out_ciphertext becomes recoverable under the FVK's ovk.
    kms_out_ciphertexts(&mut z, &map, &fvk);
    let expected = z.ironwood_action_data().unwrap();

    let pairs = install_randomizers(&mut z, &map, &ask);
    install_spend_signatures(&mut z, &pairs, &ask);

    // Round-trip: the patched ciphertexts and signatures survive the PSBT wire.
    let bytes = z.serialize_v6();
    let z = ZcashBitGoPsbt::deserialize_v6(&bytes, Network::ZcashTestnet).unwrap();

    // Every action's outgoing note is recoverable under the spending FVK's external ovk.
    let ovk = *fvk.to_ovk(Scope::External).as_ref();
    let pczt = z.ironwood_pczt().unwrap();
    for (i, action) in pczt.actions().iter().enumerate() {
        let domain = IronwoodDomain::for_pczt_action(action);
        let (note, _, _) = try_output_recovery_with_ovk(
            &domain,
            &orchard::keys::OutgoingViewingKey::from(ovk),
            action,
            action.cv_net(),
            &expected.actions[i].out_ciphertext,
        )
        .unwrap_or_else(|| panic!("action {i} recoverable under the FVK ovk"));
        assert_eq!(note.value().inner(), 90_000_000);
    }

    let raw = z
        .combine_ironwood_proof(vec![0u8; Proof::expected_proof_size(2)], OsRng)
        .unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    let bundle = tx.ironwood_bundle.as_ref().unwrap();
    assert_eq!(bundle.actions.len(), 2);
    assert_eq!(bundle.value_balance, 0);
    for (i, action) in bundle.actions.iter().enumerate() {
        assert_eq!(
            action.out_ciphertext.to_vec(),
            expected.actions[i].out_ciphertext.to_vec(),
            "action {i}'s KMS out_ciphertext survives to the broadcast transaction"
        );
    }

    use zebra_chain::serialization::ZcashDeserialize;
    use zebra_chain::transaction::Transaction as ZebraTx;
    let zebra = ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes the transfer");
    assert_eq!(zebra.ironwood_actions().count(), 2);
}

/// A 1→2 shape: one real note (100M) into two shielded outputs (40M + 50M) plus a
/// 9_999_000 transparent payout — the surplus output rides a Builder-fabricated dummy spend.
fn keyless_surplus_psbt(
    seed: &str,
) -> (
    ZcashBitGoPsbt,
    IronwoodActionMap,
    [u8; 32],
    FullViewingKey,
    SpendAuthorizingKey,
) {
    let (specs, anchor, fvk, ak) = keyless_fixture();
    let wallet_keys = root_wallet_keys(seed);
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    z.add_transparent_output(
        miniscript::bitcoin::ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac]),
        9_999_000,
        None,
    )
    .unwrap();
    let outputs = [
        wallet_output(&fvk, 100, 40_000_000),
        wallet_output(&fvk, 101, 50_000_000),
    ];
    let map = z
        .add_shielded_spends(&specs[..1], &outputs, &anchor, &ak, OsRng)
        .unwrap();
    (
        z,
        map,
        ak,
        fvk,
        SpendAuthorizingKey::from(&test_spending_key()),
    )
}

/// A 1→2 shape: the surplus output rides a Builder-fabricated dummy spend, which the IO
/// Finalizer signs at combine time — the keyless Constructor's reuse of orchard's dummy
/// fabrication works end to end.
#[test]
fn keyless_surplus_output_lifecycle_round_trips() {
    let seed = "ironwood_v6_keyless_surplus";
    let (mut z, map, _ak, fvk, ask) = keyless_surplus_psbt(seed);
    assert_eq!(z.ironwood_bundle_info().unwrap().value_balance, 10_000_000);

    kms_out_ciphertexts(&mut z, &map, &fvk);
    let pairs = install_randomizers(&mut z, &map, &ask);
    install_spend_signatures(&mut z, &pairs, &ask);

    let raw = z
        .combine_ironwood_proof(vec![0u8; Proof::expected_proof_size(2)], OsRng)
        .unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    assert_eq!(tx.ironwood_bundle.as_ref().unwrap().actions.len(), 2);

    use zebra_chain::serialization::ZcashDeserialize;
    use zebra_chain::transaction::Transaction as ZebraTx;
    ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes the surplus-output deshield");
}

/// The Zcash parse surfaces the keyless bundle's spends (verified, with the stored `ak`
/// backing the `Rk` check) and reports the signing state the workflow is in.
#[test]
fn keyless_parse_reports_verified_spends() {
    let seed = "ironwood_v6_keyless_parse";
    let (mut z, map, _ak, _fvk, ask) = keyless_deshield_psbt(seed);
    install_randomizers(&mut z, &map, &ask);

    let wallet_keys = root_wallet_keys(seed);
    let psbt = BitGoPsbt::Zcash(z.clone(), Network::ZcashTestnet);
    let parsed =
        crate::fixed_script_wallet::bitgo_psbt::zcash::parse::parse_transaction_with_wallet_keys(
            &psbt,
            &wallet_keys,
            &crate::fixed_script_wallet::ReplayProtection::new(vec![]),
            &[],
        )
        .unwrap();
    let crate::fixed_script_wallet::bitgo_psbt::zcash::parse::ZcashParsedInputs::Shielded(spends) =
        &parsed.inputs
    else {
        panic!("expected the shielded input kind");
    };
    assert_eq!(spends.len(), 1);
    assert_eq!(spends[0].action_index, map.spend_action_index(0).unwrap());
    assert_eq!(spends[0].value, 100_000_000);
    assert!(spends[0].rk_replaced, "the randomizer was installed");
    assert!(!spends[0].signed, "no signature yet");
}

/// Rule 0 (plan §3), shielded side: `add_shielded_spends` rejects a PSBT that already carries
/// transparent inputs, with the typed error code.
#[test]
fn add_shielded_spends_rejects_transparent_inputs() {
    let seed = "ironwood_v6_keyless_rule0_shielded";
    let (specs, anchor, _fvk, ak) = keyless_fixture();
    let wallet_keys = root_wallet_keys(seed);
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let mut psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    psbt.add_wallet_input(
        Txid::from_byte_array([0x44u8; 32]),
        0,
        200_000_000,
        &wallet_keys,
        ScriptId { chain: 0, index: 0 },
        WalletInputOptions::default(),
    )
    .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    let error = z
        .add_shielded_spends(&specs[..1], &[], &anchor, &ak, OsRng)
        .unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&error),
        "IronwoodPsbtError.MixedInputKinds"
    );
}

/// Rule 0, transparent side: the generic input adders reject a PSBT whose stored bundle
/// already spends real notes. A PSBT with only a shielded *output* (the shielding flow)
/// still accepts transparent inputs — see the shielding tests in [`super::ironwood`].
#[test]
fn transparent_adders_reject_after_shielded_spends() {
    let seed = "ironwood_v6_keyless_rule0_transparent";
    let wallet_keys = root_wallet_keys(seed);
    let (z, _map, _ak, _fvk, _ask) = keyless_deshield_psbt(seed);
    let mut psbt = BitGoPsbt::Zcash(z, Network::ZcashTestnet);
    let error = psbt
        .add_wallet_input(
            Txid::from_byte_array([0x46u8; 32]),
            0,
            200_000_000,
            &wallet_keys,
            ScriptId { chain: 0, index: 0 },
            WalletInputOptions::default(),
        )
        .unwrap_err();
    assert!(
        error.contains("cannot add a transparent input"),
        "unexpected error: {error}"
    );
}

/// Rule 0 at deserialize: a PSBT mixing transparent inputs with real spends (built through
/// the oracle path, which predates the rule) is rejected by `deserialize_v6`.
#[test]
fn deserialize_rejects_mixed_input_kinds() {
    let seed = "ironwood_v6_keyless_rule0_deserialize";
    let (specs, anchor, fvk, _ak) = keyless_fixture();
    let wallet_keys = root_wallet_keys(seed);
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let mut psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    psbt.add_wallet_input(
        Txid::from_byte_array([0x45u8; 32]),
        0,
        300_000_000,
        &wallet_keys,
        ScriptId { chain: 0, index: 0 },
        WalletInputOptions::default(),
    )
    .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    // The oracle path (test/orchard-proving only) still builds mixed bundles, so the
    // deserialize-side rule has something to catch.
    let req = IronwoodSpendRequest {
        fvk: fvk.to_bytes(),
        recipient: specs[0].recipient,
        value: specs[0].value,
        rho: specs[0].rho,
        rseed: specs[0].rseed,
        cmx: specs[0].cmx,
        witness: specs[0].witness,
    };
    z.add_ironwood_actions(&[req], &[], &anchor, OsRng).unwrap();

    let bytes = z.serialize_v6();
    let error = ZcashBitGoPsbt::deserialize_v6(&bytes, Network::ZcashTestnet).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("mixes transparent inputs with shielded spends"),
        "unexpected error: {error}"
    );
}

/// Only one shielded-spend call per PSBT: a second call is a typed error, not a silent
/// overwrite of the first bundle.
#[test]
fn second_add_shielded_spends_is_rejected() {
    let seed = "ironwood_v6_keyless_twice";
    let (specs, anchor, _fvk, ak) = keyless_fixture();
    let wallet_keys = root_wallet_keys(seed);
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    z.add_shielded_spends(&specs[..1], &[], &anchor, &ak, OsRng)
        .unwrap();
    let error = z
        .add_shielded_spends(&specs[..1], &[], &anchor, &ak, OsRng)
        .unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&error),
        "IronwoodPsbtError.AlreadyAdded"
    );
}

/// An empty v6 PSBT for the PSBT-level negative tests.
fn empty_v6_psbt(seed: &str) -> ZcashBitGoPsbt {
    let wallet_keys = root_wallet_keys(seed);
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    let BitGoPsbt::Zcash(z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    z
}

/// Each output's Unified Address is stored under the action index the output landed at after
/// the shuffle, and survives a serialize/deserialize round-trip.
#[test]
fn add_shielded_spends_stores_unified_addresses_by_action_index() {
    let seed = "ironwood_v6_keyless_ua";
    let (specs, anchor, fvk, ak) = keyless_fixture();
    let mut z = empty_v6_psbt(seed);
    let mut outputs = [
        wallet_output(&fvk, 100, 40_000_000),
        wallet_output(&fvk, 101, 50_000_000),
    ];
    let uas: Vec<String> = outputs
        .iter()
        .map(|o| crate::zcash::unified_address::encode_orchard_receiver(&o.recipient, "tzec"))
        .collect::<Result<_, _>>()
        .unwrap();
    for (output, ua) in outputs.iter_mut().zip(&uas) {
        output.unified_address = Some(ua.clone());
    }
    let map = z
        .add_shielded_spends(&specs, &outputs, &anchor, &ak, OsRng)
        .unwrap();

    let z = ZcashBitGoPsbt::deserialize_v6(&z.serialize_v6(), Network::ZcashTestnet).unwrap();
    let pczt = z.ironwood_pczt().unwrap();
    for (j, ua) in uas.iter().enumerate() {
        let action_index = map.output_action_index(j).unwrap();
        assert_eq!(
            crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::get_ironwood_unified_address(
                &z.psbt,
                action_index
            ),
            Some(ua.clone()),
            "output {j}'s UA is keyed by its post-shuffle action index"
        );
        // …and that action really carries output j's recipient.
        assert_eq!(
            pczt.actions()[action_index]
                .output()
                .recipient()
                .map(|a| a.to_raw_address_bytes()),
            Some(outputs[j].recipient)
        );
    }
}

/// A rejected request leaves the PSBT untouched: a mismatched UA is a typed
/// `BadUnifiedAddress`, and nothing (PCZT, `ak`, UAs) is written.
#[test]
fn add_shielded_spends_rejects_mismatched_unified_address_atomically() {
    let seed = "ironwood_v6_keyless_ua_mismatch";
    let (specs, anchor, fvk, ak) = keyless_fixture();
    let mut z = empty_v6_psbt(seed);
    let before = z.serialize_v6();
    let mut output = wallet_output(&fvk, 100, 40_000_000);
    output.unified_address = Some(
        crate::zcash::unified_address::encode_orchard_receiver(
            &fvk.address_at(999u32, Scope::External)
                .to_raw_address_bytes(),
            "tzec",
        )
        .unwrap(),
    );
    let error = z
        .add_shielded_spends(&specs[..1], &[output], &anchor, &ak, OsRng)
        .unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&error),
        "IronwoodPsbtError.BadUnifiedAddress"
    );
    assert_eq!(
        z.serialize_v6(),
        before,
        "a rejected call must not touch the PSBT"
    );
}

/// Constructor errors wrapped by `IronwoodPsbtError` surface the Constructor's own code
/// (`IronwoodBuildError.*`), and leave the PSBT untouched.
#[test]
fn add_shielded_spends_surfaces_constructor_error_codes() {
    let seed = "ironwood_v6_keyless_codes";
    let (specs, anchor, fvk, ak) = keyless_fixture();
    let mut z = empty_v6_psbt(seed);
    let before = z.serialize_v6();

    let mut with_ovk = wallet_output(&fvk, 100, 40_000_000);
    with_ovk.ovk = Some([3u8; 32]);
    let error = z
        .add_shielded_spends(&specs[..1], &[with_ovk], &anchor, &ak, OsRng)
        .unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&error),
        "IronwoodBuildError.OvkNotAllowed"
    );

    let error = z
        .add_shielded_spends(&[], &[], &anchor, &ak, OsRng)
        .unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&error),
        "IronwoodBuildError.NoSpends"
    );
    assert_eq!(
        z.serialize_v6(),
        before,
        "a rejected call must not touch the PSBT"
    );
}

/// The full local lifecycle under `orchard-proving`, for each PSBT shape (1→0 deshield,
/// 1→2 with a Builder dummy spend, 2→2 transfer): the keyless-constructed bundle proves (with
/// the FVK installed transiently by the local prover), the proof verifies against orchard's
/// own verifying key, and zebra decodes the transaction.
#[cfg(feature = "orchard-proving")]
#[test]
fn keyless_spends_prove_and_verify_locally() {
    type Build = fn(
        &str,
    ) -> (
        ZcashBitGoPsbt,
        IronwoodActionMap,
        [u8; 32],
        FullViewingKey,
        SpendAuthorizingKey,
    );
    let shapes: [(&str, Build, usize); 3] = [
        (
            "ironwood_v6_keyless_local_proof_deshield",
            keyless_deshield_psbt,
            1,
        ),
        (
            "ironwood_v6_keyless_local_proof_surplus",
            keyless_surplus_psbt,
            2,
        ),
        (
            "ironwood_v6_keyless_local_proof_transfer",
            keyless_transfer_psbt,
            2,
        ),
    ];
    for (seed, build, n_actions) in shapes {
        let (mut z, map, _ak, fvk, ask) = build(seed);
        kms_out_ciphertexts(&mut z, &map, &fvk);
        let pairs = install_randomizers(&mut z, &map, &ask);
        install_spend_signatures(&mut z, &pairs, &ask);
        prove_and_verify_locally(z, &pairs, &fvk, n_actions);
    }
}

#[cfg(feature = "orchard-proving")]
fn prove_and_verify_locally(
    z: ZcashBitGoPsbt,
    pairs: &[(usize, [u8; 32])],
    fvk: &FullViewingKey,
    n_actions: usize,
) {
    use nonempty::NonEmpty;
    use orchard::bundle::{Authorized, Bundle as OrchardBundle, BundleVersion};
    use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
    use orchard::note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext};
    use orchard::primitives::redpallas::{Binding, Signature};
    use orchard::value::ValueCommitment;
    use orchard::Action as OrchardAction;

    let raw = z
        .combine_ironwood_proof_locally_with_alphas(pairs, Some(&fvk.to_bytes()), OsRng)
        .unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    let bundle = tx.ironwood_bundle.as_ref().unwrap();
    assert_eq!(bundle.actions.len(), n_actions);
    assert_eq!(bundle.proof.len(), Proof::expected_proof_size(n_actions));

    use zebra_chain::serialization::ZcashDeserialize;
    use zebra_chain::transaction::Transaction as ZebraTx;
    let zebra = ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes the tx");
    assert_eq!(zebra.ironwood_actions().count(), n_actions);
    // Reconstruct the fully-authorized orchard bundle from the on-wire action data and ask
    // orchard itself to verify the proof against a freshly-built verifying key.
    let actions = bundle
        .actions
        .iter()
        .zip(&bundle.spend_auth_sigs)
        .map(|(a, sig)| {
            let cv_net = Option::from(ValueCommitment::from_bytes(&a.cv)).expect("valid cv_net");
            let rk = VerificationKey::<SpendAuth>::try_from(a.rk).expect("valid rk");
            let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&a.cmx)).expect("valid cmx");
            let nf = Option::from(Nullifier::from_bytes(&a.nullifier)).expect("valid nf");
            let encrypted_note = TransmittedNoteCiphertext {
                epk_bytes: a.ephemeral_key,
                enc_ciphertext: a.enc_ciphertext,
                out_ciphertext: a.out_ciphertext,
            };
            OrchardAction::from_parts(
                nf,
                rk,
                cmx,
                encrypted_note,
                cv_net,
                Signature::<SpendAuth>::from(*sig),
            )
            .expect("valid action")
        })
        .collect::<Vec<_>>();
    let actions = NonEmpty::from_vec(actions).expect("at least one action");
    let authorization = Authorized::from_parts(
        Proof::new(bundle.proof.clone()),
        Signature::<Binding>::from(bundle.binding_sig),
    );
    let orchard_bundle = OrchardBundle::<Authorized, i64>::try_from_parts(
        actions,
        BundleVersion::ironwood_v3().default_flags(),
        bundle.value_balance,
        Option::from(orchard::tree::Anchor::from_bytes(bundle.anchor)).expect("valid anchor"),
        authorization,
        BundleVersion::ironwood_v3(),
    )
    .expect("valid authorized bundle");
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    orchard_bundle
        .verify_proof(&vk)
        .expect("the keyless bundle's locally-produced proof verifies");
}
