//! Tests for the keyless Ironwood spend flow: `add_shielded_spends`, the
//! one-input-kind rule, and the deshield / shielded→shielded lifecycles the build
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
#[cfg(feature = "orchard-proving")]
use crate::zcash::ironwood_construct::IronwoodKeylessSpendSpec;
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
        .add_shielded_spends(&specs[..1], &[], &anchor, OsRng)
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
        .add_shielded_spends(&specs, &outputs, &anchor, OsRng)
        .unwrap();
    (
        z,
        map,
        ak,
        fvk,
        SpendAuthorizingKey::from(&test_spending_key()),
    )
}

/// The out-ciphertext round: re-encrypt every requested output's
/// `out_ciphertext` under the FVK's external `ovk` and deliver it through
/// [`ZcashBitGoPsbt::add_out_ciphertexts`] — the production entry point, so the pending
/// marker tracks every install.
fn fvk_out_ciphertexts(z: &mut ZcashBitGoPsbt, map: &IronwoodActionMap, fvk: &FullViewingKey) {
    let ovk = *fvk.to_ovk(Scope::External).as_ref();
    let pczt = z.ironwood_pczt().unwrap();
    let entries: Vec<_> = map
        .output_action_indices()
        .iter()
        .map(|&action_index| {
            (
                action_index,
                compute_out_ciphertext(&pczt, action_index, ovk, &mut OsRng).unwrap(),
            )
        })
        .collect();
    if !entries.is_empty() {
        z.add_out_ciphertexts(&entries).unwrap();
    }
}

/// The FROST stand-in round: install `(alpha, rk = ak.randomize(alpha))` on every real spend
/// in one [`ZcashBitGoPsbt::add_spend_randomizers`] batch, and return the
/// `(action_index, alpha)` pairs the stand-in signer needs.
fn install_randomizers(
    z: &mut ZcashBitGoPsbt,
    map: &IronwoodActionMap,
    ask: &SpendAuthorizingKey,
) -> Vec<(usize, [u8; 32])> {
    let mut pairs = Vec::new();
    for &action_index in map.spend_action_indices() {
        let alpha = pasta_curves::pallas::Scalar::random(&mut OsRng);
        let rk = <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&ask.randomize(&alpha)));
        pairs.push((action_index, alpha.to_repr(), rk));
    }
    let ak = <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(
        &ask.randomize(&pasta_curves::pallas::Scalar::ZERO),
    ));
    z.add_spend_randomizers(&pairs, Some(&ak)).unwrap();
    pairs
        .into_iter()
        .map(|(action_index, alpha_repr, _)| (action_index, alpha_repr))
        .collect()
}

/// The PSBT never carries the wallet's `ak` or a spend's `alpha`: neither appears anywhere in
/// its serialized bytes, and no real spend's PCZT `alpha` is set.
fn assert_no_ak_or_alpha(z: &ZcashBitGoPsbt, ak: &[u8; 32], pairs: &[(usize, [u8; 32])]) {
    let bytes = z.serialize_v6();
    assert!(
        !bytes.windows(32).any(|w| w == ak),
        "the wallet ak leaked into the PSBT"
    );
    for (action_index, alpha) in pairs {
        assert!(
            !bytes.windows(32).any(|w| w == alpha),
            "action {action_index}'s alpha leaked into the PSBT"
        );
    }
    let pczt = z.ironwood_pczt().unwrap();
    for action in pczt.actions() {
        if action.spend().dummy_sk().is_none() {
            assert!(
                action.spend().alpha().is_none(),
                "a real spend carries alpha"
            );
        }
    }
}

/// The FROST stand-in signatures: RedPallas over the PSBT's ZIP-244 sig digest.
fn install_spend_signatures(
    z: &mut ZcashBitGoPsbt,
    pairs: &[(usize, [u8; 32])],
    ask: &SpendAuthorizingKey,
) {
    let sighash = z.spend_sighash().unwrap();
    let signatures: Vec<(usize, [u8; 64])> = pairs
        .iter()
        .map(|(action_index, alpha_repr)| {
            let alpha = pasta_curves::pallas::Scalar::from_repr(*alpha_repr).unwrap();
            let sig = ask.randomize(&alpha).sign(OsRng, &sighash);
            (*action_index, <[u8; 64]>::from(&sig))
        })
        .collect();
    z.add_spend_signatures(&signatures).unwrap();
}

/// The full keyless deshield lifecycle: build → FROST
/// randomizers → signatures → combine. Each step survives a serialize/deserialize round-trip,
/// and zebra independently decodes the result.
#[test]
fn keyless_deshield_lifecycle_round_trips() {
    let seed = "ironwood_v6_keyless_deshield";
    let (mut z, map, ak, _fvk, ask) = keyless_deshield_psbt(seed);
    assert_no_ak_or_alpha(&z, &ak, &[]);

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
    assert_no_ak_or_alpha(&z, &ak, &pairs);
    let bytes = z.serialize_v6();
    z = ZcashBitGoPsbt::deserialize_v6(&bytes, Network::ZcashTestnet).unwrap();

    install_spend_signatures(&mut z, &pairs, &ask);
    assert_no_ak_or_alpha(&z, &ak, &pairs);
    let bytes = z.serialize_v6();
    let z = ZcashBitGoPsbt::deserialize_v6(&bytes, Network::ZcashTestnet).unwrap();

    // No shielded outputs ⇒ no out-ciphertext round for this shape.
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

/// The shielded→shielded lifecycle: two spends into two outputs, with the out-ciphertext
/// round — the patched ciphertexts are exactly what the FVK's `ovk` recovers, and they
/// survive to the broadcast transaction.
#[test]
fn keyless_shielded_transfer_lifecycle_round_trips() {
    use orchard::note_encryption::IronwoodDomain;
    use zcash_note_encryption::try_output_recovery_with_ovk;

    let seed = "ironwood_v6_keyless_transfer";
    let (mut z, map, _ak, fvk, ask) = keyless_transfer_psbt(seed);

    assert_eq!(z.ironwood_bundle_info().unwrap().value_balance, 0);

    // Ciphertext round: every output's out_ciphertext becomes recoverable under the FVK's ovk.
    fvk_out_ciphertexts(&mut z, &map, &fvk);
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
            "action {i}'s real out_ciphertext survives to the broadcast transaction"
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
        .add_shielded_spends(&specs[..1], &outputs, &anchor, OsRng)
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

    fvk_out_ciphertexts(&mut z, &map, &fvk);
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

/// The Zcash parse surfaces the keyless bundle's spends (verified) and reports the signing
/// state the workflow is in.
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

/// One input kind, shielded side: `add_shielded_spends` rejects a PSBT that already carries
/// transparent inputs, with the typed error code.
#[test]
fn add_shielded_spends_rejects_transparent_inputs() {
    let seed = "ironwood_v6_keyless_rule0_shielded";
    let (specs, anchor, _fvk, _ak) = keyless_fixture();
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
        .add_shielded_spends(&specs[..1], &[], &anchor, OsRng)
        .unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&error),
        "IronwoodPsbtError.MixedInputKinds"
    );
}

/// One input kind, transparent side: the generic input adders reject a PSBT whose stored bundle
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

/// One input kind at deserialize: a PSBT mixing transparent inputs with real spends (built through
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
    let (specs, anchor, _fvk, _ak) = keyless_fixture();
    let wallet_keys = root_wallet_keys(seed);
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    z.add_shielded_spends(&specs[..1], &[], &anchor, OsRng)
        .unwrap();
    let error = z
        .add_shielded_spends(&specs[..1], &[], &anchor, OsRng)
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
    let (specs, anchor, fvk, _ak) = keyless_fixture();
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
        .add_shielded_spends(&specs, &outputs, &anchor, OsRng)
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
/// `BadUnifiedAddress`, and nothing (PCZT, UAs) is written.
#[test]
fn add_shielded_spends_rejects_mismatched_unified_address_atomically() {
    let seed = "ironwood_v6_keyless_ua_mismatch";
    let (specs, anchor, fvk, _ak) = keyless_fixture();
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
        .add_shielded_spends(&specs[..1], &[output], &anchor, OsRng)
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
    let (specs, anchor, fvk, _ak) = keyless_fixture();
    let mut z = empty_v6_psbt(seed);
    let before = z.serialize_v6();

    let mut with_ovk = wallet_output(&fvk, 100, 40_000_000);
    with_ovk.ovk = Some([3u8; 32]);
    let error = z
        .add_shielded_spends(&specs[..1], &[with_ovk], &anchor, OsRng)
        .unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&error),
        "IronwoodBuildError.OvkNotAllowed"
    );

    let error = z.add_shielded_spends(&[], &[], &anchor, OsRng).unwrap_err();
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
        fvk_out_ciphertexts(&mut z, &map, &fvk);
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

// ---- The out_ciphertext / proof-request workflow ----

/// The real ciphertext for one action, under the FVK's external `ovk`.
fn fvk_out_ciphertext(z: &ZcashBitGoPsbt, fvk: &FullViewingKey, action_index: usize) -> [u8; 80] {
    let ovk = *fvk.to_ovk(Scope::External).as_ref();
    compute_out_ciphertext(&z.ironwood_pczt().unwrap(), action_index, ovk, &mut OsRng).unwrap()
}

/// A 2→1 PSBT: one real output and one fabricated dummy output (on a real spend).
fn keyless_two_to_one_psbt(seed: &str) -> (ZcashBitGoPsbt, IronwoodActionMap, FullViewingKey) {
    let (specs, anchor, fvk, _ak) = keyless_fixture();
    let mut z = empty_v6_psbt(seed);
    let map = z
        .add_shielded_spends(
            &specs,
            &[wallet_output(&fvk, 100, 90_000_000)],
            &anchor,
            OsRng,
        )
        .unwrap();
    (z, map, fvk)
}

/// Remove the `IronwoodOutCiphertextsSet` bitset, as a tampering party could.
fn strip_out_ciphertexts_marker(z: &mut ZcashBitGoPsbt) {
    use crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::{ZecV6KeySubtype, BITGO_ZEC_V6};
    z.psbt.proprietary.retain(|key, _| {
        !(key.prefix == BITGO_ZEC_V6
            && key.subtype == ZecV6KeySubtype::IronwoodOutCiphertextsSet as u8)
    });
}

/// A recognizable proof of the right size, so tests can tell which proof reached the wire.
fn patterned_proof(n_actions: usize) -> Vec<u8> {
    (0..Proof::expected_proof_size(n_actions))
        .map(|i| (i % 251) as u8)
        .collect()
}

/// The proof bytes of a combined v6 transaction.
fn wire_proof(raw: &[u8]) -> Vec<u8> {
    crate::zcash::v6::decode_v6_transaction(raw)
        .unwrap()
        .ironwood_bundle
        .unwrap()
        .proof
}

/// The out-ciphertext request lists exactly the real outputs — dummy outputs excluded —
/// and errors once every real output is set, when there are none, or on a shielding PSBT.
#[test]
fn out_ciphertext_request_lists_real_outputs_and_errors_when_empty() {
    let (mut z, map, fvk) = keyless_two_to_one_psbt("ironwood_v6_keyless_request");
    let (bytes, pending) = z.out_ciphertext_request().unwrap();
    assert_eq!(bytes, z.raw_ironwood_pczt_bytes().unwrap());
    assert_eq!(pending, vec![map.output_action_index(0).unwrap()]);
    assert_eq!(z.pending_out_ciphertexts().unwrap(), pending);

    // The ciphertext round resolves the request; a further request errors with NothingPending.
    let ct = fvk_out_ciphertext(&z, &fvk, pending[0]);
    z.add_out_ciphertexts(&[(pending[0], ct)]).unwrap();
    assert!(z.pending_out_ciphertexts().unwrap().is_empty());
    assert!(matches!(
        z.out_ciphertext_request(),
        Err(IronwoodPsbtError::NothingPending)
    ));

    // A spend-only bundle (no real outputs) has nothing to request either.
    let (specs, anchor, _fvk, _ak) = keyless_fixture();
    let mut spend_only = empty_v6_psbt("ironwood_v6_keyless_request_spend_only");
    spend_only
        .add_shielded_spends(&specs[..1], &[], &anchor, OsRng)
        .unwrap();
    assert!(matches!(
        spend_only.out_ciphertext_request(),
        Err(IronwoodPsbtError::NothingPending)
    ));

    // Shielding is not a spend bundle, and neither is a PSBT without a PCZT.
    let mut shield = build_shield_psbt("ironwood_v6_keyless_request_shield");
    assert!(matches!(
        shield.out_ciphertext_request(),
        Err(IronwoodPsbtError::NotSpendBundle)
    ));
    assert!(matches!(
        shield.add_out_ciphertexts(&[(0, [0u8; 80])]),
        Err(IronwoodPsbtError::NotSpendBundle)
    ));
    assert!(shield.pending_out_ciphertexts().unwrap().is_empty());
    assert!(matches!(
        empty_v6_psbt("ironwood_v6_keyless_request_empty").out_ciphertext_request(),
        Err(IronwoodPsbtError::NotSpendBundle)
    ));
}

/// `add_out_ciphertexts` is atomic: a valid entry followed by a bad one (an unknown or a
/// dummy action index) stores nothing — the PCZT bytes and the pending marker are untouched.
#[test]
fn add_out_ciphertexts_is_atomic() {
    let (mut z, map, fvk) = keyless_two_to_one_psbt("ironwood_v6_keyless_atomic");
    let before = z.raw_ironwood_pczt_bytes().unwrap();
    let real_index = map.output_action_index(0).unwrap();
    let ct = fvk_out_ciphertext(&z, &fvk, real_index);

    let error = z
        .add_out_ciphertexts(&[(real_index, ct), (99, [0u8; 80])])
        .unwrap_err();
    assert!(matches!(error, IronwoodPsbtError::UnknownAction));
    assert_eq!(z.raw_ironwood_pczt_bytes().unwrap(), before);
    assert_eq!(z.pending_out_ciphertexts().unwrap(), vec![real_index]);

    let dummy_index = 1 - real_index;
    let error = z
        .add_out_ciphertexts(&[(real_index, ct), (dummy_index, ct)])
        .unwrap_err();
    assert!(matches!(error, IronwoodPsbtError::DummyAction));
    assert_eq!(z.raw_ironwood_pczt_bytes().unwrap(), before);
    assert_eq!(z.pending_out_ciphertexts().unwrap(), vec![real_index]);

    let error = z.add_out_ciphertexts(&[]).unwrap_err();
    assert!(matches!(error, IronwoodPsbtError::NothingPending));
}

/// Re-delivering the installed bytes is a no-op; different bytes on a set index are
/// rejected and change nothing.
#[test]
fn add_out_ciphertexts_is_idempotent_for_identical_bytes_only() {
    let (mut z, map, fvk) = keyless_two_to_one_psbt("ironwood_v6_keyless_idempotent");
    let action_index = map.output_action_index(0).unwrap();
    let ct = fvk_out_ciphertext(&z, &fvk, action_index);

    z.add_out_ciphertexts(&[(action_index, ct)]).unwrap();
    let after = z.raw_ironwood_pczt_bytes().unwrap();

    // Identical bytes: accepted, nothing changes.
    z.add_out_ciphertexts(&[(action_index, ct)]).unwrap();
    assert_eq!(z.raw_ironwood_pczt_bytes().unwrap(), after);
    assert!(z.pending_out_ciphertexts().unwrap().is_empty());

    // Different bytes: rejected, nothing changes.
    let error = z
        .add_out_ciphertexts(&[(action_index, [7u8; 80])])
        .unwrap_err();
    assert!(matches!(
        error,
        IronwoodPsbtError::OutCiphertextConflict { action_index: idx } if idx == action_index
    ));
    assert_eq!(z.raw_ironwood_pczt_bytes().unwrap(), after);
}

/// Duplicates within one batch follow the same rule as re-delivery: identical bytes are
/// accepted, different bytes are a conflict that stores nothing.
#[test]
fn add_out_ciphertexts_rejects_conflicting_duplicates_in_one_batch() {
    let (mut z, map, fvk) = keyless_two_to_one_psbt("ironwood_v6_keyless_batch_duplicates");
    let action_index = map.output_action_index(0).unwrap();
    let ct = fvk_out_ciphertext(&z, &fvk, action_index);
    let before = z.raw_ironwood_pczt_bytes().unwrap();

    let error = z
        .add_out_ciphertexts(&[(action_index, ct), (action_index, [7u8; 80])])
        .unwrap_err();
    assert!(matches!(
        error,
        IronwoodPsbtError::OutCiphertextConflict { action_index: idx } if idx == action_index
    ));
    assert_eq!(z.raw_ironwood_pczt_bytes().unwrap(), before);
    assert_eq!(z.pending_out_ciphertexts().unwrap(), vec![action_index]);

    z.add_out_ciphertexts(&[(action_index, ct), (action_index, ct)])
        .unwrap();
    assert!(z.pending_out_ciphertexts().unwrap().is_empty());
    assert_eq!(
        z.ironwood_pczt().unwrap().actions()[action_index]
            .output()
            .encrypted_note()
            .out_ciphertext,
        ct
    );
}

/// A spend bundle whose bitset was stripped fails closed: every real output counts as
/// pending, the gates hold, and the ciphertext round still completes (re-creating the bitset).
#[test]
fn missing_out_ciphertexts_marker_fails_closed() {
    let seed = "ironwood_v6_keyless_marker_stripped";
    let (mut z, map, _ak, fvk, ask) = keyless_transfer_psbt(seed);
    fvk_out_ciphertexts(&mut z, &map, &fvk);
    assert!(z.pending_out_ciphertexts().unwrap().is_empty());

    strip_out_ciphertexts_marker(&mut z);
    let mut expected = map.output_action_indices().to_vec();
    expected.sort_unstable();
    assert_eq!(z.pending_out_ciphertexts().unwrap(), expected);
    assert!(matches!(
        z.proof_request(&[]),
        Err(IronwoodPsbtError::OutCiphertextPending { .. })
    ));

    // The stripped state survives the PSBT wire too.
    let bytes = z.serialize_v6();
    let mut z = ZcashBitGoPsbt::deserialize_v6(&bytes, Network::ZcashTestnet).unwrap();
    assert_eq!(z.pending_out_ciphertexts().unwrap(), expected);

    // Re-delivering (a fresh response would carry fresh randomness) resolves it.
    let entries: Vec<_> = map
        .output_action_indices()
        .iter()
        .map(|&action_index| (action_index, fvk_out_ciphertext(&z, &fvk, action_index)))
        .collect();
    z.add_out_ciphertexts(&entries).unwrap();
    assert!(z.pending_out_ciphertexts().unwrap().is_empty());
    let pairs = install_randomizers(&mut z, &map, &ask);
    install_spend_signatures(&mut z, &pairs, &ask);
    z.proof_request(&pairs).unwrap();
}

/// Frozen once signed: no ciphertext install once a spend-auth signature exists — even for the
/// already-installed (identical) bytes, which idempotent re-delivery alone would have accepted.
#[test]
fn add_out_ciphertexts_rejects_after_a_spend_signature() {
    let seed = "ironwood_v6_keyless_rule3_spend_sig";
    let (mut z, map, _ak, fvk, ask) = keyless_transfer_psbt(seed);

    fvk_out_ciphertexts(&mut z, &map, &fvk);
    let pairs = install_randomizers(&mut z, &map, &ask);
    install_spend_signatures(&mut z, &pairs, &ask);

    let entries: Vec<(usize, [u8; 80])> = map
        .output_action_indices()
        .iter()
        .map(|&action_index| (action_index, [0u8; 80]))
        .collect();
    let error = z.add_out_ciphertexts(&entries).unwrap_err();
    assert!(matches!(error, IronwoodPsbtError::AlreadySigned));
}

/// The freeze's transparent defense in depth: a shielding PSBT with a collected transparent
/// signature refuses `add_out_ciphertexts` too.
#[test]
fn add_out_ciphertexts_rejects_after_a_transparent_signature() {
    use crate::bitcoin::secp256k1::Secp256k1;

    let seed = "ironwood_v6_keyless_rule3_transparent_sig";
    let secp = Secp256k1::new();
    let wallet_keys = root_wallet_keys(seed);
    let mut shield = build_shield_psbt(seed);
    shield
        .sign_ironwood_v6(&test_wallet_xpriv(seed, 0), &wallet_keys, &secp)
        .unwrap();
    assert!(
        shield
            .psbt
            .inputs
            .iter()
            .any(|input| !input.partial_sigs.is_empty()),
        "the transparent round collected a signature"
    );

    let error = shield.add_out_ciphertexts(&[(0, [0u8; 80])]).unwrap_err();
    assert!(matches!(error, IronwoodPsbtError::AlreadySigned));
}

/// The proof request refuses a spend bundle until its ciphertexts, then its randomizers,
/// then its spend signatures are installed; a shielding bundle is served as-is.
#[test]
fn proof_request_requires_ciphertexts_randomizers_then_signatures() {
    let seed = "ironwood_v6_keyless_proof_request";
    let (mut z, map, _ak, fvk, ask) = keyless_transfer_psbt(seed);

    let mut outputs = map.output_action_indices().to_vec();
    outputs.sort_unstable();
    assert!(matches!(
        z.proof_request(&[]),
        Err(IronwoodPsbtError::OutCiphertextPending { action_indices }) if action_indices == outputs
    ));

    fvk_out_ciphertexts(&mut z, &map, &fvk);
    let mut spends = map.spend_action_indices().to_vec();
    spends.sort_unstable();
    assert!(matches!(
        z.proof_request(&[]),
        Err(IronwoodPsbtError::RandomizerPending { action_indices }) if action_indices == spends
    ));

    let pairs = install_randomizers(&mut z, &map, &ask);
    assert!(matches!(
        z.proof_request(&pairs),
        Err(IronwoodPsbtError::SpendSignaturePending { action_indices }) if action_indices == spends
    ));

    install_spend_signatures(&mut z, &pairs, &ask);
    let stored = z.raw_ironwood_pczt_bytes().unwrap();

    // Exactly one non-zero alpha per real spend.
    assert!(matches!(
        z.proof_request(&[]),
        Err(IronwoodPsbtError::RandomizerMissing { action_indices }) if action_indices == spends
    ));
    assert!(matches!(
        z.proof_request(&[pairs[0], pairs[0], pairs[1]]),
        Err(IronwoodPsbtError::DuplicateAction { .. })
    ));
    assert!(matches!(
        z.proof_request(&[(map.output_action_indices().len() + 7, [1u8; 32])]),
        Err(IronwoodPsbtError::UnknownAction)
    ));
    assert!(matches!(
        z.proof_request(&[(pairs[0].0, [0u8; 32]), pairs[1]]),
        Err(IronwoodPsbtError::Build(
            crate::zcash::ironwood_build::IronwoodBuildError::UnrandomizedRk
        ))
    ));

    // The request carries the alphas; the PSBT still does not.
    let request =
        crate::zcash::ironwood_pczt::deserialize_pczt(&z.proof_request(&pairs).unwrap()).unwrap();
    for (action_index, alpha) in &pairs {
        assert_eq!(
            request.actions()[*action_index]
                .spend()
                .alpha()
                .as_ref()
                .map(|a| a.to_repr()),
            Some(*alpha)
        );
    }
    assert_eq!(z.raw_ironwood_pczt_bytes().unwrap(), stored);

    let shield = build_shield_psbt("ironwood_v6_keyless_proof_request_shield");
    assert_eq!(
        shield.proof_request(&[]).unwrap(),
        shield.raw_ironwood_pczt_bytes().unwrap()
    );
    assert!(matches!(
        shield.proof_request(&[(0, [1u8; 32])]),
        Err(IronwoodPsbtError::DummyAction)
    ));
}

/// The ciphertexts-first gate covers every path that commits the action data: both sighashes, the
/// randomizer installer and the spend-signature path — not just the proof request.
#[test]
fn pending_out_ciphertexts_gate_sighashes_randomizers_and_signatures() {
    let seed = "ironwood_v6_keyless_rule1_gates";
    let (mut z, map, _ak, _fvk, _ask) = keyless_transfer_psbt(seed);
    let spend_index = map.spend_action_indices()[0];
    let is_ciphertext_pending = |e: &str| e.contains("pending their out_ciphertext");

    let error = z.v6_sig_digest().unwrap_err();
    assert!(is_ciphertext_pending(&error), "unexpected: {error}");
    let error = z.v6_transparent_sighash(0).unwrap_err();
    assert!(is_ciphertext_pending(&error), "unexpected: {error}");
    let error = z
        .add_spend_randomizers(&[(spend_index, [1u8; 32], [0u8; 32])], None)
        .unwrap_err();
    assert!(
        matches!(error, IronwoodPsbtError::OutCiphertextPending { .. }),
        "unexpected: {error:?}"
    );
    let error = z
        .add_spend_signatures(&[(spend_index, [0u8; 64])])
        .unwrap_err();
    assert!(
        matches!(error, IronwoodPsbtError::OutCiphertextPending { .. }),
        "unexpected: {error:?}"
    );
}

/// The full sign-then-prove lifecycle, the same shape as shielding: sign first, then the
/// finalize step requests the proof and passes it straight to `combine_ironwood_proof`. The
/// signatures made before proving stay valid (the sig digest excludes the proof), the proof
/// request survives a PSBT round trip, and exactly that proof reaches the wire.
#[test]
fn sign_then_prove_lifecycle_combines_the_requested_proof() {
    let seed = "ironwood_v6_keyless_sign_then_prove";
    let (mut z, map, _ak, fvk, ask) = keyless_transfer_psbt(seed);

    fvk_out_ciphertexts(&mut z, &map, &fvk);
    let pairs = install_randomizers(&mut z, &map, &ask);
    install_spend_signatures(&mut z, &pairs, &ask);
    let sighash = z.v6_sig_digest().unwrap();

    // Finalize, possibly in another request: the signed PSBT is all the prover needs.
    let bytes = z.serialize_v6();
    let z = ZcashBitGoPsbt::deserialize_v6(&bytes, Network::ZcashTestnet).unwrap();
    let request = z.proof_request(&pairs).unwrap();
    assert!(
        crate::zcash::ironwood_pczt::deserialize_pczt(&request)
            .unwrap()
            .zkproof()
            .is_none(),
        "the request carries no proof; the proof never enters the PSBT"
    );

    let proof = patterned_proof(2);
    let raw = z.combine_ironwood_proof(proof.clone(), OsRng).unwrap();
    assert_eq!(wire_proof(&raw), proof);

    // The spend signatures collected before proving verify against the final digest.
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    let bundle = tx.ironwood_bundle.as_ref().unwrap();
    assert_eq!(
        crate::zcash::v6::compute_v6_sig_digest(&tx, &[], &[]),
        sighash
    );
    for &(action_index, _) in &pairs {
        let rk = VerificationKey::<SpendAuth>::try_from(bundle.actions[action_index].rk).unwrap();
        let sig = orchard::primitives::redpallas::Signature::<SpendAuth>::from(
            bundle.spend_auth_sigs[action_index],
        );
        rk.verify(&sighash, &sig)
            .expect("the pre-proof spend signature verifies on the broadcast transaction");
    }

    use zebra_chain::serialization::ZcashDeserialize;
    use zebra_chain::transaction::Transaction as ZebraTx;
    ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes the signed-then-proven transfer");
}

/// `add_spend_randomizers` stores only `rk`, is atomic, and checks the pair only against a
/// caller-supplied `ak`: without one a mismatched pair is installed, and the client's key-free
/// verifier (its own `ak` + FROST randomizers) catches it.
#[test]
fn add_spend_randomizers_is_atomic_and_checks_the_pair_against_the_callers_ak() {
    use crate::zcash::ironwood_build::IronwoodBuildError;
    use crate::zcash::ironwood_verify::{verify_bundle_without_keys, KeylessVerifyContext};

    let seed = "ironwood_v6_keyless_randomizer_batch";
    let (mut z, map, ak, fvk, ask) = keyless_transfer_psbt(seed);
    fvk_out_ciphertexts(&mut z, &map, &fvk);
    let [first, second] = [map.spend_action_indices()[0], map.spend_action_indices()[1]];
    let pair = |action_index: usize| {
        let alpha = pasta_curves::pallas::Scalar::random(&mut OsRng);
        let rk = <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&ask.randomize(&alpha)));
        (action_index, alpha.to_repr(), rk)
    };
    let (good, other) = (pair(first), pair(second));
    let mismatched = (second, other.1, good.2);
    let before = z.serialize_v6();

    // One bad entry after a good one stores nothing.
    let error = z
        .add_spend_randomizers(&[good, mismatched], Some(&ak))
        .unwrap_err();
    assert!(
        matches!(
            error,
            IronwoodPsbtError::Build(IronwoodBuildError::RandomizerMismatch)
        ),
        "unexpected: {error:?}"
    );
    assert_eq!(
        z.serialize_v6(),
        before,
        "a rejected batch leaves the PSBT unchanged"
    );

    // A repeated index, an empty batch, and a dummy target are rejected.
    assert!(matches!(
        z.add_spend_randomizers(&[good, good], Some(&ak)),
        Err(IronwoodPsbtError::DuplicateAction { action_index }) if action_index == first
    ));
    assert!(matches!(
        z.add_spend_randomizers(&[], Some(&ak)),
        Err(IronwoodPsbtError::NothingPending)
    ));
    assert!(matches!(
        z.add_spend_randomizers(&[good], Some(&[0u8; 32])),
        Err(IronwoodPsbtError::Build(
            IronwoodBuildError::BadSpendValidatingKey
        ))
    ));
    assert_eq!(z.serialize_v6(), before);

    // Without the wallet's ak the mismatched pair is installed — only `rk` is stored…
    z.add_spend_randomizers(&[good, mismatched], None).unwrap();
    assert_no_ak_or_alpha(&z, &ak, &[(good.0, good.1), (mismatched.0, mismatched.1)]);
    assert!(z.shielded_status().unwrap().pending_randomizers.is_empty());

    // …and the client, checking against its own ak and randomizers, rejects it.
    let pczt = z.ironwood_pczt().unwrap();
    let honest = KeylessVerifyContext {
        expected_ak: Some(ak),
        expected_randomizers: vec![good, other],
        ..Default::default()
    };
    let error = verify_bundle_without_keys(&pczt, &honest).unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&error),
        "IronwoodVerifyError.Rk"
    );

    // Re-installing the honest pair (before any signature) fixes it.
    z.add_spend_randomizers(&[other], Some(&ak)).unwrap();
    verify_bundle_without_keys(&z.ironwood_pczt().unwrap(), &honest).unwrap();
}

/// Randomizers only target real spends of a spend bundle.
#[test]
fn add_spend_randomizers_rejects_dummy_spends_and_shielding_bundles() {
    let seed = "ironwood_v6_keyless_randomizer_targets";
    let (mut z, map, ak, fvk, _ask) = keyless_surplus_psbt(seed);
    fvk_out_ciphertexts(&mut z, &map, &fvk);
    let dummy = (0..2)
        .find(|i| !map.spend_action_indices().contains(i))
        .unwrap();
    assert!(matches!(
        z.add_spend_randomizers(&[(dummy, [1u8; 32], [0u8; 32])], Some(&ak)),
        Err(IronwoodPsbtError::DummyAction)
    ));

    let mut shield = build_shield_psbt("ironwood_v6_keyless_randomizer_shield");
    assert!(matches!(
        shield.add_spend_randomizers(&[(0, [1u8; 32], [0u8; 32])], None),
        Err(IronwoodPsbtError::NotSpendBundle)
    ));
    assert!(matches!(
        shield.add_spend_signatures(&[(0, [0u8; 64])]),
        Err(IronwoodPsbtError::NotSpendBundle)
    ));
}

/// `add_spend_signatures` is atomic: a valid signature followed by an invalid one stores
/// nothing; repeated and empty batches are rejected.
#[test]
fn add_spend_signatures_is_atomic() {
    use crate::zcash::ironwood_build::IronwoodBuildError;

    let seed = "ironwood_v6_keyless_signature_batch";
    let (mut z, map, _ak, fvk, ask) = keyless_transfer_psbt(seed);
    fvk_out_ciphertexts(&mut z, &map, &fvk);
    let pairs = install_randomizers(&mut z, &map, &ask);
    let sighash = z.spend_sighash().unwrap();
    let sign = |&(action_index, alpha): &(usize, [u8; 32])| {
        let alpha = pasta_curves::pallas::Scalar::from_repr(alpha).unwrap();
        (
            action_index,
            <[u8; 64]>::from(&ask.randomize(&alpha).sign(OsRng, &sighash)),
        )
    };
    let (good, other) = (sign(&pairs[0]), sign(&pairs[1]));
    let before = z.serialize_v6();

    let error = z
        .add_spend_signatures(&[good, (other.0, [7u8; 64])])
        .unwrap_err();
    assert!(
        matches!(
            error,
            IronwoodPsbtError::Build(IronwoodBuildError::InvalidExternalSignature)
        ),
        "unexpected: {error:?}"
    );
    assert_eq!(
        z.serialize_v6(),
        before,
        "a rejected batch leaves the PSBT unchanged"
    );
    assert!(matches!(
        z.add_spend_signatures(&[good, good]),
        Err(IronwoodPsbtError::DuplicateAction { .. })
    ));
    assert!(matches!(
        z.add_spend_signatures(&[]),
        Err(IronwoodPsbtError::NothingPending)
    ));

    // Signatures may arrive in several batches.
    z.add_spend_signatures(&[good]).unwrap();
    z.add_spend_signatures(&[other]).unwrap();
    assert!(z
        .shielded_status()
        .unwrap()
        .pending_spend_signatures
        .is_empty());
}

/// Combine reports an unsigned real spend by action index before touching orchard.
#[test]
fn combine_rejects_an_unsigned_spend_with_a_typed_error() {
    let seed = "ironwood_v6_keyless_combine_unsigned";
    let (mut z, map, _ak, fvk, ask) = keyless_transfer_psbt(seed);
    fvk_out_ciphertexts(&mut z, &map, &fvk);
    install_randomizers(&mut z, &map, &ask);
    let mut spends = map.spend_action_indices().to_vec();
    spends.sort_unstable();
    assert!(matches!(
        z.combine_ironwood_proof(patterned_proof(2), OsRng),
        Err(IronwoodPsbtError::SpendSignaturePending { action_indices }) if action_indices == spends
    ));
}

/// `shielded_status` tracks every stage of the spend workflow, and is ready for the proof only
/// once ciphertexts, randomizers and signatures are all installed.
#[test]
fn shielded_status_tracks_every_stage() {
    use super::super::ironwood_spend::IronwoodInputKind;

    let seed = "ironwood_v6_keyless_status";
    let (mut z, map, _ak, fvk, ask) = keyless_transfer_psbt(seed);
    let sorted = |indices: &[usize]| {
        let mut indices = indices.to_vec();
        indices.sort_unstable();
        indices
    };
    let (spends, outputs) = (
        sorted(map.spend_action_indices()),
        sorted(map.output_action_indices()),
    );

    let status = z.shielded_status().unwrap();
    assert_eq!(status.input_kind, IronwoodInputKind::Shielded);
    assert_eq!(status.pending_out_ciphertexts, outputs);
    assert_eq!(status.pending_randomizers, spends);
    assert_eq!(status.pending_spend_signatures, spends);
    assert!(!status.ready_for_proof);

    fvk_out_ciphertexts(&mut z, &map, &fvk);
    let status = z.shielded_status().unwrap();
    assert!(status.pending_out_ciphertexts.is_empty());
    assert!(!status.ready_for_proof);

    let pairs = install_randomizers(&mut z, &map, &ask);
    let status = z.shielded_status().unwrap();
    assert!(status.pending_randomizers.is_empty());
    assert_eq!(status.pending_spend_signatures, spends);
    assert!(!status.ready_for_proof);

    install_spend_signatures(&mut z, &pairs, &ask);
    let status = z.shielded_status().unwrap();
    assert!(status.pending_spend_signatures.is_empty());
    assert!(status.ready_for_proof);
    z.proof_request(&pairs).unwrap();

    // A shielding PSBT is transparent-kind and waits on its transparent signatures.
    let shield = build_shield_psbt("ironwood_v6_keyless_status_shield");
    let status = shield.shielded_status().unwrap();
    assert_eq!(status.input_kind, IronwoodInputKind::Transparent);
    assert!(status.pending_randomizers.is_empty());
    assert!(!status.ready_for_proof);

    // No PCZT at all: transparent, nothing pending, nothing to prove.
    let status = empty_v6_psbt("ironwood_v6_keyless_status_empty")
        .shielded_status()
        .unwrap();
    assert_eq!(status.input_kind, IronwoodInputKind::Transparent);
    assert!(!status.ready_for_proof);
}

// ---- The TS fixture generator (test/fixedScript/zcashIronwoodSpend.ts) ----
//
// The TS suite cannot produce the viewing-key holder's or prover's responses — the out-ciphertexts need the FVK and the proof
// needs Halo2 — so this `#[ignore]`d generator writes them into `test/fixtures/zcash/`. Run:
//
//   cargo test --features orchard-proving generate_ts_spend_fixtures -- --ignored --nocapture
//
// The construction is seeded, so the post-construction PSBT bytes, the action map and the
// ZIP-317 fee are reproducible across runs. The ciphertexts, signatures and proof draw
// fresh `OsRng` entropy each run — they are internally consistent (same run produced the
// sighash chain and the proof), so regenerate every field together.

#[cfg(feature = "orchard-proving")]
#[allow(clippy::too_many_arguments)]
fn spend_fixture_json(
    name: &str,
    mut z: ZcashBitGoPsbt,
    map: IronwoodActionMap,
    anchor: [u8; 32],
    fvk: &FullViewingKey,
    ak: [u8; 32],
    ask: &SpendAuthorizingKey,
    specs: &[IronwoodKeylessSpendSpec],
    outputs: &[IronwoodOutputRequest],
    transparent_output: Option<(Vec<u8>, u64)>,
) -> serde_json::Value {
    use base64::Engine;
    let to_hex = |bytes: &[u8]| hex::encode(bytes);

    // Deterministic construction: the shuffle (and therefore the action map) must be
    // reproducible, since the TS lifecycle replays this exact PSBT.
    let psbt_bytes = z.serialize_v6();
    let fee = z.zip317_conventional_fee().unwrap();

    // The ciphertext round: one 80-byte ciphertext per real output, under the FVK's
    // external `ovk`. A pure deshield has no real outputs and the request errors instead.
    let out_ciphertexts: Vec<(usize, [u8; 80])> = match z.out_ciphertext_request() {
        Ok((_, pending)) => {
            let ovk = *fvk.to_ovk(Scope::External).as_ref();
            let pczt = z.ironwood_pczt().unwrap();
            let entries: Vec<(usize, [u8; 80])> = pending
                .iter()
                .map(|&action_index| {
                    (
                        action_index,
                        compute_out_ciphertext(&pczt, action_index, ovk, &mut OsRng).unwrap(),
                    )
                })
                .collect();
            z.add_out_ciphertexts(&entries).unwrap();
            entries
        }
        Err(IronwoodPsbtError::NothingPending) => Vec::new(),
        Err(error) => panic!("unexpected out-ciphertext request error: {error}"),
    };

    // The FROST stand-in: one (alpha, rk = ak.randomize(alpha)) pair per real spend. Only
    // `rk` is stored; the alphas ride along out of band for the proof request.
    let randomizers: Vec<(usize, [u8; 32], [u8; 32])> = map
        .spend_action_indices()
        .iter()
        .map(|&action_index| {
            let alpha = pasta_curves::pallas::Scalar::random(&mut OsRng);
            let rk = <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&ask.randomize(&alpha)));
            (action_index, alpha.to_repr(), rk)
        })
        .collect();
    z.add_spend_randomizers(&randomizers, Some(&ak)).unwrap();

    let sighash = z.spend_sighash().unwrap();
    let signatures: Vec<(usize, [u8; 64])> = randomizers
        .iter()
        .map(|&(action_index, alpha_repr, _)| {
            let alpha = pasta_curves::pallas::Scalar::from_repr(alpha_repr).unwrap();
            (
                action_index,
                <[u8; 64]>::from(&ask.randomize(&alpha).sign(OsRng, &sighash)),
            )
        })
        .collect();
    z.add_spend_signatures(&signatures).unwrap();

    let alphas: Vec<(usize, [u8; 32])> = randomizers
        .iter()
        .map(|&(action_index, alpha, _)| (action_index, alpha))
        .collect();
    let proof_request_bytes = z.proof_request(&alphas).unwrap();
    // The ZIP-244 txid commits the action data but neither signatures nor the proof, so it is
    // the one stage value the TS run reproduces exactly. Recorded in display order, matching
    // the `ironwood_v6_txid` wasm binding's `Txid::to_string()` convention (the TS test
    // compares it against `getId()`).
    let expected_txid = Txid::from_byte_array(z.v6_txid().unwrap()).to_string();

    // The proof: what the keyed prover (here, the local prover) returns
    // for the alpha-patched request bytes. Prove-and-combine locally, then slice the proof
    // out of the transaction; the TS run re-does the combine itself via `combineProof`.
    let raw = z
        .clone()
        .combine_ironwood_proof_locally_with_alphas(&alphas, Some(&fvk.to_bytes()), OsRng)
        .unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    let proof = tx.ironwood_bundle.as_ref().unwrap().proof.clone();

    serde_json::json!({
        "name": name,
        "network": "zcashTest",
        "blockHeight": crate::zcash::NetworkUpgrade::Nu6_3.testnet_activation_height(),
        "request": {
            "anchor": to_hex(&anchor),
            "spends": specs.iter().map(|spec| serde_json::json!({
                "recipient": to_hex(&spec.recipient),
                "value": spec.value.to_string(),
                "rho": to_hex(&spec.rho),
                "rseed": to_hex(&spec.rseed),
                "cmx": to_hex(&spec.cmx),
                "witness": {
                    "position": spec.witness.position,
                    "authPath": spec.witness.auth_path.iter().map(|h| to_hex(h)).collect::<Vec<_>>(),
                },
                "nullifier": to_hex(&spec.nullifier),
            })).collect::<Vec<_>>(),
            "outputs": outputs.iter().map(|output| serde_json::json!({
                "recipient": to_hex(&output.recipient),
                "amount": output.amount.to_string(),
                "memo": to_hex(&output.memo),
                "unifiedAddress": output.unified_address,
            })).collect::<Vec<_>>(),
            "transparentOutput": transparent_output.map(|(script, value)| serde_json::json!({
                "script": to_hex(&script),
                "value": value.to_string(),
            })),
        },
        "psbt": base64::engine::general_purpose::STANDARD.encode(&psbt_bytes),
        "spendActionIndices": map.spend_action_indices(),
        "outputActionIndices": map.output_action_indices(),
        "ak": to_hex(&ak),
        "outCiphertexts": out_ciphertexts.iter().map(|&(action_index, out_ciphertext)|
            serde_json::json!({
                "actionIndex": action_index,
                "outCiphertext": to_hex(&out_ciphertext),
            })).collect::<Vec<_>>(),
        "randomizers": randomizers.iter().map(|&(action_index, alpha, rk)|
            serde_json::json!({
                "actionIndex": action_index,
                "alpha": to_hex(&alpha),
                "rk": to_hex(&rk),
            })).collect::<Vec<_>>(),
        "sighash": to_hex(&sighash),
        "signatures": signatures.iter().map(|&(action_index, signature)|
            serde_json::json!({
                "actionIndex": action_index,
                "signature": to_hex(&signature),
            })).collect::<Vec<_>>(),
        "expectedTxid": expected_txid,
        "proofRequest": to_hex(&proof_request_bytes),
        "proof": to_hex(&proof),
        "zip317ConventionalFee": fee.to_string(),
    })
}

/// The transparent payout of the deshield fixture.
#[cfg(feature = "orchard-proving")]
const DESHIELD_PAYOUT_SCRIPT: [u8; 5] = [0x76, 0xa9, 0x14, 0x88, 0xac];

/// Generate both TS fixtures: the 1→0 deshield (transparent payout, no shielded outputs, so
/// no ciphertext round) and the 2→2 shielded→shielded transfer (ciphertexts). Both pay
/// exactly the ZIP-317 conventional fee for their shape.
#[test]
#[ignore]
#[cfg(feature = "orchard-proving")]
fn generate_ts_spend_fixtures() {
    use rand::{rngs::StdRng, SeedableRng};

    let dir = std::path::Path::new("test/fixtures/zcash");
    std::fs::create_dir_all(dir).unwrap();

    for (seed, (name, is_deshield)) in [("deshield", true), ("transfer", false)]
        .into_iter()
        .enumerate()
    {
        let (specs, anchor, fvk, ak) = keyless_fixture();
        let ask = SpendAuthorizingKey::from(&test_spending_key());
        let mut z = empty_v6_psbt(&format!("ironwood_ts_spend_{name}"));
        // Both shapes come to two logical actions (the deshield's Ironwood action plus its
        // transparent output, the transfer's two Ironwood actions): the ZIP-317 grace floor.
        let fee = 10_000;
        let (specs_used, outputs, transparent_output) = if is_deshield {
            let payout = specs[0].value - fee;
            z.add_transparent_output(
                miniscript::bitcoin::ScriptBuf::from(DESHIELD_PAYOUT_SCRIPT.to_vec()),
                payout,
                None,
            )
            .unwrap();
            (
                &specs[..1],
                Vec::new(),
                Some((DESHIELD_PAYOUT_SCRIPT.to_vec(), payout)),
            )
        } else {
            let total: u64 = specs.iter().map(|spec| spec.value).sum::<u64>() - fee;
            let outputs = vec![
                wallet_output(&fvk, 100, total / 2),
                wallet_output(&fvk, 101, total - total / 2),
            ];
            (&specs[..], outputs, None)
        };
        // Seeded construction: the shuffle and the action map are reproducible.
        let map = z
            .add_shielded_spends(
                specs_used,
                &outputs,
                &anchor,
                StdRng::seed_from_u64(0xC511_0000 + seed as u64),
            )
            .unwrap();
        assert_eq!(z.zip317_conventional_fee().unwrap(), fee);
        let fixture = spend_fixture_json(
            name,
            z,
            map,
            anchor,
            &fvk,
            ak,
            &ask,
            specs_used,
            &outputs,
            transparent_output,
        );
        let path = dir.join(format!("ironwood_spend_{name}.json"));
        std::fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
        println!("wrote {}", path.display());
    }
}
