//! Tests for shielded (Ironwood) PSBT behavior and ZIP-317 accounting. Native-only (orchard + zebra).

use super::super::ironwood::estimated_script_sig_len;
use super::*;
use crate::bitcoin::bip32::Xpub;
use crate::bitcoin::hashes::Hash;
use crate::bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use crate::bitcoin::{CompressedPublicKey, PublicKey, Txid};
use crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::WalletInputOptions;
use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt;
use crate::fixed_script_wallet::script_id::ScriptId;
use crate::fixed_script_wallet::test_utils::get_test_wallet_keys;
use crate::fixed_script_wallet::RootWalletKeys;
use crate::networks::Network;
use crate::zcash::ironwood_build::test_field_bytes as field_bytes;
use crate::zcash::NetworkUpgrade;
use ff::Field;
use orchard::keys::SpendAuthorizingKey;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, Note, RandomSeed, Rho};
use orchard::primitives::redpallas::{SpendAuth, VerificationKey};
use orchard::tree::Anchor;
use orchard::value::NoteValue;
use orchard::Proof;
use rand::rngs::OsRng;

/// Golden vector pinning the Ironwood PCZT wire format — the postcard-encoded bundle the
/// client ships to the external prover. Guards the wire contract with external PCZT
/// consumers: a field-order, field-set, or encoding change here fails this test instead of
/// failing live proof requests.
///
/// The construction is fully deterministic: fixed wallet keys, the fixed spending key and
/// note of [`test_spend_request`], and a seeded RNG standing in for `OsRng` (the builder's
/// per-build randomness — `alpha`, `rk`, value-commitment trapdoors, ephemeral keys — is the
/// only source of variance).
///
/// If the wire format changes intentionally, bump
/// [`FORMAT_VERSION`](crate::zcash::ironwood_pczt::FORMAT_VERSION) and regenerate the fixture:
///
/// ```text
/// WASM_UTXO_REGEN_PCZT_GOLDEN=1 cargo test --lib ironwood_pczt_wire_golden_vector
/// ```
#[test]
fn ironwood_pczt_wire_golden_vector() {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let seed = "ironwood_pczt_wire_golden";
    let wallet_keys = root_wallet_keys(seed);
    let mut z = ZcashBitGoPsbt::new_v6(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu6_3.branch_id(),
        None,
        None,
    );

    // One real spend (keyless after the constructor's scrub: fvk omitted, alpha cleared,
    // placeholder rk) self-shielded back to the spent note's own address, minus the fee.
    let (req, anchor, _ask) = test_spend_request();
    let mut memo = [0u8; 512];
    memo[0] = 0xf6; // ZIP-302 "no memo"
    let out = IronwoodOutputRequest {
        recipient: req.recipient,
        amount: req.value - 10_000,
        ovk: None,
        memo,
        unified_address: None,
    };
    let mut rng = StdRng::seed_from_u64(0x1de0_77ea);
    z.add_ironwood_actions(&[req], &[out], &anchor, &mut rng)
        .unwrap();

    let bytes = z.raw_ironwood_pczt_bytes().unwrap();
    assert_eq!(
        bytes[0],
        crate::zcash::ironwood_pczt::FORMAT_VERSION,
        "PCZT wire format version changed"
    );
    let actual = hex::encode(&bytes);

    let fixture_name = "ironwood_pczt_wire_golden.hex";
    if std::env::var("WASM_UTXO_REGEN_PCZT_GOLDEN").is_ok() {
        let path = format!(
            "{}/test/fixtures/zcash/{}",
            env!("CARGO_MANIFEST_DIR"),
            fixture_name
        );
        std::fs::write(&path, format!("{actual}\n")).unwrap();
        println!("regenerated {path}");
    }
    let expected = crate::fixed_script_wallet::test_utils::fixtures::load_fixture(&format!(
        "zcash/{fixture_name}"
    ))
    .unwrap();
    assert_eq!(
        actual,
        expected.trim(),
        "PCZT wire format changed — if intentional, bump FORMAT_VERSION and regenerate the \
         golden fixture with WASM_UTXO_REGEN_PCZT_GOLDEN=1 cargo test --lib \
         ironwood_pczt_wire_golden_vector"
    );
}

#[test]
fn build_sign_combine_produces_valid_v6_tx() {
    let seed = "ironwood_v6_psbt";
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys(seed));
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();

    // Build: one 2-of-3 P2SH transparent input (2 ZEC), a transparent change output, and a
    // shielded Ironwood output (1 ZEC).
    let mut psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    psbt.add_wallet_input(
        Txid::from_byte_array([0x22u8; 32]),
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
    assert!(z.is_ironwood_v6());
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

    // The v6 txid is defined at build time (before signing/proving).
    let txid = z.v6_txid().unwrap();

    // Serialize → deserialize preserves the transparent skeleton, PCZT, branch id, and v6 params.
    let bytes = z.serialize_v6();
    let z2 = ZcashBitGoPsbt::deserialize_v6(&bytes, Network::ZcashTestnet).unwrap();
    assert!(z2.is_ironwood_v6());
    assert_eq!(z2.v6_txid().unwrap(), txid, "txid survives PSBT round-trip");

    // Sign the transparent input with user + bitgo (keys 0 and 2) over the ZIP-244 sighash.
    let secp = Secp256k1::new();
    let sighash = z.v6_transparent_sighash(0).unwrap();
    let msg = Message::from_digest(sighash);
    for i in [0usize, 2] {
        let sk = signing_secret_keys(seed, 0, 0)[i];
        let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
        let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
        der.push(0x01); // SIGHASH_ALL
        z.add_v6_transparent_signature(0, pubkey, &der).unwrap();
    }

    // Combine with a canonical-length placeholder proof (stands in for the external prover).
    let proof = vec![0u8; Proof::expected_proof_size(1)];
    let raw = z.combine_ironwood_proof(proof, OsRng).unwrap();

    // The result is a well-formed v6 transaction with a finalized transparent input and the
    // shielded bundle.
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    assert_eq!(tx.transparent.input.len(), 1);
    assert_eq!(tx.transparent.output.len(), 1);
    assert!(
        !tx.transparent.input[0].script_sig.is_empty(),
        "input finalized"
    );
    let bundle = tx.ironwood_bundle.as_ref().unwrap();
    assert_eq!(bundle.actions.len(), 1);
    assert_eq!(bundle.spend_auth_sigs.len(), 1);
    assert_eq!(bundle.proof.len(), Proof::expected_proof_size(1));

    // txid is unchanged by signing/proving (ZIP-244 excludes scriptSigs, proof, and sigs).
    let mut internal = crate::zcash::v6::compute_v6_txid(&tx);
    assert_eq!(internal, txid);

    // zebra-chain independently decodes the combined tx and agrees on the txid.
    use zebra_chain::serialization::ZcashDeserialize;
    use zebra_chain::transaction::Transaction as ZebraTx;
    let zebra = ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes v6 tx");
    assert_eq!(zebra.version(), 6);
    assert_eq!(zebra.ironwood_actions().count(), 1);
    internal.reverse();
    assert_eq!(
        zebra.hash().to_string(),
        hex::encode(internal),
        "zebra txid == ours"
    );
}

/// `combine_ironwood_proof_locally` (the `orchard-proving` path) produces a *real* Halo2 proof
/// that verifies — unlike [`build_sign_combine_produces_valid_v6_tx`]'s canonical-length
/// all-zero placeholder, which is only structurally valid, not cryptographically. This is what
/// makes the CLI's locally-combined transaction actually broadcastable.
#[cfg(feature = "orchard-proving")]
#[test]
fn combine_ironwood_proof_locally_produces_a_verifying_proof() {
    use nonempty::NonEmpty;
    use orchard::bundle::{Authorized, Bundle as OrchardBundle, BundleVersion};
    use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
    use orchard::note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext};
    use orchard::primitives::redpallas::{Binding, Signature, SpendAuth, VerificationKey};
    use orchard::value::ValueCommitment;
    use orchard::{Action as OrchardAction, Proof};

    let seed = "ironwood_v6_local_proof";
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys(seed));
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();

    let mut psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
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

    let secp = Secp256k1::new();
    let sighash = z.v6_transparent_sighash(0).unwrap();
    let msg = Message::from_digest(sighash);
    for i in [0usize, 2] {
        let sk = signing_secret_keys(seed, 0, 0)[i];
        let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
        let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
        der.push(0x01);
        z.add_v6_transparent_signature(0, pubkey, &der).unwrap();
    }

    let raw = z.combine_ironwood_proof_locally(OsRng).unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    let bundle = tx.ironwood_bundle.as_ref().unwrap();

    // Reconstruct the fully-authorized orchard bundle from the on-wire action data, so we can
    // ask orchard itself to verify the proof against a freshly-built verifying key.
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
        Option::from(Anchor::from_bytes(bundle.anchor)).expect("valid anchor"),
        authorization,
        BundleVersion::ironwood_v3(),
    )
    .expect("valid authorized bundle");

    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    orchard_bundle
        .verify_proof(&vk)
        .expect("locally-produced proof verifies");
}

/// End-to-end: the server builds a **keyless** v6 shielding PSBT — one transparent input, one
/// Ironwood output, exactly the shape `add_ironwood_output(.., ovk: None, ..)` produces — and
/// hands its serialized bytes to "the client". The client deserializes, derives its `ovk` on the
/// fly as the ECDH agreement of the BitGo cosigner pubkey and its own signing private key,
/// patches `out_ciphertext` in via [`ZcashBitGoPsbt::set_ironwood_out_ciphertext`], and only then
/// computes the ZIP-244 transparent sighash and produces the ECDSA signature for the
/// transparent→shielded ("shielding") transaction.
#[test]
fn keyless_server_build_client_sets_out_ciphertext_via_ecdh_then_signs_and_combines() {
    let seed = "ironwood_v6_ovk_psbt";
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys(seed));
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();

    // ---- Server: build a keyless PSBT (one transparent input, one Ironwood output). ----
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
    psbt.add_wallet_output(0, 1, 99_900_000, &wallet_keys)
        .unwrap();
    let BitGoPsbt::Zcash(mut server, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    assert!(server.is_ironwood_v6());
    server
        .add_ironwood_output(
            &test_recipient(),
            100_000_000,
            None, // keyless: the server never sees an ovk
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            None, // unified_address
            OsRng,
        )
        .unwrap();
    assert_eq!(
        server.psbt.unsigned_tx.input.len(),
        1,
        "single transparent input"
    );
    assert_eq!(
        server.ironwood_action_data().unwrap().actions.len(),
        1,
        "single Ironwood output"
    );
    let placeholder_out_ciphertext =
        server.ironwood_action_data().unwrap().actions[0].out_ciphertext;

    // Server hands off the serialized PSBT bytes to the client.
    let server_bytes = server.serialize_v6();

    // ---- Client: deserialize, derive ovk via ECDH, patch out_ciphertext. ----
    let mut client = ZcashBitGoPsbt::deserialize_v6(&server_bytes, Network::ZcashTestnet)
        .expect("client deserializes the server's PSBT");
    assert!(client.is_ironwood_v6());

    let secp = Secp256k1::new();
    let bitgo_sk = SecretKey::from_slice(&[0x77u8; 32]).unwrap();
    let bitgo_pubkey = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &bitgo_sk);
    let user_privkey = SecretKey::from_slice(&[0x88u8; 32]).unwrap();

    client
        .set_ironwood_out_ciphertext(0, &bitgo_pubkey.serialize(), &user_privkey.secret_bytes())
        .expect("client re-encrypts out_ciphertext under its ECDH-derived ovk");

    let patched_out_ciphertext = client.ironwood_action_data().unwrap().actions[0].out_ciphertext;
    assert_ne!(
        patched_out_ciphertext.to_vec(),
        placeholder_out_ciphertext.to_vec(),
        "client's ovk-encrypted ciphertext differs from the server's keyless placeholder"
    );
    // Everything else about the Ironwood action is untouched by the patch.
    let before = server.ironwood_action_data().unwrap();
    let after = client.ironwood_action_data().unwrap();
    assert_eq!(before.actions[0].cv, after.actions[0].cv);
    assert_eq!(before.actions[0].cmx, after.actions[0].cmx);
    assert_eq!(
        before.actions[0].enc_ciphertext,
        after.actions[0].enc_ciphertext
    );
    assert_eq!(before.value_balance, after.value_balance);

    // Setting out_ciphertext changes the transparent sighash (it is committed by ZIP-244), which
    // is exactly why it must happen before signing.
    let sighash_before_patch = server.v6_transparent_sighash(0).unwrap();
    let sighash_after_patch = client.v6_transparent_sighash(0).unwrap();
    assert_ne!(
        sighash_before_patch, sighash_after_patch,
        "out_ciphertext is sighash-committed"
    );

    // The ordering guard rejects patching out_ciphertext again after a signature exists.
    {
        let mut too_late = client.clone();
        let secp = Secp256k1::new();
        let sighash = too_late.v6_transparent_sighash(0).unwrap();
        let msg = Message::from_digest(sighash);
        let sk = signing_secret_keys(seed, 0, 0)[0];
        let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
        let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
        der.push(0x01);
        too_late
            .add_v6_transparent_signature(0, pubkey, &der)
            .unwrap();
        let err = too_late
            .set_ironwood_out_ciphertext(0, &bitgo_pubkey.serialize(), &user_privkey.secret_bytes())
            .unwrap_err();
        assert!(
            err.contains("after a transparent signature has been collected"),
            "unexpected error: {err}"
        );
    }

    // ---- Client signs the (now-final) transparent sighash of the shielding transaction. ----
    let mut z = client;
    let sighash = z.v6_transparent_sighash(0).unwrap();
    let msg = Message::from_digest(sighash);
    for i in [0usize, 2] {
        let sk = signing_secret_keys(seed, 0, 0)[i];
        let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
        let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
        der.push(0x01); // SIGHASH_ALL
        z.add_v6_transparent_signature(0, pubkey, &der).unwrap();
    }

    // ---- Combine and verify the result decodes as a valid v6 transaction. ----
    let proof = vec![0u8; Proof::expected_proof_size(1)];
    let raw = z.combine_ironwood_proof(proof, OsRng).unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    assert_eq!(tx.transparent.input.len(), 1);
    assert!(
        !tx.transparent.input[0].script_sig.is_empty(),
        "transparent input finalized with the ECDSA signature"
    );
    let bundle = tx.ironwood_bundle.as_ref().unwrap();
    assert_eq!(bundle.actions.len(), 1);
    assert_eq!(
        bundle.actions[0].out_ciphertext.to_vec(),
        patched_out_ciphertext.to_vec(),
        "the client-set out_ciphertext survives to the broadcast transaction"
    );

    // zebra-chain independently decodes the combined tx.
    use zebra_chain::serialization::ZcashDeserialize;
    use zebra_chain::transaction::Transaction as ZebraTx;
    let zebra = ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes v6 tx");
    assert_eq!(zebra.version(), 6);
    assert_eq!(zebra.ironwood_actions().count(), 1);
}

/// The multi-recipient counterpart of [`build_shield_psbt`]: the same transparent side, but
/// `add_ironwood_outputs` with one keyless action per recipient.
fn build_shield_psbt_multi(seed: &str, recipients: &[[u8; 43]]) -> ZcashBitGoPsbt {
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys(seed));
    let mut psbt = BitGoPsbt::new_zcash_v6_at_height(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu6_3.testnet_activation_height(),
        None,
        None,
    )
    .unwrap();
    psbt.add_wallet_input(
        Txid::from_byte_array([0x77u8; 32]),
        0,
        300_000_000,
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
    z.add_ironwood_outputs(
        &recipients
            .iter()
            .map(|&recipient| IronwoodOutputRequest {
                recipient,
                amount: 100_000_000,
                ovk: None,
                memo: [0u8; 512],
                unified_address: None,
            })
            .collect::<Vec<_>>(),
        &Anchor::empty_tree().to_bytes(),
        OsRng,
    )
    .unwrap();
    z
}

/// `sign_ironwood_v6`: the user signs first (setting `out_ciphertext` via its ECDH-derived
/// `ovk`), then Bitgo signs second (a no-op on the ciphertext, since it's already final) —
/// producing a fully-signed transparent side ready for `combine_ironwood_proof`.
#[test]
fn sign_ironwood_v6_user_then_bitgo_produces_a_valid_v6_tx() {
    let seed = "ironwood_v6_sign_api";
    let secp = Secp256k1::new();
    let wallet_keys = root_wallet_keys(seed);

    let mut z = build_shield_psbt(seed);
    let placeholder_ciphertext = z.ironwood_action_data().unwrap().actions[0].out_ciphertext;

    // User signs first, passing the bitgo pubkey: this is expected to set out_ciphertext.
    let user_xpriv = test_wallet_xpriv(seed, 0);
    let signed_by_user = z
        .sign_ironwood_v6(&user_xpriv, &wallet_keys, &secp)
        .unwrap();
    assert_eq!(signed_by_user, vec![0], "signed the one transparent input");

    let after_user = z.ironwood_action_data().unwrap().actions[0].out_ciphertext;
    assert_ne!(
        after_user.to_vec(),
        placeholder_ciphertext.to_vec(),
        "user's call derived the ovk and finalized out_ciphertext"
    );
    assert_eq!(
        z.psbt.inputs[0].partial_sigs.len(),
        1,
        "one signature collected so far"
    );

    // Bitgo signs second, passing the same (its own) pubkey — harmless, since a signature
    // already exists and the ciphertext-setting step is skipped.
    let bitgo_xpriv = test_wallet_xpriv(seed, 2);
    let signed_by_bitgo = z
        .sign_ironwood_v6(&bitgo_xpriv, &wallet_keys, &secp)
        .unwrap();
    assert_eq!(signed_by_bitgo, vec![0]);

    let after_bitgo = z.ironwood_action_data().unwrap().actions[0].out_ciphertext;
    assert_eq!(
        after_bitgo.to_vec(),
        after_user.to_vec(),
        "bitgo's call did not touch out_ciphertext a second time"
    );
    assert_eq!(
        z.psbt.inputs[0].partial_sigs.len(),
        2,
        "both required signatures collected"
    );

    // Combine and check the result is a valid, zebra-agreeing v6 transaction.
    let proof = vec![0u8; Proof::expected_proof_size(1)];
    let raw = z.combine_ironwood_proof(proof, OsRng).unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    assert!(!tx.transparent.input[0].script_sig.is_empty());
    let bundle = tx.ironwood_bundle.as_ref().unwrap();
    assert_eq!(
        bundle.actions[0].out_ciphertext.to_vec(),
        after_user.to_vec(),
        "the user-set out_ciphertext survives to the broadcast transaction"
    );

    use zebra_chain::serialization::ZcashDeserialize;
    use zebra_chain::transaction::Transaction as ZebraTx;
    let zebra = ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes v6 tx");
    assert_eq!(zebra.version(), 6);
    assert_eq!(zebra.ironwood_actions().count(), 1);

    // Independently verify the note data: reconstruct an orchard action from zebra's own
    // parsed (not ours) action fields, then decrypt it with the recipient's incoming viewing
    // key. This proves the shielded output zebra sees on the wire really does carry the
    // expected recipient/amount, not just that our own bundle does.
    use orchard::keys::{FullViewingKey, IncomingViewingKey, PreparedIncomingViewingKey};
    use orchard::note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext};
    use orchard::note_encryption::IronwoodDomain;
    use orchard::primitives::redpallas::{SpendAuth, VerificationKey};
    use orchard::value::{NoteValue, ValueCommitment};
    use orchard::Action as OrchardAction;

    // zebra-chain links its own orchard release, a different crate version than ours, so its
    // `Action` cannot be fed to our `zcash_note_encryption` directly. Round-trip through the
    // canonical byte encoding of each field to rebuild the action against our orchard.
    let zebra_action = zebra
        .ironwood_actions()
        .next()
        .expect("one ironwood action");
    let cv_bytes: [u8; 32] = zebra_action.cv_net().to_bytes();
    let nf_bytes: [u8; 32] = zebra_action.nullifier().to_bytes();
    let rk_bytes: [u8; 32] = zebra_action.rk().into();
    let cmx_bytes: [u8; 32] = zebra_action.cmx().to_bytes();
    let encrypted = zebra_action.encrypted_note();
    let epk_bytes: [u8; 32] = encrypted.epk_bytes;
    // zebra's newer zcash_note_encryption wraps `enc_ciphertext` in `NoteBytesData`; take the
    // inner bytes so they land in our crate version's plain-array field.
    let enc_bytes: [u8; 580] = encrypted
        .enc_ciphertext
        .as_ref()
        .try_into()
        .expect("enc_ciphertext is 580 bytes");
    let out_bytes: [u8; 80] = encrypted.out_ciphertext;

    let cv_net = Option::from(ValueCommitment::from_bytes(&cv_bytes)).expect("valid cv_net");
    let rk = VerificationKey::<SpendAuth>::try_from(rk_bytes).expect("valid rk");
    let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&cmx_bytes)).expect("valid cmx");
    let nf = Option::from(Nullifier::from_bytes(&nf_bytes)).expect("valid nullifier");
    let encrypted_note = TransmittedNoteCiphertext {
        epk_bytes,
        enc_ciphertext: enc_bytes,
        out_ciphertext: out_bytes,
    };
    let zebra_parsed_action =
        OrchardAction::from_parts(nf, rk, cmx, encrypted_note, cv_net, ()).expect("valid action");

    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let ivk: IncomingViewingKey = fvk.to_ivk(Scope::External);
    let prepared_ivk = PreparedIncomingViewingKey::new(&ivk);
    let domain = IronwoodDomain::for_action(&zebra_parsed_action);
    let (note, recovered_recipient, _memo) =
        zcash_note_encryption::try_note_decryption(&domain, &prepared_ivk, &zebra_parsed_action)
            .expect("the recipient's ivk decrypts zebra's own parsed action");
    assert_eq!(
        note.value(),
        NoteValue::from_raw(100_000_000),
        "zebra's parsed action carries the expected shielded amount"
    );
    assert_eq!(
        recovered_recipient.to_raw_address_bytes(),
        test_recipient(),
        "zebra's parsed action carries the expected recipient"
    );
}

/// Multi-recipient build: `sign_ironwood_v6`'s first round finalizes EVERY action's
/// `out_ciphertext` under the wallet's ECDH `ovk` — not just action 0 — so every note is
/// recoverable with that ovk, and the user-set ciphertexts survive Bitgo's second round and
/// combine. A single-action auto-step would leave action 1 on its keyless placeholder, which no
/// real ovk can recover.
#[test]
fn sign_ironwood_v6_finalizes_out_ciphertext_for_every_action() {
    use orchard::note_encryption::IronwoodDomain;
    use zcash_note_encryption::try_output_recovery_with_ovk;

    let seed = "ironwood_v6_sign_multi_action";
    let secp = Secp256k1::new();
    let wallet_keys = root_wallet_keys(seed);

    let recipient_a = test_recipient();
    let recipient_b = {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([11u8; 32])).unwrap();
        FullViewingKey::from(&sk)
            .address_at(0u32, Scope::External)
            .to_raw_address_bytes()
    };
    let mut z = build_shield_psbt_multi(seed, &[recipient_a, recipient_b]);

    let before = z.ironwood_action_data().unwrap();
    assert_eq!(before.actions.len(), 2, "one action per recipient");
    let by_recipient: std::collections::HashMap<usize, [u8; 43]> = z
        .ironwood_shielded_outputs_info()
        .unwrap()
        .into_iter()
        .map(|(action_index, _, recipient)| (action_index, recipient))
        .collect();

    let user_xpriv = test_wallet_xpriv(seed, 0);
    assert_eq!(
        z.sign_ironwood_v6(&user_xpriv, &wallet_keys, &secp)
            .unwrap(),
        vec![0],
        "signed the one transparent input"
    );

    // Every action's keyless placeholder was replaced — not just action 0.
    let after = z.ironwood_action_data().unwrap();
    for (i, action) in after.actions.iter().enumerate() {
        assert_ne!(
            action.out_ciphertext.to_vec(),
            before.actions[i].out_ciphertext.to_vec(),
            "action {i}'s out_ciphertext was finalized"
        );
    }

    // And every action is recoverable under the wallet's ECDH ovk.
    let ovk = crate::zcash::ironwood_build::derive_client_ovk(
        &wallet_keys.bitgo_key().public_key.serialize(),
        &user_xpriv.private_key.secret_bytes(),
    )
    .unwrap();
    let pczt = z.ironwood_pczt().unwrap();
    for (i, action) in pczt.actions().iter().enumerate() {
        let domain = IronwoodDomain::for_pczt_action(action);
        let (note, recipient, _) = try_output_recovery_with_ovk(
            &domain,
            &orchard::keys::OutgoingViewingKey::from(ovk),
            action,
            action.cv_net(),
            &after.actions[i].out_ciphertext,
        )
        .unwrap_or_else(|| panic!("action {i} recoverable under the wallet's ECDH ovk"));
        assert_eq!(
            recipient.to_raw_address_bytes(),
            by_recipient[&i],
            "action {i} decrypts to its own recipient"
        );
        assert_eq!(note.value().inner(), 100_000_000);
    }

    // Bitgo's second round skips the out_ciphertext step (a signature already exists); the
    // user-set values survive combine.
    let bitgo_xpriv = test_wallet_xpriv(seed, 2);
    z.sign_ironwood_v6(&bitgo_xpriv, &wallet_keys, &secp)
        .unwrap();

    let proof = vec![0u8; Proof::expected_proof_size(2)];
    let raw = z.combine_ironwood_proof(proof, OsRng).unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    let bundle = tx.ironwood_bundle.as_ref().unwrap();
    assert_eq!(bundle.actions.len(), 2);
    for (i, action) in bundle.actions.iter().enumerate() {
        assert_eq!(
            action.out_ciphertext.to_vec(),
            after.actions[i].out_ciphertext.to_vec(),
            "action {i}'s user-set out_ciphertext survives to the broadcast transaction"
        );
    }
}

/// Calling `sign_ironwood_v6` with a key this PSBT has no `bip32_derivation` entries for (e.g. a
/// stranger's xpriv) signs nothing and returns an empty index list, rather than erroring.
#[test]
fn sign_ironwood_v6_with_an_unrelated_key_signs_nothing() {
    let seed = "ironwood_v6_sign_api_unrelated";
    let secp = Secp256k1::new();
    let mut z = build_shield_psbt(seed);
    let wallet_keys = root_wallet_keys(seed);

    let placeholder = z.ironwood_action_data().unwrap().actions[0].out_ciphertext;
    let stranger_xpriv = test_wallet_xpriv("not-this-wallet", 0);
    let signed = z
        .sign_ironwood_v6(&stranger_xpriv, &wallet_keys, &secp)
        .unwrap();
    assert!(signed.is_empty());
    assert!(z.psbt.inputs[0].partial_sigs.is_empty());
    // out_ciphertext is untouched: nothing resolved, so the ovk-derivation step never ran.
    assert_eq!(
        z.ironwood_action_data().unwrap().actions[0]
            .out_ciphertext
            .to_vec(),
        placeholder.to_vec()
    );
}

/// Signing out of order is rejected, not silently absorbed: only the user key may open the first
/// signing round, because that round is what fixes `out_ciphertext` under the wallet's `ovk`. If
/// Bitgo (or the backup key) could sign first, its key would be used as if it were the user's,
/// deriving an `ovk` from Bitgo's key agreeing with itself — a value neither the user nor the
/// server can reproduce — and the user's later round could not correct it, since a signature
/// would already exist. That failure is invisible (the transaction still broadcasts; the shielded
/// output is simply never recoverable), so it fails loudly here instead.
#[test]
fn sign_ironwood_v6_rejects_a_first_round_opened_by_a_non_user_key() {
    let seed = "ironwood_v6_sign_api_out_of_order";
    let secp = Secp256k1::new();
    let wallet_keys = root_wallet_keys(seed);

    let mut z = build_shield_psbt(seed);
    let placeholder = z.ironwood_action_data().unwrap().actions[0].out_ciphertext;

    // Bitgo tries to sign first, out of the expected order.
    let bitgo_xpriv = test_wallet_xpriv(seed, 2);
    let err = z
        .sign_ironwood_v6(&bitgo_xpriv, &wallet_keys, &secp)
        .unwrap_err();
    assert!(
        err.contains("user root key") && err.contains("must sign"),
        "unexpected error: {err}"
    );
    // Nothing happened: no signature, and out_ciphertext still the keyless placeholder.
    assert!(z.psbt.inputs[0].partial_sigs.is_empty());
    assert_eq!(
        z.ironwood_action_data().unwrap().actions[0]
            .out_ciphertext
            .to_vec(),
        placeholder.to_vec()
    );

    // The backup key is likewise rejected: it cannot define this transaction's ovk either.
    let backup_xpriv = test_wallet_xpriv(seed, 1);
    assert!(z
        .sign_ironwood_v6(&backup_xpriv, &wallet_keys, &secp)
        .is_err());

    // In the correct order the user opens the round, and Bitgo's round then succeeds.
    let user_xpriv = test_wallet_xpriv(seed, 0);
    z.sign_ironwood_v6(&user_xpriv, &wallet_keys, &secp)
        .unwrap();
    let after_user = z.ironwood_action_data().unwrap().actions[0].out_ciphertext;
    assert_ne!(after_user.to_vec(), placeholder.to_vec());
    z.sign_ironwood_v6(&bitgo_xpriv, &wallet_keys, &secp)
        .unwrap();
    assert_eq!(
        z.ironwood_action_data().unwrap().actions[0]
            .out_ciphertext
            .to_vec(),
        after_user.to_vec(),
        "bitgo's in-order round does not touch out_ciphertext"
    );
    assert_eq!(z.psbt.inputs[0].partial_sigs.len(), 2);
}

/// The `ovk` `sign_ironwood_v6` uses is the wallet's, derived from the two *root* keys — so it is
/// independent of the transaction's inputs, and the server can re-derive it from
/// `ECDH(bitgo_root_privkey, user_root_pubkey)` to validate `out_ciphertext` before
/// countersigning. Pinning that here is what makes the server-side contract checkable: it is the
/// property that would break silently if the derivation ever switched to a per-input leaf key.
#[test]
fn sign_ironwood_v6_derives_the_ovk_from_the_two_root_keys() {
    let seed = "ironwood_v6_sign_api_root_ovk";
    let secp = Secp256k1::new();
    let wallet_keys = root_wallet_keys(seed);

    let mut z = build_shield_psbt(seed);
    // Same PCZT (same note, hence same cmx/epk), so the two paths below are comparable: only the
    // ovk can make their out_ciphertext differ.
    let mut expected = z.clone();

    let user_xpriv = test_wallet_xpriv(seed, 0);
    z.sign_ironwood_v6(&user_xpriv, &wallet_keys, &secp)
        .unwrap();
    let signed_ciphertext = z.ironwood_action_data().unwrap().actions[0].out_ciphertext;

    // Patching the same PCZT directly with the root-key pair yields the same out_ciphertext.
    expected
        .set_ironwood_out_ciphertext(
            0,
            &wallet_keys.bitgo_key().public_key.serialize(),
            &user_xpriv.private_key.secret_bytes(),
        )
        .unwrap();
    assert_eq!(
        expected.ironwood_action_data().unwrap().actions[0]
            .out_ciphertext
            .to_vec(),
        signed_ciphertext.to_vec(),
        "the ovk is ECDH(bitgo root pubkey, user root privkey)"
    );

    // The server re-derives the identical ovk from the other side of the pair and recovers the
    // note from out_ciphertext — the check it runs before countersigning.
    use orchard::note_encryption::IronwoodDomain;
    let server_ovk = crate::zcash::ironwood_build::derive_client_ovk(
        &Xpub::from_priv(&secp, &user_xpriv).public_key.serialize(),
        &test_wallet_xpriv(seed, 2).private_key.secret_bytes(),
    )
    .unwrap();
    let pczt = z.ironwood_pczt().unwrap();
    let action = &pczt.actions()[0];
    let domain = IronwoodDomain::for_pczt_action(action);
    let (note, recipient, _memo) = zcash_note_encryption::try_output_recovery_with_ovk(
        &domain,
        &orchard::keys::OutgoingViewingKey::from(server_ovk),
        action,
        action.cv_net(),
        &signed_ciphertext,
    )
    .expect("server validates out_ciphertext with its independently-derived ovk");
    assert_eq!(recipient.to_raw_address_bytes(), test_recipient());
    assert_eq!(note.value().inner(), 100_000_000);
}

/// `set_ironwood_out_ciphertext_for_user` rejects a key that is not the wallet's user root key,
/// which is what makes the ordering guarantee in `sign_ironwood_v6` enforceable rather than a
/// caller obligation.
#[test]
fn set_ironwood_out_ciphertext_for_user_rejects_a_non_user_key() {
    let seed = "ironwood_v6_ovk_user_key_check";
    let secp = Secp256k1::new();
    let wallet_keys = root_wallet_keys(seed);
    let mut z = build_shield_psbt(seed);

    for (i, label) in [(1u8, "backup"), (2, "bitgo")] {
        let err = z
            .set_ironwood_out_ciphertext_for_user(
                0,
                &test_wallet_xpriv(seed, i),
                &wallet_keys,
                &secp,
            )
            .unwrap_err();
        assert!(err.contains("user root key"), "{label}: {err}");
    }
    let stranger = test_wallet_xpriv("not-this-wallet", 0);
    assert!(z
        .set_ironwood_out_ciphertext_for_user(0, &stranger, &wallet_keys, &secp)
        .is_err());

    // The user root key is accepted.
    z.set_ironwood_out_ciphertext_for_user(0, &test_wallet_xpriv(seed, 0), &wallet_keys, &secp)
        .unwrap();
}

/// A second shielded output is an error, not a silent overwrite of the first note.
#[test]
fn add_ironwood_output_twice_is_rejected() {
    let mut z = build_shield_psbt("v6_double_output");
    let err = z
        .add_ironwood_output(
            &test_recipient(),
            1,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            None, // unified_address
            OsRng,
        )
        .unwrap_err();
    assert!(err.contains("already present"), "unexpected error: {err}");
}

/// `mark_ironwood_extracted` makes extraction terminal for callers that must clone rather than
/// consume the PSBT (the wasm bindings): the PCZT is gone, so every later Ironwood operation
/// fails loudly instead of silently re-running against already-extracted state — and because the
/// PCZT is absent from the serialized bytes too, a round-trip cannot launder it back.
#[test]
fn mark_ironwood_extracted_is_terminal() {
    let mut z = build_shield_psbt("v6_extracted");
    assert!(z.v6_txid().is_ok(), "usable before extraction");

    assert!(z.mark_ironwood_extracted(), "a PCZT was present");
    assert!(!z.mark_ironwood_extracted(), "second call is a no-op");

    // Every operation that reads the shielded state now fails. (`combine_ironwood_proof` is not
    // listed because its transparent-signature check fires first on this unsigned PSBT; it reads
    // the PCZT via the same `ironwood_pczt()` accessor as this.)
    let err = z.ironwood_action_data().unwrap_err();
    assert!(err.contains("no Ironwood PCZT"), "unexpected error: {err}");

    // `v6_txid` and `v6_transparent_sighash` both check `require_no_shielded_output_ever_added`
    // first (so they can compute a bundle-less digest for the transparent-only case), which
    // surfaces the more specific "already extracted" error rather than the bare "no Ironwood
    // PCZT" one.
    for err in [
        z.v6_txid().unwrap_err(),
        z.v6_transparent_sighash(0).unwrap_err(),
    ] {
        assert!(
            err.contains("already been extracted"),
            "unexpected error: {err}"
        );
    }

    // The serialized bytes no longer carry a PCZT, and `deserialize` rejects that outright.
    let err = ZcashBitGoPsbt::deserialize(&z.serialize().unwrap(), Network::ZcashTestnet)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("missing its Ironwood PCZT"),
        "unexpected error: {err}"
    );
}

/// `unsigned_v6_txid` and `ironwood_shielded_outputs_info` both key off PCZT presence to decide
/// whether a shielded output exists. Once extracted, the PCZT is gone but a shielded output
/// *did* exist — treating that the same as "never added" would silently compute a wrong
/// (transparent-only) txid, and silently drop the shielded amount back into the caller's fee
/// calculation. Both must error instead.
#[test]
fn unsigned_v6_txid_and_shielded_output_info_error_after_extraction() {
    let mut z = build_shield_psbt("v6_extracted_accounting");

    // Before extraction: both see the shielded output.
    assert!(z.unsigned_v6_txid().is_ok());
    assert!(
        !z.ironwood_shielded_outputs_info().unwrap().is_empty(),
        "shielded output present before extraction"
    );

    assert!(z.mark_ironwood_extracted(), "a PCZT was present");

    // After extraction: neither silently falls back to "no shielded output".
    let txid_err = z.unsigned_v6_txid().unwrap_err();
    assert!(
        txid_err.contains("already been extracted"),
        "unexpected error: {txid_err}"
    );
    let info_err = z.ironwood_shielded_outputs_info().unwrap_err();
    assert!(
        info_err.contains("already been extracted"),
        "unexpected error: {info_err}"
    );
}

/// The counterpart to the extraction case above: a v6 PSBT that never had a shielded output
/// added at all must still work — `unsigned_v6_txid` and `v6_txid` both compute the
/// transparent-only txid (and agree with each other), and `ironwood_shielded_outputs_info`
/// reports an empty Vec, none of the three erroring.
#[test]
fn unsigned_v6_txid_and_shielded_output_info_handle_no_shielded_output_ever_added() {
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("v6_never_shielded"));
    let mut psbt = BitGoPsbt::new_zcash_v6_at_height(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu6_3.testnet_activation_height(),
        None,
        None,
    )
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
    psbt.add_wallet_output(0, 1, 199_900_000, &wallet_keys)
        .unwrap();
    let BitGoPsbt::Zcash(z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };

    assert!(z.unsigned_v6_txid().is_ok());
    assert_eq!(
        z.v6_txid().unwrap(),
        z.unsigned_v6_txid().unwrap(),
        "v6_txid must agree with unsigned_v6_txid for a transparent-only PSBT"
    );
    assert!(z.ironwood_shielded_outputs_info().unwrap().is_empty());
}

/// An under-signed transparent input is rejected before the (expensive) shielded
/// finalize/combine work runs, not after.
#[test]
fn combine_ironwood_proof_fails_fast_on_missing_signatures() {
    let mut z = build_shield_psbt("v6_undersigned");
    let seed = "v6_undersigned";
    let secp = Secp256k1::new();
    let msg = Message::from_digest(z.v6_transparent_sighash(0).unwrap());
    // Only one of the required two signatures.
    let sk = signing_secret_keys(seed, 0, 0)[0];
    let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
    let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
    der.push(0x01);
    z.add_v6_transparent_signature(0, pubkey, &der).unwrap();

    let err = z
        .combine_ironwood_proof(vec![0u8; Proof::expected_proof_size(1)], OsRng)
        .unwrap_err();
    assert!(
        err.contains("required signatures collected"),
        "unexpected error: {err}"
    );
}

/// `ironwood_shielded_outputs_info` returns an empty Vec before a shielded output has been added, and
/// the exact (value, recipient) passed to `add_ironwood_output` afterwards — regardless of
/// whether the transparent input has been signed yet, since it reads the PCZT's plaintext
/// fields rather than anything sighash/signature-dependent.
#[test]
fn ironwood_shielded_output_info_reflects_added_output() {
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("v6_output_info"));
    let mut psbt = BitGoPsbt::new_zcash_v6_at_height(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu6_3.testnet_activation_height(),
        None,
        None,
    )
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
    psbt.add_wallet_output(0, 1, 99_900_000, &wallet_keys)
        .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };

    // No shielded output yet (unsigned transparent skeleton).
    assert!(z.ironwood_shielded_outputs_info().unwrap().is_empty());

    let recipient = test_recipient();
    z.add_ironwood_output(
        &recipient,
        100_000_000,
        None,
        &Anchor::empty_tree().to_bytes(),
        &[0u8; 512],
        None, // unified_address
        OsRng,
    )
    .unwrap();
    let outputs = z.ironwood_shielded_outputs_info().unwrap();
    assert_eq!(outputs.len(), 1);
    let (_action_index, value, got_recipient) = outputs[0];
    assert_eq!(value, 100_000_000);
    assert_eq!(got_recipient, recipient);

    // Still reflects the same output once the transparent input is (half/fully) signed — the
    // shielded output info does not depend on transparent signing state.
    let secp = Secp256k1::new();
    let sighash = z.v6_transparent_sighash(0).unwrap();
    let msg = Message::from_digest(sighash);
    let sk = signing_secret_keys("v6_output_info", 0, 0)[0];
    let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
    let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
    der.push(0x01);
    z.add_v6_transparent_signature(0, pubkey, &der).unwrap();
    let outputs = z.ironwood_shielded_outputs_info().unwrap();
    assert_eq!(outputs.len(), 1);
    let (_action_index, value, got_recipient) = outputs[0];
    assert_eq!(value, 100_000_000);
    assert_eq!(got_recipient, recipient);
}

/// `add_ironwood_output`'s optional `unified_address` is stored verbatim in the proprietary map
/// and survives a `serialize_v6`/`deserialize_v6` round-trip, so a caller who supplies the UA
/// they built the output from gets it back byte-for-byte later — unlike the raw 43-byte
/// `recipient`, which alone cannot reconstruct a multi-receiver UA.
#[test]
fn add_ironwood_output_unified_address_round_trips() {
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("v6_ua_roundtrip"));
    let mut psbt = BitGoPsbt::new_zcash_v6_at_height(
        Network::ZcashTestnet,
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

    let recipient = test_recipient();
    let ua = crate::zcash::unified_address::encode_orchard_receiver(&recipient, "tzec").unwrap();
    z.add_ironwood_output(
        &recipient,
        100_000_000,
        None,
        &Anchor::empty_tree().to_bytes(),
        &[0u8; 512],
        Some(&ua),
        OsRng,
    )
    .unwrap();
    assert_eq!(
        crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::get_ironwood_unified_address(
            &z.psbt, 0
        ),
        Some(ua.clone())
    );

    // Survives serialize/deserialize, not just in-memory state.
    let round = ZcashBitGoPsbt::deserialize_v6(&z.serialize_v6(), Network::ZcashTestnet).unwrap();
    assert_eq!(
        crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::get_ironwood_unified_address(
            &round.psbt,
            0
        ),
        Some(ua)
    );
}

/// `add_ironwood_output` rejects a `unified_address` whose Orchard receiver doesn't match
/// `recipient` — a caller passing mismatched values is a bug, not something to silently store.
#[test]
fn add_ironwood_output_rejects_mismatched_unified_address() {
    let mut z = build_shield_psbt("v6_ua_mismatch");
    // Force a second call attempt by clearing the PCZT the helper already added, so we can
    // exercise the mismatch path in isolation (the "already present" guard would otherwise fire
    // first).
    z.mark_ironwood_extracted();
    assert!(
        crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::get_ironwood_pczt(&z.psbt).is_none()
    );

    let other_recipient = {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([9u8; 32])).unwrap();
        FullViewingKey::from(&sk)
            .address_at(0u32, Scope::External)
            .to_raw_address_bytes()
    };
    let mismatched_ua =
        crate::zcash::unified_address::encode_orchard_receiver(&other_recipient, "tzec").unwrap();

    let err = z
        .add_ironwood_output(
            &test_recipient(),
            100_000_000,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            Some(&mismatched_ua),
            OsRng,
        )
        .unwrap_err();
    assert!(
        err.contains("does not match recipient"),
        "unexpected error: {err}"
    );
}

/// A stored `unified_address` must not survive onto a *different* shielded output added later
/// in the PSBT's lifetime. `mark_ironwood_extracted`/`take_ironwood_pczt` drop only the PCZT
/// key, not the UA key, so `add_ironwood_output` is reachable a second time on the same PSBT
/// (exactly as in `add_ironwood_output_rejects_mismatched_unified_address` above); a `None`
/// `unified_address` on that second call must clear the first call's UA rather than leaving it
/// to be silently misattributed to the new recipient.
#[test]
fn add_ironwood_output_clears_stale_unified_address_on_reuse() {
    let mut z = build_shield_psbt("v6_ua_stale");
    z.mark_ironwood_extracted();
    assert!(
        crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::get_ironwood_pczt(&z.psbt).is_none()
    );

    let recipient_a = test_recipient();
    let ua_a =
        crate::zcash::unified_address::encode_orchard_receiver(&recipient_a, "tzec").unwrap();
    z.add_ironwood_output(
        &recipient_a,
        100_000_000,
        None,
        &Anchor::empty_tree().to_bytes(),
        &[0u8; 512],
        Some(&ua_a),
        OsRng,
    )
    .unwrap();
    assert_eq!(
        crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::get_ironwood_unified_address(
            &z.psbt, 0
        ),
        Some(ua_a.clone())
    );

    // Reuse the PSBT for a second (different) shielded output, without a unified_address.
    z.mark_ironwood_extracted();
    let recipient_b = {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([13u8; 32])).unwrap();
        FullViewingKey::from(&sk)
            .address_at(0u32, Scope::External)
            .to_raw_address_bytes()
    };
    assert_ne!(recipient_a, recipient_b);
    z.add_ironwood_output(
        &recipient_b,
        100_000_000,
        None,
        &Anchor::empty_tree().to_bytes(),
        &[0u8; 512],
        None, // unified_address
        OsRng,
    )
    .unwrap();

    // The stale UA from recipient_a must be gone, not silently attributed to recipient_b.
    assert_eq!(
        crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::get_ironwood_unified_address(
            &z.psbt, 0
        ),
        None
    );
}

/// `add_ironwood_outputs` builds a single bundle with one action per recipient — each carrying
/// its own value, recipient, and (if supplied) stored Unified Address — and that survives a
/// serialize/deserialize round-trip. This is the actual multi-recipient path;
/// `add_ironwood_output` is just its one-recipient special case.
#[test]
fn add_ironwood_outputs_supports_multiple_recipients() {
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("v6_multi_recipient"));
    let mut psbt = BitGoPsbt::new_zcash_v6_at_height(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu6_3.testnet_activation_height(),
        None,
        None,
    )
    .unwrap();
    psbt.add_wallet_input(
        Txid::from_byte_array([0x66u8; 32]),
        0,
        300_000_000,
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

    let recipient_a = test_recipient();
    let recipient_b = {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([11u8; 32])).unwrap();
        FullViewingKey::from(&sk)
            .address_at(0u32, Scope::External)
            .to_raw_address_bytes()
    };
    let ua_a =
        crate::zcash::unified_address::encode_orchard_receiver(&recipient_a, "tzec").unwrap();

    z.add_ironwood_outputs(
        &[
            IronwoodOutputRequest {
                recipient: recipient_a,
                amount: 100_000_000,
                ovk: None,
                memo: [0u8; 512],
                unified_address: Some(ua_a.clone()),
            },
            IronwoodOutputRequest {
                recipient: recipient_b,
                amount: 100_000_000,
                ovk: None,
                memo: [0u8; 512],
                unified_address: None,
            },
        ],
        &Anchor::empty_tree().to_bytes(),
        OsRng,
    )
    .unwrap();

    // Both recipients are present, each with its own value/recipient, and each's stored UA
    // (or lack of one) tracks its own action index — not just index 0.
    let outputs = z.ironwood_shielded_outputs_info().unwrap();
    assert_eq!(outputs.len(), 2);
    let mut by_recipient: std::collections::HashMap<_, _> = outputs
        .iter()
        .map(|&(action_index, value, recipient)| (recipient, (action_index, value)))
        .collect();
    let (index_a, value_a) = by_recipient
        .remove(&recipient_a)
        .expect("recipient_a present");
    let (index_b, value_b) = by_recipient
        .remove(&recipient_b)
        .expect("recipient_b present");
    assert_eq!(value_a, 100_000_000);
    assert_eq!(value_b, 100_000_000);
    assert_ne!(index_a, index_b);
    assert_eq!(
        crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::get_ironwood_unified_address(
            &z.psbt, index_a
        ),
        Some(ua_a.clone())
    );
    assert_eq!(
        crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::get_ironwood_unified_address(
            &z.psbt, index_b
        ),
        None
    );

    // Survives serialize/deserialize.
    let round = ZcashBitGoPsbt::deserialize_v6(&z.serialize_v6(), Network::ZcashTestnet).unwrap();
    let round_outputs = round.ironwood_shielded_outputs_info().unwrap();
    assert_eq!(round_outputs.len(), 2);
    assert_eq!(
        crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::get_ironwood_unified_address(
            &round.psbt,
            index_a
        ),
        Some(ua_a)
    );
}

/// A second call to `add_ironwood_outputs`/`add_ironwood_output` is rejected outright, even for
/// a multi-recipient batch: every recipient must go in the single call.
#[test]
fn add_ironwood_outputs_twice_is_rejected() {
    let mut z = build_shield_psbt("v6_multi_twice");
    let err = z
        .add_ironwood_outputs(
            &[IronwoodOutputRequest {
                recipient: test_recipient(),
                amount: 1,
                ovk: None,
                memo: [0u8; 512],
                unified_address: None,
            }],
            &Anchor::empty_tree().to_bytes(),
            OsRng,
        )
        .unwrap_err();
    assert!(err.contains("already present"), "unexpected error: {err}");
}

/// Build a PCZT whose action data equals the given bundle's, with all witness fields absent —
/// enough for the effects-only (action-data) view the sighash/txid need. Used to reconstruct
/// the on-chain fixture's shielded state inside a PSBT.
fn pczt_bytes_from_action_data(bundle: &crate::zcash::v6::IronwoodBundle) -> Vec<u8> {
    use orchard::bundle::BundleVersion;
    use orchard::note::Nullifier;
    use orchard::pczt::{
        Action as PcztAction, Bundle as PcztBundle, Output as PcztOutput, Spend as PcztSpend,
    };
    use std::collections::BTreeMap;

    let bundle_version = BundleVersion::ironwood_v3();
    let note_version = bundle_version.note_version();

    let actions = bundle
        .actions
        .iter()
        .map(|a| {
            let mut spend_proprietary = BTreeMap::new();
            spend_proprietary.insert(
                crate::zcash::ironwood_pczt::SPEND_RK_STATE_PROPRIETARY_KEY.to_string(),
                vec![1],
            );
            let spend = PcztSpend::parse(
                a.nullifier,
                a.rk,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                note_version,
                spend_proprietary,
            )
            .expect("valid spend");
            let spend_nullifier =
                Option::<Nullifier>::from(Nullifier::from_bytes(&a.nullifier)).unwrap();
            let output = PcztOutput::parse(
                spend_nullifier,
                a.cmx,
                a.ephemeral_key,
                a.enc_ciphertext.to_vec(),
                a.out_ciphertext.to_vec(),
                None,
                None,
                None,
                None,
                None,
                None,
                note_version,
                BTreeMap::new(),
            )
            .expect("valid output");
            PcztAction::parse(a.cv, spend, output, None).expect("valid action")
        })
        .collect::<Vec<_>>();

    let magnitude = bundle.value_balance.unsigned_abs();
    let negative = bundle.value_balance.is_negative();
    let pczt = PcztBundle::parse(
        actions,
        bundle.flags,
        bundle_version,
        (magnitude, negative),
        bundle.anchor,
        None,
        None,
    )
    .expect("valid pczt bundle");
    crate::zcash::ironwood_pczt::serialize_pczt(&pczt).unwrap()
}

/// The public/consensus-committed values from the reference build of the on-chain `shield1zec`
/// transaction. The spent output's value and scriptPubKey are committed by ZIP-244 but are not
/// on the wire, so they can only come from the reference — hence the fixture rather than
/// literals in the test body.
#[derive(serde::Deserialize)]
struct Shield1ZecDetails {
    txid: String,
    expiry_height: u32,
    lock_time: u32,
    transparent_utxos_spent: Vec<Shield1ZecUtxo>,
    value_balance_zat: i64,
    flags_byte: u8,
    num_actions: usize,
    transparent_public_key_sec1: String,
}

#[derive(serde::Deserialize)]
struct Shield1ZecUtxo {
    txid: String,
    index: u32,
    value_zat: i64,
    script_pubkey: String,
}

fn shield1zec_details() -> Shield1ZecDetails {
    serde_json::from_str(
        &crate::fixed_script_wallet::test_utils::fixtures::load_fixture(
            "zcash/v6_shield1zec_details.json",
        )
        .unwrap(),
    )
    .unwrap()
}

/// Golden PSBT-level oracle: the `v6_transparent_sighash` the PSBT produces from the on-chain
/// `shield1zec` transaction verifies the transaction's **real** ECDSA signature, and the PSBT's
/// `v6_txid` reproduces the transaction's **real** txid.
///
/// This closes a gap the synthetic end-to-end test cannot: there the sighash is computed for
/// both signing and verifying by the same code, so a consistently-wrong spent-output
/// value/script would still verify. Here the signature was produced by an **external** signer
/// using the true amount + scriptPubKey, so it only verifies if the PSBT threaded the real
/// spent-output value and scriptCode into the sighash correctly.
///
/// The txid assertion is the complementary half: the ZIP-244 txid does not commit to input
/// amounts/scripts (so it cannot catch what the sighash check catches), but it does commit to
/// the shielded action data, which pins `pczt_bytes_from_action_data` → `ironwood_action_data`
/// → `to_v6_transaction` against a value produced entirely outside this codebase.
#[test]
fn golden_shield1zec_psbt_sighash_verifies_real_signature() {
    use crate::bitcoin::script::Instruction;
    use crate::bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey as SecpPk, Secp256k1};
    use crate::bitcoin::{Amount, ScriptBuf, TxOut};
    use crate::zcash::v6::{compute_v6_transparent_sighash, decode_v6_transaction};

    let raw = hex::decode(
        crate::fixed_script_wallet::test_utils::fixtures::load_fixture(
            "zcash/v6_shield1zec_rawtx.hex",
        )
        .unwrap()
        .trim(),
    )
    .unwrap();
    let tx = decode_v6_transaction(&raw).unwrap();
    let bundle = tx.ironwood_bundle.clone().expect("ironwood bundle");
    assert_eq!(tx.transparent.input.len(), 1);

    // Cross-check the decoded tx against the reference's record of it, so a fixture/raw-tx
    // mismatch fails here rather than as a confusing sighash mismatch below.
    let details = shield1zec_details();
    assert_eq!(details.transparent_utxos_spent.len(), 1);
    let spent = &details.transparent_utxos_spent[0];
    assert_eq!(tx.expiry_height, details.expiry_height);
    assert_eq!(
        tx.transparent.lock_time.to_consensus_u32(),
        details.lock_time
    );
    assert_eq!(
        tx.transparent.input[0].previous_output.txid.to_string(),
        spent.txid
    );
    assert_eq!(tx.transparent.input[0].previous_output.vout, spent.index);
    assert_eq!(bundle.actions.len(), details.num_actions);
    assert_eq!(bundle.value_balance, details.value_balance_zat);
    assert_eq!(bundle.flags, details.flags_byte);

    // Spent output committed by ZIP-244 but absent from the wire (from the reference build).
    let prevout_value: i64 = spent.value_zat;
    let prevout_script = ScriptBuf::from(hex::decode(&spent.script_pubkey).unwrap());

    // The real P2PKH signature + pubkey from the on-chain scriptSig.
    let pushes: Vec<Vec<u8>> = tx.transparent.input[0]
        .script_sig
        .instructions()
        .map(|i| i.expect("valid scriptSig"))
        .filter_map(|i| match i {
            Instruction::PushBytes(pb) => Some(pb.as_bytes().to_vec()),
            Instruction::Op(_) => None,
        })
        .collect();
    assert_eq!(pushes.len(), 2);
    let der = &pushes[0][..pushes[0].len() - 1]; // strip trailing SIGHASH_ALL byte
    let pubkey_bytes = &pushes[1];
    assert_eq!(
        hex::encode(pubkey_bytes),
        details.transparent_public_key_sec1,
        "on-chain scriptSig pubkey == the reference's signing key"
    );

    // Reconstruct the fixture's state inside a v6 PSBT: transparent skeleton (scriptSigs
    // stripped), the spent output hydrated as witness_utxo (this is the extraction under test),
    // and the shielded action data as a stored PCZT.
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("shield1zec_psbt"));
    let mut z = ZcashBitGoPsbt::new_v6(
        Network::ZcashTestnet,
        &wallet_keys,
        tx.consensus_branch_id,
        Some(tx.transparent.lock_time.to_consensus_u32()),
        Some(tx.expiry_height),
    );
    let mut skeleton = tx.transparent.clone();
    for i in skeleton.input.iter_mut() {
        i.script_sig = ScriptBuf::new();
    }
    z.psbt.unsigned_tx = skeleton;
    let mut input = crate::bitcoin::psbt::Input {
        witness_utxo: Some(TxOut {
            value: Amount::from_sat(prevout_value as u64),
            script_pubkey: prevout_script.clone(),
        }),
        ..Default::default()
    };
    // `redeem_script` is overloaded here to carry the scriptCode, not a real P2SH redeem
    // script: for a P2PKH input the scriptCode is just the scriptPubKey, and the wrapper below
    // reads scriptCode from redeem/witness_script.
    input.redeem_script = Some(prevout_script.clone());
    z.psbt.inputs = vec![input];
    z.psbt.outputs = vec![crate::bitcoin::psbt::Output::default(); tx.transparent.output.len()];
    crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::set_ironwood_pczt(
        &mut z.psbt,
        pczt_bytes_from_action_data(&bundle),
    );
    // The synthetic PCZT carries no plaintext or dummy markers, so it reads as a spend
    // bundle; its ciphertexts are the golden transaction's final ones.
    crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::set_ironwood_out_ciphertexts_set(
        &mut z.psbt,
        vec![0xff; bundle.actions.len().div_ceil(8)],
    );

    // The PSBT-derived sighash must equal the codec's sighash — i.e. the PSBT
    // threaded the spent-output value + script through correctly.
    let psbt_sighash = z.v6_transparent_sighash(0).unwrap();
    let codec_sighash = compute_v6_transparent_sighash(
        &tx,
        0,
        &[prevout_value],
        std::slice::from_ref(&prevout_script),
    )
    .unwrap();
    assert_eq!(psbt_sighash, codec_sighash, "PSBT sighash == codec golden");

    // And the transaction's real signature verifies against the PSBT-derived sighash.
    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest(psbt_sighash);
    let mut sig = Signature::from_der(der).expect("DER signature");
    sig.normalize_s();
    let pk = SecpPk::from_slice(pubkey_bytes).expect("valid pubkey");
    secp.verify_ecdsa(&msg, &sig, &pk)
        .expect("real signature verifies against the PSBT-derived v6 sighash");

    // And the PSBT reproduces the transaction's real, externally-produced txid — the shielded
    // action data survived the PCZT round-trip byte-for-byte. `v6_txid` is internal byte order;
    // the fixture records the display order.
    let mut psbt_txid = z.v6_txid().unwrap();
    psbt_txid.reverse();
    assert_eq!(
        hex::encode(psbt_txid),
        details.txid,
        "PSBT-derived v6 txid == the on-chain txid"
    );
}

/// A real-spend fixture for the PSBT layer: a wallet note (fvk/recipient/value/rho/rseed)
/// with a self-consistent witness around its cmx, the bundle anchor the witness recomputes
/// to, and the note's own spend authorizing key for the FROST stand-in.
fn test_spend_request() -> (
    IronwoodSpendRequest,
    crate::zcash::ironwood_build::AnchorBytes,
    SpendAuthorizingKey,
) {
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
    let rho = Option::<Rho>::from(Rho::from_bytes(&field_bytes(100))).unwrap();
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes([42u8; 32], &rho)).unwrap();
    let address =
        Option::<orchard::Address>::from(orchard::Address::from_raw_address_bytes(&recipient))
            .unwrap();
    let note = Option::<Note>::from(Note::from_parts(
        address,
        NoteValue::from_raw(100_000_000),
        rho,
        rseed,
        orchard::bundle::BundleVersion::ironwood_v3().note_version(),
    ))
    .unwrap();
    let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();

    let position = 5u32;
    let auth_path: crate::zcash::ironwood_build::WitnessAuthPath =
        std::array::from_fn(|i| field_bytes(i as u64 + 1));
    let sibling_hashes: [orchard::tree::MerkleHashOrchard; 32] =
        auth_path.map(|s| Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&s)).unwrap());
    let anchor = orchard::tree::MerklePath::from_parts(position, sibling_hashes)
        .root(
            Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&cmx))
                .unwrap(),
        )
        .to_bytes();

    (
        IronwoodSpendRequest {
            fvk: fvk.to_bytes(),
            recipient,
            value: 100_000_000,
            rho: rho.to_bytes(),
            rseed: *rseed.as_bytes(),
            cmx,
            witness: crate::zcash::ironwood_build::IronwoodWitness {
                position,
                auth_path,
            },
        },
        anchor,
        SpendAuthorizingKey::from(&sk),
    )
}

/// A fresh v6 PSBT with one real Ironwood spend (100M zatoshi) and a transparent payout of
/// 99_999_000 — an unshielding transaction with a 1_000-zatoshi fee and no transparent
/// inputs.
fn build_unshield_psbt(seed: &str) -> (ZcashBitGoPsbt, RootWalletKeys) {
    let wallet_keys = root_wallet_keys(seed);
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    let (req, anchor, _ask) = test_spend_request();
    z.add_ironwood_spends(&[req], &anchor, OsRng).unwrap();
    z.add_transparent_output(
        miniscript::bitcoin::ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac]),
        99_999_000,
        None,
    )
    .unwrap();
    (z, wallet_keys)
}

#[test]
fn add_ironwood_spends_placeholder_state_and_round_trip() {
    let (mut z, _keys) = build_unshield_psbt("ironwood_v6_spends_roundtrip");

    // The PCZT keeps note plaintext and placeholder-rk state, but not the full viewing key.
    let bytes = z.raw_ironwood_pczt_bytes().unwrap();
    let pczt = crate::zcash::ironwood_pczt::deserialize_pczt(&bytes).unwrap();
    let spend = pczt.actions()[0].spend();
    let (req, _anchor, _ask) = test_spend_request();
    assert!(spend.fvk().is_none());
    assert!(!bytes
        .windows(req.fvk.len())
        .any(|window| window == &req.fvk[..]));
    assert!(spend.alpha().is_none());
    assert_eq!(
        <[u8; 32]>::from(spend.rk()),
        <[u8; 32]>::try_from(&req.fvk[0..32]).unwrap()
    );
    assert_eq!(spend.value().map(|v| v.inner()), Some(req.value));
    assert_eq!(spend.rho().map(|r| r.to_bytes()), Some(req.rho));
    assert_eq!(spend.rseed().map(|r| *r.as_bytes()), Some(req.rseed));
    assert_eq!(
        spend
            .proprietary()
            .get(crate::zcash::ironwood_build::CMX_PROPRIETARY_KEY),
        Some(&req.cmx.to_vec())
    );

    let round = ZcashBitGoPsbt::deserialize_v6(&z.serialize_v6(), Network::ZcashTestnet).unwrap();
    assert_eq!(
        round.raw_ironwood_pczt_bytes().unwrap(),
        bytes,
        "the PCZT round-trips the PSBT bytes losslessly"
    );

    // A second constructor call is rejected.
    let (req, anchor, _ask) = test_spend_request();
    assert!(z.add_ironwood_spends(&[req], &anchor, OsRng).is_err());
}

#[test]
fn sighash_gates_on_unpatched_rk_and_replace_rejects_bad_context() {
    let (mut z, _keys) = build_unshield_psbt("ironwood_v6_spends_guard");

    let err = z.v6_sig_digest().unwrap_err();
    assert!(err.contains("placeholder"), "unexpected: {err}");

    // Replacing on a non-existent action is rejected.
    assert!(z.replace_ironwood_spend_rk(1, [0u8; 32]).is_err());
    // A non-canonical rk is rejected (the wire patcher validates the point).
    assert!(z.replace_ironwood_spend_rk(0, [0xffu8; 32]).is_err());

    // FROST stand-in: randomized rk from a fresh randomizer.
    let (_req, _anchor, ask) = test_spend_request();
    let mut rng = OsRng;
    let alpha = pasta_curves::pallas::Scalar::random(&mut rng);
    let rsk = ask.randomize(&alpha);
    let rk = <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&rsk));
    z.replace_ironwood_spend_rk(0, rk).unwrap();

    // The digest is now fixed, and re-patching is idempotent.
    z.v6_sig_digest().unwrap();
    z.replace_ironwood_spend_rk(0, rk).unwrap();
}

#[test]
fn unshield_frost_flow_produces_a_valid_v6_tx() {
    let (mut z, _keys) = build_unshield_psbt("ironwood_v6_unshield_e2e");

    // FROST stand-in round 1: the coordinator derives alpha, computes rk, delivers it.
    let (_req, _anchor, ask) = test_spend_request();
    let mut rng = OsRng;
    let alpha = pasta_curves::pallas::Scalar::random(&mut rng);
    let rsk = ask.randomize(&alpha);
    let rk = <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&rsk));
    z.replace_ironwood_spend_rk(0, rk).unwrap();

    // The digest commits the final rk; the spend-auth signature is over exactly this digest.
    let sighash = z.v6_sig_digest().unwrap();

    // Accounting: 100M shielded in, 99.999M transparent out, no transparent inputs,
    // fee 1_000 zatoshi; the bundle value balance is net +100M out of the pool.
    let info = z.ironwood_bundle_info().unwrap();
    assert_eq!(info.spends.len(), 1);
    assert_eq!(info.spends[0].value, 100_000_000);
    assert!(info.outputs.is_empty());
    assert_eq!(info.transparent_in, 0);
    assert_eq!(info.transparent_out, 99_999_000);
    assert_eq!(info.fee, 1_000);
    assert_eq!(info.value_balance, 100_000_000);

    // FROST stand-in round 2: RedPallas signature over the digest.
    let sig = rsk.sign(rng, &sighash);
    z.apply_ironwood_spend_signature(0, <[u8; 64]>::from(&sig))
        .unwrap();
    // A second application with a different digest-shaped signature fails loudly and
    // leaves the stored signature untouched.
    let bad = rsk.sign(rng, &[0u8; 32]);
    assert!(z
        .apply_ironwood_spend_signature(0, <[u8; 64]>::from(&bad))
        .is_err());

    let proof = vec![0u8; Proof::expected_proof_size(1)];
    let raw = z.combine_ironwood_proof(proof, OsRng).unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    let bundle = tx.ironwood_bundle.as_ref().unwrap();
    assert_eq!(
        bundle.actions[0].rk, rk,
        "the randomized rk reached the wire"
    );

    use zebra_chain::serialization::ZcashDeserialize;
    use zebra_chain::transaction::Transaction as ZebraTx;
    let zebra = ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes the unshield tx");
    assert_eq!(zebra.version(), 6);
    assert_eq!(zebra.ironwood_actions().count(), 1);
}

#[test]
fn combine_rejects_a_transaction_that_does_not_conserve_value() {
    let wallet_keys = root_wallet_keys("ironwood_v6_unshield_negative_fee");
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    let (req, anchor, _ask) = test_spend_request();
    z.add_ironwood_spends(&[req], &anchor, OsRng).unwrap();
    // Payout exceeds the spend by 1 zatoshi: fee -1.
    z.add_transparent_output(
        miniscript::bitcoin::ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac]),
        100_000_001,
        None,
    )
    .unwrap();
    assert_eq!(z.ironwood_bundle_info().unwrap().fee, -1);

    let err = z
        .combine_ironwood_proof(vec![0u8; Proof::expected_proof_size(1)], OsRng)
        .unwrap_err();
    assert!(err.contains("does not conserve value"), "unexpected: {err}");
}

#[test]
fn zip317_counts_and_fee() {
    let (z, _keys) = build_unshield_psbt("ironwood_v6_zip317");

    // The fixture has NO transparent input (spend + transparent output only): the input
    // term is 0. The single transparent output (5-byte script): 8 + 1 + 5 = 14. One
    // Ironwood action from the stored PCZT.
    let counts = z.zip317_action_counts().unwrap();
    assert_eq!(counts.tx_in_total_size, 0);
    assert_eq!(counts.tx_out_total_size, 14);
    assert_eq!(counts.n_actions_ironwood, 1);
    assert_eq!(z.ironwood_real_spend_and_output_counts().unwrap(), (1, 0));
    // logical_actions = max(0, ceil(14/34) = 1) + 1 = 2 ⇒ 10_000 zatoshi.
    assert_eq!(z.zip317_conventional_fee().unwrap(), 10_000);

    // A PSBT with no stored PCZT has no Ironwood term.
    let mut fresh = {
        let psbt = BitGoPsbt::new_zcash_v6_at_height(
            Network::ZcashTestnet,
            &root_wallet_keys("ironwood_v6_zip317_fresh"),
            NetworkUpgrade::Nu6_3.testnet_activation_height(),
            None,
            None,
        )
        .unwrap();
        match psbt {
            BitGoPsbt::Zcash(z, _) => z,
            _ => panic!("expected Zcash PSBT"),
        }
    };
    fresh
        .add_transparent_output(
            miniscript::bitcoin::ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac]),
            99_999_000,
            None,
        )
        .unwrap();
    let fresh_counts = fresh.zip317_action_counts().unwrap();
    assert_eq!(fresh_counts.n_actions_ironwood, 0);
    assert_eq!(
        fresh.ironwood_real_spend_and_output_counts().unwrap(),
        (0, 0)
    );
}

/// Extraction drops the PCZT, but the ZIP-317 counts (and fee) must survive it: they are
/// recorded by `mark_ironwood_extracted`.
#[test]
fn zip317_counts_survive_extraction() {
    let mut shield = build_shield_psbt_multi("zip317_extract_shield", &[test_recipient(); 2]);
    let (mut unshield, _keys) = build_unshield_psbt("zip317_extract_unshield");
    for z in [&mut shield, &mut unshield] {
        let counts = z.zip317_action_counts().unwrap();
        let spends_and_outputs = z.ironwood_real_spend_and_output_counts().unwrap();
        assert!(z.mark_ironwood_extracted());
        assert!(z.raw_ironwood_pczt_bytes().is_none());
        assert_eq!(
            z.ironwood_real_spend_and_output_counts().unwrap(),
            spends_and_outputs
        );
        assert_eq!(z.zip317_action_counts().unwrap(), counts);
        assert_eq!(
            z.zip317_conventional_fee().unwrap(),
            crate::zcash::zip317::conventional_fee(&counts)
        );
    }
    assert_eq!(
        shield.ironwood_real_spend_and_output_counts().unwrap(),
        (0, 2)
    );
    assert_eq!(
        unshield.ironwood_real_spend_and_output_counts().unwrap(),
        (1, 0)
    );

    // A PCZT dropped without recording counts errors instead of reporting no actions.
    let mut legacy = build_shield_psbt("zip317_extract_legacy");
    assert!(super::super::propkv::take_ironwood_pczt(&mut legacy.psbt));
    let err = legacy.zip317_action_counts().unwrap_err();
    assert!(err.contains("without recording"), "unexpected: {err}");
}

/// `max(real spends, real outputs)` is the stored bundle's action count: the Constructor
/// builds UNPADDED bundles, pairing each real side with a dummy where the other is missing.
#[test]
fn zip317_ironwood_term_matches_the_stored_action_count() {
    let shield = build_shield_psbt_multi("zip317_shield_multi", &[test_recipient(); 3]);
    let (unshield, _keys) = build_unshield_psbt("zip317_unshield");
    for (z, expected) in [(shield, (0, 3)), (unshield, (1, 0))] {
        let (spends, outputs) = z.ironwood_real_spend_and_output_counts().unwrap();
        assert_eq!((spends, outputs), expected);
        let pczt =
            crate::zcash::ironwood_pczt::deserialize_pczt(&z.raw_ironwood_pczt_bytes().unwrap())
                .unwrap();
        assert_eq!(spends.max(outputs), pczt.actions().len());
    }
}

#[test]
fn ironwood_bundle_info_rejects_a_tampered_plaintext_value() {
    // The spend's plaintext value is not bound by the proofs (only `cv_net`/`cm` are), so a
    // plaintext that disagrees with the bundle's commitments must be caught by the keyless
    // verifier rather than silently flowing into the fee: the action's own `cv_net` (`CvNet`)
    // rejects it before the bundle-level `value_sum` cross-check (`ValueSum`) is reached.
    let (mut z, _keys) = build_unshield_psbt("ironwood_v6_tampered_plaintext");

    // The honest bundle accounts cleanly: fee = 0 - 99_999_000 + 100_000_000.
    assert_eq!(z.ironwood_bundle_info().unwrap().fee, 1_000);

    // Tamper the spend plaintext value (+1 zatoshi) without touching the committed
    // value_sum or cv_net, re-store, and expect the verifier to reject it.
    let bytes =
        crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::get_ironwood_pczt(&z.psbt).unwrap();
    let tampered = crate::zcash::ironwood_pczt::with_spend_value(&bytes, 0, 100_000_001).unwrap();
    crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::set_ironwood_pczt(&mut z.psbt, tampered);
    let err = z.ironwood_bundle_info().unwrap_err();
    assert!(err.contains("cv_net check"), "unexpected: {err}");
}

/// Fixture bundle of [`build_signed_multi_spend_psbt`], factored out for clippy's
/// `type_complexity`.
type SignedMultiSpendFixture = (
    ZcashBitGoPsbt,
    [(usize, [u8; 32]); 2],
    [[u8; 32]; 2],
    crate::zcash::ironwood_build::FvkBytes,
);

/// B3/B5 shared fixture: a 2-spend/2-output Ironwood bundle built against a real 2-leaf
/// Orchard tree, with both placeholder rks replaced (FROST stand-in: `rk = ak.randomize
/// (alpha)`), the transparent side signed, and both spend-auth signatures applied. Returns
/// the PSBT, the `(action_index, alpha)` pairs the local prover needs, each action's
/// randomized `rk`, and the spending FVK.
fn build_signed_multi_spend_psbt(seed: &str) -> SignedMultiSpendFixture {
    use crate::zcash::ironwood_build::test_util::{real_two_leaf_tree, RealLeaf};
    use ff::PrimeField;

    let secp = Secp256k1::new();
    let wallet_keys = root_wallet_keys(seed);
    let mut psbt = BitGoPsbt::new_zcash_v6_at_height(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu6_3.testnet_activation_height(),
        None,
        None,
    )
    .unwrap();
    psbt.add_wallet_input(
        Txid::from_byte_array([0x77u8; 32]),
        0,
        300_000_000,
        &wallet_keys,
        ScriptId { chain: 0, index: 0 },
        WalletInputOptions::default(),
    )
    .unwrap();
    // Accounting: 300M transparent in + 180M shielded in (the two spends); 279_999_000
    // transparent out + 200M shielded out (the two payments) ⇒ exactly 1_000 zatoshi fee
    // (value_balance is -20M: the transparent side funds 20M into the shielded pool).
    psbt.add_wallet_output(0, 1, 279_999_000, &wallet_keys)
        .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };

    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let (anchor, leaves) = real_two_leaf_tree(
        &fvk,
        [
            (100_000_000u64, field_bytes(200), [52u8; 32]),
            (80_000_000u64, field_bytes(201), [53u8; 32]),
        ],
    );
    let req = |leaf: &RealLeaf| IronwoodSpendRequest {
        fvk: fvk.to_bytes(),
        recipient: leaf.recipient,
        value: leaf.value,
        rho: leaf.rho,
        rseed: leaf.rseed,
        cmx: leaf.cmx,
        witness: leaf.witness,
    };
    let spends = [req(&leaves[0]), req(&leaves[1])];
    // Shielded self-payments back to this wallet's two addresses.
    let outputs = [
        IronwoodOutputRequest {
            recipient: spends[0].recipient,
            amount: 100_000_000,
            ovk: None,
            memo: [0u8; 512],
            unified_address: None,
        },
        IronwoodOutputRequest {
            recipient: spends[1].recipient,
            amount: 100_000_000,
            ovk: None,
            memo: [0u8; 512],
            unified_address: None,
        },
    ];
    let action_map = z
        .add_ironwood_actions(&spends, &outputs, &anchor, OsRng)
        .unwrap();
    let ask = SpendAuthorizingKey::from(&sk);
    let mut pairs = [(0usize, [0u8; 32]); 2];
    let mut rks = [[0u8; 32]; 2];
    for (i, action_index) in action_map.spend_action_indices().iter().enumerate() {
        let alpha = pasta_curves::pallas::Scalar::random(&mut OsRng);
        let rsk = ask.randomize(&alpha);
        let rk = <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&rsk));
        z.replace_ironwood_spend_rk(*action_index, rk).unwrap();
        pairs[i] = (*action_index, alpha.to_repr());
        rks[i] = rk;
    }

    // The transparent side: real-spend bundles skip the client-ovk round, so either key
    // may open; sign user-then-bitgo like the shielding flow.
    z.sign_ironwood_v6(&test_wallet_xpriv(seed, 0), &wallet_keys, &secp)
        .unwrap();
    z.sign_ironwood_v6(&test_wallet_xpriv(seed, 2), &wallet_keys, &secp)
        .unwrap();

    let sighash = z.v6_sig_digest().unwrap();
    for (i, action_index) in action_map.spend_action_indices().iter().enumerate() {
        let alpha = pasta_curves::pallas::Scalar::from_repr(pairs[i].1).unwrap();
        let rsk = ask.randomize(&alpha);
        let sig = rsk.sign(OsRng, &sighash);
        z.apply_ironwood_spend_signature(*action_index, <[u8; 64]>::from(&sig))
            .unwrap();
    }
    (z, pairs, rks, fvk.to_bytes())
}

/// B3: a 2-spend/2-output bundle signs and combines end-to-end with a proof sized for its
/// action count, and zebra independently decodes the result.
#[test]
fn multi_spend_multi_output_round_trips() {
    let (z, pairs, rks, _fvk) = build_signed_multi_spend_psbt("ironwood_v6_multi_spend_multi_out");
    let raw = z
        .combine_ironwood_proof(vec![0u8; Proof::expected_proof_size(2)], OsRng)
        .unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    let bundle = tx.ironwood_bundle.as_ref().unwrap();
    assert_eq!(bundle.actions.len(), 2);
    assert_eq!(bundle.proof.len(), Proof::expected_proof_size(2));
    assert_eq!(bundle.spend_auth_sigs.len(), 2);

    use zebra_chain::serialization::ZcashDeserialize;
    use zebra_chain::transaction::Transaction as ZebraTx;
    let zebra = ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes the tx");
    assert_eq!(zebra.version(), 6);
    assert_eq!(zebra.ironwood_actions().count(), 2);
    // Each action carries exactly the randomized rk installed for its request — the map's
    // action routing survives the builder's reordering all the way to the wire.
    for (i, (action_index, _alpha)) in pairs.iter().enumerate() {
        assert_eq!(
            bundle.actions[*action_index].rk, rks[i],
            "action {action_index} must carry spend {i}'s randomized rk"
        );
    }
}

/// B3: the Transaction Extractor rejects a proof sized for the wrong action count.
#[test]
fn combine_rejects_a_proof_sized_for_a_different_action_count() {
    let (z, _pairs, _rks, _fvk) = build_signed_multi_spend_psbt("ironwood_v6_wrong_size_proof");
    let err = z
        .combine_ironwood_proof(vec![0u8; Proof::expected_proof_size(1)], OsRng)
        .unwrap_err();
    assert!(
        err.contains("non-canonical length"),
        "expected a proof-size rejection, got: {err}"
    );
}

/// PR-4 end-to-end under the proving feature: construct (placeholder rk) -> install real
/// alphas/rks -> sign -> finalize IO -> prove LOCALLY -> extract -> verify the proof with
/// orchard's own verifier — with the spending FVK supplied by the local prover (the holder).
#[cfg(feature = "orchard-proving")]
#[test]
fn multi_spend_multi_output_proves_and_verifies_locally() {
    use nonempty::NonEmpty;
    use orchard::bundle::{Authorized, Bundle as OrchardBundle, BundleVersion};
    use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
    use orchard::note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext};
    use orchard::primitives::redpallas::{Binding, Signature, SpendAuth, VerificationKey};
    use orchard::value::ValueCommitment;
    use orchard::{Action as OrchardAction, Proof};

    let (z, pairs, _rks, fvk_bytes) =
        build_signed_multi_spend_psbt("ironwood_v6_multi_local_proof");
    let raw = z
        .combine_ironwood_proof_locally_with_alphas(&pairs, Some(&fvk_bytes), OsRng)
        .unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    let bundle = tx.ironwood_bundle.as_ref().unwrap();
    assert_eq!(bundle.actions.len(), 2);
    assert_eq!(bundle.proof.len(), Proof::expected_proof_size(2));

    use zebra_chain::serialization::ZcashDeserialize;
    use zebra_chain::transaction::Transaction as ZebraTx;
    let zebra = ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes the tx");
    assert_eq!(zebra.ironwood_actions().count(), 2);

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
        .expect("locally-produced 2-action proof verifies");
}

#[cfg(feature = "orchard-proving")]
#[test]
fn combine_ironwood_proof_locally_rejects_a_transaction_that_does_not_conserve_value() {
    // Mirror of the external-path negative-fee test: the local path must hit the same
    // pre-flight conservation guard before any (expensive) proof generation runs.
    let wallet_keys = root_wallet_keys("ironwood_v6_local_negative_fee");
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    let (req, anchor, _ask) = test_spend_request();
    z.add_ironwood_spends(&[req], &anchor, OsRng).unwrap();
    // Payout exceeds the spend by 1 zatoshi: fee -1.
    z.add_transparent_output(
        miniscript::bitcoin::ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac]),
        100_000_001,
        None,
    )
    .unwrap();
    let err = z.combine_ironwood_proof_locally(OsRng).unwrap_err();
    assert!(err.contains("does not conserve value"), "unexpected: {err}");
}

#[test]
fn mixed_transparent_and_shielded_signs_and_combines() {
    let seed = "ironwood_v6_mixed";
    let secp = Secp256k1::new();
    let wallet_keys = root_wallet_keys(seed);
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let mut psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    psbt.add_wallet_input(
        Txid::from_byte_array([0x33u8; 32]),
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
    // 200M transparent in + 100M shielded in; 299.999M transparent out + 1_000 fee.
    z.add_transparent_output(
        miniscript::bitcoin::ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac]),
        299_999_000,
        None,
    )
    .unwrap();
    let (req, anchor, ask) = test_spend_request();
    let action_map = z.add_ironwood_actions(&[req], &[], &anchor, OsRng).unwrap();
    assert_eq!(action_map.spend_action_indices(), &[0]);

    // rk before any transparent signature (the replace guard enforces the ordering).
    let mut rng = OsRng;
    let alpha = pasta_curves::pallas::Scalar::random(&mut rng);
    let rsk = ask.randomize(&alpha);
    let rk = <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&rsk));
    z.replace_ironwood_spend_rk(0, rk).unwrap();

    // Mixed flows skip the client-ovk first round: any key may open the round.
    let bitgo_xpriv = test_wallet_xpriv(seed, 2);
    let signed = z
        .sign_ironwood_v6(&bitgo_xpriv, &wallet_keys, &secp)
        .unwrap();
    assert_eq!(
        signed,
        vec![0],
        "bitgo key signed the transparent input first"
    );

    let sighash = z.v6_sig_digest().unwrap();
    let sig = rsk.sign(rng, &sighash);
    z.apply_ironwood_spend_signature(0, <[u8; 64]>::from(&sig))
        .unwrap();

    let user_xpriv = test_wallet_xpriv(seed, 0);
    z.sign_ironwood_v6(&user_xpriv, &wallet_keys, &secp)
        .unwrap();
    assert_eq!(z.psbt.inputs[0].partial_sigs.len(), 2);

    let proof = vec![0u8; Proof::expected_proof_size(1)];
    let raw = z.combine_ironwood_proof(proof, OsRng).unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    assert_eq!(tx.ironwood_bundle.as_ref().unwrap().actions[0].rk, rk);

    use zebra_chain::serialization::ZcashDeserialize;
    use zebra_chain::transaction::Transaction as ZebraTx;
    let zebra = ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes the mixed tx");
    assert_eq!(zebra.ironwood_actions().count(), 1);
}

/// Randomize the test note's spend authorizing key and return `(rsk, rk)` — the FROST
/// signer stand-in for one real spend.
fn randomized_spend_key(
    ask: &SpendAuthorizingKey,
) -> (
    orchard::primitives::redpallas::SigningKey<SpendAuth>,
    [u8; 32],
) {
    let alpha = pasta_curves::pallas::Scalar::random(OsRng);
    let rsk = ask.randomize(&alpha);
    let rk = <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&rsk));
    (rsk, rk)
}

#[test]
fn spend_bundle_accounting_skips_dummy_outputs_and_counts_spends() {
    let (z, wallet_keys) = build_unshield_psbt("ironwood_v6_unshield_parse");

    // The spend-only action's fabricated output is not a real output.
    assert!(z.ironwood_shielded_outputs_info().unwrap().is_empty());
    let spends = z.ironwood_shielded_spends_info().unwrap();
    assert_eq!(spends.len(), 1);
    assert_eq!(spends[0].value, 100_000_000);

    // The Zcash parse folds the shielded spend into the input total, so the unshield's
    // fee is the 1_000-zatoshi difference rather than an underflow. The generic parse
    // refuses the PSBT outright instead of dropping the shielded side.
    let psbt = BitGoPsbt::Zcash(z, Network::ZcashTestnet);
    let generic_error = psbt
        .parse_transaction_with_wallet_keys(
            &wallet_keys,
            &crate::fixed_script_wallet::ReplayProtection::new(vec![]),
            &[],
        )
        .unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&generic_error),
        "ParseTransactionError.UseZcashParse"
    );

    let parsed =
        crate::fixed_script_wallet::bitgo_psbt::zcash::parse::parse_transaction_with_wallet_keys(
            &psbt,
            &wallet_keys,
            &crate::fixed_script_wallet::ReplayProtection::new(vec![]),
            &[],
        )
        .unwrap();
    assert_eq!(parsed.miner_fee, 1_000);
    assert!(parsed.outputs.iter().all(|output| !output.is_shielded));
    assert!(parsed.is_ironwood_v6);
    assert_eq!(parsed.value_balance, 100_000_000);
    let crate::fixed_script_wallet::bitgo_psbt::zcash::parse::ZcashParsedInputs::Shielded(
        shielded_spends,
    ) = &parsed.inputs
    else {
        panic!("a deshield parses as shielded inputs");
    };
    assert_eq!(shielded_spends.len(), 1);
    assert_eq!(shielded_spends[0].value, 100_000_000);
    assert_eq!(shielded_spends[0].nullifier, spends[0].nullifier);
    assert_eq!(
        shielded_spends[0].recipient,
        test_spend_request().0.recipient
    );
    assert!(!shielded_spends[0].rk_replaced);
    assert!(!shielded_spends[0].signed);
    // The spend's address is its own receiver's UA — never an output's stored UA.
    assert_eq!(
        shielded_spends[0].address,
        crate::zcash::unified_address::encode_orchard_receiver(
            &shielded_spends[0].recipient,
            Network::ZcashTestnet.to_coin_name(),
        )
        .unwrap()
    );
}

/// The Zcash parse reports each spend's randomizer and signature state from the PCZT
/// rather than assuming the Constructor's placeholder state.
#[test]
fn zcash_parse_reports_spend_signing_state() {
    let (mut z, wallet_keys) = build_unshield_psbt("ironwood_v6_parse_signing_state");
    let parse_spend = |z: &ZcashBitGoPsbt| {
        let psbt = BitGoPsbt::Zcash(z.clone(), Network::ZcashTestnet);
        let parsed =
            crate::fixed_script_wallet::bitgo_psbt::zcash::parse::parse_transaction_with_wallet_keys(
                &psbt,
                &wallet_keys,
                &crate::fixed_script_wallet::ReplayProtection::new(vec![]),
                &[],
            )
            .unwrap();
        match parsed.inputs {
            crate::fixed_script_wallet::bitgo_psbt::zcash::parse::ZcashParsedInputs::Shielded(
                mut spends,
            ) => spends.remove(0),
            _ => panic!("a deshield parses as shielded inputs"),
        }
    };

    let (_req, _anchor, ask) = test_spend_request();
    let (rsk, rk) = randomized_spend_key(&ask);
    z.replace_ironwood_spend_rk(0, rk).unwrap();
    let spend = parse_spend(&z);
    assert!(spend.rk_replaced);
    assert!(!spend.signed);

    let sighash = z.v6_sig_digest().unwrap();
    let sig = rsk.sign(OsRng, &sighash);
    z.apply_ironwood_spend_signature(0, <[u8; 64]>::from(&sig))
        .unwrap();
    let spend = parse_spend(&z);
    assert!(spend.rk_replaced);
    assert!(spend.signed);
}

/// The Zcash parse refuses a PSBT that mixes transparent inputs with shielded spends
/// rather than dropping either side.
#[test]
fn zcash_parse_rejects_mixed_input_kinds() {
    let wallet_keys = root_wallet_keys("ironwood_v6_parse_mixed");
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let mut psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    psbt.add_wallet_input(
        Txid::from_byte_array([0x33u8; 32]),
        0,
        200_000_000,
        &wallet_keys,
        ScriptId { chain: 0, index: 0 },
        WalletInputOptions::default(),
    )
    .unwrap();
    let BitGoPsbt::Zcash(mut z, network) = psbt else {
        panic!("expected Zcash PSBT");
    };
    z.add_transparent_output(
        miniscript::bitcoin::ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac]),
        299_999_000,
        None,
    )
    .unwrap();
    let (req, anchor, _ask) = test_spend_request();
    z.add_ironwood_actions(&[req], &[], &anchor, OsRng).unwrap();

    let psbt = BitGoPsbt::Zcash(z, network);
    let error =
        crate::fixed_script_wallet::bitgo_psbt::zcash::parse::parse_transaction_with_wallet_keys(
            &psbt,
            &wallet_keys,
            &crate::fixed_script_wallet::ReplayProtection::new(vec![]),
            &[],
        )
        .unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&error),
        "ZcashParseTransactionError.MixedInputKinds"
    );
}

/// Transparent failures in the Zcash parse keep the coin-neutral `ParseTransactionError.*`
/// codes: routing every Zcash PSBT through the Zcash parse changes no existing error code.
#[test]
fn zcash_parse_keeps_transparent_error_codes() {
    let error =
        crate::fixed_script_wallet::bitgo_psbt::zcash::parse::ZcashParseTransactionError::from(
            crate::fixed_script_wallet::bitgo_psbt::ParseTransactionError::FeeCalculation,
        );
    assert_eq!(
        crate::error::WasmErrorCode::code(&error),
        "ParseTransactionError.FeeCalculation"
    );
}

/// `apply_ironwood_spend_signature` must refuse to ingest a spend-auth signature while a
/// real spend still carries the Constructor's placeholder `rk` (= its `ak`): a RedPallas
/// signature made with `alpha = 0` verifies against `rk = ak`, so signature verification
/// alone cannot catch it — the gate is what keeps an unrandomized (linkable) rk off the
/// chain. Fires before any signature bytes are examined.
#[test]
fn apply_spend_signature_rejects_a_placeholder_rk() {
    let (mut z, _keys) = build_unshield_psbt("ironwood_v6_apply_rk_guard");
    // Placeholder rk (marker [0]): any 64 bytes would be "verifiable" if the signer used
    // alpha = 0, so the gate must fire on the STATE, not on signature validity.
    let err = z.apply_ironwood_spend_signature(0, [7u8; 64]).unwrap_err();
    assert!(
        err.contains("placeholder"),
        "expected the placeholder-rk gate, got: {err}"
    );

    // After the rk is replaced, the same bytes pass the gate (and fail RedPallas
    // verification instead, which is the correct next layer).
    let (req, _anchor, ask) = test_spend_request();
    let _ = req;
    let alpha = pasta_curves::pallas::Scalar::random(OsRng);
    let rsk = ask.randomize(&alpha);
    let rk = <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&rsk));
    z.replace_ironwood_spend_rk(0, rk).unwrap();
    let err = z.apply_ironwood_spend_signature(0, [7u8; 64]).unwrap_err();
    assert!(
        !err.contains("placeholder"),
        "the gate must not fire once the rk is replaced, got: {err}"
    );
}

#[test]
fn replace_rk_rejects_the_placeholder_and_runs_only_before_spend_signatures() {
    let (mut z, _keys) = build_unshield_psbt("ironwood_v6_replace_rk_guard");
    let (req, _anchor, ask) = test_spend_request();

    // The placeholder itself (the unrandomized ak) is not a randomized rk.
    let ak = <[u8; 32]>::try_from(&req.fvk[0..32]).unwrap();
    let err = z.replace_ironwood_spend_rk(0, ak).unwrap_err();
    assert!(err.contains("placeholder"), "unexpected: {err}");

    let (rsk, rk) = randomized_spend_key(&ask);
    z.replace_ironwood_spend_rk(0, rk).unwrap();
    let sighash = z.v6_sig_digest().unwrap();
    z.apply_ironwood_spend_signature(0, <[u8; 64]>::from(&rsk.sign(OsRng, &sighash)))
        .unwrap();

    // No transparent inputs exist to trip the partial_sigs guard, but the applied spend-auth
    // signature commits rk: replacing it now (even with the same value) is rejected.
    let (_rsk2, rk2) = randomized_spend_key(&ask);
    for new_rk in [rk2, rk] {
        let err = z.replace_ironwood_spend_rk(0, new_rk).unwrap_err();
        assert!(err.contains("spend-auth signature"), "unexpected: {err}");
    }
    assert_eq!(z.v6_sig_digest().unwrap(), sighash, "digest unchanged");
}

/// The shielding flow (transparent inputs → Ironwood output) carries a PCZT, but its actions
/// pair dummy spends with the real outputs: it must keep the bitcoin-weight virtual size the
/// indexer's fee selection and fee-rate checks already use.
#[test]
fn shielding_v6_keeps_the_bitcoin_weight_virtual_size() {
    let seed = "v6_shield_vsize";
    let z = build_shield_psbt(seed);
    assert!(z.raw_ironwood_pczt_bytes().is_some());
    let weight_vsize = z.psbt.unsigned_tx.weight().to_vbytes_ceil();

    let psbt = BitGoPsbt::Zcash(z, Network::ZcashTestnet);
    let parsed =
        crate::fixed_script_wallet::bitgo_psbt::zcash::parse::parse_transaction_with_wallet_keys(
            &psbt,
            &RootWalletKeys::new(get_test_wallet_keys(seed)),
            &crate::fixed_script_wallet::ReplayProtection::new(vec![]),
            &[],
        )
        .unwrap();
    assert_eq!(parsed.virtual_size as u64, weight_vsize);
}

/// The ZIP-317 input-size estimate for a P2SH 2-of-3 wallet input must cover the real
/// finalized scriptSig (`OP_0 <sig> <sig> <redeemScript>`), never undercount it.
#[test]
fn estimated_script_sig_len_covers_a_finalized_multisig_input() {
    let seed = "v6_script_sig_estimate";
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys(seed));
    let mut psbt = BitGoPsbt::new_zcash_v6_at_height(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu6_3.testnet_activation_height(),
        None,
        None,
    )
    .unwrap();
    psbt.add_wallet_input(
        Txid::from_byte_array([0x46u8; 32]),
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
    let estimate = estimated_script_sig_len(&z.psbt.inputs[0]);

    let secp = Secp256k1::new();
    let msg = Message::from_digest(z.v6_transparent_sighash(0).unwrap());
    for sk in signing_secret_keys(seed, 0, 0).iter().take(2) {
        let pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, sk);
        let pubkey = PublicKey::from(CompressedPublicKey(pk));
        let mut der = secp.sign_ecdsa(&msg, sk).serialize_der().to_vec();
        der.push(0x01);
        z.add_v6_transparent_signature(0, pubkey, &der).unwrap();
    }
    let counts = z.zip317_action_counts().unwrap();
    let tx = z.finalized_transparent_tx().unwrap();
    let actual = tx.input[0].script_sig.len();
    assert!(
        estimate >= actual && estimate - actual <= 4,
        "estimate {estimate} must cover and tightly bound the real scriptSig {actual}"
    );

    // The ZIP-317 input term is the whole serialized input — outpoint (36), scriptSig with
    // its CompactSize, sequence (4) — and must cover the real finalized input too.
    let actual_input = crate::bitcoin::consensus::serialize(&tx.input[0]).len() as u64;
    assert!(
        counts.tx_in_total_size >= actual_input && counts.tx_in_total_size - actual_input <= 4,
        "ZIP-317 input size {} must cover and tightly bound the real input {actual_input}",
        counts.tx_in_total_size
    );
}

/// A finalized input is sized from its real scriptSig, even though the finalizer cleared
/// its redeem script (which would otherwise fall through to the P2PKH estimate).
#[test]
fn estimated_script_sig_len_uses_a_finalized_script_sig() {
    let script_sig = miniscript::bitcoin::ScriptBuf::from(vec![0u8; 253]);
    let input = crate::bitcoin::psbt::Input {
        final_script_sig: Some(script_sig.clone()),
        ..Default::default()
    };
    assert_eq!(estimated_script_sig_len(&input), 253);
}

/// A P2SH-P2PK replay-protection input's scriptSig is `<sig> <redeemScript>`, not the 2-of-3
/// multisig form.
#[test]
fn estimated_script_sig_len_sizes_a_replay_protection_input() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
    let pubkey = PublicKey::from(CompressedPublicKey(
        crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk),
    ));
    let redeem = miniscript::bitcoin::script::Builder::new()
        .push_key(&pubkey)
        .push_opcode(miniscript::bitcoin::opcodes::all::OP_CHECKSIG)
        .into_script();
    let input = crate::bitcoin::psbt::Input {
        redeem_script: Some(redeem.clone()),
        ..Default::default()
    };
    // push(73-byte max sig) + push(35-byte redeem script)
    assert_eq!(estimated_script_sig_len(&input), 74 + 1 + redeem.len());
}

/// A transparent-only v6 PSBT still signs over ZIP-244, so the v4 (ZIP-243) signing and
/// combining paths must keep refusing it even though it carries no Ironwood bundle.
#[test]
fn transparent_only_v6_is_refused_by_the_v4_signing_paths() {
    let seed = "v6_transparent_v4_paths";
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys(seed));
    let mut psbt = BitGoPsbt::new_zcash_v6_at_height(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu6_3.testnet_activation_height(),
        None,
        None,
    )
    .unwrap();
    psbt.add_wallet_input(
        Txid::from_byte_array([0x47u8; 32]),
        0,
        200_000_000,
        &wallet_keys,
        ScriptId { chain: 0, index: 0 },
        WalletInputOptions::default(),
    )
    .unwrap();
    psbt.add_wallet_output(0, 1, 199_900_000, &wallet_keys)
        .unwrap();
    match &psbt {
        BitGoPsbt::Zcash(z, _) => assert!(z.raw_ironwood_pczt_bytes().is_none()),
        _ => panic!("expected Zcash PSBT"),
    }

    let sk = signing_secret_keys(seed, 0, 0)[0];
    let err = psbt.sign_with_privkey(0, &sk).unwrap_err();
    assert!(err.contains("v6"), "unexpected: {err}");
    let err = psbt.sign_single_input_with_privkey(0, &sk).unwrap_err();
    assert!(err.contains("v6"), "unexpected: {err}");
    let BitGoPsbt::Zcash(z, _) = &psbt else {
        panic!("expected Zcash PSBT");
    };
    assert!(
        z.psbt.inputs[0].partial_sigs.is_empty(),
        "no ZIP-243 signature may be stored"
    );

    let bytes = psbt.serialize().unwrap();
    let err = psbt.combine_inputs(&bytes).unwrap_err();
    assert!(err.contains("not supported for v6"), "unexpected: {err}");
}

/// Generator for the TS tampered-parse fixture:
/// a shielded-output PSBT whose stored PCZT output recipient was swapped at equal value.
/// Run with `cargo test --lib write_tampered_psbt_fixture -- --ignored`.
#[test]
#[ignore = "fixture generator: run with --ignored to rewrite the fixture"]
fn write_tampered_psbt_fixture() {
    let z = build_shield_psbt("ironwood-ts");
    let bytes = crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::get_ironwood_pczt(&z.psbt)
        .expect("shielded PCZT stored");
    // A valid but different recipient (a different key's address) at equal value.
    let other_sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([9u8; 32])).unwrap();
    let other_recipient = FullViewingKey::from(&other_sk)
        .address_at(0u32, Scope::External)
        .to_raw_address_bytes();
    let tampered =
        crate::zcash::ironwood_pczt::with_output_recipient_for_test(&bytes, 0, &other_recipient)
            .unwrap();
    let mut psbt = z;
    crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::set_ironwood_pczt(
        &mut psbt.psbt,
        tampered,
    );
    let psbt_bytes = psbt.serialize().unwrap();
    let hex = hex::encode(psbt_bytes);
    let path = format!(
        "{}/test/fixtures/zcash/ironwood_tampered_recipient.hex",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::write(&path, hex).unwrap();
    println!("wrote {path}");
}

/// The TS tampered-parse fixture fails the parse with the failing check's code.
#[test]
fn tampered_fixture_fails_with_note_commitment_code() {
    let hex = crate::fixed_script_wallet::test_utils::fixtures::load_fixture(
        "zcash/ironwood_tampered_recipient.hex",
    )
    .unwrap();
    let bytes = hex::decode(hex.trim()).unwrap();
    let psbt = crate::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt::deserialize(
        &bytes,
        crate::networks::Network::ZcashTestnet,
    )
    .unwrap();
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("ironwood-ts"));
    let err =
        crate::fixed_script_wallet::bitgo_psbt::zcash::parse::parse_transaction_with_wallet_keys(
            &crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt::Zcash(
                psbt,
                crate::networks::Network::ZcashTestnet,
            ),
            &wallet_keys,
            &crate::fixed_script_wallet::ReplayProtection::new(vec![]),
            &[],
        )
        .unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&err),
        "IronwoodVerifyError.NoteCommitment",
        "unexpected: {err:?}"
    );
}

/// A shielded side that cannot be read (here: the PCZT was already extracted) keeps the
/// `ZcashParseTransactionError.Shielded` code — only verifier failures carry
/// `IronwoodVerifyError.<check>`.
#[test]
fn zcash_parse_of_an_extracted_pczt_keeps_the_shielded_code() {
    let mut z = build_shield_psbt("ironwood-ts");
    assert!(z.mark_ironwood_extracted());
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("ironwood-ts"));
    let err =
        crate::fixed_script_wallet::bitgo_psbt::zcash::parse::parse_transaction_with_wallet_keys(
            &BitGoPsbt::Zcash(z, Network::ZcashTestnet),
            &wallet_keys,
            &crate::fixed_script_wallet::ReplayProtection::new(vec![]),
            &[],
        )
        .unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&err),
        "ZcashParseTransactionError.Shielded"
    );
}

/// A zero-valued Ironwood output is rejected at build time, on every constructor path.
#[test]
fn add_ironwood_outputs_rejects_a_zero_value_output() {
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("ironwood_v6_zero_output"));
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let psbt =
        BitGoPsbt::new_zcash_v6_at_height(Network::ZcashTestnet, &wallet_keys, nu6_3, None, None)
            .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    let (req, anchor, _ask) = test_spend_request();
    let err = z
        .add_ironwood_outputs(
            &[IronwoodOutputRequest {
                recipient: req.recipient,
                amount: 0,
                ovk: None,
                memo: [0u8; 512],
                unified_address: None,
            }],
            &anchor,
            OsRng,
        )
        .unwrap_err();
    assert!(err.contains("zero value"), "unexpected: {err}");
}
