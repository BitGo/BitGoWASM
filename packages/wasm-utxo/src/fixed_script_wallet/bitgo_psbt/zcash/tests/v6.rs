//! Tests for transparent v6 (Ironwood) PSBT behavior.

use super::*;
use crate::bitcoin::hashes::Hash;
use crate::bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use crate::bitcoin::{CompressedPublicKey, PublicKey, Txid};
use crate::error::WasmErrorCode;
use crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::WalletInputOptions;
use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt;
use crate::fixed_script_wallet::script_id::ScriptId;
use crate::fixed_script_wallet::test_utils::get_test_wallet_keys;
use crate::fixed_script_wallet::RootWalletKeys;
use crate::networks::Network;
use crate::zcash::NetworkUpgrade;
use orchard::tree::Anchor;
use orchard::Proof;
use rand::rngs::OsRng;

/// A transparent-only v6 (Ironwood) PSBT — no shielded output is ever added — is the shape
/// IMS will build once t->t ZEC sends move to v6 ahead of a shielded-send path existing for
/// them. Verifies the dedicated no-PCZT extractor produces a structurally valid, zebra-chain-
/// agreeing v6 transaction with an empty Ironwood bundle slot.
#[test]
fn extract_transparent_only_v6_tx_produces_a_valid_v6_tx() {
    let seed = "v6_transparent_only";
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys(seed));
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
    psbt.add_wallet_output(0, 1, 199_900_000, &wallet_keys)
        .unwrap();

    let BitGoPsbt::Zcash(z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    assert!(z.is_ironwood_v6());
    // No add_ironwood_output call: this PSBT never has a shielded output or a PCZT.
    assert!(z.raw_ironwood_pczt_bytes().is_none());

    let txid_before_signing = z.unsigned_v6_txid().unwrap();

    let secp = Secp256k1::new();
    let sighash = z.v6_transparent_sighash(0).unwrap();
    let msg = Message::from_digest(sighash);
    let mut z = z;
    for i in [0usize, 2] {
        let sk = signing_secret_keys(seed, 0, 0)[i];
        let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
        let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
        der.push(0x01); // SIGHASH_ALL
        z.add_v6_transparent_signature(0, pubkey, &der).unwrap();
    }

    let raw = z.extract_transparent_only_v6_tx().unwrap();

    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    assert_eq!(tx.transparent.input.len(), 1);
    assert_eq!(tx.transparent.output.len(), 1);
    assert!(
        !tx.transparent.input[0].script_sig.is_empty(),
        "input finalized"
    );
    assert!(
        tx.ironwood_bundle.is_none(),
        "transparent-only v6 tx has no Ironwood bundle"
    );

    // The unsigned v6 txid (defined before any signature existed) is unchanged by finalizing
    // the transparent input — ZIP-244 excludes scriptSigs, exactly as it does for the
    // shielded case in `build_sign_combine_produces_valid_v6_tx`.
    let internal_txid = crate::zcash::v6::compute_v6_txid(&tx);
    assert_eq!(internal_txid, txid_before_signing);

    // Not terminal: calling it again re-finalizes the same already-signed inputs rather than
    // erroring, unlike `combine_ironwood_proof`.
    let raw_again = z.extract_transparent_only_v6_tx().unwrap();
    assert_eq!(raw, raw_again);

    // zebra-chain independently decodes the tx and agrees: v6, zero Ironwood actions.
    use zebra_chain::serialization::ZcashDeserialize;
    use zebra_chain::transaction::Transaction as ZebraTx;
    let zebra = ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes v6 tx");
    assert_eq!(zebra.version(), 6);
    assert_eq!(zebra.ironwood_actions().count(), 0);
}

/// `sign_ironwood_v6` — the high-level signer behind the JS `sign()` call — must also work for
/// a transparent-only v6 PSBT: no `ovk`/`out_ciphertext` step applies (there is no PCZT), and
/// unlike the shielded case, the first signing round is not restricted to the user key, since
/// that restriction exists only to protect the `ovk` derivation.
#[test]
fn sign_ironwood_v6_signs_and_extracts_a_transparent_only_psbt() {
    let seed = "v6_sign_transparent_only";
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
        Txid::from_byte_array([0x55u8; 32]),
        0,
        200_000_000,
        &wallet_keys,
        ScriptId { chain: 0, index: 0 },
        WalletInputOptions::default(),
    )
    .unwrap();
    psbt.add_wallet_output(0, 1, 199_900_000, &wallet_keys)
        .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    assert!(z.raw_ironwood_pczt_bytes().is_none());

    // Bitgo signs *first* here — the opposite of the shielded-flow ordering requirement —
    // which would be rejected outright on a PSBT with a shielded output.
    let bitgo_xpriv = test_wallet_xpriv(seed, 2);
    assert_eq!(
        z.sign_ironwood_v6(&bitgo_xpriv, &wallet_keys, &secp)
            .unwrap(),
        vec![0]
    );
    let user_xpriv = test_wallet_xpriv(seed, 0);
    assert_eq!(
        z.sign_ironwood_v6(&user_xpriv, &wallet_keys, &secp)
            .unwrap(),
        vec![0]
    );

    let raw = z.extract_transparent_only_v6_tx().unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    assert!(tx.ironwood_bundle.is_none());
    assert!(!tx.transparent.input[0].script_sig.is_empty());
}

/// The no-PCZT extractor is only valid for a PSBT that never had a shielded output added — a
/// PSBT carrying one (even unsigned/unproven) must go through `combine_ironwood_proof`
/// instead, since its ZIP-244 digest already commits to real action data.
#[test]
fn extract_transparent_only_v6_tx_rejects_a_psbt_with_a_shielded_output() {
    let z = build_shield_psbt("extract_transparent_only_rejects_shielded");
    let err = z.extract_transparent_only_v6_tx().unwrap_err();
    assert!(
        err.contains("combine_ironwood_proof"),
        "unexpected error: {err}"
    );
}

/// `sign_ironwood_v6` on a v4/Sapling PSBT is rejected with a clear message rather than silently
/// doing nothing (there is no `bip32_derivation`-based ZIP-244 signing to do).
#[test]
fn sign_ironwood_v6_rejects_a_non_v6_psbt() {
    let seed = "ironwood_v6_sign_api_v4";
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys(seed));
    let mut z = ZcashBitGoPsbt::new(
        Network::ZcashTestnet,
        &wallet_keys,
        0x76b809bb, // an arbitrary consensus branch id
        None,
        None,
        None,
        None,
    );
    assert!(!z.is_ironwood_v6());
    let secp = Secp256k1::new();
    let user_xpriv = test_wallet_xpriv(seed, 0);
    let err = z
        .sign_ironwood_v6(&user_xpriv, &wallet_keys, &secp)
        .unwrap_err();
    assert!(err.contains("v6 (Ironwood)"), "unexpected error: {err}");
}

/// `new_v6_at_height` rejects a height before NU6.3 rather than stamping the transaction with a
/// branch id that only fails at broadcast.
#[test]
fn new_v6_at_height_rejects_pre_nu6_3_height() {
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("v6_height"));
    let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
    let err = ZcashBitGoPsbt::new_v6_at_height(
        Network::ZcashTestnet,
        &wallet_keys,
        nu6_3 - 1,
        None,
        None,
    )
    .unwrap_err();
    assert!(err.contains("NU6.3"), "unexpected error: {err}");
    // The activation height itself is accepted.
    assert!(ZcashBitGoPsbt::new_v6_at_height(
        Network::ZcashTestnet,
        &wallet_keys,
        nu6_3,
        None,
        None
    )
    .is_ok());
}

/// `verify_v6_signature_with_pub`/`_with_xpub` on a transparent-only v6 PSBT (no shielded
/// output ever added): a PR review comment on the Ironwood transparent-only PSBT work noted
/// that `getId`/`verifySignature` still required a PCZT and would throw for a pure
/// transparent-to-transparent transaction. This is the fixed happy path — real signers verify
/// over the bundle-less ZIP-244 transparent sighash, others don't — mirroring
/// `verify_v6_signature_reports_real_signers_and_rejects_others`, but without ever adding a
/// shielded output.
#[test]
fn verify_v6_signature_handles_transparent_only_psbt() {
    let seed = "v6_verify_transparent_only";
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
        Txid::from_byte_array([0x55u8; 32]),
        0,
        200_000_000,
        &wallet_keys,
        ScriptId { chain: 0, index: 0 },
        WalletInputOptions::default(),
    )
    .unwrap();
    psbt.add_wallet_output(0, 1, 199_900_000, &wallet_keys)
        .unwrap();
    let BitGoPsbt::Zcash(mut z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };

    // `getId` (`v6_txid`) must be usable before any signature is collected, same as a shielded
    // PSBT.
    assert!(z.v6_txid().is_ok());

    // Nothing collected yet: every key reports false (no error) — in particular, no
    // `MissingIronwoodPczt` just because a shielded output was never added.
    assert!(!z
        .verify_v6_signature_with_xpub(&secp, 0, wallet_keys.user_key())
        .unwrap());

    // Sign user then bitgo — no `ovk`/`out_ciphertext` step applies here (there is no shielded
    // output), so either key may open the first round.
    z.sign_ironwood_v6(&test_wallet_xpriv(seed, 0), &wallet_keys, &secp)
        .unwrap();
    z.sign_ironwood_v6(&test_wallet_xpriv(seed, 2), &wallet_keys, &secp)
        .unwrap();
    assert_eq!(z.psbt.inputs[0].partial_sigs.len(), 2);

    assert!(z
        .verify_v6_signature_with_xpub(&secp, 0, wallet_keys.user_key())
        .unwrap());
    assert!(z
        .verify_v6_signature_with_xpub(&secp, 0, wallet_keys.bitgo_key())
        .unwrap());
    // The backup key is not in this input's 2-of-3 redeem script (signer user, cosigner bitgo).
    assert!(!z
        .verify_v6_signature_with_xpub(&secp, 0, wallet_keys.backup_key())
        .unwrap());

    let user_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &signing_secret_keys(seed, 0, 0)[0],
    );
    let backup_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &signing_secret_keys(seed, 0, 0)[1],
    );
    assert!(z.verify_v6_signature_with_pub(&secp, 0, &user_pk).unwrap());
    assert!(!z
        .verify_v6_signature_with_pub(&secp, 0, &backup_pk)
        .unwrap());

    // `getId` remains usable after signing, and the signed PSBT's txid still matches the
    // unsigned one — v6/ZIP-244 txids do not commit to the transparent scriptSig.
    assert_eq!(z.v6_txid().unwrap(), z.unsigned_v6_txid().unwrap());
}

/// A signature from a key outside the input's redeem script is rejected at ingest, rather than
/// being silently dropped at finalization.
#[test]
fn add_v6_signature_rejects_foreign_pubkey() {
    let mut z = build_shield_psbt("v6_foreign_key");
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
    let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
    let msg = Message::from_digest(z.v6_transparent_sighash(0).unwrap());
    let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
    der.push(0x01);
    let err = z.add_v6_transparent_signature(0, pubkey, &der).unwrap_err();
    assert!(
        err.contains("not one of the redeem script's keys"),
        "unexpected error: {err}"
    );
}

/// A signature tagged with a sighash type other than SIGHASH_ALL is rejected at ingest: the
/// sighash it was verified against is always the SIGHASH_ALL digest, so re-emitting it with a
/// different type byte would make a verifier recompute a different (mismatching) digest.
#[test]
fn add_v6_signature_rejects_non_sighash_all() {
    let mut z = build_shield_psbt("v6_wrong_sighash_type");
    let seed = "v6_wrong_sighash_type";
    let secp = Secp256k1::new();
    let sk = signing_secret_keys(seed, 0, 0)[0];
    let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
    let msg = Message::from_digest(z.v6_transparent_sighash(0).unwrap());
    let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
    der.push(0x02); // SIGHASH_NONE, not SIGHASH_ALL
    let err = z.add_v6_transparent_signature(0, pubkey, &der).unwrap_err();
    assert!(err.contains("SIGHASH_ALL"), "unexpected error: {err}");
}

/// A 2-of-3 input signed by all three keys still produces a 2-signature scriptSig;
/// `OP_CHECKMULTISIG` pops exactly two, so a third push would fail the script.
#[test]
fn combine_uses_only_required_signatures() {
    let seed = "v6_three_sigs";
    let mut z = build_shield_psbt(seed);
    let secp = Secp256k1::new();
    let msg = Message::from_digest(z.v6_transparent_sighash(0).unwrap());
    for sk in signing_secret_keys(seed, 0, 0) {
        let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
        let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
        der.push(0x01);
        z.add_v6_transparent_signature(0, pubkey, &der).unwrap();
    }
    assert_eq!(z.psbt.inputs[0].partial_sigs.len(), 3);
    let redeem_script = z.psbt.inputs[0].redeem_script.clone().unwrap();

    let raw = z
        .combine_ironwood_proof(vec![0u8; Proof::expected_proof_size(1)], OsRng)
        .unwrap();
    let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
    // rust-bitcoin decodes OP_0 as a zero-length push, so the expected shape is
    // `<empty> <sig> <sig> <redeemScript>` — four pushes, two of them signatures. A third
    // signature here would make OP_CHECKMULTISIG fail on the leftover stack element.
    let pushes: Vec<Vec<u8>> = tx.transparent.input[0]
        .script_sig
        .instructions()
        .map(|i| i.expect("valid scriptSig"))
        .filter_map(|i| match i {
            crate::bitcoin::script::Instruction::PushBytes(pb) => Some(pb.as_bytes().to_vec()),
            crate::bitcoin::script::Instruction::Op(_) => None,
        })
        .collect();
    assert_eq!(pushes.len(), 4, "OP_0 <sig> <sig> <redeemScript>");
    assert!(pushes[0].is_empty(), "OP_0 dummy");
    assert_eq!(pushes[3], redeem_script.as_bytes());
    // The two signatures are the first two redeem-script keys that signed, in script order.
    for sig in &pushes[1..3] {
        assert_eq!(*sig.last().unwrap(), 0x01, "SIGHASH_ALL");
    }
}

/// The v4 code paths refuse a v6 PSBT instead of emitting a v4-shaped transaction (which would
/// be unbroadcastable) or a ZIP-243 signature (which could never verify).
///
/// `serialize()` is deliberately excluded: it is v6-aware (routes to `serialize_v6()` when
/// `is_ironwood_v6()`), so a v6 PSBT round-trips through the standard `serialize`/`fromBytes`
/// path without the v4 tx-replacement dance — see `serialize()`'s doc comment.
#[test]
fn v4_paths_reject_a_v6_psbt() {
    let z = build_shield_psbt("v6_v4_guard");
    for err in [
        z.extract_unsigned_zcash_transaction()
            .unwrap_err()
            .to_string(),
        z.compute_txid().unwrap_err().to_string(),
        z.clone().extract_tx().unwrap_err().to_string(),
    ] {
        assert!(
            err.contains("v6 (Ironwood) PSBT"),
            "unexpected error: {err}"
        );
    }

    // `serialize()` succeeds for v6 (v6-aware) and round-trips via `deserialize()`.
    let bytes = z.serialize().unwrap();
    let round = ZcashBitGoPsbt::deserialize(&bytes, Network::ZcashTestnet).unwrap();
    assert!(round.is_ironwood_v6());

    // The generic sign path refuses too, so no ZIP-243 signature can reach `partial_sigs`.
    let mut generic = BitGoPsbt::Zcash(z, Network::ZcashTestnet);
    let err = generic
        .sign_all_with_xpriv(&test_wallet_xpriv("v6_v4_guard", 0))
        .unwrap_err();
    assert!(
        err.contains("v6 (Ironwood) PSBT"),
        "unexpected error: {err}"
    );
    assert!(
        generic.psbt().inputs[0].partial_sigs.is_empty(),
        "no ZIP-243 signature reached partial_sigs"
    );
}

/// A client passes a Unified Address as the recipient on a legacy v4 PSBT;
/// `add_transparent_output` resolves its transparent receiver to a scriptPubkey, verifies it
/// against the caller-supplied script, stores the UA, and adds the ordinary transparent
/// output — alongside a wallet change output. `transparent_output_unified_address` returns
/// the exact original UA — receivers and all — after a `serialize`/`deserialize` round trip,
/// not merely a bare address reconstructed from the scriptPubkey.
#[test]
fn add_transparent_output_unified_address_round_trips_on_v4() {
    let fixtures: serde_json::Value = serde_json::from_str(
        &crate::fixed_script_wallet::test_utils::fixtures::load_fixture(
            "zcash/unified_address.json",
        )
        .unwrap(),
    )
    .unwrap();
    // The client only ever hands us the UA itself, not a bare transparent address.
    let ua = fixtures["testnetWallet"]["unified"].as_str().unwrap();

    let parsed = crate::zcash::unified_address::UnifiedAddress::parse(ua, "tzec").unwrap();
    let transparent_script = parsed
        .transparent_script()
        .unwrap()
        .expect("fixture UA has a transparent receiver");

    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("v4_ua_transparent_roundtrip"));
    let mut psbt = BitGoPsbt::new_zcash(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu5.branch_id(),
        None,
        None,
        None,
        None,
    );
    psbt.add_wallet_input(
        Txid::from_byte_array([0x66u8; 32]),
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
    assert!(!z.is_ironwood_v6());
    // Recipient output: the UA's transparent receiver, resolved and verified from the UA the
    // client passed in — not from a separately-supplied plain transparent address.
    let recipient_output_index = z
        .add_transparent_output(
            miniscript::bitcoin::ScriptBuf::from_bytes(transparent_script.clone()),
            100_000_000,
            Some(ua),
        )
        .unwrap();
    assert_eq!(
        z.transparent_output_unified_address(recipient_output_index),
        Some(ua.to_string())
    );

    // Change output: an ordinary wallet output, unrelated to the UA — added via the outer
    // `BitGoPsbt` the way any wallet change output normally is.
    let mut psbt = BitGoPsbt::Zcash(z, Network::ZcashTestnet);
    psbt.add_wallet_output(0, 1, 199_900_000, &wallet_keys)
        .unwrap();

    let round = BitGoPsbt::deserialize(&psbt.serialize().unwrap(), Network::ZcashTestnet).unwrap();
    let BitGoPsbt::Zcash(round, _) = round else {
        panic!("expected Zcash PSBT");
    };

    // The recipient output's scriptPubkey survives the round trip...
    assert_eq!(
        round.psbt.unsigned_tx.output[recipient_output_index]
            .script_pubkey
            .as_bytes(),
        transparent_script.as_slice()
    );
    // ...and so does the exact UA string the client originally passed in.
    assert_eq!(
        round.transparent_output_unified_address(recipient_output_index),
        Some(ua.to_string())
    );

    // `parse_outputs_with_wallet_keys` resolves this output's `address` to the stored UA
    // itself — mirroring how a shielded Ironwood output's `address` prefers its stored UA
    // over a bare address reconstructed from the raw receiver — rather than the plain
    // transparent address a script-only resolution would produce.
    let round_bitgo_psbt = BitGoPsbt::Zcash(round, Network::ZcashTestnet);
    let parsed_outputs = round_bitgo_psbt
        .parse_outputs_with_wallet_keys(&wallet_keys, &[])
        .unwrap();
    assert_eq!(
        parsed_outputs[recipient_output_index].address,
        Some(ua.to_string())
    );
}

/// `add_transparent_output` rejects a `unified_address` whose transparent receiver doesn't
/// match `script` — a caller passing mismatched values is a bug, not something to silently
/// store, mirroring `add_ironwood_output`'s Orchard-side contract.
#[test]
fn add_transparent_output_rejects_mismatched_unified_address() {
    let fixtures: serde_json::Value = serde_json::from_str(
        &crate::fixed_script_wallet::test_utils::fixtures::load_fixture(
            "zcash/unified_address.json",
        )
        .unwrap(),
    )
    .unwrap();
    let ua = fixtures["testnetWallet"]["unified"].as_str().unwrap();

    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("v4_ua_transparent_mismatch"));
    let mut z = ZcashBitGoPsbt::new(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu5.branch_id(),
        None,
        None,
        None,
        None,
    );

    let wrong_script = miniscript::bitcoin::ScriptBuf::from_bytes(vec![
        0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac,
    ]);
    let err = z
        .add_transparent_output(wrong_script, 100_000_000, Some(ua))
        .unwrap_err();
    assert!(err.contains("does not match"), "unexpected error: {err}");
    // Nothing was inserted on the rejected call.
    assert!(z.psbt.unsigned_tx.output.is_empty());
}

/// `add_transparent_output` rejects a `unified_address` that fails to parse as a ZIP-316
/// Unified Address at all (bad Bech32m, wrong HRP, etc.) — a malformed string is a caller
/// bug, not something to fall back to the plain `script`/`value` behavior for.
#[test]
fn add_transparent_output_rejects_an_unparseable_unified_address() {
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("v4_ua_transparent_bad_ua"));
    let mut z = ZcashBitGoPsbt::new(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu5.branch_id(),
        None,
        None,
        None,
        None,
    );

    let script = miniscript::bitcoin::ScriptBuf::from_bytes(vec![
        0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac,
    ]);
    let err = z
        .add_transparent_output(script, 100_000_000, Some("not-a-valid-unified-address"))
        .unwrap_err();
    assert!(
        err.contains("invalid unified_address"),
        "unexpected error: {err}"
    );
    // Nothing was inserted on the rejected call.
    assert!(z.psbt.unsigned_tx.output.is_empty());
}

/// `add_transparent_output` rejects a `unified_address` that has no transparent receiver at
/// all (Orchard-only, say) — there is nothing to verify `script` against, so this must error
/// rather than silently accept `script` unchecked.
#[test]
fn add_transparent_output_rejects_a_unified_address_with_no_transparent_receiver() {
    let recipient = test_recipient();
    let orchard_only_ua =
        crate::zcash::unified_address::encode_orchard_receiver(&recipient, "tzec").unwrap();

    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("v4_ua_transparent_no_transparent"));
    let mut z = ZcashBitGoPsbt::new(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu5.branch_id(),
        None,
        None,
        None,
        None,
    );

    let script = miniscript::bitcoin::ScriptBuf::from_bytes(vec![
        0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac,
    ]);
    let err = z
        .add_transparent_output(script, 100_000_000, Some(&orchard_only_ua))
        .unwrap_err();
    assert!(
        err.contains("no transparent receiver"),
        "unexpected error: {err}"
    );
    // Nothing was inserted on the rejected call.
    assert!(z.psbt.unsigned_tx.output.is_empty());
}

/// `add_transparent_output` rejects `unified_address` outright on a v6 (Ironwood) PSBT — that
/// format's shielded side already has its own UA path (`add_ironwood_output`), so this one is
/// reserved for legacy v4 PSBTs. A bare `script`/`value` call (no `unified_address`) is
/// exactly the legacy Zcash form and must keep working unchanged on either format.
#[test]
fn add_transparent_output_rejects_unified_address_on_v6_psbt() {
    let fixtures: serde_json::Value = serde_json::from_str(
        &crate::fixed_script_wallet::test_utils::fixtures::load_fixture(
            "zcash/unified_address.json",
        )
        .unwrap(),
    )
    .unwrap();
    let ua = fixtures["testnetWallet"]["unified"].as_str().unwrap();
    let parsed = crate::zcash::unified_address::UnifiedAddress::parse(ua, "tzec").unwrap();
    let transparent_script = parsed.transparent_script().unwrap().unwrap();

    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("v6_ua_transparent_rejected"));
    let mut z = ZcashBitGoPsbt::new_v6_at_height(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu6_3.testnet_activation_height(),
        None,
        None,
    )
    .unwrap();
    assert!(z.is_ironwood_v6());

    let err = z
        .add_transparent_output(
            miniscript::bitcoin::ScriptBuf::from_bytes(transparent_script.clone()),
            100_000_000,
            Some(ua),
        )
        .unwrap_err();
    assert!(err.contains("v4"), "unexpected error: {err}");

    // The legacy form (no unified_address) is unaffected.
    let index = z
        .add_transparent_output(
            miniscript::bitcoin::ScriptBuf::from_bytes(transparent_script.clone()),
            100_000_000,
            None,
        )
        .unwrap();
    assert_eq!(
        z.psbt.unsigned_tx.output[index].script_pubkey.as_bytes(),
        transparent_script.as_slice()
    );
    assert_eq!(z.transparent_output_unified_address(index), None);
}

/// `combine_inputs` refuses a v6 PSBT outright.
///
/// It parses the incoming bytes with `deserialize_stripped`, whose whole purpose is to accept a
/// signer response that has dropped everything but the signatures. v6 bytes short-circuit to
/// `deserialize_v6`, which requires the branch id and the PCZT, so a stripped v6 response would
/// otherwise fail with "missing its Ironwood PCZT" — an error describing a corrupt PSBT rather
/// than an unsupported code path.
#[test]
fn combine_inputs_rejects_a_v6_psbt() {
    let z = build_shield_psbt("v6_combine_inputs");
    // A stripped response: the same PSBT with the shielded state removed, as a stripped signer response would carry.
    let mut stripped = z.clone();
    stripped.mark_ironwood_extracted();
    let stripped_bytes = stripped.serialize_v6();

    let mut generic = BitGoPsbt::Zcash(z, Network::ZcashTestnet);
    let err = generic.combine_inputs(&stripped_bytes).unwrap_err();
    assert!(
        err.contains("not supported for v6 (Ironwood)"),
        "unexpected error: {err}"
    );
    assert!(
        err.contains("add_v6_transparent_signature"),
        "the error names the supported path: {err}"
    );
}

/// `deserialize_v6` validates the version group id rather than trusting it — an unchecked value
/// would leave `is_ironwood_v6()` false and route `serialize` back down the v4 path.
#[test]
fn deserialize_v6_rejects_a_non_ironwood_version_group_id() {
    let mut z = build_shield_psbt("v6_bad_vgid");
    crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::set_zec_v6_params(
        &mut z.psbt,
        ZCASH_SAPLING_VERSION_GROUP_ID,
        0,
    );
    let err = ZcashBitGoPsbt::deserialize_v6(&z.serialize_v6(), Network::ZcashTestnet)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("expected the Ironwood id"),
        "unexpected error: {err}"
    );
}

/// The *general* `deserialize` entry point routes v6-shaped bytes through `deserialize_v6`, so
/// it inherits that validation. Without the delegation a PSBT carrying ZecV6Params but a
/// non-Ironwood version group id would deserialize with `is_ironwood_v6() == false` and then
/// serialize back down the v4 path.
#[test]
fn deserialize_rejects_a_v6_psbt_with_a_non_ironwood_version_group_id() {
    let mut z = build_shield_psbt("v6_bad_vgid_general");
    crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::set_zec_v6_params(
        &mut z.psbt,
        ZCASH_SAPLING_VERSION_GROUP_ID,
        0,
    );
    let err = ZcashBitGoPsbt::deserialize(&z.serialize_v6(), Network::ZcashTestnet)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("expected the Ironwood id"),
        "unexpected error: {err}"
    );
}

/// `deserialize_v6` rejects a PSBT missing its consensus branch id, rather than deserializing
/// successfully and failing later (with a less obvious error) in v6_txid/combine.
#[test]
fn deserialize_v6_rejects_a_missing_branch_id() {
    let z = build_shield_psbt("v6_missing_branch_id");
    let mut psbt = z.psbt.clone();
    psbt.proprietary.retain(|k, _| {
        !(k.prefix == crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::BITGO_ZEC_V6
            && k.subtype == 0x00)
    });
    let err = ZcashBitGoPsbt::deserialize_v6(&psbt.serialize(), Network::ZcashTestnet)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("missing its consensus branch id"),
        "unexpected error: {err}"
    );
}

/// `deserialize_v6` rejects a PSBT missing its Ironwood PCZT, rather than deserializing
/// successfully and failing later (with a less obvious error) in v6_txid/combine.
#[test]
fn deserialize_v6_rejects_a_missing_pczt() {
    let z = build_shield_psbt("v6_missing_pczt");
    let mut psbt = z.psbt.clone();
    psbt.proprietary.retain(|k, _| {
        !(k.prefix == crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::BITGO_ZEC_V6
            && k.subtype == 0x01)
    });
    let err = ZcashBitGoPsbt::deserialize_v6(&psbt.serialize(), Network::ZcashTestnet)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("missing its Ironwood PCZT"),
        "unexpected error: {err}"
    );
}

/// `deserialize_v6_pre_shield` accepts exactly the bytes `deserialize_v6` rejects in the test
/// above — a v6 PSBT with its transparent skeleton but no PCZT yet — while still enforcing the
/// v6 params/branch id checks both share.
#[test]
fn deserialize_v6_pre_shield_accepts_a_missing_pczt() {
    let z = build_shield_psbt("v6_pre_shield");
    let mut psbt = z.psbt.clone();
    psbt.proprietary.retain(|k, _| {
        !(k.prefix == crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::BITGO_ZEC_V6
            && k.subtype == 0x01)
    });
    let bytes = psbt.serialize();

    let err = ZcashBitGoPsbt::deserialize_v6(&bytes, Network::ZcashTestnet).unwrap_err();
    assert!(err.to_string().contains("missing its Ironwood PCZT"));

    let round = ZcashBitGoPsbt::deserialize_v6_pre_shield(&bytes, Network::ZcashTestnet)
        .expect("pre-shield deserialize accepts a missing PCZT");
    assert!(round.is_ironwood_v6());
    assert!(round.ironwood_shielded_outputs_info().unwrap().is_empty());

    // Still rejects a v6 PSBT missing its branch id — that check isn't gated by `require_pczt`.
    let mut psbt_no_branch = z.psbt.clone();
    psbt_no_branch.proprietary.retain(|k, _| {
        !(k.prefix == crate::fixed_script_wallet::bitgo_psbt::zcash::propkv::BITGO_ZEC_V6
            && k.subtype == 0x00)
    });
    let err = ZcashBitGoPsbt::deserialize_v6_pre_shield(
        &psbt_no_branch.serialize(),
        Network::ZcashTestnet,
    )
    .unwrap_err();
    assert!(err.to_string().contains("missing its consensus branch id"));
}

/// `new_v6_bare` mirrors the CLI's standalone build flow — a bare v6 PSBT (no wallet xpubs),
/// with a transparent input/output and a shielded output added directly, round-tripping
/// through `serialize`/`deserialize_v6_pre_shield` between steps the way the CLI's
/// serialize-per-command round trip does.
#[test]
fn new_v6_bare_supports_the_cli_build_flow_end_to_end() {
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("v6_bare_cli_flow"));

    let consensus_branch_id = crate::zcash::branch_id_for_height(
        NetworkUpgrade::Nu6_3.testnet_activation_height(),
        false,
    )
    .unwrap();
    let mut z = ZcashBitGoPsbt::new_v6_bare(Network::ZcashTestnet, consensus_branch_id, None, None);
    assert!(z.is_ironwood_v6());
    assert!(z.ironwood_shielded_outputs_info().unwrap().is_empty());

    // Round-trip through serialize/deserialize before adding the transparent input, as the
    // CLI does between each subcommand.
    let bytes = z.serialize().unwrap();
    z = ZcashBitGoPsbt::deserialize_v6_pre_shield(&bytes, Network::ZcashTestnet).unwrap();

    let mut psbt = BitGoPsbt::Zcash(z, Network::ZcashTestnet);
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

    // Round-trip again before adding the shielded output, as the CLI does between
    // `add-output` and `add-shielded-output`.
    let bytes = z.serialize().unwrap();
    z = ZcashBitGoPsbt::deserialize_v6_pre_shield(&bytes, Network::ZcashTestnet).unwrap();

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

    // Final round-trip: now that the PCZT is present, plain `deserialize_v6` accepts it too.
    let bytes = z.serialize().unwrap();
    let round = ZcashBitGoPsbt::deserialize_v6(&bytes, Network::ZcashTestnet).unwrap();
    assert!(!round.ironwood_shielded_outputs_info().unwrap().is_empty());
    assert_eq!(
        round.unsigned_v6_txid().unwrap(),
        z.unsigned_v6_txid().unwrap()
    );
}

/// `verify_v6_signature_with_xpub`/`verify_v6_signature_with_pub`: the happy path (signers verify
/// over the ZIP-244 transparent sighash, non-signers don't) plus the guards the JS layer relies
/// on — a v6 PSBT with no PCZT errors rather than guessing at a digest, and the generic v4
/// verifier refuses a v6 PSBT outright instead of computing a meaningless ZIP-243 digest.
#[test]
fn verify_v6_signature_reports_real_signers_and_rejects_others() {
    let seed = "v6_verify_signature";
    let secp = Secp256k1::new();
    let wallet_keys = root_wallet_keys(seed);

    let mut z = build_shield_psbt(seed);

    // Nothing collected yet: every key reports false (no error).
    assert!(!z
        .verify_v6_signature_with_xpub(&secp, 0, wallet_keys.user_key())
        .unwrap());
    assert!(!z
        .verify_v6_signature_with_xpub(&secp, 0, wallet_keys.bitgo_key())
        .unwrap());

    // Sign user (first round — also finalizes out_ciphertext) then bitgo.
    z.sign_ironwood_v6(&test_wallet_xpriv(seed, 0), &wallet_keys, &secp)
        .unwrap();
    z.sign_ironwood_v6(&test_wallet_xpriv(seed, 2), &wallet_keys, &secp)
        .unwrap();
    assert_eq!(z.psbt.inputs[0].partial_sigs.len(), 2);

    // xpub form: the wallet's root keys derive the input's keys via bip32_derivation.
    assert!(z
        .verify_v6_signature_with_xpub(&secp, 0, wallet_keys.user_key())
        .unwrap());
    assert!(z
        .verify_v6_signature_with_xpub(&secp, 0, wallet_keys.bitgo_key())
        .unwrap());
    // The backup key is not in this input's 2-of-3 redeem script (signer user, cosigner bitgo).
    assert!(!z
        .verify_v6_signature_with_xpub(&secp, 0, wallet_keys.backup_key())
        .unwrap());
    // A stranger's xpub has no matching fingerprint in the input at all.
    let stranger = RootWalletKeys::new(get_test_wallet_keys("a-different-wallet"));
    assert!(!z
        .verify_v6_signature_with_xpub(&secp, 0, stranger.user_key())
        .unwrap());

    // pub form: the derived pubkeys (m/0/0/0/0) verify; unrelated ones don't.
    let user_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &signing_secret_keys(seed, 0, 0)[0],
    );
    let bitgo_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &signing_secret_keys(seed, 0, 0)[2],
    );
    let backup_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &signing_secret_keys(seed, 0, 0)[1],
    );
    for (pk, expected) in [(&user_pk, true), (&bitgo_pk, true), (&backup_pk, false)] {
        assert_eq!(
            z.verify_v6_signature_with_pub(&secp, 0, pk).unwrap(),
            expected,
            "pubkey verification mismatch"
        );
    }

    // Out-of-range index errors before any sighash work — as a typed variant, not a message.
    let err = z
        .verify_v6_signature_with_xpub(&secp, 5, wallet_keys.user_key())
        .unwrap_err();
    assert_eq!(
        err.code(),
        "VerifyV6SignatureError.InputIndexOutOfRange",
        "typed out-of-range error code"
    );
}

/// The generic `verify_signature_with_*` family computes a ZIP-243 (Sapling) digest for Zcash
/// PSBTs. Fed a v6 PSBT it would produce a meaningless digest and report `Ok(false)` for a
/// validly-signed input — a wrong false downstream code reads as "not signed yet" — so it must
/// refuse a v6 PSBT outright (see `V6_NOT_SUPPORTED_BY_V4_PATH`).
#[test]
fn generic_verify_rejects_a_v6_psbt() {
    let seed = "v6_generic_verify";
    let secp = Secp256k1::new();
    let wallet_keys = root_wallet_keys(seed);
    let mut z = build_shield_psbt(seed);
    z.sign_ironwood_v6(&test_wallet_xpriv(seed, 0), &wallet_keys, &secp)
        .unwrap();

    // The generic verifiers live on the `BitGoPsbt` enum, so re-wrap the Zcash variant.
    let generic: BitGoPsbt = BitGoPsbt::Zcash(z, Network::ZcashTestnet);
    let err = generic
        .verify_signature_with_xpub(&secp, 0, wallet_keys.user_key())
        .unwrap_err();
    assert!(err.contains("v6 (Ironwood)"), "unexpected error: {err}");

    // The refusal must hold even when the xpub does NOT match the input — the early exits for
    // "no derivation path" must not silently answer false before the v6 check. Backup key is
    // absent from this input's 2-of-3 script, and a stranger's xpub matches no fingerprint at
    // all; both would have returned Ok(false) before the guard was hoisted.
    let stranger_wallet = RootWalletKeys::new(get_test_wallet_keys("an-unrelated-wallet"));
    for xpub in [wallet_keys.backup_key(), stranger_wallet.user_key()] {
        let err = generic
            .verify_signature_with_xpub(&secp, 0, xpub)
            .unwrap_err();
        assert!(
            err.contains("v6 (Ironwood)"),
            "unexpected error for non-matching xpub: {err}"
        );
    }

    let user_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &signing_secret_keys(seed, 0, 0)[0],
    );
    let err = generic
        .verify_signature_with_pub(&secp, 0, &user_pk)
        .unwrap_err();
    assert!(err.contains("v6 (Ironwood)"), "unexpected error: {err}");
}

/// `verify_v6_signature_with_*` is only defined for v6 (Ironwood) PSBTs; on a v4/Sapling PSBT
/// the ZIP-244 sighash does not exist. Both forms must error — including the xpub form with a
/// *non-matching* xpub, whose derivation would otherwise short-circuit to Ok(false) before the
/// v6 check (the exact early-exit shape the generic `verify_signature_with_xpub` was hardened
/// against).
#[test]
fn verify_v6_signature_rejects_a_v4_psbt() {
    let seed = "v6_verify_v4";
    let secp = Secp256k1::new();
    let wallet_keys = root_wallet_keys(seed);
    let mut psbt = BitGoPsbt::new_zcash_at_height(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu6_3.testnet_activation_height(),
        None,
        None,
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
    let BitGoPsbt::Zcash(z, _) = psbt else {
        panic!("expected Zcash PSBT");
    };
    assert!(!z.is_ironwood_v6(), "sanity: this is a v4/Sapling PSBT");

    let user_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &signing_secret_keys(seed, 0, 0)[0],
    );
    for err in [
        z.verify_v6_signature_with_pub(&secp, 0, &user_pk)
            .unwrap_err(),
        z.verify_v6_signature_with_xpub(&secp, 0, wallet_keys.user_key())
            .unwrap_err(),
        // A non-matching xpub must not exit the derivation `None` arm with Ok(false) first.
        z.verify_v6_signature_with_xpub(&secp, 0, wallet_keys.backup_key())
            .unwrap_err(),
    ] {
        assert_eq!(
            err.code(),
            "VerifyV6SignatureError.NotIronwoodV6",
            "unexpected error: {err}"
        );
    }
}

/// `verify_v6_signature_with_*` cannot compute the ZIP-244 sighash once the PCZT is gone — the
/// shielded action data is sighash-committed — even though the collected partial signatures
/// survive. It errors rather than guessing at a digest, matching the doc contract on the Rust
/// API and the JS `verifySignature` override.
#[test]
fn verify_v6_signature_requires_the_ironwood_pczt() {
    let seed = "v6_verify_no_pczt";
    let secp = Secp256k1::new();
    let wallet_keys = root_wallet_keys(seed);

    // A fully-signed v6 PSBT, then drop its PCZT the way `combine_ironwood_proof` does: the
    // transparent signatures stay in `partial_sigs`, but no v6 sighash can be computed.
    let mut z = build_shield_psbt(seed);
    z.sign_ironwood_v6(&test_wallet_xpriv(seed, 0), &wallet_keys, &secp)
        .unwrap();
    assert_eq!(z.psbt.inputs[0].partial_sigs.len(), 1);
    assert!(z.mark_ironwood_extracted(), "a PCZT was present");

    let user_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &signing_secret_keys(seed, 0, 0)[0],
    );
    for err in [
        z.verify_v6_signature_with_pub(&secp, 0, &user_pk)
            .unwrap_err(),
        z.verify_v6_signature_with_xpub(&secp, 0, wallet_keys.user_key())
            .unwrap_err(),
    ] {
        assert_eq!(
            err.code(),
            "VerifyV6SignatureError.MissingIronwoodPczt",
            "unexpected error: {err}"
        );
    }
}

/// Existing wallets: a transparent-only v6 PSBT (no Ironwood bundle) must keep the
/// bitcoin-weight virtual size and must not see the shielded fee path.
#[test]
fn transparent_only_v6_keeps_the_bitcoin_weight_virtual_size() {
    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("v6_transparent_vsize"));
    let mut psbt = BitGoPsbt::new_zcash_v6_at_height(
        Network::ZcashTestnet,
        &wallet_keys,
        NetworkUpgrade::Nu6_3.testnet_activation_height(),
        None,
        None,
    )
    .unwrap();
    psbt.add_wallet_input(
        Txid::from_byte_array([0x45u8; 32]),
        0,
        200_000_000,
        &wallet_keys,
        ScriptId { chain: 0, index: 0 },
        WalletInputOptions::default(),
    )
    .unwrap();
    psbt.add_wallet_output(0, 1, 199_900_000, &wallet_keys)
        .unwrap();
    let weight_vsize = match &psbt {
        BitGoPsbt::Zcash(z, _) => {
            assert!(z.is_ironwood_v6());
            assert!(z.raw_ironwood_pczt_bytes().is_none());
            z.psbt.unsigned_tx.weight().to_vbytes_ceil()
        }
        _ => panic!("expected Zcash PSBT"),
    };
    let parsed = psbt
        .parse_transaction_with_wallet_keys(
            &wallet_keys,
            &crate::fixed_script_wallet::ReplayProtection::new(vec![]),
            &[],
        )
        .unwrap();
    assert_eq!(parsed.virtual_size as u64, weight_vsize);
}
