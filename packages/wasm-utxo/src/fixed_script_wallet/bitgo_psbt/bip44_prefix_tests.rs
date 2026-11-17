//! Classification of PSBT inputs and outputs recorded under the wallet's BIP44-style prefix
//! `44/<coin_type>/<h1>/<h2>` (see `RootWalletKeys::with_bip44_coin_type`).

use std::str::FromStr;

use miniscript::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use miniscript::bitcoin::hashes::Hash;
use miniscript::bitcoin::secp256k1::Secp256k1;
use miniscript::bitcoin::Txid;

use super::psbt_wallet_input::{SignPath, SignerKey};
use super::{BitGoPsbt, ParsedTransaction, ScriptId, WalletInputOptions};
use crate::fixed_script_wallet::test_utils::get_test_wallet_keys;
use crate::fixed_script_wallet::wallet_keys::tests::get_test_wallet_xprvs;
use crate::fixed_script_wallet::wallet_prefix::derive_wallet_prefix_path;
use crate::fixed_script_wallet::{ReplayProtection, RootWalletKeys, XpubTriple};
use crate::Network;

const BTC_COIN_TYPE: u32 = 0;
const SEED: &str = "bip44_prefix_tests";

fn xpubs() -> XpubTriple {
    get_test_wallet_keys(SEED)
}

fn prefix(s: &str) -> DerivationPath {
    DerivationPath::from_str(s).unwrap()
}

/// Keys that build under `prefix` on all three keys.
fn keys_with_prefix(xpubs: XpubTriple, prefix: DerivationPath) -> RootWalletKeys {
    RootWalletKeys::new_with_derivation_prefixes(xpubs, [prefix.clone(), prefix.clone(), prefix])
        .unwrap()
}

/// Keys that build under the wallet's canonical BIP44-style prefix.
fn bip44_build_keys(xpubs: XpubTriple, coin_type: u32) -> RootWalletKeys {
    keys_with_prefix(xpubs, derive_wallet_prefix_path(&xpubs, coin_type).unwrap())
}

/// Default (`0/0`) keys that also recognise the BIP44-style subtree: what a verifier holds.
fn verifier_keys(xpubs: XpubTriple) -> RootWalletKeys {
    RootWalletKeys::new(xpubs)
        .with_bip44_coin_type(BTC_COIN_TYPE)
        .unwrap()
}

fn sign_path_for(chain: u32) -> Option<SignPath> {
    (30..=41).contains(&chain).then_some(SignPath {
        signer: SignerKey::User,
        cosigner: SignerKey::Bitgo,
    })
}

fn add_input(psbt: &mut BitGoPsbt, keys: &RootWalletKeys, vout: u32, chain: u32) {
    psbt.add_wallet_input(
        Txid::all_zeros(),
        vout,
        100_000,
        keys,
        ScriptId { chain, index: vout },
        WalletInputOptions {
            sign_path: sign_path_for(chain),
            ..Default::default()
        },
    )
    .unwrap();
}

fn parse(psbt: &BitGoPsbt, keys: &RootWalletKeys) -> Result<ParsedTransaction, String> {
    psbt.parse_transaction_with_wallet_keys(keys, &ReplayProtection::new(vec![]), &[])
        .map_err(|e| e.to_string())
}

/// Chains of every script type BTC supports (external chain of each).
const BTC_CHAINS: [u32; 5] = [0, 10, 20, 30, 40];

#[test]
fn bip44_inputs_and_outputs_parse_with_default_keys_that_know_the_coin_type() {
    let xpubs = xpubs();
    let build = bip44_build_keys(xpubs, BTC_COIN_TYPE);
    let mut psbt = BitGoPsbt::new(Network::Bitcoin, &build, Some(2), Some(0));
    for (vout, chain) in BTC_CHAINS.iter().enumerate() {
        add_input(&mut psbt, &build, vout as u32, *chain);
        psbt.add_wallet_output(chain + 1, vout as u32, 1_000, &build)
            .unwrap();
    }

    let parsed = parse(&psbt, &verifier_keys(xpubs)).unwrap();
    let bip44 = derive_wallet_prefix_path(&xpubs, BTC_COIN_TYPE).unwrap();
    for (i, input) in parsed.inputs.iter().enumerate() {
        let path = input.derivation_path.as_ref().unwrap();
        assert_eq!(
            *path,
            bip44
                .child(miniscript::bitcoin::bip32::ChildNumber::Normal {
                    index: BTC_CHAINS[i]
                })
                .child(miniscript::bitcoin::bip32::ChildNumber::Normal { index: i as u32 })
        );
    }
    assert!(parsed.outputs.iter().all(|o| !o.is_external()));
    assert_eq!(parsed.spend_amount, 0);
}

#[test]
fn bip44_inputs_fail_without_the_coin_type() {
    // Without the coin type the keys only accept their own prefix, as before this change.
    let xpubs = xpubs();
    let build = bip44_build_keys(xpubs, BTC_COIN_TYPE);
    let mut psbt = BitGoPsbt::new(Network::Bitcoin, &build, Some(2), Some(0));
    add_input(&mut psbt, &build, 0, 20);
    let err = parse(&psbt, &RootWalletKeys::new(xpubs)).unwrap_err();
    assert!(err.contains("wallet validation failed"), "{err}");
}

#[test]
fn mixed_legacy_and_bip44_inputs_and_outputs_parse_with_one_key_set() {
    let xpubs = xpubs();
    let legacy = RootWalletKeys::new(xpubs);
    let bip44 = bip44_build_keys(xpubs, BTC_COIN_TYPE);
    // Built with two key sets on one PSBT: inputs and outputs carry their own prefix.
    let mut psbt = BitGoPsbt::new(Network::Bitcoin, &legacy, Some(2), Some(0));
    for (vout, chain) in BTC_CHAINS.iter().enumerate() {
        let keys = if vout % 2 == 0 { &legacy } else { &bip44 };
        add_input(&mut psbt, keys, vout as u32, *chain);
        psbt.add_wallet_output(chain + 1, vout as u32, 1_000, keys)
            .unwrap();
    }

    let parsed = parse(&psbt, &verifier_keys(xpubs)).unwrap();
    for (i, input) in parsed.inputs.iter().enumerate() {
        let path = input.derivation_path.as_ref().unwrap().to_string();
        let expected_prefix = if i % 2 == 0 { "0/0/" } else { "44/0/" };
        assert!(path.starts_with(expected_prefix), "input {i}: {path}");
    }
    assert!(parsed.outputs.iter().all(|o| !o.is_external()));
}

#[test]
fn per_key_prefixes_still_parse_taproot_and_musig2_inputs() {
    // Recovery builds keys as `[userKeyPath, 0/0, 0/0]`; taproot inputs record two key origins.
    let xpubs = xpubs();
    let keys = RootWalletKeys::new_with_derivation_prefixes(
        xpubs,
        [prefix("m/1/2"), prefix("m/0/0"), prefix("m/0/0")],
    )
    .unwrap();
    let mut psbt = BitGoPsbt::new(Network::Bitcoin, &keys, Some(2), Some(0));
    for (vout, chain) in [30u32, 40, 20].iter().enumerate() {
        add_input(&mut psbt, &keys, vout as u32, *chain);
    }
    parse(&psbt, &keys).unwrap();
    parse(
        &psbt,
        &keys.clone().with_bip44_coin_type(BTC_COIN_TYPE).unwrap(),
    )
    .unwrap();
}

#[test]
fn outputs_with_wallet_fingerprints_under_any_other_prefix_fail_the_parse() {
    // An output whose key origins all carry this wallet's fingerprints but whose script is not
    // derived under an accepted prefix is never wallet change: the parse fails closed.
    let xpubs = xpubs();
    let legacy = RootWalletKeys::new(xpubs);
    let (h1, h2) = crate::fixed_script_wallet::wallet_prefix::derive_wallet_account(&xpubs);
    let other_prefixes = [
        prefix("m/7/7"),
        // Right account, wrong coin type.
        prefix(&format!("m/44/2/{h1}/{h2}")),
        // Right coin type, wrong account.
        prefix(&format!("m/44/0/{h1}/{}", h2 ^ 1)),
        // Boundary accounts that are not this wallet's.
        prefix("m/44/0/0/0"),
        prefix("m/44/0/2147483647/2147483647"),
    ];

    for other in other_prefixes {
        let rogue = keys_with_prefix(xpubs, other.clone());
        for chain in [1u32, 11, 21, 31, 41] {
            let mut psbt = BitGoPsbt::new(Network::Bitcoin, &legacy, Some(2), Some(0));
            add_input(&mut psbt, &legacy, 0, 20);
            psbt.add_wallet_output(chain, 5, 90_000, &rogue).unwrap();

            let err = parse(&psbt, &verifier_keys(xpubs)).unwrap_err();
            assert!(
                err.contains("Output 0") && err.contains("no script type matches"),
                "prefix {other} chain {chain}: {err}"
            );
        }
    }
}

#[test]
fn inputs_under_any_other_prefix_are_rejected() {
    let xpubs = xpubs();
    let rogue = keys_with_prefix(xpubs, prefix("m/44/0/0/0"));
    let mut psbt = BitGoPsbt::new(Network::Bitcoin, &rogue, Some(2), Some(0));
    add_input(&mut psbt, &rogue, 0, 30);
    let err = parse(&psbt, &verifier_keys(xpubs)).unwrap_err();
    assert!(err.contains("wallet validation failed"), "{err}");
}

#[test]
fn sibling_wallet_bip44_output_is_external() {
    // Shares user and backup keys, different bitgo key: a different (h1, h2) and bitgo leaf.
    let xpubs = xpubs();
    let sibling: XpubTriple = [xpubs[0], xpubs[1], get_test_wallet_keys("sibling")[2]];
    let legacy = RootWalletKeys::new(xpubs);
    let mut psbt = BitGoPsbt::new(Network::Bitcoin, &legacy, Some(2), Some(0));
    add_input(&mut psbt, &legacy, 0, 20);
    let sibling_build = bip44_build_keys(sibling, BTC_COIN_TYPE);
    for chain in [1u32, 21, 31, 41] {
        psbt.add_wallet_output(chain, 0, 1_000, &sibling_build)
            .unwrap();
    }

    let parsed = parse(&psbt, &verifier_keys(xpubs)).unwrap();
    assert!(parsed.outputs.iter().all(|o| o.is_external()));
}

#[test]
fn get_wallet_keys_from_psbt_resolves_bip44_and_mixed_psbts() {
    let xpubs = xpubs();
    let legacy = RootWalletKeys::new(xpubs);
    let bip44 = bip44_build_keys(xpubs, BTC_COIN_TYPE);
    let mut psbt = BitGoPsbt::new(Network::Bitcoin, &legacy, Some(2), Some(0));
    add_input(&mut psbt, &bip44, 0, 20);
    add_input(&mut psbt, &legacy, 1, 40);

    let shuffled = [xpubs[2], xpubs[0], xpubs[1]];
    assert!(super::to_wallet_keys(&psbt, shuffled, None).is_err());
    let resolved = super::to_wallet_keys(&psbt, shuffled, Some(BTC_COIN_TYPE)).unwrap();
    assert_eq!(resolved.xpubs, xpubs);
    assert_eq!(
        resolved.bip44_prefix(),
        Some(&derive_wallet_prefix_path(&xpubs, BTC_COIN_TYPE).unwrap())
    );
}

#[test]
fn bip44_inputs_sign_and_verify_ecdsa_and_musig2() {
    let secp = Secp256k1::new();
    let xprvs = get_test_wallet_xprvs(SEED);
    let xpubs = xprvs.map(|x| Xpub::from_priv(&secp, &x));
    let build = bip44_build_keys(xpubs, BTC_COIN_TYPE);
    let mut psbt = BitGoPsbt::new(Network::Bitcoin, &build, Some(2), Some(0));
    for (vout, chain) in BTC_CHAINS.iter().enumerate() {
        add_input(&mut psbt, &build, vout as u32, *chain);
    }

    // MuSig2 (chain 40, input 4): nonce rounds for user and bitgo, then both sign.
    let user: &Xpriv = &xprvs[0];
    let bitgo: &Xpriv = &xprvs[2];
    let musig2_input = 4;
    let (user_first_round, user_nonce) = psbt
        .generate_nonce_first_round(musig2_input, user, [1u8; 32])
        .unwrap();
    let (bitgo_first_round, bitgo_nonce) = psbt
        .generate_nonce_first_round(musig2_input, bitgo, [2u8; 32])
        .unwrap();
    let _ = (user_nonce, bitgo_nonce);
    psbt.sign_with_first_round(musig2_input, user_first_round, user)
        .unwrap();
    psbt.sign_with_first_round(musig2_input, bitgo_first_round, bitgo)
        .unwrap();

    // ECDSA and taproot script path for the rest.
    psbt.sign_all_with_xpriv(user).unwrap();
    psbt.sign_all_with_xpriv(bitgo).unwrap();

    for input_index in 0..BTC_CHAINS.len() {
        assert!(
            psbt.verify_signature_with_xpub(&secp, input_index, &xpubs[0])
                .unwrap(),
            "user signature on input {input_index}"
        );
        assert!(
            psbt.verify_signature_with_xpub(&secp, input_index, &xpubs[2])
                .unwrap(),
            "bitgo signature on input {input_index}"
        );
    }
    parse(&psbt, &verifier_keys(xpubs)).unwrap();
}

#[test]
fn zcash_bip44_inputs_and_outputs_parse() {
    use crate::zcash::NetworkUpgrade;

    let xpubs = xpubs();
    // zec coin type 133
    let build = bip44_build_keys(xpubs, 133);
    let mut psbt = BitGoPsbt::new_zcash_at_height(
        Network::ZcashTestnet,
        &build,
        NetworkUpgrade::Nu5.testnet_activation_height(),
        None,
        None,
        None,
        None,
    )
    .unwrap();
    add_input(&mut psbt, &build, 0, 0);
    psbt.add_wallet_output(1, 0, 1_000, &build).unwrap();

    let verifier = RootWalletKeys::new(xpubs)
        .with_bip44_coin_type(133)
        .unwrap();
    let parsed = parse(&psbt, &verifier).unwrap();
    assert!(parsed.outputs.iter().all(|o| !o.is_external()));
    // Wrong coin type: not recognised.
    let err = parse(
        &psbt,
        &RootWalletKeys::new(xpubs)
            .with_bip44_coin_type(BTC_COIN_TYPE)
            .unwrap(),
    )
    .unwrap_err();
    assert!(err.contains("wallet validation failed"), "{err}");
}

#[test]
fn with_bip44_coin_type_rejects_a_hardened_coin_type() {
    let err = RootWalletKeys::new(xpubs())
        .with_bip44_coin_type(0x8000_0000)
        .unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&crate::error::WasmUtxoError::from(err)),
        "WalletPrefixError.CoinTypeOutOfRange"
    );
}

#[test]
fn hardened_derivation_prefix_is_an_error() {
    let err = RootWalletKeys::new_with_derivation_prefixes(
        xpubs(),
        [prefix("m/44'/0"), prefix("m/0/0"), prefix("m/0/0")],
    )
    .unwrap_err();
    assert_eq!(
        crate::error::WasmErrorCode::code(&crate::error::WasmUtxoError::from(err)),
        "WalletKeysError.HardenedDerivationPrefix"
    );
}
