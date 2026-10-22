//! Helpers shared by the native-only [`super::v6`] and [`super::ironwood`] tests.

use super::super::*;

use crate::bitcoin::bip32::{DerivationPath, Xpriv};
use crate::bitcoin::hashes::{sha256, Hash};
use crate::bitcoin::secp256k1::{Secp256k1, SecretKey};
use crate::bitcoin::{Network as BtcNetwork, Txid};

use crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::WalletInputOptions;
use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt;
use crate::fixed_script_wallet::script_id::ScriptId;
use crate::fixed_script_wallet::test_utils::get_test_wallet_keys;
use crate::fixed_script_wallet::wallet_scripts::chain_index_path;
use crate::fixed_script_wallet::RootWalletKeys;
use crate::networks::Network;
use crate::zcash::NetworkUpgrade;

use orchard::keys::{FullViewingKey, Scope, SpendingKey};

use orchard::tree::Anchor;

use rand::rngs::OsRng;
use std::str::FromStr;

/// A deterministic Ironwood receiver derived from a fixed spending key.
pub(crate) fn test_recipient() -> [u8; 43] {
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
    FullViewingKey::from(&sk)
        .address_at(0u32, Scope::External)
        .to_raw_address_bytes()
}

/// The three wallet signing keys derived at `chain/index`, matching `get_test_wallet_keys`
/// (same `seed.N` scheme), so their pubkeys equal the multisig redeem script's.
///
/// `RootWalletKeys::new` derives the same keys from the seed (the path is
/// `m/0/0/<chain>/<index>`), so the two must stay in sync.
pub(crate) fn signing_secret_keys(seed: &str, chain: u32, index: u32) -> [SecretKey; 3] {
    let secp = Secp256k1::new();
    let prefix = DerivationPath::from_str("m/0/0").unwrap();
    let path = prefix.extend(chain_index_path(chain, index));
    let mut keys = Vec::with_capacity(3);
    for i in 0..3u8 {
        let hash = sha256::Hash::hash(format!("{seed}.{i}").as_bytes()).to_byte_array();
        let master = Xpriv::new_master(BtcNetwork::Testnet, &hash).unwrap();
        keys.push(master.derive_priv(&secp, &path).unwrap().private_key);
    }
    keys.try_into().unwrap()
}

/// The root `Xpriv` behind key `i` of `get_test_wallet_keys(seed)` (same `seed.N` scheme).
pub(crate) fn test_wallet_xpriv(seed: &str, i: u8) -> Xpriv {
    let hash = sha256::Hash::hash(format!("{seed}.{i}").as_bytes()).to_byte_array();
    Xpriv::new_master(BtcNetwork::Testnet, &hash).unwrap()
}

/// A minimal v6 PSBT with one 2-of-3 P2SH input, a change output, and a shielded output.
pub(crate) fn build_shield_psbt(seed: &str) -> ZcashBitGoPsbt {
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
        Txid::from_byte_array([0x33u8; 32]),
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
    z
}

/// The same `RootWalletKeys` `build_shield_psbt(seed)` builds internally — so its
/// `bitgo_key()`'s raw pubkey matches what's actually in this PSBT's `bip32_derivation` entries.
pub(crate) fn root_wallet_keys(seed: &str) -> RootWalletKeys {
    RootWalletKeys::new(get_test_wallet_keys(seed))
}
