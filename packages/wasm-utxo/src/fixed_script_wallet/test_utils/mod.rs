//! Test utilities for fixed_script_wallet module

pub mod fixtures;

use super::wallet_keys::XpubTriple;
use super::wallet_scripts::{Chain, WalletScripts};
use crate::bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use crate::bitcoin::psbt::{Input as PsbtInput, Output as PsbtOutput, Psbt};
use crate::bitcoin::{Transaction, TxIn, TxOut};
use crate::{fixed_script_wallet::RootWalletKeys, Network};
use std::collections::BTreeMap;
use std::str::FromStr;

/// Get test wallet xpubs from a seed string
/// This matches the TypeScript getWalletKeysForSeed function from keys.ts
pub fn get_test_wallet_keys(seed: &str) -> XpubTriple {
    use crate::bitcoin::hashes::{sha256, Hash};
    use crate::bitcoin::Network;

    fn get_xpriv_from_seed(seed: &str) -> Xpriv {
        let seed_hash = sha256::Hash::hash(seed.as_bytes()).to_byte_array();
        Xpriv::new_master(Network::Testnet, &seed_hash).expect("could not create xpriv from seed")
    }

    // Note: TypeScript uses `.` separator (e.g., "seed.0", "seed.1", "seed.2")
    // to match utxo-lib's getKeyTriple function in keys.ts
    let a = get_xpriv_from_seed(&format!("{}.0", seed));
    let b = get_xpriv_from_seed(&format!("{}.1", seed));
    let c = get_xpriv_from_seed(&format!("{}.2", seed));

    let secp = crate::bitcoin::secp256k1::Secp256k1::new();
    [a, b, c].map(|x| Xpub::from_priv(&secp, &x))
}

/// Create a PSBT output for an external wallet (different keys)
pub fn create_external_output(seed: &str) -> PsbtOutput {
    let xpubs = get_test_wallet_keys(seed);
    let _scripts = WalletScripts::from_wallet_keys(
        &RootWalletKeys::new(xpubs),
        Chain::P2wshExternal,
        0,
        &Network::Bitcoin.output_script_support(),
    )
    .unwrap();
    PsbtOutput {
        bip32_derivation: BTreeMap::new(),
        // witness_script: scripts.witness_script,
        // redeem_script: scripts.redeem_script,
        ..Default::default()
    }
}

/// Composable function to create a test PSBT from inputs and outputs
pub fn create_test_psbt(
    xpubs: &XpubTriple,
    inputs: Vec<PsbtInput>,
    tx_inputs: Vec<TxIn>,
    outputs: Vec<PsbtOutput>,
    tx_outputs: Vec<TxOut>,
) -> Psbt {
    let tx = Transaction {
        version: crate::bitcoin::transaction::Version::TWO,
        lock_time: crate::bitcoin::locktime::absolute::LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };

    Psbt {
        unsigned_tx: tx,
        version: 0,
        xpub: {
            let mut map = BTreeMap::new();
            for (i, xpub) in xpubs.iter().enumerate() {
                let path = DerivationPath::from_str(&format!("m/999'/0'/{}'", i))
                    .expect("invalid derivation path");
                map.insert(*xpub, (Fingerprint::default(), path));
            }
            map
        },
        proprietary: BTreeMap::new(),
        unknown: BTreeMap::new(),
        inputs,
        outputs,
    }
}
