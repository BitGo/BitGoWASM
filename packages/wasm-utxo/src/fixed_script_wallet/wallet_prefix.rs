//! Per-wallet derivation prefix for BitGo fixed-script wallets.
//!
//! Besides the legacy layout `<root>/0/0/<chain>/<index>`, a wallet may derive its addresses
//! below a BIP44-style prefix `<root>/44/<coin_type>/<h1>/<h2>/<chain>/<index>`. All levels are
//! non-hardened, so everything can be derived from xpubs alone.
//!
//! `h1` and `h2` are never stored: they are a pure function of the three wallet root keys,
//!
//! ```text
//! d  = sha256("BitGo/utxo/wallet-prefix/v1" || K_user || K_backup || K_bitgo)
//! K  = compressed public key (33 bytes) || chain code (32 bytes)   (of the neutered root key)
//! h1 = u32be(d[0..4]) & 0x7fffffff
//! h2 = u32be(d[4..8]) & 0x7fffffff
//! ```
//!
//! The result depends on the key order `[user, backup, bitgo]`.

use crate::bitcoin::hashes::{sha256, Hash};

use super::wallet_keys::XpubTriple;

/// Domain-separation tag hashed in front of the three root keys.
const WALLET_PREFIX_TAG: &[u8] = b"BitGo/utxo/wallet-prefix/v1";

/// Largest value of a non-hardened BIP32 child index (`2^31 - 1`).
pub const MAX_SOFT_INDEX: u32 = 0x7fff_ffff;

/// Errors while computing a wallet prefix.
#[derive(Debug, Clone, PartialEq, Eq, strum::IntoStaticStr)]
pub enum WalletPrefixError {
    /// The coin type is not a valid non-hardened index (`> 2^31 - 1`).
    CoinTypeOutOfRange { coin_type: u32 },
}

impl std::fmt::Display for WalletPrefixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CoinTypeOutOfRange { coin_type } => write!(
                f,
                "coin type {coin_type} is out of range: must be at most {MAX_SOFT_INDEX}"
            ),
        }
    }
}

impl std::error::Error for WalletPrefixError {}
crate::impl_wasm_error_code!(WalletPrefixError);

/// Compute the `(h1, h2)` account indices of a wallet from its three root keys
/// `[user, backup, bitgo]`.
///
/// Only the public key and chain code of each key enter the hash, so the result is the same
/// whether the keys were an xprv or the matching xpub, and on any network.
pub fn derive_wallet_account(xpubs: &XpubTriple) -> (u32, u32) {
    let mut preimage = Vec::with_capacity(WALLET_PREFIX_TAG.len() + 3 * 65);
    preimage.extend_from_slice(WALLET_PREFIX_TAG);
    for xpub in xpubs {
        preimage.extend_from_slice(&xpub.public_key.serialize());
        preimage.extend_from_slice(&xpub.chain_code.to_bytes());
    }
    let digest = sha256::Hash::hash(&preimage).to_byte_array();

    let word = |offset: usize| {
        let bytes: [u8; 4] = [
            digest[offset],
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ];
        u32::from_be_bytes(bytes) & MAX_SOFT_INDEX
    };
    (word(0), word(4))
}

/// Compute the relative derivation prefix `44/<coin_type>/<h1>/<h2>` of a wallet (no leading
/// `/` or `m/`).
///
/// `coin_type` is the BIP44 coin type of the coin family (supplied by the caller: wasm-utxo has
/// no coin registry). It must be a valid non-hardened index.
pub fn derive_wallet_prefix(
    xpubs: &XpubTriple,
    coin_type: u32,
) -> Result<String, WalletPrefixError> {
    if coin_type > MAX_SOFT_INDEX {
        return Err(WalletPrefixError::CoinTypeOutOfRange { coin_type });
    }
    let (h1, h2) = derive_wallet_account(xpubs);
    Ok(format!("44/{coin_type}/{h1}/{h2}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::bip32::Xpub;
    use crate::error::WasmErrorCode;
    use crate::fixed_script_wallet::wallet_keys::tests::get_xpriv_from_seed;
    use crate::fixed_script_wallet::RootWalletKeys;

    fn xpub_from_seed(seed: &str) -> Xpub {
        let secp = crate::bitcoin::secp256k1::Secp256k1::new();
        Xpub::from_priv(&secp, &get_xpriv_from_seed(seed))
    }

    fn triple(bitgo_seed: &str) -> XpubTriple {
        [
            xpub_from_seed("wcn3907-u"),
            xpub_from_seed("wcn3907-b"),
            xpub_from_seed(bitgo_seed),
        ]
    }

    /// Shared with the mocha test `test/fixedScript/walletPrefix.ts`.
    const VECTORS: [(&str, u32, u32); 3] = [
        ("wcn3907-g1", 1528449227, 506574854),
        ("wcn3907-g2", 1401193521, 285195054),
        ("wcn3907-g", 1639221447, 1133889609),
    ];

    #[test]
    fn derive_wallet_account_matches_the_ticket_vectors() {
        for (bitgo_seed, h1, h2) in VECTORS {
            assert_eq!(
                derive_wallet_account(&triple(bitgo_seed)),
                (h1, h2),
                "bitgo seed {bitgo_seed}"
            );
        }
    }

    #[test]
    fn derive_wallet_prefix_formats_the_relative_prefix() {
        assert_eq!(
            derive_wallet_prefix(&triple("wcn3907-g"), 0).unwrap(),
            "44/0/1639221447/1133889609"
        );
        assert_eq!(
            derive_wallet_prefix(&triple("wcn3907-g1"), 145).unwrap(),
            "44/145/1528449227/506574854"
        );
        assert_eq!(
            derive_wallet_prefix(&triple("wcn3907-g2"), MAX_SOFT_INDEX).unwrap(),
            "44/2147483647/1401193521/285195054"
        );
    }

    #[test]
    fn derive_wallet_prefix_rejects_a_hardened_coin_type() {
        let err = derive_wallet_prefix(&triple("wcn3907-g"), MAX_SOFT_INDEX + 1).unwrap_err();
        assert_eq!(
            err,
            WalletPrefixError::CoinTypeOutOfRange {
                coin_type: MAX_SOFT_INDEX + 1
            }
        );
        assert_eq!(
            crate::error::WasmUtxoError::from(err).code(),
            "WalletPrefixError.CoinTypeOutOfRange"
        );
        assert!(derive_wallet_prefix(&triple("wcn3907-g"), u32::MAX).is_err());
    }

    #[test]
    fn derive_wallet_account_depends_on_key_order() {
        let [user, backup, bitgo] = triple("wcn3907-g");
        assert_ne!(
            derive_wallet_account(&[user, backup, bitgo]),
            derive_wallet_account(&[backup, user, bitgo])
        );
        assert_ne!(
            derive_wallet_account(&[user, backup, bitgo]),
            derive_wallet_account(&[user, bitgo, backup])
        );
    }

    #[test]
    fn derive_wallet_account_ignores_derivation_prefixes_of_the_wallet_keys() {
        // The account depends on the three root keys only, not on how a RootWalletKeys derives.
        let xpubs = triple("wcn3907-g");
        let keys = RootWalletKeys::new(xpubs);
        assert_eq!(
            derive_wallet_account(&keys.xpubs),
            derive_wallet_account(&xpubs)
        );
    }
}
