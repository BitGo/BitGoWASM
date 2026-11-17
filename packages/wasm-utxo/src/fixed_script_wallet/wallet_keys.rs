use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryInto;
use std::str::FromStr;

use crate::bitcoin::bip32::{ChildNumber, DerivationPath};
use crate::bitcoin::{bip32::Xpub, secp256k1::Secp256k1, CompressedPublicKey};
use crate::error::WasmUtxoError;

pub type XpubTriple = [Xpub; 3];

pub type PubTriple = [CompressedPublicKey; 3];

pub fn to_pub_triple(xpubs: &XpubTriple) -> PubTriple {
    xpubs
        .iter()
        .map(|x| x.to_pub())
        .collect::<Vec<_>>()
        .try_into()
        .expect("could not convert vec to array")
}

pub fn derivation_path(prefix: &DerivationPath, chain: u32, index: u32) -> DerivationPath {
    prefix
        .child(ChildNumber::Normal { index: chain })
        .child(ChildNumber::Normal { index })
}

/// Maximum number of (chain, index) pairs to cache
const DERIVATION_CACHE_MAX_SIZE: usize = 128;

type DerivationCache = RefCell<HashMap<(u32, u32), XpubTriple>>;

/// The canonical BIP44-style subtree `44/<coin_type>/<h1>/<h2>` of a wallet, shared by all three
/// keys (see [`crate::fixed_script_wallet::wallet_prefix`]).
#[derive(Debug)]
struct Bip44Subtree {
    /// `44/<coin_type>/<h1>/<h2>`
    prefix: DerivationPath,
    /// The three root keys derived to `prefix`
    prefix_derived: XpubTriple,
    derivation_cache: DerivationCache,
}

impl Clone for Bip44Subtree {
    fn clone(&self) -> Self {
        Self {
            prefix: self.prefix.clone(),
            prefix_derived: self.prefix_derived,
            derivation_cache: RefCell::new(self.derivation_cache.borrow().clone()),
        }
    }
}

pub struct RootWalletKeys {
    pub xpubs: XpubTriple,
    pub derivation_prefixes: [DerivationPath; 3],
    /// Keys derived to prefix level (computed once in constructor)
    prefix_derived: XpubTriple,
    /// Keys derived to (chain, index) level (cached on-demand, bounded size)
    derivation_cache: DerivationCache,
    /// The wallet's BIP44-style subtree, recognised in addition to `derivation_prefixes` when
    /// classifying PSBT inputs and outputs. Set by [`RootWalletKeys::with_bip44_coin_type`].
    bip44: Option<Bip44Subtree>,
    /// Shared secp256k1 context (avoids repeated allocation)
    secp: Secp256k1<crate::bitcoin::secp256k1::All>,
}

/// Names of the three wallet keys in `[user, backup, bitgo]` order, for error messages.
const KEY_NAMES: [&str; 3] = ["user", "backup", "bitgo"];

/// Errors while building a [`RootWalletKeys`].
#[derive(Debug, Clone, PartialEq, Eq, strum::IntoStaticStr)]
pub enum WalletKeysError {
    /// A derivation prefix contains a hardened component. Wallet keys are public (xpub)
    /// keys, so only non-hardened (soft) derivation is possible.
    HardenedDerivationPrefix { key: &'static str, prefix: String },
    /// Deriving a key along its prefix failed for a reason other than hardening.
    PrefixDerivation {
        key: &'static str,
        prefix: String,
        reason: String,
    },
}

impl std::fmt::Display for WalletKeysError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HardenedDerivationPrefix { key, prefix } => write!(
                f,
                "derivation prefix of the {key} key contains a hardened component \
                 (only non-hardened derivation is possible from an xpub): {prefix}"
            ),
            Self::PrefixDerivation {
                key,
                prefix,
                reason,
            } => write!(
                f,
                "could not derive the {key} key along prefix {prefix}: {reason}"
            ),
        }
    }
}

impl std::error::Error for WalletKeysError {}
crate::impl_wasm_error_code!(WalletKeysError);

impl RootWalletKeys {
    /// Build wallet keys with one derivation prefix per key.
    ///
    /// Returns an error if a prefix has a hardened component (an xpub cannot derive it).
    pub fn new_with_derivation_prefixes(
        xpubs: XpubTriple,
        derivation_prefixes: [DerivationPath; 3],
    ) -> Result<Self, WalletKeysError> {
        let secp = Secp256k1::new();

        // Pre-derive keys to prefix level (e.g., m/0/0)
        let prefix_derived: XpubTriple = {
            let mut derived = Vec::with_capacity(3);
            for (i, (xpub, prefix)) in xpubs.iter().zip(derivation_prefixes.iter()).enumerate() {
                if prefix.into_iter().any(|c| c.is_hardened()) {
                    return Err(WalletKeysError::HardenedDerivationPrefix {
                        key: KEY_NAMES[i],
                        prefix: prefix.to_string(),
                    });
                }
                derived.push(xpub.derive_pub(&secp, prefix).map_err(|e| {
                    WalletKeysError::PrefixDerivation {
                        key: KEY_NAMES[i],
                        prefix: prefix.to_string(),
                        reason: e.to_string(),
                    }
                })?);
            }
            derived.try_into().expect("3 keys")
        };

        Ok(Self {
            xpubs,
            derivation_prefixes,
            prefix_derived,
            derivation_cache: RefCell::new(HashMap::new()),
            bip44: None,
            secp,
        })
    }

    /// Also recognise the wallet's BIP44-style subtree `44/<coin_type>/<h1>/<h2>` when
    /// classifying PSBT inputs and outputs, with `(h1, h2)` computed from the three root keys.
    ///
    /// The derivation prefixes used to build addresses, inputs and outputs are unchanged.
    /// `coin_type` is the BIP44 coin type of the coin family, supplied by the caller (wasm-utxo has
    /// no coin registry); it must be a non-hardened index.
    pub fn with_bip44_coin_type(
        mut self,
        coin_type: u32,
    ) -> Result<Self, crate::fixed_script_wallet::wallet_prefix::WalletPrefixError> {
        let prefix = crate::fixed_script_wallet::wallet_prefix::derive_wallet_prefix_path(
            &self.xpubs,
            coin_type,
        )?;
        let prefix_derived: XpubTriple = self.xpubs.map(|xpub| {
            xpub.derive_pub(&self.secp, &prefix)
                .expect("non-hardened prefix is derivable from an xpub")
        });
        self.bip44 = Some(Bip44Subtree {
            prefix,
            prefix_derived,
            derivation_cache: RefCell::new(HashMap::new()),
        });
        Ok(self)
    }

    /// The BIP44-style prefix `44/<coin_type>/<h1>/<h2>` recognised by these keys, if any.
    pub fn bip44_prefix(&self) -> Option<&DerivationPath> {
        self.bip44.as_ref().map(|b| &b.prefix)
    }

    pub fn user_key(&self) -> &Xpub {
        &self.xpubs[0]
    }

    pub fn backup_key(&self) -> &Xpub {
        &self.xpubs[1]
    }

    pub fn bitgo_key(&self) -> &Xpub {
        &self.xpubs[2]
    }

    /// Wallet keys with the legacy `m/0/0` prefix on all three keys.
    pub fn new(xpubs: XpubTriple) -> Self {
        Self::new_with_derivation_prefixes(
            xpubs,
            [
                DerivationPath::from_str("m/0/0").unwrap(),
                DerivationPath::from_str("m/0/0").unwrap(),
                DerivationPath::from_str("m/0/0").unwrap(),
            ],
        )
        .expect("m/0/0 is a valid non-hardened prefix")
    }

    /// Derive keys from `self.prefix_derived` along `path`.
    /// Caches using the last two Normal path components as `(chain, index)`.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<XpubTriple, WasmUtxoError> {
        derive_cached(
            &self.secp,
            &self.prefix_derived,
            &self.derivation_cache,
            path,
        )
    }

    /// The three keys at `<recorded prefix>/<chain>/<index>` if the recorded prefix is one these
    /// keys accept: the BIP44-style prefix (when set via [`Self::with_bip44_coin_type`]), else the
    /// keys' own `derivation_prefixes`.
    ///
    /// `recorded_path` is a full path as recorded in a PSBT key origin. Any prefix other than the
    /// BIP44-style one falls back to the keys' own prefixes, so a PSBT path under an unknown
    /// prefix derives keys that do not match its script.
    pub(crate) fn derive_for_recorded_path(
        &self,
        recorded_path: &DerivationPath,
        chain: u32,
        index: u32,
    ) -> Result<XpubTriple, WasmUtxoError> {
        let tail = DerivationPath::from(vec![
            ChildNumber::Normal { index: chain },
            ChildNumber::Normal { index },
        ]);
        if let Some(bip44) = &self.bip44 {
            let recorded: &[ChildNumber] = recorded_path.as_ref();
            let prefix: &[ChildNumber] = bip44.prefix.as_ref();
            if recorded.len() == prefix.len() + 2 && recorded.starts_with(prefix) {
                return derive_cached(
                    &self.secp,
                    &bip44.prefix_derived,
                    &bip44.derivation_cache,
                    &tail,
                );
            }
        }
        self.derive_path(&tail)
    }
}

fn derive_cached(
    secp: &Secp256k1<crate::bitcoin::secp256k1::All>,
    prefix_derived: &XpubTriple,
    derivation_cache: &DerivationCache,
    path: &DerivationPath,
) -> Result<XpubTriple, WasmUtxoError> {
    let cache_key: Option<(u32, u32)> = {
        let children: Vec<_> = path.into_iter().cloned().collect();
        let n = children.len();
        match (children.get(n.wrapping_sub(2)), children.last()) {
            (Some(ChildNumber::Normal { index: c }), Some(ChildNumber::Normal { index: i })) => {
                Some((*c, *i))
            }
            _ => None,
        }
    };
    if let Some(key) = cache_key {
        if let Some(cached) = derivation_cache.borrow().get(&key) {
            return Ok(*cached);
        }
    }
    let derived: XpubTriple = prefix_derived
        .iter()
        .map(|xpub| {
            xpub.derive_pub(secp, path)
                .map_err(|e| WasmUtxoError::new(&format!("Error deriving xpub: {}", e)))
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| WasmUtxoError::new("Expected exactly 3 derived xpubs"))?;
    if let Some(key) = cache_key {
        let mut cache = derivation_cache.borrow_mut();
        if cache.len() >= DERIVATION_CACHE_MAX_SIZE {
            cache.clear();
        }
        cache.insert(key, derived);
    }
    Ok(derived)
}

impl Clone for RootWalletKeys {
    fn clone(&self) -> Self {
        Self {
            xpubs: self.xpubs,
            derivation_prefixes: self.derivation_prefixes.clone(),
            prefix_derived: self.prefix_derived,
            derivation_cache: RefCell::new(self.derivation_cache.borrow().clone()),
            bip44: self.bip44.clone(),
            secp: Secp256k1::new(),
        }
    }
}

impl std::fmt::Debug for RootWalletKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootWalletKeys")
            .field("xpubs", &self.xpubs)
            .field("derivation_prefixes", &self.derivation_prefixes)
            .field("prefix_derived", &self.prefix_derived)
            .field(
                "derivation_cache_size",
                &self.derivation_cache.borrow().len(),
            )
            .field("bip44_prefix", &self.bip44_prefix())
            .finish()
    }
}

#[cfg(test)]
pub mod tests {
    use crate::bitcoin::bip32::{Xpriv, Xpub};
    use crate::bitcoin::hashes::{sha256, Hash};
    use crate::fixed_script_wallet::RootWalletKeys;

    pub type XprivTriple = [Xpriv; 3];

    pub fn get_xpriv_from_seed(seed: &str) -> Xpriv {
        use crate::bitcoin::bip32::Xpriv;
        use crate::bitcoin::Network;

        // hash seed into 32 bytes
        let seed_hash = sha256::Hash::hash(seed.as_bytes()).to_byte_array();

        Xpriv::new_master(Network::Testnet, &seed_hash).expect("could not create xpriv from seed")
    }

    pub fn get_test_wallet_xprvs(seed: &str) -> XprivTriple {
        let a = get_xpriv_from_seed(&format!("{}/0", seed));
        let b = get_xpriv_from_seed(&format!("{}/1", seed));
        let c = get_xpriv_from_seed(&format!("{}/2", seed));
        [a, b, c]
    }

    pub fn get_test_wallet_keys(seed: &str) -> RootWalletKeys {
        let xprvs = get_test_wallet_xprvs(seed);
        let secp = crate::bitcoin::key::Secp256k1::new();
        RootWalletKeys::new(xprvs.map(|x| Xpub::from_priv(&secp, &x)))
    }

    #[test]
    fn it_works() {
        let keys = get_test_wallet_keys("test");
        assert!(keys
            .derive_path(&crate::fixed_script_wallet::wallet_scripts::chain_index_path(0, 0))
            .is_ok());
    }
}
