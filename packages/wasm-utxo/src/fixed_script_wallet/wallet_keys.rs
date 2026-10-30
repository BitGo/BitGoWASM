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

pub struct RootWalletKeys {
    pub xpubs: XpubTriple,
    pub derivation_prefixes: [DerivationPath; 3],
    /// Keys derived to prefix level (computed once in constructor)
    prefix_derived: XpubTriple,
    /// Keys derived to (chain, index) level (cached on-demand, bounded size)
    derivation_cache: RefCell<HashMap<(u32, u32), XpubTriple>>,
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
            secp,
        })
    }

    /// Shared secp256k1 context.
    pub(crate) fn secp(&self) -> &Secp256k1<crate::bitcoin::secp256k1::All> {
        &self.secp
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
        let cache_key: Option<(u32, u32)> = {
            let children: Vec<_> = path.into_iter().cloned().collect();
            let n = children.len();
            match (children.get(n.wrapping_sub(2)), children.last()) {
                (
                    Some(ChildNumber::Normal { index: c }),
                    Some(ChildNumber::Normal { index: i }),
                ) => Some((*c, *i)),
                _ => None,
            }
        };
        if let Some(key) = cache_key {
            if let Some(cached) = self.derivation_cache.borrow().get(&key) {
                return Ok(*cached);
            }
        }
        let derived: XpubTriple = self
            .prefix_derived
            .iter()
            .map(|xpub| {
                xpub.derive_pub(&self.secp, path)
                    .map_err(|e| WasmUtxoError::new(&format!("Error deriving xpub: {}", e)))
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| WasmUtxoError::new("Expected exactly 3 derived xpubs"))?;
        if let Some(key) = cache_key {
            let mut cache = self.derivation_cache.borrow_mut();
            if cache.len() >= DERIVATION_CACHE_MAX_SIZE {
                cache.clear();
            }
            cache.insert(key, derived);
        }
        Ok(derived)
    }
}

impl Clone for RootWalletKeys {
    fn clone(&self) -> Self {
        Self {
            xpubs: self.xpubs,
            derivation_prefixes: self.derivation_prefixes.clone(),
            prefix_derived: self.prefix_derived,
            derivation_cache: RefCell::new(self.derivation_cache.borrow().clone()),
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
