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

impl RootWalletKeys {
    pub fn new_with_derivation_prefixes(
        xpubs: XpubTriple,
        derivation_prefixes: [DerivationPath; 3],
    ) -> Self {
        let secp = Secp256k1::new();

        // Pre-derive keys to prefix level (e.g., m/0/0)
        let prefix_derived: XpubTriple = xpubs
            .iter()
            .zip(derivation_prefixes.iter())
            .map(|(xpub, prefix)| {
                xpub.derive_pub(&secp, prefix)
                    .expect("valid prefix derivation")
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("3 keys");

        Self {
            xpubs,
            derivation_prefixes,
            prefix_derived,
            derivation_cache: RefCell::new(HashMap::new()),
            secp,
        }
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

    pub fn new(xpubs: XpubTriple) -> Self {
        Self::new_with_derivation_prefixes(
            xpubs,
            [
                DerivationPath::from_str("m/0/0").unwrap(),
                DerivationPath::from_str("m/0/0").unwrap(),
                DerivationPath::from_str("m/0/0").unwrap(),
            ],
        )
    }

    pub fn derive_for_chain_and_index(
        &self,
        chain: u32,
        index: u32,
    ) -> Result<XpubTriple, WasmUtxoError> {
        let cache_key = (chain, index);

        // Check cache first
        {
            let cache = self.derivation_cache.borrow();
            if let Some(cached) = cache.get(&cache_key) {
                return Ok(cached.clone());
            }
        }

        // Derive from prefix to chain+index (2 levels)
        let path = DerivationPath::from(vec![
            ChildNumber::Normal { index: chain },
            ChildNumber::Normal { index },
        ]);
        let derived: XpubTriple = self
            .prefix_derived
            .iter()
            .map(|xpub| {
                xpub.derive_pub(&self.secp, &path)
                    .map_err(|e| WasmUtxoError::new(&format!("Error deriving xpub: {}", e)))
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| WasmUtxoError::new("Expected exactly 3 derived xpubs"))?;

        // Cache the result (with bounded size)
        {
            let mut cache = self.derivation_cache.borrow_mut();
            if cache.len() >= DERIVATION_CACHE_MAX_SIZE {
                cache.clear();
            }
            cache.insert(cache_key, derived.clone());
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
        assert!(keys.derive_for_chain_and_index(0, 0).is_ok());
    }
}
