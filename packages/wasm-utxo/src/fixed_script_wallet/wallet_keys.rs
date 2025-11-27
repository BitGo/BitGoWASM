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

#[derive(Debug, Clone)]
pub struct RootWalletKeys {
    pub xpubs: XpubTriple,
    pub derivation_prefixes: [DerivationPath; 3],
}

impl RootWalletKeys {
    pub fn new_with_derivation_prefixes(
        xpubs: XpubTriple,
        derivation_prefixes: [DerivationPath; 3],
    ) -> Self {
        Self {
            xpubs,
            derivation_prefixes,
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
        let paths: Vec<DerivationPath> = self
            .derivation_prefixes
            .iter()
            .map(|p| derivation_path(p, chain, index))
            .collect::<Vec<_>>();

        let ctx = Secp256k1::new();

        // zip xpubs and paths, and return a Result<XpubTriple, WasmUtxoError>
        self.xpubs
            .iter()
            .zip(paths.iter())
            .map(|(x, p)| {
                x.derive_pub(&ctx, p)
                    .map_err(|e| WasmUtxoError::new(&format!("Error deriving xpub: {}", e)))
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| WasmUtxoError::new("Expected exactly 3 derived xpubs"))
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
