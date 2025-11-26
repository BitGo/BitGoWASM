use crate::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use crate::bitcoin::PrivateKey;
use crate::error::WasmUtxoError;
use wasm_bindgen::prelude::*;

// Internal enum to hold either public-only or private+public keys
#[derive(Debug, Clone)]
enum ECPairKey {
    PublicOnly(PublicKey),
    Private {
        secret_key: SecretKey,
        public_key: PublicKey,
    },
}

impl ECPairKey {
    fn public_key(&self) -> PublicKey {
        match self {
            ECPairKey::PublicOnly(pk) => *pk,
            ECPairKey::Private { public_key, .. } => *public_key,
        }
    }

    fn secret_key(&self) -> Option<SecretKey> {
        match self {
            ECPairKey::PublicOnly(_) => None,
            ECPairKey::Private { secret_key, .. } => Some(*secret_key),
        }
    }
}

/// WASM wrapper for elliptic curve key pairs (always uses compressed keys)
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmECPair {
    key: ECPairKey,
}

impl WasmECPair {
    /// Get the public key as a secp256k1::PublicKey (for internal Rust use)
    pub(crate) fn get_public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    /// Get the private key as a secp256k1::SecretKey (for internal Rust use)
    pub(crate) fn get_private_key(&self) -> Result<SecretKey, WasmUtxoError> {
        self.key
            .secret_key()
            .ok_or_else(|| WasmUtxoError::new("Cannot get private key from public-only ECPair"))
    }
}

#[wasm_bindgen]
impl WasmECPair {
    /// Create an ECPair from a private key (always uses compressed keys)
    #[wasm_bindgen]
    pub fn from_private_key(private_key: &[u8]) -> Result<WasmECPair, WasmUtxoError> {
        if private_key.len() != 32 {
            return Err(WasmUtxoError::new("Private key must be 32 bytes"));
        }

        let secret_key = SecretKey::from_slice(private_key)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid private key: {}", e)))?;

        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        Ok(WasmECPair {
            key: ECPairKey::Private {
                secret_key,
                public_key,
            },
        })
    }

    /// Create an ECPair from a public key (always uses compressed keys)
    #[wasm_bindgen]
    pub fn from_public_key(public_key: &[u8]) -> Result<WasmECPair, WasmUtxoError> {
        let public_key = PublicKey::from_slice(public_key)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid public key: {}", e)))?;

        Ok(WasmECPair {
            key: ECPairKey::PublicOnly(public_key),
        })
    }

    fn from_wif_with_network_check(
        wif_string: &str,
        expected_network: Option<crate::bitcoin::NetworkKind>,
    ) -> Result<WasmECPair, WasmUtxoError> {
        let private_key = PrivateKey::from_wif(wif_string)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid WIF: {}", e)))?;

        if let Some(expected) = expected_network {
            if private_key.network != expected {
                let network_name = match expected {
                    crate::bitcoin::NetworkKind::Main => "mainnet",
                    crate::bitcoin::NetworkKind::Test => "testnet",
                };
                return Err(WasmUtxoError::new(&format!(
                    "Expected {} WIF",
                    network_name
                )));
            }
        }

        let secp = Secp256k1::new();
        let secret_key = private_key.inner;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        Ok(WasmECPair {
            key: ECPairKey::Private {
                secret_key,
                public_key,
            },
        })
    }

    /// Create an ECPair from a WIF string (auto-detects network)
    #[wasm_bindgen]
    pub fn from_wif(wif_string: &str) -> Result<WasmECPair, WasmUtxoError> {
        Self::from_wif_with_network_check(wif_string, None)
    }

    /// Create an ECPair from a mainnet WIF string
    #[wasm_bindgen]
    pub fn from_wif_mainnet(wif_string: &str) -> Result<WasmECPair, WasmUtxoError> {
        use crate::bitcoin::NetworkKind;
        Self::from_wif_with_network_check(wif_string, Some(NetworkKind::Main))
    }

    /// Create an ECPair from a testnet WIF string
    #[wasm_bindgen]
    pub fn from_wif_testnet(wif_string: &str) -> Result<WasmECPair, WasmUtxoError> {
        use crate::bitcoin::NetworkKind;
        Self::from_wif_with_network_check(wif_string, Some(NetworkKind::Test))
    }

    /// Get the private key as a Uint8Array (if available)
    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Option<js_sys::Uint8Array> {
        self.key
            .secret_key()
            .map(|sk| js_sys::Uint8Array::from(&sk.secret_bytes()[..]))
    }

    /// Get the compressed public key as a Uint8Array (always 33 bytes)
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> js_sys::Uint8Array {
        let pk = self.key.public_key();
        let bytes = pk.serialize();
        js_sys::Uint8Array::from(&bytes[..])
    }

    /// Convert to WIF string (mainnet)
    #[wasm_bindgen]
    pub fn to_wif(&self) -> Result<String, WasmUtxoError> {
        self.to_wif_mainnet()
    }

    /// Convert to mainnet WIF string
    #[wasm_bindgen]
    pub fn to_wif_mainnet(&self) -> Result<String, WasmUtxoError> {
        use crate::bitcoin::NetworkKind;
        self.to_wif_with_network(NetworkKind::Main)
    }

    /// Convert to testnet WIF string
    #[wasm_bindgen]
    pub fn to_wif_testnet(&self) -> Result<String, WasmUtxoError> {
        use crate::bitcoin::NetworkKind;
        self.to_wif_with_network(NetworkKind::Test)
    }

    fn to_wif_with_network(
        &self,
        network: crate::bitcoin::NetworkKind,
    ) -> Result<String, WasmUtxoError> {
        let secret_key = self
            .key
            .secret_key()
            .ok_or_else(|| WasmUtxoError::new("Cannot get WIF from public key"))?;

        let private_key = PrivateKey::new(secret_key, network);
        Ok(private_key.to_wif())
    }
}
