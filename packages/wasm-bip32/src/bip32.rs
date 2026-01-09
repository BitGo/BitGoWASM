use crate::error::WasmBip32Error;
use bip32::{ChildNumber, DerivationPath, Prefix, XPrv, XPub};
use k256::ecdsa::VerifyingKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

/// Internal enum to hold either public or private extended key
#[derive(Debug, Clone)]
enum BIP32Key {
    Public(XPub),
    Private(XPrv),
}

impl BIP32Key {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            BIP32Key::Public(xpub) => *xpub.public_key(),
            BIP32Key::Private(xprv) => *xprv.private_key().verifying_key(),
        }
    }

    fn is_neutered(&self) -> bool {
        matches!(self, BIP32Key::Public(_))
    }

    fn depth(&self) -> u8 {
        match self {
            BIP32Key::Public(xpub) => xpub.attrs().depth,
            BIP32Key::Private(xprv) => xprv.attrs().depth,
        }
    }

    fn chain_code(&self) -> &[u8; 32] {
        match self {
            BIP32Key::Public(xpub) => &xpub.attrs().chain_code,
            BIP32Key::Private(xprv) => &xprv.attrs().chain_code,
        }
    }

    fn child_number(&self) -> ChildNumber {
        match self {
            BIP32Key::Public(xpub) => xpub.attrs().child_number,
            BIP32Key::Private(xprv) => xprv.attrs().child_number,
        }
    }

    fn parent_fingerprint(&self) -> [u8; 4] {
        match self {
            BIP32Key::Public(xpub) => xpub.attrs().parent_fingerprint,
            BIP32Key::Private(xprv) => xprv.attrs().parent_fingerprint,
        }
    }

    fn derive(&self, index: u32) -> Result<BIP32Key, WasmBip32Error> {
        let child_number = ChildNumber::new(index, false)
            .map_err(|_| WasmBip32Error::new("Invalid child number"))?;

        match self {
            BIP32Key::Public(xpub) => {
                let derived = xpub.derive_child(child_number)?;
                Ok(BIP32Key::Public(derived))
            }
            BIP32Key::Private(xprv) => {
                let derived = xprv.derive_child(child_number)?;
                Ok(BIP32Key::Private(derived))
            }
        }
    }

    fn derive_hardened(&self, index: u32) -> Result<BIP32Key, WasmBip32Error> {
        let child_number = ChildNumber::new(index, true)
            .map_err(|_| WasmBip32Error::new("Invalid child number"))?;

        match self {
            BIP32Key::Public(_) => Err(WasmBip32Error::new(
                "Cannot derive hardened key from public key",
            )),
            BIP32Key::Private(xprv) => {
                let derived = xprv.derive_child(child_number)?;
                Ok(BIP32Key::Private(derived))
            }
        }
    }

    fn derive_path(&self, path: &str) -> Result<BIP32Key, WasmBip32Error> {
        // Remove leading 'm/' or 'M/' if present
        let path_str = path
            .strip_prefix("m/")
            .or_else(|| path.strip_prefix("M/"))
            .unwrap_or(path);

        // Handle empty path
        if path_str.is_empty() {
            return Ok(self.clone());
        }

        let derivation_path = DerivationPath::from_str(&format!("m/{}", path_str))
            .map_err(|e| WasmBip32Error::new(&format!("Invalid derivation path: {}", e)))?;

        let mut current = self.clone();
        for child_number in derivation_path {
            current = match current {
                BIP32Key::Public(xpub) => {
                    if child_number.is_hardened() {
                        return Err(WasmBip32Error::new(
                            "Cannot derive hardened key from public key",
                        ));
                    }
                    BIP32Key::Public(xpub.derive_child(child_number)?)
                }
                BIP32Key::Private(xprv) => BIP32Key::Private(xprv.derive_child(child_number)?),
            };
        }
        Ok(current)
    }

    fn to_base58(&self, testnet: bool) -> String {
        match self {
            BIP32Key::Public(xpub) => {
                let prefix = if testnet { Prefix::TPUB } else { Prefix::XPUB };
                xpub.to_string(prefix).to_string()
            }
            BIP32Key::Private(xprv) => {
                let prefix = if testnet { Prefix::TPRV } else { Prefix::XPRV };
                xprv.to_string(prefix).to_string()
            }
        }
    }

    fn to_wif(&self, testnet: bool) -> Result<String, WasmBip32Error> {
        match self {
            BIP32Key::Public(_) => Err(WasmBip32Error::new("Cannot get WIF from public key")),
            BIP32Key::Private(xprv) => {
                let secret_bytes = xprv.private_key().to_bytes();
                let version = if testnet { 0xefu8 } else { 0x80u8 };

                // WIF format: version (1) + secret (32) + compression flag (1)
                let mut data = Vec::with_capacity(34);
                data.push(version);
                data.extend_from_slice(&secret_bytes);
                data.push(0x01); // Always compressed

                Ok(bs58::encode(&data).with_check().into_string())
            }
        }
    }
}

/// WASM wrapper for BIP32 extended keys
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmBIP32 {
    key: BIP32Key,
    testnet: bool,
}

#[wasm_bindgen]
impl WasmBIP32 {
    /// Create a BIP32 key from a base58 string (xpub/xprv/tpub/tprv)
    #[wasm_bindgen]
    pub fn from_base58(base58_str: &str) -> Result<WasmBIP32, WasmBip32Error> {
        let testnet = base58_str.starts_with('t');

        // Try parsing as private key first
        if let Ok(xprv) = XPrv::from_str(base58_str) {
            return Ok(WasmBIP32 {
                key: BIP32Key::Private(xprv),
                testnet,
            });
        }

        // Try parsing as public key
        if let Ok(xpub) = XPub::from_str(base58_str) {
            return Ok(WasmBIP32 {
                key: BIP32Key::Public(xpub),
                testnet,
            });
        }

        Err(WasmBip32Error::new("Invalid base58 encoded key"))
    }

    /// Create a BIP32 master key from a seed
    #[wasm_bindgen]
    pub fn from_seed(seed: &[u8], network: Option<String>) -> Result<WasmBIP32, WasmBip32Error> {
        let testnet = matches!(
            network.as_deref(),
            Some("testnet") | Some("BitcoinTestnet3") | Some("BitcoinTestnet4")
        );

        let xprv = XPrv::new(seed)?;

        Ok(WasmBIP32 {
            key: BIP32Key::Private(xprv),
            testnet,
        })
    }

    /// Get the chain code as a Uint8Array
    #[wasm_bindgen(getter)]
    pub fn chain_code(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.key.chain_code()[..])
    }

    /// Get the depth
    #[wasm_bindgen(getter)]
    pub fn depth(&self) -> u8 {
        self.key.depth()
    }

    /// Get the child index
    #[wasm_bindgen(getter)]
    pub fn index(&self) -> u32 {
        self.key.child_number().into()
    }

    /// Get the parent fingerprint
    #[wasm_bindgen(getter)]
    pub fn parent_fingerprint(&self) -> u32 {
        u32::from_be_bytes(self.key.parent_fingerprint())
    }

    /// Get the private key as a Uint8Array (if available)
    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Option<js_sys::Uint8Array> {
        match &self.key {
            BIP32Key::Public(_) => None,
            BIP32Key::Private(xprv) => {
                Some(js_sys::Uint8Array::from(&xprv.private_key().to_bytes()[..]))
            }
        }
    }

    /// Get the public key as a Uint8Array (33 bytes, compressed)
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> js_sys::Uint8Array {
        let verifying_key = self.key.verifying_key();
        let bytes = verifying_key.to_sec1_bytes();
        js_sys::Uint8Array::from(&bytes[..])
    }

    /// Get the identifier (hash160 of public key)
    #[wasm_bindgen(getter)]
    pub fn identifier(&self) -> js_sys::Uint8Array {
        let pubkey_bytes = self.key.verifying_key().to_sec1_bytes();
        let sha256_hash = Sha256::digest(&pubkey_bytes);
        let hash160 = Ripemd160::digest(sha256_hash);
        js_sys::Uint8Array::from(&hash160[..])
    }

    /// Get the fingerprint (first 4 bytes of identifier)
    #[wasm_bindgen(getter)]
    pub fn fingerprint(&self) -> js_sys::Uint8Array {
        let pubkey_bytes = self.key.verifying_key().to_sec1_bytes();
        let sha256_hash = Sha256::digest(&pubkey_bytes);
        let hash160 = Ripemd160::digest(sha256_hash);
        js_sys::Uint8Array::from(&hash160[..4])
    }

    /// Check if this is a neutered (public) key
    #[wasm_bindgen]
    pub fn is_neutered(&self) -> bool {
        self.key.is_neutered()
    }

    /// Get the neutered (public) version of this key
    #[wasm_bindgen]
    pub fn neutered(&self) -> WasmBIP32 {
        match &self.key {
            BIP32Key::Public(_) => self.clone(),
            BIP32Key::Private(xprv) => WasmBIP32 {
                key: BIP32Key::Public(xprv.public_key()),
                testnet: self.testnet,
            },
        }
    }

    /// Serialize to base58 string
    #[wasm_bindgen]
    pub fn to_base58(&self) -> String {
        self.key.to_base58(self.testnet)
    }

    /// Get the WIF encoding of the private key
    #[wasm_bindgen]
    pub fn to_wif(&self) -> Result<String, WasmBip32Error> {
        self.key.to_wif(self.testnet)
    }

    /// Derive a normal (non-hardened) child key
    #[wasm_bindgen]
    pub fn derive(&self, index: u32) -> Result<WasmBIP32, WasmBip32Error> {
        Ok(WasmBIP32 {
            key: self.key.derive(index)?,
            testnet: self.testnet,
        })
    }

    /// Derive a hardened child key (only works for private keys)
    #[wasm_bindgen]
    pub fn derive_hardened(&self, index: u32) -> Result<WasmBIP32, WasmBip32Error> {
        Ok(WasmBIP32 {
            key: self.key.derive_hardened(index)?,
            testnet: self.testnet,
        })
    }

    /// Derive a key using a derivation path (e.g., "0/1/2" or "m/0/1/2")
    #[wasm_bindgen]
    pub fn derive_path(&self, path: &str) -> Result<WasmBIP32, WasmBip32Error> {
        Ok(WasmBIP32 {
            key: self.key.derive_path(path)?,
            testnet: self.testnet,
        })
    }
}
