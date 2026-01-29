use std::str::FromStr;

use crate::bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use crate::bitcoin::secp256k1::Secp256k1;
use crate::bitcoin::{PrivateKey, PublicKey};
use crate::error::WasmUtxoError;
use crate::wasm::try_from_js_value::{get_buffer_field, get_field, get_nested_field};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

// Internal enum to hold either Xpub or Xpriv
#[derive(Debug, Clone)]
enum BIP32Key {
    Public(Xpub),
    Private(Xpriv),
}

impl BIP32Key {
    fn to_xpub(&self) -> Xpub {
        match self {
            BIP32Key::Public(xpub) => *xpub,
            BIP32Key::Private(xpriv) => Xpub::from_priv(&Secp256k1::new(), xpriv),
        }
    }

    fn is_neutered(&self) -> bool {
        matches!(self, BIP32Key::Public(_))
    }

    fn derive(&self, index: u32) -> Result<BIP32Key, WasmUtxoError> {
        let secp = Secp256k1::new();
        let child_number = ChildNumber::Normal { index };

        match self {
            BIP32Key::Public(xpub) => {
                let derived = xpub
                    .derive_pub(&secp, &[child_number])
                    .map_err(|e| WasmUtxoError::new(&format!("Failed to derive: {}", e)))?;
                Ok(BIP32Key::Public(derived))
            }
            BIP32Key::Private(xpriv) => {
                let derived = xpriv
                    .derive_priv(&secp, &[child_number])
                    .map_err(|e| WasmUtxoError::new(&format!("Failed to derive: {}", e)))?;
                Ok(BIP32Key::Private(derived))
            }
        }
    }

    fn derive_hardened(&self, index: u32) -> Result<BIP32Key, WasmUtxoError> {
        let secp = Secp256k1::new();
        let child_number = ChildNumber::Hardened { index };

        match self {
            BIP32Key::Public(_) => Err(WasmUtxoError::new(
                "Cannot derive hardened key from public key",
            )),
            BIP32Key::Private(xpriv) => {
                let derived = xpriv.derive_priv(&secp, &[child_number]).map_err(|e| {
                    WasmUtxoError::new(&format!("Failed to derive hardened: {}", e))
                })?;
                Ok(BIP32Key::Private(derived))
            }
        }
    }

    fn derive_path(&self, path: &str) -> Result<BIP32Key, WasmUtxoError> {
        let secp = Secp256k1::new();

        // Remove leading 'm/' or 'M/' if present
        let path_str = path
            .strip_prefix("m/")
            .or_else(|| path.strip_prefix("M/"))
            .unwrap_or(path);

        let derivation_path = DerivationPath::from_str(&format!("m/{}", path_str))
            .map_err(|e| WasmUtxoError::new(&format!("Invalid derivation path: {}", e)))?;

        match self {
            BIP32Key::Public(xpub) => {
                let derived = xpub
                    .derive_pub(&secp, &derivation_path)
                    .map_err(|e| WasmUtxoError::new(&format!("Failed to derive path: {}", e)))?;
                Ok(BIP32Key::Public(derived))
            }
            BIP32Key::Private(xpriv) => {
                let derived = xpriv
                    .derive_priv(&secp, &derivation_path)
                    .map_err(|e| WasmUtxoError::new(&format!("Failed to derive path: {}", e)))?;
                Ok(BIP32Key::Private(derived))
            }
        }
    }

    fn to_base58(&self) -> String {
        match self {
            BIP32Key::Public(xpub) => xpub.to_string(),
            BIP32Key::Private(xpriv) => xpriv.to_string(),
        }
    }

    fn to_wif(&self) -> Result<String, WasmUtxoError> {
        match self {
            BIP32Key::Public(_) => Err(WasmUtxoError::new("Cannot get WIF from public key")),
            BIP32Key::Private(xpriv) => {
                let privkey = PrivateKey::new(xpriv.private_key, xpriv.network);
                Ok(privkey.to_wif())
            }
        }
    }
}

/// WASM wrapper for BIP32 extended keys (Xpub/Xpriv)
/// Implements the BIP32Interface TypeScript interface
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmBIP32(BIP32Key);

#[wasm_bindgen]
impl WasmBIP32 {
    /// Create a BIP32 key from a base58 string (xpub/xprv/tpub/tprv)
    #[wasm_bindgen]
    pub fn from_base58(base58_str: &str) -> Result<WasmBIP32, WasmUtxoError> {
        // Try to parse as Xpriv first, then Xpub
        if let Ok(xpriv) = Xpriv::from_str(base58_str) {
            Ok(WasmBIP32(BIP32Key::Private(xpriv)))
        } else if let Ok(xpub) = Xpub::from_str(base58_str) {
            Ok(WasmBIP32(BIP32Key::Public(xpub)))
        } else {
            Err(WasmUtxoError::new("Invalid base58 encoded key"))
        }
    }

    /// Create a BIP32 key from an xpub string (base58-encoded)
    #[wasm_bindgen]
    pub fn from_xpub(xpub_str: &str) -> Result<WasmBIP32, WasmUtxoError> {
        let xpub = Xpub::from_str(xpub_str)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to parse xpub: {}", e)))?;
        Ok(WasmBIP32(BIP32Key::Public(xpub)))
    }

    /// Create a BIP32 key from an xprv string (base58-encoded)
    #[wasm_bindgen]
    pub fn from_xprv(xprv_str: &str) -> Result<WasmBIP32, WasmUtxoError> {
        let xprv = Xpriv::from_str(xprv_str)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to parse xprv: {}", e)))?;
        Ok(WasmBIP32(BIP32Key::Private(xprv)))
    }

    /// Create a BIP32 key from a BIP32Interface JavaScript object properties
    /// Expects an object with: network.bip32.public, depth, parentFingerprint,
    /// index, chainCode, and publicKey properties
    #[wasm_bindgen]
    pub fn from_bip32_interface(bip32_key: &JsValue) -> Result<WasmBIP32, WasmUtxoError> {
        Self::from_bip32_properties(bip32_key)
    }

    /// Create a BIP32 key from BIP32 properties
    /// Extracts properties from a JavaScript object and constructs an xpub
    #[wasm_bindgen]
    pub fn from_bip32_properties(bip32_key: &JsValue) -> Result<WasmBIP32, WasmUtxoError> {
        // Extract properties using helper functions
        let version: u32 = get_nested_field(bip32_key, "network.bip32.public")?;
        let depth: u8 = get_field(bip32_key, "depth")?;
        let parent_fingerprint: u32 = get_field(bip32_key, "parentFingerprint")?;
        let index: u32 = get_field(bip32_key, "index")?;
        let chain_code_bytes: [u8; 32] = get_buffer_field(bip32_key, "chainCode")?;
        let public_key_bytes: [u8; 33] = get_buffer_field(bip32_key, "publicKey")?;

        // Build BIP32 serialization (78 bytes total)
        let mut data = Vec::with_capacity(78);
        data.extend_from_slice(&version.to_be_bytes()); // 4 bytes: version
        data.push(depth); // 1 byte: depth
        data.extend_from_slice(&parent_fingerprint.to_be_bytes()); // 4 bytes: parent fingerprint
        data.extend_from_slice(&index.to_be_bytes()); // 4 bytes: index
        data.extend_from_slice(&chain_code_bytes); // 32 bytes: chain code
        data.extend_from_slice(&public_key_bytes); // 33 bytes: public key

        // Use the Xpub::decode method which properly handles network detection and constructs the Xpub
        let xpub = Xpub::decode(&data)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to decode xpub: {}", e)))?;
        Ok(WasmBIP32(BIP32Key::Public(xpub)))
    }

    /// Create a BIP32 master key from a seed
    #[wasm_bindgen]
    pub fn from_seed(seed: &[u8], network: Option<String>) -> Result<WasmBIP32, WasmUtxoError> {
        use crate::bitcoin::Network as BitcoinNetwork;

        let network = if let Some(net_str) = network {
            crate::Network::from_str(&net_str)
                .map_err(|_| WasmUtxoError::new(&format!("Invalid network: {}", net_str)))?
        } else {
            crate::Network::Bitcoin
        };

        // Map our Network to bitcoin::Network
        let bitcoin_network = match network {
            crate::Network::Bitcoin => BitcoinNetwork::Bitcoin,
            crate::Network::BitcoinTestnet3 => BitcoinNetwork::Testnet,
            crate::Network::BitcoinTestnet4 => BitcoinNetwork::Testnet,
            crate::Network::BitcoinPublicSignet => BitcoinNetwork::Signet,
            crate::Network::BitcoinBitGoSignet => BitcoinNetwork::Signet,
            _ => BitcoinNetwork::Bitcoin, // Default for non-bitcoin networks
        };

        let xpriv = Xpriv::new_master(bitcoin_network, seed)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to create master key: {}", e)))?;

        Ok(WasmBIP32(BIP32Key::Private(xpriv)))
    }

    /// Create a BIP32 master key from a string by hashing it with SHA256.
    /// This is useful for deterministic test key generation.
    #[wasm_bindgen]
    pub fn from_seed_sha256(
        seed_string: &str,
        network: Option<String>,
    ) -> Result<WasmBIP32, WasmUtxoError> {
        use crate::bitcoin::hashes::{sha256, Hash};
        let hash = sha256::Hash::hash(seed_string.as_bytes());
        Self::from_seed(&hash[..], network)
    }

    /// Get the chain code as a Uint8Array
    #[wasm_bindgen(getter)]
    pub fn chain_code(&self) -> js_sys::Uint8Array {
        let chain_code = match &self.0 {
            BIP32Key::Public(xpub) => xpub.chain_code.to_bytes(),
            BIP32Key::Private(xpriv) => xpriv.chain_code.to_bytes(),
        };
        js_sys::Uint8Array::from(&chain_code[..])
    }

    /// Get the depth
    #[wasm_bindgen(getter)]
    pub fn depth(&self) -> u8 {
        match &self.0 {
            BIP32Key::Public(xpub) => xpub.depth,
            BIP32Key::Private(xpriv) => xpriv.depth,
        }
    }

    /// Get the child index
    #[wasm_bindgen(getter)]
    pub fn index(&self) -> u32 {
        match &self.0 {
            BIP32Key::Public(xpub) => u32::from(xpub.child_number),
            BIP32Key::Private(xpriv) => u32::from(xpriv.child_number),
        }
    }

    /// Get the parent fingerprint
    #[wasm_bindgen(getter)]
    pub fn parent_fingerprint(&self) -> u32 {
        match &self.0 {
            BIP32Key::Public(xpub) => u32::from_be_bytes(xpub.parent_fingerprint.to_bytes()),
            BIP32Key::Private(xpriv) => u32::from_be_bytes(xpriv.parent_fingerprint.to_bytes()),
        }
    }

    /// Get the private key as a Uint8Array (if available)
    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Option<js_sys::Uint8Array> {
        match &self.0 {
            BIP32Key::Public(_) => None,
            BIP32Key::Private(xpriv) => Some(js_sys::Uint8Array::from(
                &xpriv.private_key.secret_bytes()[..],
            )),
        }
    }

    /// Get the public key as a Uint8Array
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> js_sys::Uint8Array {
        let xpub = self.0.to_xpub();
        let pubkey = PublicKey::new(xpub.public_key);
        js_sys::Uint8Array::from(&pubkey.to_bytes()[..])
    }

    /// Get the identifier as a Uint8Array
    #[wasm_bindgen(getter)]
    pub fn identifier(&self) -> js_sys::Uint8Array {
        let xpub = self.0.to_xpub();
        js_sys::Uint8Array::from(&xpub.identifier()[..])
    }

    /// Get the fingerprint as a Uint8Array
    #[wasm_bindgen(getter)]
    pub fn fingerprint(&self) -> js_sys::Uint8Array {
        let xpub = self.0.to_xpub();
        js_sys::Uint8Array::from(&xpub.fingerprint()[..])
    }

    /// Check if this is a neutered (public) key
    #[wasm_bindgen]
    pub fn is_neutered(&self) -> bool {
        self.0.is_neutered()
    }

    /// Get the neutered (public) version of this key
    #[wasm_bindgen]
    pub fn neutered(&self) -> WasmBIP32 {
        WasmBIP32(BIP32Key::Public(self.0.to_xpub()))
    }

    /// Serialize to base58 string
    #[wasm_bindgen]
    pub fn to_base58(&self) -> String {
        self.0.to_base58()
    }

    /// Get the WIF encoding of the private key
    #[wasm_bindgen]
    pub fn to_wif(&self) -> Result<String, WasmUtxoError> {
        self.0.to_wif()
    }

    /// Derive a normal (non-hardened) child key
    #[wasm_bindgen]
    pub fn derive(&self, index: u32) -> Result<WasmBIP32, WasmUtxoError> {
        Ok(WasmBIP32(self.0.derive(index)?))
    }

    /// Derive a hardened child key (only works for private keys)
    #[wasm_bindgen]
    pub fn derive_hardened(&self, index: u32) -> Result<WasmBIP32, WasmUtxoError> {
        Ok(WasmBIP32(self.0.derive_hardened(index)?))
    }

    /// Derive a key using a derivation path (e.g., "0/1/2" or "m/0/1/2")
    #[wasm_bindgen]
    pub fn derive_path(&self, path: &str) -> Result<WasmBIP32, WasmUtxoError> {
        Ok(WasmBIP32(self.0.derive_path(path)?))
    }
}

// Non-WASM methods for internal use
impl WasmBIP32 {
    /// Create from Xpub (for internal Rust use, not exposed to JS)
    pub(crate) fn from_xpub_internal(xpub: crate::bitcoin::bip32::Xpub) -> WasmBIP32 {
        WasmBIP32(BIP32Key::Public(xpub))
    }

    /// Convert to Xpub (for internal Rust use, not exposed to JS)
    pub(crate) fn to_xpub(&self) -> Result<crate::bitcoin::bip32::Xpub, WasmUtxoError> {
        Ok(self.0.to_xpub())
    }

    /// Convert to Xpriv (for internal Rust use, not exposed to JS)
    pub(crate) fn to_xpriv(&self) -> Result<crate::bitcoin::bip32::Xpriv, WasmUtxoError> {
        match &self.0 {
            BIP32Key::Private(xpriv) => Ok(*xpriv),
            BIP32Key::Public(_) => Err(WasmUtxoError::new("Cannot get xpriv from public key")),
        }
    }
}
