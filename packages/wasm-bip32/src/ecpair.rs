use crate::error::WasmBip32Error;
use crate::message;
use k256::ecdsa::{SigningKey, VerifyingKey};
use wasm_bindgen::prelude::*;

/// Network kind for WIF encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    Main,
    Test,
}

/// Internal enum to hold either public-only or private+public keys
#[derive(Debug, Clone)]
enum ECPairKey {
    PublicOnly(VerifyingKey),
    Private {
        signing_key: SigningKey,
        verifying_key: VerifyingKey,
    },
}

impl ECPairKey {
    fn verifying_key(&self) -> &VerifyingKey {
        match self {
            ECPairKey::PublicOnly(vk) => vk,
            ECPairKey::Private { verifying_key, .. } => verifying_key,
        }
    }

    fn signing_key(&self) -> Option<&SigningKey> {
        match self {
            ECPairKey::PublicOnly(_) => None,
            ECPairKey::Private { signing_key, .. } => Some(signing_key),
        }
    }
}

/// WASM wrapper for elliptic curve key pairs (always uses compressed keys)
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmECPair {
    key: ECPairKey,
}

#[wasm_bindgen]
impl WasmECPair {
    /// Create an ECPair from a private key (always uses compressed keys)
    #[wasm_bindgen]
    pub fn from_private_key(private_key: &[u8]) -> Result<WasmECPair, WasmBip32Error> {
        if private_key.len() != 32 {
            return Err(WasmBip32Error::new("Private key must be 32 bytes"));
        }

        let signing_key = SigningKey::from_slice(private_key)
            .map_err(|e| WasmBip32Error::new(&format!("Invalid private key: {}", e)))?;

        let verifying_key = *signing_key.verifying_key();

        Ok(WasmECPair {
            key: ECPairKey::Private {
                signing_key,
                verifying_key,
            },
        })
    }

    /// Create an ECPair from a public key (always uses compressed keys)
    #[wasm_bindgen]
    pub fn from_public_key(public_key: &[u8]) -> Result<WasmECPair, WasmBip32Error> {
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| WasmBip32Error::new(&format!("Invalid public key: {}", e)))?;

        Ok(WasmECPair {
            key: ECPairKey::PublicOnly(verifying_key),
        })
    }

    fn from_wif_with_network_check(
        wif_string: &str,
        expected_network: Option<NetworkKind>,
    ) -> Result<WasmECPair, WasmBip32Error> {
        let decoded = bs58::decode(wif_string)
            .with_check(None)
            .into_vec()
            .map_err(|e| WasmBip32Error::new(&format!("Invalid WIF: {}", e)))?;

        if decoded.is_empty() {
            return Err(WasmBip32Error::new("Invalid WIF: empty"));
        }

        let version = decoded[0];
        let actual_network = match version {
            0x80 => NetworkKind::Main,
            0xef => NetworkKind::Test,
            _ => return Err(WasmBip32Error::new("Invalid WIF version byte")),
        };

        if let Some(expected) = expected_network {
            if actual_network != expected {
                let network_name = match expected {
                    NetworkKind::Main => "mainnet",
                    NetworkKind::Test => "testnet",
                };
                return Err(WasmBip32Error::new(&format!(
                    "Expected {} WIF",
                    network_name
                )));
            }
        }

        // Check for compression flag
        let private_key_bytes = if decoded.len() == 34 && decoded[33] == 0x01 {
            // Compressed
            &decoded[1..33]
        } else if decoded.len() == 33 {
            // Uncompressed (we'll still use compressed public key)
            &decoded[1..33]
        } else {
            return Err(WasmBip32Error::new("Invalid WIF length"));
        };

        let signing_key = SigningKey::from_slice(private_key_bytes)
            .map_err(|e| WasmBip32Error::new(&format!("Invalid private key in WIF: {}", e)))?;

        let verifying_key = *signing_key.verifying_key();

        Ok(WasmECPair {
            key: ECPairKey::Private {
                signing_key,
                verifying_key,
            },
        })
    }

    /// Create an ECPair from a WIF string (auto-detects network)
    #[wasm_bindgen]
    pub fn from_wif(wif_string: &str) -> Result<WasmECPair, WasmBip32Error> {
        Self::from_wif_with_network_check(wif_string, None)
    }

    /// Create an ECPair from a mainnet WIF string
    #[wasm_bindgen]
    pub fn from_wif_mainnet(wif_string: &str) -> Result<WasmECPair, WasmBip32Error> {
        Self::from_wif_with_network_check(wif_string, Some(NetworkKind::Main))
    }

    /// Create an ECPair from a testnet WIF string
    #[wasm_bindgen]
    pub fn from_wif_testnet(wif_string: &str) -> Result<WasmECPair, WasmBip32Error> {
        Self::from_wif_with_network_check(wif_string, Some(NetworkKind::Test))
    }

    /// Get the private key as a Uint8Array (if available)
    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Option<js_sys::Uint8Array> {
        self.key
            .signing_key()
            .map(|sk| js_sys::Uint8Array::from(&sk.to_bytes()[..]))
    }

    /// Get the compressed public key as a Uint8Array (always 33 bytes)
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> js_sys::Uint8Array {
        let vk = self.key.verifying_key();
        let bytes = vk.to_sec1_bytes();
        js_sys::Uint8Array::from(&bytes[..])
    }

    fn to_wif_with_network(&self, network: NetworkKind) -> Result<String, WasmBip32Error> {
        let signing_key = self
            .key
            .signing_key()
            .ok_or_else(|| WasmBip32Error::new("Cannot get WIF from public key"))?;

        let version = match network {
            NetworkKind::Main => 0x80u8,
            NetworkKind::Test => 0xefu8,
        };

        // WIF format: version (1) + secret (32) + compression flag (1)
        let mut data = Vec::with_capacity(34);
        data.push(version);
        data.extend_from_slice(&signing_key.to_bytes());
        data.push(0x01); // Always compressed

        Ok(bs58::encode(&data).with_check().into_string())
    }

    /// Convert to WIF string (mainnet)
    #[wasm_bindgen]
    pub fn to_wif(&self) -> Result<String, WasmBip32Error> {
        self.to_wif_mainnet()
    }

    /// Convert to mainnet WIF string
    #[wasm_bindgen]
    pub fn to_wif_mainnet(&self) -> Result<String, WasmBip32Error> {
        self.to_wif_with_network(NetworkKind::Main)
    }

    /// Convert to testnet WIF string
    #[wasm_bindgen]
    pub fn to_wif_testnet(&self) -> Result<String, WasmBip32Error> {
        self.to_wif_with_network(NetworkKind::Test)
    }

    /// Sign a 32-byte message hash (raw ECDSA)
    #[wasm_bindgen]
    pub fn sign(&self, message_hash: &[u8]) -> Result<js_sys::Uint8Array, WasmBip32Error> {
        if message_hash.len() != 32 {
            return Err(WasmBip32Error::new("Message hash must be 32 bytes"));
        }

        let signing_key = self
            .key
            .signing_key()
            .ok_or_else(|| WasmBip32Error::new("Cannot sign with public key only"))?;

        let signature = message::sign_raw(signing_key, message_hash)?;
        Ok(js_sys::Uint8Array::from(&signature[..]))
    }

    /// Verify a signature against a 32-byte message hash (raw ECDSA)
    #[wasm_bindgen]
    pub fn verify(&self, message_hash: &[u8], signature: &[u8]) -> Result<bool, WasmBip32Error> {
        if message_hash.len() != 32 {
            return Err(WasmBip32Error::new("Message hash must be 32 bytes"));
        }

        let verifying_key = self.key.verifying_key();
        Ok(message::verify_raw(verifying_key, message_hash, signature))
    }

    /// Sign a message using Bitcoin message signing (BIP-137)
    /// Returns 65-byte signature (1-byte header + 64-byte signature)
    #[wasm_bindgen]
    pub fn sign_message(&self, message: &str) -> Result<js_sys::Uint8Array, WasmBip32Error> {
        let signing_key = self
            .key
            .signing_key()
            .ok_or_else(|| WasmBip32Error::new("Cannot sign with public key only"))?;

        let signature = message::sign_bitcoin_message(signing_key, message)?;
        Ok(js_sys::Uint8Array::from(&signature[..]))
    }

    /// Verify a Bitcoin message signature (BIP-137)
    /// Signature must be 65 bytes (1-byte header + 64-byte signature)
    #[wasm_bindgen]
    pub fn verify_message(&self, message: &str, signature: &[u8]) -> Result<bool, WasmBip32Error> {
        let verifying_key = self.key.verifying_key();
        message::verify_bitcoin_message(verifying_key, message, signature)
    }
}
