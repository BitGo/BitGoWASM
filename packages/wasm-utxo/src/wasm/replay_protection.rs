use wasm_bindgen::prelude::*;

use crate::error::WasmUtxoError;
use crate::fixed_script_wallet::replay_protection::ReplayProtection;

/// WASM wrapper for ReplayProtection
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmReplayProtection {
    inner: ReplayProtection,
}

#[wasm_bindgen]
impl WasmReplayProtection {
    /// Create from output scripts directly
    #[wasm_bindgen]
    // Box<[T]> is required by wasm-bindgen for passing JavaScript arrays
    #[allow(clippy::boxed_local)]
    pub fn from_output_scripts(output_scripts: Box<[js_sys::Uint8Array]>) -> WasmReplayProtection {
        let scripts = output_scripts
            .iter()
            .map(|arr| {
                let bytes = arr.to_vec();
                miniscript::bitcoin::ScriptBuf::from_bytes(bytes)
            })
            .collect();
        WasmReplayProtection {
            inner: ReplayProtection::new(scripts),
        }
    }

    /// Create from addresses (requires network for decoding)
    #[wasm_bindgen]
    // Box<[T]> is required by wasm-bindgen for passing JavaScript arrays
    #[allow(clippy::boxed_local)]
    pub fn from_addresses(
        addresses: Box<[JsValue]>,
        network: &str,
    ) -> Result<WasmReplayProtection, WasmUtxoError> {
        // Parse network
        let network = crate::networks::Network::from_utxolib_name(network)
            .or_else(|| crate::networks::Network::from_coin_name(network))
            .ok_or_else(|| {
                WasmUtxoError::new(&format!(
                    "Unknown network '{}'. Expected a utxolib name (e.g., 'bitcoin', 'testnet') or coin name (e.g., 'btc', 'tbtc')",
                    network
                ))
            })?;

        // Convert addresses to scripts
        let mut scripts = Vec::new();
        for (i, addr) in addresses.iter().enumerate() {
            let address_str = addr.as_string().ok_or_else(|| {
                WasmUtxoError::new(&format!("Address at index {} is not a string", i))
            })?;

            let script =
                crate::address::networks::to_output_script_with_network(&address_str, network)
                    .map_err(|e| {
                        WasmUtxoError::new(&format!(
                            "Failed to decode address '{}': {}",
                            address_str, e
                        ))
                    })?;
            scripts.push(script);
        }

        Ok(WasmReplayProtection {
            inner: ReplayProtection::new(scripts),
        })
    }

    /// Create from public keys (derives P2SH-P2PK output scripts)
    #[wasm_bindgen]
    // Box<[T]> is required by wasm-bindgen for passing JavaScript arrays
    #[allow(clippy::boxed_local)]
    pub fn from_public_keys(
        public_keys: Box<[js_sys::Uint8Array]>,
    ) -> Result<WasmReplayProtection, WasmUtxoError> {
        let compressed_keys = public_keys
            .iter()
            .enumerate()
            .map(|(i, arr)| {
                let bytes = arr.to_vec();

                if bytes.len() != 33 {
                    return Err(WasmUtxoError::new(&format!(
                        "Public key at index {} has invalid length: {} (expected 33 bytes)",
                        i,
                        bytes.len()
                    )));
                }

                miniscript::bitcoin::CompressedPublicKey::from_slice(&bytes).map_err(|e| {
                    WasmUtxoError::new(&format!("Invalid public key at index {}: {}", i, e))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(WasmReplayProtection {
            inner: ReplayProtection::from_public_keys(compressed_keys),
        })
    }
}

// Non-WASM methods for internal use
impl WasmReplayProtection {
    /// Get the inner ReplayProtection (for internal Rust use, not exposed to JS)
    pub(crate) fn inner(&self) -> &ReplayProtection {
        &self.inner
    }
}
