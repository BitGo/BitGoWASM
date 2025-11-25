use std::str::FromStr;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

use crate::bitcoin::bip32::DerivationPath;
use crate::error::WasmUtxoError;
use crate::fixed_script_wallet::RootWalletKeys;
use crate::wasm::bip32::WasmBIP32;
use crate::wasm::wallet_keys_helpers::root_wallet_keys_from_jsvalue;

/// WASM wrapper for RootWalletKeys
/// Represents a set of three extended public keys with their derivation prefixes
#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmRootWalletKeys {
    inner: RootWalletKeys,
}

impl WasmRootWalletKeys {
    /// Get a reference to the inner RootWalletKeys
    pub(crate) fn inner(&self) -> &RootWalletKeys {
        &self.inner
    }
}

#[wasm_bindgen]
impl WasmRootWalletKeys {
    /// Create a RootWalletKeys from any compatible format
    /// Uses default derivation prefix of m/0/0 for all three keys
    #[wasm_bindgen(constructor)]
    pub fn new(xpubs: JsValue) -> Result<WasmRootWalletKeys, WasmUtxoError> {
        let inner = root_wallet_keys_from_jsvalue(&xpubs)?;
        Ok(WasmRootWalletKeys { inner })
    }

    /// Create a RootWalletKeys from three xpub strings
    /// Uses default derivation prefix of m/0/0 for all three keys
    #[wasm_bindgen]
    pub fn new_from_xpubs(xpubs: JsValue) -> Result<WasmRootWalletKeys, WasmUtxoError> {
        let inner = root_wallet_keys_from_jsvalue(&xpubs)?;
        Ok(WasmRootWalletKeys { inner })
    }

    /// Create a RootWalletKeys from three xpub strings with custom derivation prefixes
    ///
    /// # Arguments
    /// - `xpubs`: Array of 3 xpub strings or WalletKeys object
    /// - `derivation_prefixes`: Array of 3 derivation path strings (e.g., ["m/0/0", "m/0/0", "m/0/0"])
    #[wasm_bindgen]
    pub fn with_derivation_prefixes(
        xpubs: JsValue,
        derivation_prefixes: JsValue,
    ) -> Result<WasmRootWalletKeys, WasmUtxoError> {
        // First get the xpubs
        let inner = root_wallet_keys_from_jsvalue(&xpubs)?;

        // Parse derivation prefixes if provided
        if !derivation_prefixes.is_undefined() && !derivation_prefixes.is_null() {
            let prefixes_array = js_sys::Array::from(&derivation_prefixes);
            if prefixes_array.length() != 3 {
                return Err(WasmUtxoError::new("Expected exactly 3 derivation prefixes"));
            }

            let prefix_strings: Result<[String; 3], _> = (0..3)
                .map(|i| {
                    prefixes_array
                        .get(i)
                        .as_string()
                        .ok_or_else(|| WasmUtxoError::new("Prefix is not a string"))
                })
                .collect::<Result<Vec<_>, _>>()
                .and_then(|v| {
                    v.try_into()
                        .map_err(|_| WasmUtxoError::new("Failed to convert to array"))
                });

            let derivation_paths: [DerivationPath; 3] = prefix_strings?
                .iter()
                .map(|p| {
                    // Remove leading 'm/' if present and add it back
                    let p = p.strip_prefix("m/").unwrap_or(p);
                    DerivationPath::from_str(&format!("m/{}", p)).map_err(|e| {
                        WasmUtxoError::new(&format!("Invalid derivation prefix: {}", e))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| WasmUtxoError::new("Failed to convert derivation paths"))?;

            Ok(WasmRootWalletKeys {
                inner: RootWalletKeys::new_with_derivation_prefixes(inner.xpubs, derivation_paths),
            })
        } else {
            Ok(WasmRootWalletKeys { inner })
        }
    }

    /// Get the user key (first xpub)
    #[wasm_bindgen]
    pub fn user_key(&self) -> WasmBIP32 {
        WasmBIP32::from_xpub_internal(*self.inner.user_key())
    }

    /// Get the backup key (second xpub)
    #[wasm_bindgen]
    pub fn backup_key(&self) -> WasmBIP32 {
        WasmBIP32::from_xpub_internal(*self.inner.backup_key())
    }

    /// Get the bitgo key (third xpub)
    #[wasm_bindgen]
    pub fn bitgo_key(&self) -> WasmBIP32 {
        WasmBIP32::from_xpub_internal(*self.inner.bitgo_key())
    }
}
