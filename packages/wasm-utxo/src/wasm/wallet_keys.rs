use std::str::FromStr;
use wasm_bindgen::prelude::*;

use crate::bitcoin::bip32::DerivationPath;
use crate::error::WasmUtxoError;
use crate::fixed_script_wallet::RootWalletKeys;
use crate::wasm::bip32::WasmBIP32;

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
    /// Create a RootWalletKeys from three BIP32 keys
    /// Uses default derivation prefix of m/0/0 for all three keys
    ///
    /// # Arguments
    /// - `user`: User key (first xpub)
    /// - `backup`: Backup key (second xpub)
    /// - `bitgo`: BitGo key (third xpub)
    #[wasm_bindgen(constructor)]
    pub fn new(
        user: &WasmBIP32,
        backup: &WasmBIP32,
        bitgo: &WasmBIP32,
    ) -> Result<WasmRootWalletKeys, WasmUtxoError> {
        let xpubs = [user.to_xpub()?, backup.to_xpub()?, bitgo.to_xpub()?];
        let inner = RootWalletKeys::new_with_derivation_prefixes(
            xpubs,
            [
                DerivationPath::from_str("m/0/0").unwrap(),
                DerivationPath::from_str("m/0/0").unwrap(),
                DerivationPath::from_str("m/0/0").unwrap(),
            ],
        );
        Ok(WasmRootWalletKeys { inner })
    }

    /// Create a RootWalletKeys from three BIP32 keys with custom derivation prefixes
    ///
    /// # Arguments
    /// - `user`: User key (first xpub)
    /// - `backup`: Backup key (second xpub)
    /// - `bitgo`: BitGo key (third xpub)
    /// - `user_derivation`: Derivation path for user key (e.g., "m/0/0")
    /// - `backup_derivation`: Derivation path for backup key (e.g., "m/0/0")
    /// - `bitgo_derivation`: Derivation path for bitgo key (e.g., "m/0/0")
    #[wasm_bindgen]
    pub fn with_derivation_prefixes(
        user: &WasmBIP32,
        backup: &WasmBIP32,
        bitgo: &WasmBIP32,
        user_derivation: &str,
        backup_derivation: &str,
        bitgo_derivation: &str,
    ) -> Result<WasmRootWalletKeys, WasmUtxoError> {
        let xpubs = [user.to_xpub()?, backup.to_xpub()?, bitgo.to_xpub()?];

        let derivation_paths = [user_derivation, backup_derivation, bitgo_derivation]
            .iter()
            .map(|p| {
                // Remove leading 'm/' if present and add it back
                let p = p.strip_prefix("m/").unwrap_or(p);
                DerivationPath::from_str(&format!("m/{}", p))
                    .map_err(|e| WasmUtxoError::new(&format!("Invalid derivation prefix: {}", e)))
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| WasmUtxoError::new("Failed to convert derivation paths"))?;

        let inner = RootWalletKeys::new_with_derivation_prefixes(xpubs, derivation_paths);
        Ok(WasmRootWalletKeys { inner })
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
