//! Zcash-scoped WASM bindings.
//!
//! Groups the `zcash_*` free functions and the [`ZcashUnifiedAddress`] wrapper so
//! Zcash surface lives in one zec-namespaced module rather than spread through the
//! generic fixed-script-wallet bindings.

use crate::error::WasmUtxoError;
use wasm_bindgen::prelude::*;

/// Return the Zcash consensus branch ID active at `height` on `network`.
///
/// `network`: "zcash" / "zec" for mainnet, "zcashTest" / "tzec" for testnet.
/// Returns `None` if `height` is before Overwinter activation.
/// Throws if `network` is not a recognised Zcash network name.
///
/// Errors are thrown as the crate-standard [`WasmUtxoError`] (a marked `js_sys::Error`
/// with `.message` and `.code`), not a bare string.
#[wasm_bindgen]
pub fn zcash_branch_id_for_height(
    network: &str,
    height: u32,
) -> Result<Option<u32>, WasmUtxoError> {
    let is_mainnet = match network {
        "zcash" | "zec" => true,
        "zcashTest" | "tzec" => false,
        _ => {
            return Err(WasmUtxoError::from(format!(
                "unknown Zcash network {network:?}: expected \"zcash\", \"zec\", \"zcashTest\", or \"tzec\""
            )))
        }
    };
    Ok(crate::zcash::branch_id_for_height(height, is_mainnet))
}

/// A parsed ZIP-316 Unified Address.
///
/// Decode once with [`ZcashUnifiedAddress::parse`], then read each component through
/// its accessor (returns `undefined` when absent). Ironwood reuses the Orchard
/// receiver, so `orchardReceiver` is the shielded receiver for Ironwood output notes.
#[wasm_bindgen]
pub struct ZcashUnifiedAddress {
    inner: crate::zcash::unified_address::UnifiedAddress,
    orchard: Option<Vec<u8>>,
    sapling: Option<Vec<u8>>,
    transparent: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl ZcashUnifiedAddress {
    /// Parse a Unified Address for `network` ("zcash"/"zec" or "zcashTest"/"tzec").
    ///
    /// All receiver components are resolved and validated eagerly, so the accessors
    /// below are infallible. Throws if the address is malformed or on the wrong network.
    #[wasm_bindgen]
    pub fn parse(address: &str, network: &str) -> Result<ZcashUnifiedAddress, WasmUtxoError> {
        let inner = crate::zcash::unified_address::UnifiedAddress::parse(address, network)?;
        let orchard = inner.orchard_receiver()?;
        let sapling = inner.sapling_receiver()?;
        let transparent = inner.transparent_script()?;
        Ok(ZcashUnifiedAddress {
            inner,
            orchard,
            sapling,
            transparent,
        })
    }

    /// The Orchard/Ironwood receiver's raw 43 bytes (diversifier + pk_d), or `undefined`.
    #[wasm_bindgen(getter, js_name = orchardReceiver)]
    pub fn orchard_receiver(&self) -> Option<Vec<u8>> {
        self.orchard.clone()
    }

    /// The Sapling receiver's raw 43 bytes (diversifier + pk_d), or `undefined`.
    #[wasm_bindgen(getter, js_name = saplingReceiver)]
    pub fn sapling_receiver(&self) -> Option<Vec<u8>> {
        self.sapling.clone()
    }

    /// The transparent receiver as scriptPubKey bytes (P2PKH/P2SH), or `undefined`.
    #[wasm_bindgen(getter, js_name = transparentScript)]
    pub fn transparent_script(&self) -> Option<Vec<u8>> {
        self.transparent.clone()
    }

    /// Whether `candidate` (another Unified Address, or a transparent Zcash address
    /// on the same network) is a receiver of this Unified Address.
    #[wasm_bindgen]
    pub fn contains(&self, candidate: &str) -> Result<bool, WasmUtxoError> {
        Ok(self.inner.contains(candidate)?)
    }
}
