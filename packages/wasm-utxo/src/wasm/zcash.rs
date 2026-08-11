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

/// The Zcash v6 (Ironwood / NU6.3) version group id.
///
/// Exported so the TypeScript layer can derive its `IRONWOOD_VERSION_GROUP_ID` from the Rust
/// constant instead of hard-coding a second copy: the two are used together to tell v6 PSBTs from
/// v4/Sapling ones, and a silent divergence would route v6 bytes down the v4 path.
#[wasm_bindgen]
pub fn zcash_ironwood_version_group_id() -> u32 {
    crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID
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

/// A parsed Zcash v6 (Ironwood / NU6.3) transaction — for inspection and txid.
///
/// This wraps the raw v6 wire codec. The transaction id is exposed as an instance
/// method [`ZcashV6Transaction::get_id`] (canonical display-order hex), matching the
/// `getId()` convention used by the other transaction/PSBT wrappers, so callers never
/// pass raw bytes to a txid function or juggle internal vs display byte order.
#[wasm_bindgen]
pub struct ZcashV6Transaction {
    inner: crate::zcash::v6::ZcashV6Transaction,
}

#[wasm_bindgen]
impl ZcashV6Transaction {
    /// Decode a v6 transaction from raw wire bytes. Throws if the bytes are not a
    /// valid v6 (Ironwood) transaction.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<ZcashV6Transaction, WasmUtxoError> {
        Ok(ZcashV6Transaction {
            inner: crate::zcash::v6::ZcashV6Transaction::from_bytes(bytes)?,
        })
    }

    /// Serialize back to raw v6 wire bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, WasmUtxoError> {
        Ok(self.inner.to_bytes()?)
    }

    /// The canonical (display-order) ZIP-244 txid as a lowercase hex string.
    ///
    /// `Txid`'s `Display` emits display-order (byte-reversed) hex, matching how a
    /// transaction id is printed everywhere else in the codebase.
    #[wasm_bindgen(js_name = getId)]
    pub fn get_id(&self) -> String {
        use miniscript::bitcoin::hashes::Hash;
        miniscript::bitcoin::Txid::from_byte_array(self.inner.txid()).to_string()
    }

    /// The ZIP-244 txid in internal (non-reversed) byte order.
    #[wasm_bindgen(js_name = txidBytes)]
    pub fn txid_bytes(&self) -> Vec<u8> {
        self.inner.txid().to_vec()
    }

    /// Consensus branch id carried in the v6 header.
    #[wasm_bindgen(getter, js_name = consensusBranchId)]
    pub fn consensus_branch_id(&self) -> u32 {
        self.inner.consensus_branch_id
    }

    /// Expiry height.
    #[wasm_bindgen(getter, js_name = expiryHeight)]
    pub fn expiry_height(&self) -> u32 {
        self.inner.expiry_height
    }

    /// Number of Ironwood actions (0 when the Ironwood slot is empty).
    #[wasm_bindgen(getter, js_name = ironwoodActionCount)]
    pub fn ironwood_action_count(&self) -> usize {
        self.inner
            .ironwood_bundle
            .as_ref()
            .map_or(0, |b| b.actions.len())
    }

    /// Net value crossing the Ironwood pool boundary (0 when there is no bundle).
    #[wasm_bindgen(getter, js_name = ironwoodValueBalance)]
    pub fn ironwood_value_balance(&self) -> i64 {
        self.inner
            .ironwood_bundle
            .as_ref()
            .map_or(0, |b| b.value_balance)
    }

    /// The Ironwood bundle flag byte, or `undefined` when there is no bundle.
    #[wasm_bindgen(getter, js_name = ironwoodFlags)]
    pub fn ironwood_flags(&self) -> Option<u8> {
        self.inner.ironwood_bundle.as_ref().map(|b| b.flags)
    }

    /// The Ironwood note-commitment tree anchor (32 bytes), or `undefined`.
    #[wasm_bindgen(getter, js_name = ironwoodAnchor)]
    pub fn ironwood_anchor(&self) -> Option<Vec<u8>> {
        self.inner
            .ironwood_bundle
            .as_ref()
            .map(|b| b.anchor.to_vec())
    }

    /// The ZIP-244 per-input transparent sighash (32 bytes) for transparent input `index` of
    /// this transaction — the free-standing counterpart to
    /// `ZcashIronwoodBitGoPsbt.transparentSighash`, for a transaction inspected directly from
    /// its raw bytes rather than one built via this codebase's PSBT flow (e.g. independently
    /// verifying an already-broadcast transaction's signatures).
    ///
    /// `input_amounts`/`input_script_pubkeys` are the spent outputs' values (zatoshi) and
    /// scriptPubKeys for *every* transparent input of this transaction, in input order — the
    /// same data `add-input`/`addWalletInput` would have carried in a PSBT's `witness_utxo`.
    #[wasm_bindgen(js_name = transparentSighash)]
    pub fn transparent_sighash(
        &self,
        index: usize,
        input_amounts: Vec<i64>,
        input_script_pubkeys: Vec<js_sys::Uint8Array>,
    ) -> Result<Vec<u8>, WasmUtxoError> {
        let scripts: Vec<miniscript::bitcoin::ScriptBuf> = input_script_pubkeys
            .iter()
            .map(|u| miniscript::bitcoin::ScriptBuf::from(u.to_vec()))
            .collect();
        crate::zcash::v6::compute_v6_transparent_sighash(
            &self.inner,
            index,
            &input_amounts,
            &scripts,
        )
        .map(|h| h.to_vec())
        .map_err(|e| WasmUtxoError::new(&e.to_string()))
    }
}
