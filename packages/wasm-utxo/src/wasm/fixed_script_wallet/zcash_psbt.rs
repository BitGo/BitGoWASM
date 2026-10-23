//! Zcash-specific wasm bindings for [`BitGoPsbt`]: constructors, header getters, Ironwood
//! shielded-output methods, v6 signature verification and extraction, plus the JS conversion
//! for the Zcash-only `IronwoodOutputRequest`.
//!
//! Split out of `wasm/fixed_script_wallet/mod.rs`; wasm-bindgen merges this `impl` with
//! the generic one, so the JS class and method names are unchanged.

use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

use super::fee_policy_from_js;
use super::parse_network;
use super::BitGoPsbt;
use crate::error::WasmUtxoError;
use crate::fixed_script_wallet::bitgo_psbt::zcash::error::IronwoodPsbtError;
use crate::fixed_script_wallet::bitgo_psbt::zcash::ironwood_spend::{
    IronwoodInputKind, IronwoodShieldedStatus,
};
use crate::fixed_script_wallet::bitgo_psbt::zcash::parse::{
    ZcashParsedInput, ZcashParsedInputs, ZcashParsedOutput, ZcashParsedTransaction,
    ZcashShieldedSpend,
};
use crate::fixed_script_wallet::bitgo_psbt::zcash::IronwoodOutputRequest;
use crate::wasm::bip32::WasmBIP32;
use crate::wasm::ecpair::WasmECPair;
use crate::wasm::try_from_js_value::{
    get_field, get_required_raw_field, get_required_u64_field, TryFromJsValue,
};
use crate::wasm::try_into_js_value::js_obj;
use crate::wasm::try_into_js_value::TryIntoJsValue;
use crate::wasm::wallet_keys::WasmRootWalletKeys;
use crate::zcash::ironwood_build::{
    AnchorBytes, IronwoodActionMap, IronwoodWitness, MemoBytes, OrchardAddressBytes, OvkBytes,
    WitnessAuthPath, IRONWOOD_MERKLE_DEPTH,
};
use crate::zcash::ironwood_construct::IronwoodKeylessSpendSpec;

impl BitGoPsbt {
    /// Borrow the inner `ZcashBitGoPsbt`, erroring if this is not a Zcash PSBT.
    fn zcash(
        &self,
    ) -> Result<&crate::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt, WasmUtxoError> {
        use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt as InnerBitGoPsbt;
        match &self.psbt {
            InnerBitGoPsbt::Zcash(z, _) => Ok(z),
            _ => Err(WasmUtxoError::new("not a Zcash PSBT")),
        }
    }

    /// Mutably borrow the inner `ZcashBitGoPsbt`, erroring if this is not a Zcash PSBT.
    fn zcash_mut(
        &mut self,
    ) -> Result<&mut crate::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt, WasmUtxoError> {
        use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt as InnerBitGoPsbt;
        match &mut self.psbt {
            InnerBitGoPsbt::Zcash(z, _) => Ok(z),
            _ => Err(WasmUtxoError::new("not a Zcash PSBT")),
        }
    }
}

#[wasm_bindgen]
impl BitGoPsbt {
    /// Create an empty Zcash PSBT with the required consensus branch ID
    ///
    /// This method is specifically for Zcash networks which require additional
    /// parameters for sighash computation.
    ///
    /// # Arguments
    /// * `network` - Network name (must be "zcash" or "zcashTest")
    /// * `wallet_keys` - The wallet's root keys (used to set global xpubs)
    /// * `consensus_branch_id` - Zcash consensus branch ID (e.g., 0xC2D6D0B4 for NU5)
    /// * `version` - Optional transaction version (default: 4 for Zcash Sapling+)
    /// * `lock_time` - Optional lock time (default: 0)
    /// * `version_group_id` - Optional version group ID (defaults to Sapling: 0x892F2085)
    /// * `expiry_height` - Optional expiry height
    pub fn create_empty_zcash(
        network: &str,
        wallet_keys: &WasmRootWalletKeys,
        consensus_branch_id: u32,
        version: Option<i32>,
        lock_time: Option<u32>,
        version_group_id: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Result<BitGoPsbt, WasmUtxoError> {
        let network = parse_network(network)?;
        let wallet_keys = wallet_keys.inner();

        let psbt = crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt::new_zcash(
            network,
            wallet_keys,
            consensus_branch_id,
            version,
            lock_time,
            version_group_id,
            expiry_height,
        );

        Ok(BitGoPsbt {
            psbt,
            first_rounds: HashMap::new(),
        })
    }

    /// Create an empty Zcash PSBT with consensus branch ID determined from block height
    ///
    /// This method automatically determines the correct consensus branch ID based on
    /// the network and block height using the network upgrade activation heights.
    ///
    /// # Arguments
    /// * `network` - Network name (must be "zcash" or "zcashTest")
    /// * `wallet_keys` - The wallet's root keys (used to set global xpubs)
    /// * `block_height` - Block height to determine consensus rules
    /// * `version` - Optional transaction version (default: 4 for Zcash Sapling+)
    /// * `lock_time` - Optional lock time (default: 0)
    /// * `version_group_id` - Optional version group ID (defaults to Sapling: 0x892F2085)
    /// * `expiry_height` - Optional expiry height
    ///
    /// # Errors
    /// Returns error if block height is before Overwinter activation, or if the height is
    /// at or after NU7 activation and the build would be a version 4 transaction — version 4
    /// is invalid under NU7 per ZIP-2003; use `create_empty_zcash_v6_at_height` instead
    #[allow(clippy::too_many_arguments)]
    pub fn create_empty_zcash_at_height(
        network: &str,
        wallet_keys: &WasmRootWalletKeys,
        block_height: u32,
        version: Option<i32>,
        lock_time: Option<u32>,
        version_group_id: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Result<BitGoPsbt, WasmUtxoError> {
        let network = parse_network(network)?;
        let wallet_keys = wallet_keys.inner();

        let psbt = crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt::new_zcash_at_height(
            network,
            wallet_keys,
            block_height,
            version,
            lock_time,
            version_group_id,
            expiry_height,
        )
        .map_err(|e| WasmUtxoError::new(&e))?;

        Ok(BitGoPsbt {
            psbt,
            first_rounds: HashMap::new(),
        })
    }

    // ---- Zcash v6 (Ironwood / NU6.3) shielding ----

    /// Create an empty Zcash **v6 (Ironwood)** shielding PSBT with an explicit consensus branch id.
    ///
    /// The version group id is fixed by the v6 format, but the consensus branch id tracks the active
    /// network upgrade and stays caller-supplied — the v6 analogue of `create_empty_zcash`. Prefer
    /// `create_empty_zcash_v6_at_height`, which derives it from a block height and rejects heights
    /// before NU6.3 activation; this is the escape hatch for callers that already know the value.
    pub fn create_empty_zcash_v6(
        network: &str,
        wallet_keys: &WasmRootWalletKeys,
        consensus_branch_id: u32,
        lock_time: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Result<BitGoPsbt, WasmUtxoError> {
        let network = parse_network(network)?;
        let wallet_keys = wallet_keys.inner();
        let psbt = crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt::new_zcash_v6(
            network,
            wallet_keys,
            consensus_branch_id,
            lock_time,
            expiry_height,
        );
        Ok(BitGoPsbt {
            psbt,
            first_rounds: HashMap::new(),
        })
    }

    /// Create an empty Zcash **v6 (Ironwood)** shielding PSBT, with the consensus branch id
    /// resolved from `block_height`. Transparent inputs/outputs are added with the usual
    /// `add_wallet_input` / `add_wallet_output`; the shielded output and the v6 sign/combine
    /// steps use the dedicated `add_ironwood_output` / `ironwood_v6_*` / `combine_ironwood_proof`
    /// methods.
    pub fn create_empty_zcash_v6_at_height(
        network: &str,
        wallet_keys: &WasmRootWalletKeys,
        block_height: u32,
        lock_time: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Result<BitGoPsbt, WasmUtxoError> {
        let network = parse_network(network)?;
        let wallet_keys = wallet_keys.inner();
        let psbt = crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt::new_zcash_v6_at_height(
            network,
            wallet_keys,
            block_height,
            lock_time,
            expiry_height,
        )
        .map_err(|e| WasmUtxoError::new(&e))?;
        Ok(BitGoPsbt {
            psbt,
            first_rounds: HashMap::new(),
        })
    }

    /// Get the Zcash version group ID (returns None for non-Zcash PSBTs)
    pub fn version_group_id(&self) -> Option<u32> {
        use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt as InnerBitGoPsbt;
        match &self.psbt {
            InnerBitGoPsbt::Zcash(zcash_psbt, _) => zcash_psbt.version_group_id,
            InnerBitGoPsbt::BitcoinLike(_, _) => None,
            InnerBitGoPsbt::Dash(_, _) => None,
        }
    }

    /// Get the Zcash expiry height (returns None for non-Zcash PSBTs)
    pub fn expiry_height(&self) -> Option<u32> {
        use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt as InnerBitGoPsbt;
        match &self.psbt {
            InnerBitGoPsbt::Zcash(zcash_psbt, _) => zcash_psbt.expiry_height,
            InnerBitGoPsbt::BitcoinLike(_, _) => None,
            InnerBitGoPsbt::Dash(_, _) => None,
        }
    }

    /// Get the Zcash consensus branch ID from the PSBT proprietary map (returns None for non-Zcash PSBTs)
    pub fn consensus_branch_id(&self) -> Option<u32> {
        use crate::fixed_script_wallet::bitgo_psbt::{
            zcash::propkv::get_zec_consensus_branch_id, BitGoPsbt as InnerBitGoPsbt,
        };
        match &self.psbt {
            InnerBitGoPsbt::Zcash(z, _) => get_zec_consensus_branch_id(&z.psbt),
            _ => None,
        }
    }

    /// Constructor: add the shielded Ironwood output as an orchard PCZT stored in the PSBT.
    ///
    /// * `recipient` - raw Orchard/Ironwood address ([`ORCHARD_ADDRESS_SIZE`] bytes)
    /// * `amount` - note value in zatoshi
    /// * `ovk` - optional outgoing viewing key ([`OVK_SIZE`] bytes; `None` for a keyless build).
    ///   Has no effect in the normal flow: `sign_ironwood_v6`'s first round re-encrypts every
    ///   action's `out_ciphertext` under the wallet `ovk`, replacing whatever this produced
    /// * `anchor` - Ironwood note-commitment-tree root ([`ANCHOR_SIZE`] bytes)
    /// * `memo` - ZIP-302 memo field ([`MEMO_SIZE`] bytes)
    /// * `unified_address` - optional full Unified Address the output was addressed to; if given,
    ///   its Orchard receiver must match `recipient`, and it is stored verbatim so output parsing
    ///   can later return it in full (transparent/Sapling receivers included) instead of
    ///   reconstructing a single-receiver UA from `recipient` alone
    ///
    /// [`ORCHARD_ADDRESS_SIZE`]: crate::zcash::ironwood_build::ORCHARD_ADDRESS_SIZE
    /// [`OVK_SIZE`]: crate::zcash::ironwood_build::OVK_SIZE
    /// [`ANCHOR_SIZE`]: crate::zcash::ironwood_build::ANCHOR_SIZE
    /// [`MEMO_SIZE`]: crate::zcash::ironwood_build::MEMO_SIZE
    pub fn add_ironwood_output(
        &mut self,
        recipient: &[u8],
        amount: u64,
        ovk: Option<Vec<u8>>,
        anchor: &[u8],
        memo: &[u8],
        unified_address: Option<String>,
    ) -> Result<(), WasmUtxoError> {
        let recipient: OrchardAddressBytes = fixed_bytes(recipient, "recipient")?;
        let anchor: AnchorBytes = fixed_bytes(anchor, "anchor")?;
        let memo: MemoBytes = fixed_bytes(memo, "memo")?;
        let ovk: Option<OvkBytes> = ovk.map(|v| fixed_bytes(&v, "ovk")).transpose()?;
        self.zcash_mut()?
            .add_ironwood_output(
                &recipient,
                amount,
                ovk,
                &anchor,
                &memo,
                unified_address.as_deref(),
                rand::rngs::OsRng,
            )
            .map(|_action_index| ())
            .map_err(|e| WasmUtxoError::new(&e))
    }

    /// Constructor: add one or more shielded Ironwood outputs as a single orchard PCZT stored in
    /// the PSBT — the multi-recipient counterpart to [`Self::add_ironwood_output`].
    ///
    /// `outputs` is an array of `{ recipient: Uint8Array, amount: bigint, memo: Uint8Array,
    /// ovk?: Uint8Array, unifiedAddress?: string }`, one entry per recipient — see
    /// [`Self::add_ironwood_output`] for the meaning of each field. `anchor` is shared by every
    /// output.
    ///
    /// Returns the action index assigned to each output, in the same order as `outputs` — the
    /// orchard builder pads/reorders actions, so a caller correlating per-action data (a stored
    /// Unified Address, an explicit `set_ironwood_out_ciphertext` call) must use these indices, not
    /// the position in `outputs` — though note `sign_ironwood_v6`'s first round already patches
    /// every action's `out_ciphertext` with the wallet `ovk` on its own.
    pub fn add_ironwood_outputs(
        &mut self,
        outputs: JsValue,
        anchor: &[u8],
    ) -> Result<Vec<u32>, WasmUtxoError> {
        let anchor: AnchorBytes = fixed_bytes(anchor, "anchor")?;

        let arr = js_sys::Array::from(&outputs);
        let requests = arr
            .iter()
            .map(|item| IronwoodOutputRequest::try_from_js_value(&item))
            .collect::<Result<Vec<_>, _>>()?;

        self.zcash_mut()?
            .add_ironwood_outputs(&requests, &anchor, rand::rngs::OsRng)
            .map(|indices| indices.into_iter().map(|i| i as u32).collect())
            .map_err(|e| WasmUtxoError::new(&e))
    }

    /// Client-managed `ovk`: re-encrypt the Ironwood output's `out_ciphertext` under this wallet's
    /// `ovk`, derived as the ECDH agreement of `root_wallet_keys.bitgo_key()` and `user_xpriv` — two
    /// root keys, so the result is transaction-independent and the server can re-derive the identical
    /// `ovk` from its own privkey plus the user's pubkey in order to validate `out_ciphertext`. The
    /// server never sees `user_xpriv` or the `ovk` itself.
    ///
    /// `user_xpriv` must be the wallet's user root key; any other key is rejected, since an `ovk`
    /// derived from it is one neither the user nor the server can reproduce.
    ///
    /// Must be called before signing: `out_ciphertext` is ZIP-244 sighash-committed, so calling this
    /// after any transparent signature has been collected for the PSBT is rejected (it would
    /// silently invalidate that signature).
    pub fn set_ironwood_out_ciphertext(
        &mut self,
        action_index: usize,
        user_xpriv: &WasmBIP32,
        root_wallet_keys: &WasmRootWalletKeys,
    ) -> Result<(), WasmUtxoError> {
        let user_xpriv = user_xpriv.to_xpriv()?;
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();
        self.zcash_mut()?
            .set_ironwood_out_ciphertext_for_user(
                action_index,
                &user_xpriv,
                root_wallet_keys.inner(),
                &secp,
            )
            .map_err(|e| WasmUtxoError::new(&e))
    }

    /// The canonical (display-order) ZIP-244 v6 txid as a lowercase hex string, matching the
    /// `getId()` convention used elsewhere (see [`crate::wasm::zcash::ZcashV6Transaction::get_id`]).
    pub fn ironwood_v6_txid(&self) -> Result<String, WasmUtxoError> {
        use miniscript::bitcoin::hashes::Hash;
        let txid = self
            .zcash()?
            .v6_txid()
            .map_err(|e| WasmUtxoError::new(&e))?;
        Ok(miniscript::bitcoin::Txid::from_byte_array(txid).to_string())
    }

    /// The ZIP-244 per-input transparent sighash (32 bytes) that the key controlling transparent
    /// input `index` must sign.
    pub fn ironwood_v6_transparent_sighash(&self, index: usize) -> Result<Vec<u8>, WasmUtxoError> {
        self.zcash()?
            .v6_transparent_sighash(index)
            .map(|h| h.to_vec())
            .map_err(|e| WasmUtxoError::new(&e))
    }

    /// Ingest a transparent-input signature (`sig`: DER ECDSA with the trailing SIGHASH_ALL byte)
    /// after verifying it against `ironwood_v6_transparent_sighash(index)`.
    pub fn add_ironwood_v6_signature(
        &mut self,
        index: usize,
        pubkey: &[u8],
        sig: &[u8],
    ) -> Result<(), WasmUtxoError> {
        let pk = miniscript::bitcoin::PublicKey::from_slice(pubkey)
            .map_err(|e| WasmUtxoError::new(&format!("invalid pubkey: {e}")))?;
        self.zcash_mut()?
            .add_v6_transparent_signature(index, pk, sig)
            .map_err(|e| WasmUtxoError::new(&e))
    }

    /// Sign every transparent input `xpriv` resolves a key for, over the ZIP-244 transparent
    /// sighash — the v6 (Ironwood) counterpart to `sign_all_wallet_inputs`, which rejects v6 PSBTs
    /// (it only knows the ZIP-243 digest).
    ///
    /// If no transparent signature has been collected yet, this is the first signing round and
    /// `xpriv` must be the wallet's user root key: it is used with `root_wallet_keys.bitgo_key()` to
    /// derive this wallet's `ovk` and finalize every action's `out_ciphertext` (multi-recipient
    /// builds included) before computing any sighash (it is
    /// sighash-committed). Any other key signing first is rejected, rather than deriving an `ovk`
    /// nobody can reproduce. Once a signature exists, the step is skipped and any key may sign — so
    /// callers pass `root_wallet_keys` unconditionally on every signing round without needing to know
    /// which key is signing; it is mandatory precisely so the step can never be skipped by omission.
    ///
    /// Returns the indices of the transparent inputs that were signed.
    pub fn sign_ironwood_v6(
        &mut self,
        xpriv: &WasmBIP32,
        root_wallet_keys: &WasmRootWalletKeys,
    ) -> Result<Vec<usize>, WasmUtxoError> {
        let xpriv = xpriv.to_xpriv()?;
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();
        self.zcash_mut()?
            .sign_ironwood_v6(&xpriv, root_wallet_keys.inner(), &secp)
            .map_err(|e| WasmUtxoError::new(&e))
    }

    /// Transaction Extractor: given the external prover's `proof` bytes, finalize the transparent
    /// inputs, apply the shielded binding signature, and return the broadcast-ready v6 transaction
    /// bytes. Requires the transparent inputs to be signed (via `add_ironwood_v6_signature`).
    ///
    /// Terminal: on success the stored PCZT is dropped, so a second call — or any other Ironwood
    /// operation, including after a `serialize`/`from_bytes` round-trip — fails rather than silently
    /// re-running against already-extracted state. Build a fresh PSBT instead. On failure nothing is
    /// dropped, so a call that errors (bad proof, unsigned input) leaves the PSBT retryable.
    pub fn combine_ironwood_proof(&mut self, proof: &[u8]) -> Result<Vec<u8>, WasmUtxoError> {
        // The inner `combine_ironwood_proof` takes `self` by value (it is a consuming Extractor
        // step), which does not translate across the wasm boundary — so clone, and mark this
        // instance spent only once the clone has actually produced a transaction.
        let tx = self
            .zcash()?
            .clone()
            .combine_ironwood_proof(proof.to_vec(), rand::rngs::OsRng)?;
        self.zcash_mut()?.mark_ironwood_extracted();
        Ok(tx)
    }

    /// Transaction Extractor for a transparent-only v6 (Ironwood) PSBT: no shielded output was
    /// ever added, so there is no PCZT and nothing to combine an external proof into. Returns
    /// broadcast-ready v6 transaction bytes with an empty Ironwood bundle slot.
    ///
    /// Not terminal (unlike `combine_ironwood_proof`): there is no stored PCZT to drop, so
    /// calling this more than once is safe.
    ///
    /// Errors if a shielded output was ever added to this PSBT, or if any transparent input is
    /// missing a required signature. See
    /// [`crate::fixed_script_wallet::bitgo_psbt::zcash::ZcashBitGoPsbt::extract_transparent_only_v6_tx`].
    pub fn extract_transparent_only_v6_tx(&self) -> Result<Vec<u8>, WasmUtxoError> {
        self.zcash()?
            .extract_transparent_only_v6_tx()
            .map_err(|e| WasmUtxoError::new(&e))
    }

    /// The raw serialized orchard PCZT (Partially Created Zcash Transaction) bundle stored in
    /// this v6 (Ironwood) PSBT's proprietary key-value map, or `undefined` if none is present.
    ///
    /// A PCZT is the shielded-bundle counterpart to a PSBT: it accumulates the orchard action
    /// (spend + output), the ZIP-244-committed `out_ciphertext`, and — once
    /// [`Self::combine_ironwood_proof`] has run — the Halo2 `zkproof` and binding signature,
    /// bridging this PSBT to an external prover and back (see
    /// [`crate::zcash::ironwood_pczt`] / [`crate::zcash::ironwood_build`]).
    ///
    /// Present only after [`Self::add_ironwood_output`] has been called on a v6 PSBT; `undefined`
    /// beforehand, and `undefined` again after [`Self::combine_ironwood_proof`] succeeds, since
    /// that call drops the stored PCZT to make extraction terminal (see its doc comment).
    pub fn ironwood_pczt_bytes(&self) -> Option<Vec<u8>> {
        self.zcash().ok().and_then(|z| z.raw_ironwood_pczt_bytes())
    }

    /// Convert a network-format Zcash transaction (0, 1, or 2 sigs) to a PSBT (with block height).
    ///
    /// Accepts unsigned, half-signed, and fully-signed Zcash transactions.
    ///
    /// # Arguments
    /// * `tx` - The decoded Zcash transaction
    /// * `network` - Network name ("zec" or "tzec")
    /// * `wallet_keys` - The wallet's root keys
    /// * `unspents` - Array of `{ chain: number, index: number, value: bigint }` for each input
    /// * `block_height` - Block height to determine consensus branch ID
    #[wasm_bindgen]
    pub fn from_network_format_zcash_with_block_height(
        tx: &crate::wasm::transaction::WasmZcashTransaction,
        network: &str,
        wallet_keys: &WasmRootWalletKeys,
        unspents: JsValue,
        block_height: u32,
    ) -> Result<BitGoPsbt, WasmUtxoError> {
        let network_parsed = parse_network(network)?;
        let is_mainnet = matches!(network_parsed, crate::networks::Network::Zcash);

        let consensus_branch_id = crate::zcash::branch_id_for_height(block_height, is_mainnet)
            .ok_or_else(|| {
                WasmUtxoError::new(&format!(
                    "Block height {} is before Overwinter activation on {}",
                    block_height,
                    if is_mainnet { "mainnet" } else { "testnet" }
                ))
            })?;

        Self::from_network_format_zcash_with_branch_id(
            tx,
            network,
            wallet_keys,
            unspents,
            consensus_branch_id,
        )
    }

    /// Convert a network-format Zcash transaction (0, 1, or 2 sigs) to a PSBT (with consensus branch ID).
    ///
    /// Accepts unsigned, half-signed, and fully-signed Zcash transactions.
    ///
    /// # Arguments
    /// * `tx` - The decoded Zcash transaction
    /// * `network` - Network name ("zec" or "tzec")
    /// * `wallet_keys` - The wallet's root keys
    /// * `unspents` - Array of `{ chain: number, index: number, value: bigint }` for each input
    /// * `consensus_branch_id` - Zcash consensus branch ID
    #[wasm_bindgen]
    pub fn from_network_format_zcash_with_branch_id(
        tx: &crate::wasm::transaction::WasmZcashTransaction,
        network: &str,
        wallet_keys: &WasmRootWalletKeys,
        unspents: JsValue,
        consensus_branch_id: u32,
    ) -> Result<BitGoPsbt, WasmUtxoError> {
        use crate::fixed_script_wallet::bitgo_psbt::HydrationUnspentInput;

        let network = parse_network(network)?;
        let wallet_keys = wallet_keys.inner();

        let arr = js_sys::Array::from(&unspents);
        let parsed_unspents = arr
            .iter()
            .map(|item| HydrationUnspentInput::try_from_js_value(&item))
            .collect::<Result<Vec<_>, _>>()?;

        let zcash = crate::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt::from_network_format(
            &tx.parts,
            network,
            wallet_keys,
            &parsed_unspents,
            consensus_branch_id,
        )
        .map_err(|e| WasmUtxoError::new(&e))?;

        Ok(BitGoPsbt {
            psbt: crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt::Zcash(zcash, network),
            first_rounds: HashMap::new(),
        })
    }

    /// Zcash-only: add a plain transparent output. Just `script`/`value`
    /// (`unified_address: undefined`) is the legacy `add_output` behavior, unchanged.
    ///
    /// If `unified_address` is given, this PSBT must be a legacy v4 Zcash PSBT — a v6 (Ironwood)
    /// PSBT's shielded side already has its own UA path (`add_ironwood_output`). The UA must be a
    /// Unified Address whose transparent receiver is exactly `script`; mismatches are rejected
    /// rather than silently stored. It is then kept verbatim, keyed by this output's index, so
    /// `transparent_output_unified_address` can later return the original UA string rather than
    /// just the bare scriptPubkey.
    pub fn add_transparent_output(
        &mut self,
        script: &[u8],
        value: u64,
        unified_address: Option<String>,
    ) -> Result<usize, WasmUtxoError> {
        use miniscript::bitcoin::ScriptBuf;
        let script = ScriptBuf::from_bytes(script.to_vec());
        self.zcash_mut()?
            .add_transparent_output(script, value, unified_address.as_deref())
            .map_err(|e| WasmUtxoError::new(&e))
    }

    /// Zcash-only: the Unified Address stored by [`Self::add_transparent_output`] for output
    /// `index`, if the caller supplied one — `undefined` otherwise (including for a non-Zcash
    /// PSBT).
    pub fn transparent_output_unified_address(&self, index: usize) -> Option<String> {
        self.zcash()
            .ok()
            .and_then(|z| z.transparent_output_unified_address(index))
    }

    /// Verify if a valid signature exists for an extended public key at the specified input
    /// index, computed over the ZIP-244 v6 (Ironwood) transparent sighash — the v6 (Ironwood)
    /// counterpart to `verify_signature_with_xpub`, which digests ZIP-243 (Sapling) and would
    /// report `Ok(false)` for a valid v6 signature. Only v6 (Ironwood) Zcash PSBTs are
    /// supported.
    pub fn verify_ironwood_v6_signature_with_xpub(
        &self,
        input_index: usize,
        xpub: &WasmBIP32,
    ) -> Result<bool, WasmUtxoError> {
        let xpub_inner = xpub.to_xpub()?;
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::verification_only();
        self.psbt
            .verify_v6_signature_with_xpub(&secp, input_index, &xpub_inner)
            .map_err(Into::into)
    }

    /// Verify if a valid signature exists for a given ECPair key at the specified input index,
    /// computed over the ZIP-244 v6 (Ironwood) transparent sighash — the v6 (Ironwood)
    /// counterpart to `verify_signature_with_pub`, which digests ZIP-243 (Sapling) and would
    /// report `Ok(false)` for a valid v6 signature. Only v6 (Ironwood) Zcash PSBTs are
    /// supported.
    pub fn verify_ironwood_v6_signature_with_pub(
        &self,
        input_index: usize,
        ecpair: &WasmECPair,
    ) -> Result<bool, WasmUtxoError> {
        let public_key = ecpair.get_public_key();
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::verification_only();
        self.psbt
            .verify_v6_signature_with_pub(&secp, input_index, &public_key)
            .map_err(Into::into)
    }

    /// Extract the final transaction as a WasmZcashTransaction (for Zcash networks)
    ///
    /// This avoids re-parsing bytes by returning the transaction directly.
    /// Only valid for Zcash networks.
    pub fn extract_zcash_transaction(
        &self,
        max_fee_rate_sat_per_vb: Option<f64>,
    ) -> Result<crate::wasm::transaction::WasmZcashTransaction, WasmUtxoError> {
        let parts = self
            .psbt
            .clone()
            .extract_zcash_tx_with_fee_policy(fee_policy_from_js(max_fee_rate_sat_per_vb))
            .map_err(|e| WasmUtxoError::new(&e))?;
        Ok(crate::wasm::transaction::WasmZcashTransaction::from_parts(
            parts,
        ))
    }
}
// =============================================================================
// Zcash v6 (Ironwood) shielded spends: the build → ciphertexts → sign → prove flow
// =============================================================================

#[wasm_bindgen]
impl BitGoPsbt {
    /// Constructor: add the shielded spends (and optionally shielded outputs) as a single
    /// **keyless** orchard PCZT stored in the PSBT — the deshield and shielded→shielded
    /// Constructor for a caller that holds no viewing keys.
    ///
    /// * `spends` - one entry per spent note: `{ recipient: Uint8Array, value: bigint,
    ///   rho: Uint8Array, rseed: Uint8Array, cmx: Uint8Array, witness: { position: number,
    ///   authPath: Uint8Array }, nullifier: Uint8Array }` — the note's plaintext, its Merkle
    ///   witness (`authPath` is the 32 sibling hashes flattened, as `IronwoodWitness.auth_path`
    ///   returns it; validated against the anchor at construction), and the nullifier (from
    ///   the note store or derived by the viewing-key holder)
    /// * `outputs` - zero or more requested shielded outputs, shaped exactly like
    ///   `add_ironwood_outputs`' entries; every output's `ovk` must be omitted (encryption
    ///   belongs to the viewing-key holder in the spend flow) and its amount must be > 0
    /// * `anchor` - the Ironwood note-commitment-tree root every spend's witness commits to
    ///   (32 bytes)
    ///
    /// One input kind: rejected when the PSBT already carries transparent inputs, and one
    /// call per PSBT. Every real spend carries the placeholder `rk` and no `alpha`; the
    /// signer installs the randomized `rk` (`add_ironwood_spend_randomizers`) before any
    /// sighash is computed. Every output's `out_ciphertext` is a random placeholder,
    /// replaced under the FVK's `ovk`. No key material is accepted or stored.
    ///
    /// Returns `{ spendActionIndices: number[], outputActionIndices: number[] }` — the action
    /// index each requested spend/output landed at. The actions are shuffled, so request
    /// order does not equal action order: any caller correlating per-action data (a stored
    /// Unified Address, an out-ciphertext) must go through these indices.
    pub fn add_ironwood_shielded_spends(
        &mut self,
        spends: JsValue,
        outputs: JsValue,
        anchor: &[u8],
    ) -> Result<JsValue, WasmUtxoError> {
        let anchor: AnchorBytes = fixed_bytes(anchor, "anchor")?;
        let spends = js_sys::Array::from(&spends)
            .iter()
            .map(|item| IronwoodKeylessSpendSpec::try_from_js_value(&item))
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = js_sys::Array::from(&outputs)
            .iter()
            .map(|item| IronwoodOutputRequest::try_from_js_value(&item))
            .collect::<Result<Vec<_>, _>>()?;
        self.zcash_mut()?
            .add_shielded_spends(&spends, &outputs, &anchor, rand::rngs::OsRng)
            .map_err(WasmUtxoError::from)?
            .try_to_js_value()
    }

    /// The out-ciphertext request: `{ pczt: Uint8Array, actionIndices: number[] }` — the raw
    /// PCZT bytes plus the real outputs still pending their `out_ciphertext`. The viewing-key
    /// holder re-encrypts each pending output under its FVK `ovk` and returns one 80-byte
    /// ciphertext per action index, applied with `add_ironwood_out_ciphertexts`.
    ///
    /// Throws when the PSBT carries no spend bundle (`IronwoodPsbtError.NotSpendBundle`) or
    /// nothing is pending (`IronwoodPsbtError.NothingPending`, e.g. a pure deshield).
    pub fn ironwood_out_ciphertext_request(&self) -> Result<JsValue, WasmUtxoError> {
        let (pczt, action_indices) = self
            .zcash()?
            .out_ciphertext_request()
            .map_err(WasmUtxoError::from)?;
        js_obj!(
            "pczt" => pczt,
            "actionIndices" => action_indices,
        )
    }

    /// Apply the out-ciphertext response: an array of
    /// `{ actionIndex: number, outCiphertext: Uint8Array }` — one per pending real output.
    /// **Atomic**: every entry is validated before anything is written, so one bad entry
    /// stores nothing. Idempotent for identical bytes; different bytes for an already-set
    /// index throw (`IronwoodPsbtError.OutCiphertextConflict`). Rejected once any signature
    /// exists (`IronwoodPsbtError.AlreadySigned`).
    pub fn add_ironwood_out_ciphertexts(&mut self, entries: JsValue) -> Result<(), WasmUtxoError> {
        let entries: Vec<OutCiphertextEntry> = serde_wasm_bindgen::from_value(entries)
            .map_err(|e| WasmUtxoError::new(&format!("invalid out-ciphertext entries: {e}")))?;
        let entries = entries
            .into_iter()
            .map(|entry| {
                Ok((
                    entry.action_index,
                    fixed_bytes(&entry.out_ciphertext, "outCiphertext")?,
                ))
            })
            .collect::<Result<Vec<_>, IronwoodPsbtError>>()?;
        self.zcash_mut()?
            .add_out_ciphertexts(&entries)
            .map_err(WasmUtxoError::from)
    }

    /// Install the signer's randomized `rk`s: an array of
    /// `{ actionIndex: number, alpha: Uint8Array, rk: Uint8Array }` — one per real spend,
    /// with `rk = ak.randomize(alpha)`. **Only `rk` is stored**: the PSBT never carries
    /// `alpha` or the wallet's `ak` (with `rk`, an `alpha` would reveal `ak`).
    ///
    /// `spendValidatingKey` (the wallet's 32-byte `ak`, optional) makes the installer check
    /// `rk == ak.randomize(alpha)` before storing; without it the pair is checked later, by
    /// the client's key-free verifier and by the keyed prover. **Atomic**, and rejected once
    /// any signature exists (`IronwoodPsbtError.AlreadySigned`).
    pub fn add_ironwood_spend_randomizers(
        &mut self,
        entries: JsValue,
        spend_validating_key: Option<Vec<u8>>,
    ) -> Result<(), WasmUtxoError> {
        let entries: Vec<SpendRandomizerEntry> = serde_wasm_bindgen::from_value(entries)
            .map_err(|e| WasmUtxoError::new(&format!("invalid spend randomizer entries: {e}")))?;
        let ak: Option<[u8; 32]> = spend_validating_key
            .map(|bytes| fixed_bytes(&bytes, "spendValidatingKey"))
            .transpose()?;
        let entries = entries
            .into_iter()
            .map(|entry| {
                Ok((
                    entry.action_index,
                    fixed_bytes(&entry.alpha, "alpha")?,
                    fixed_bytes(&entry.rk, "rk")?,
                ))
            })
            .collect::<Result<Vec<_>, IronwoodPsbtError>>()?;
        self.zcash_mut()?
            .add_spend_randomizers(&entries, ak.as_ref())
            .map_err(WasmUtxoError::from)
    }

    /// The ZIP-244 sig digest (32 bytes) the real spends' spend-auth signatures are computed
    /// over. Every real output's `out_ciphertext` and every real spend's randomized `rk`
    /// must be installed first — the digest commits both.
    pub fn ironwood_spend_sighash(&self) -> Result<Vec<u8>, WasmUtxoError> {
        self.zcash()?
            .spend_sighash()
            .map(|digest| digest.to_vec())
            .map_err(WasmUtxoError::from)
    }

    /// Apply the signer's spend-auth signatures: an array of
    /// `{ actionIndex: number, signature: Uint8Array }` — one per real spend, each a 64-byte
    /// RedPallas signature over `ironwood_spend_sighash`, verified against the spend's
    /// installed `rk` before it is stored. **Atomic.**
    pub fn add_ironwood_spend_signatures(&mut self, entries: JsValue) -> Result<(), WasmUtxoError> {
        let entries: Vec<SpendSignatureEntry> = serde_wasm_bindgen::from_value(entries)
            .map_err(|e| WasmUtxoError::new(&format!("invalid spend signature entries: {e}")))?;
        let entries = entries
            .into_iter()
            .map(|entry| {
                Ok((
                    entry.action_index,
                    fixed_bytes(&entry.signature, "signature")?,
                ))
            })
            .collect::<Result<Vec<_>, IronwoodPsbtError>>()?;
        self.zcash_mut()?
            .add_spend_signatures(&entries)
            .map_err(WasmUtxoError::from)
    }

    /// The proof request for the keyed prover: the raw PCZT bytes with each real spend's
    /// randomizer `alpha` patched in — `randomizers` is an array of
    /// `{ actionIndex: number, alpha: Uint8Array }`, exactly one per real spend. The alphas
    /// are written only to the returned bytes, never stored (with `rk`, an `alpha` would
    /// reveal the wallet's `ak`). The proof the prover returns goes
    /// straight to `combine_ironwood_proof`.
    ///
    /// Gated: every real output's `out_ciphertext`, every real spend's randomized `rk`, and
    /// every real spend's spend-auth signature must be installed first. A shielding bundle
    /// (dummy spends only) takes an empty array and is served as-is — but the shielding flow
    /// hands the prover `getPczt()` bytes instead.
    pub fn ironwood_proof_request(&self, randomizers: JsValue) -> Result<Vec<u8>, WasmUtxoError> {
        let randomizers: Vec<ProofRequestAlpha> = serde_wasm_bindgen::from_value(randomizers)
            .map_err(|e| WasmUtxoError::new(&format!("invalid proof request randomizers: {e}")))?;
        let alphas = randomizers
            .into_iter()
            .map(|entry| Ok((entry.action_index, fixed_bytes(&entry.alpha, "alpha")?)))
            .collect::<Result<Vec<_>, IronwoodPsbtError>>()?;
        self.zcash()?
            .proof_request(&alphas)
            .map_err(WasmUtxoError::from)
    }

    /// The orchestration view of the shielded workflow, as
    /// `{ inputKind: "transparent" | "shielded", pendingOutCiphertexts: number[],
    /// pendingRandomizers: number[], pendingSpendSignatures: number[], readyForProof:
    /// boolean }` — `readyForProof` means `ironwood_proof_request(randomizers)` succeeds and
    /// `combine_ironwood_proof` then needs only the proof.
    pub fn ironwood_shielded_status(&self) -> Result<JsValue, WasmUtxoError> {
        self.zcash()?
            .shielded_status()
            .map_err(WasmUtxoError::from)?
            .try_to_js_value()
    }
}

/// Length-check a boundary byte string, naming the field and its expected size in the error.
fn fixed_bytes<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; N], IronwoodPsbtError> {
    bytes.try_into().map_err(|_| IronwoodPsbtError::BadLength {
        field,
        expected: N,
        actual: bytes.len(),
    })
}

/// Read a required fixed-size byte field off a JS object.
fn required_fixed_bytes<const N: usize>(
    item: &JsValue,
    field: &'static str,
) -> Result<[u8; N], WasmUtxoError> {
    let bytes = Vec::<u8>::try_from_js_value(&get_required_raw_field(item, field)?)?;
    Ok(fixed_bytes(&bytes, field)?)
}

/// One `add_ironwood_out_ciphertexts` entry from JS: `{ actionIndex, outCiphertext }`.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct OutCiphertextEntry {
    action_index: usize,
    out_ciphertext: serde_bytes::ByteBuf,
}

/// One `add_ironwood_spend_randomizers` entry from JS: `{ actionIndex, alpha, rk }`.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpendRandomizerEntry {
    action_index: usize,
    alpha: serde_bytes::ByteBuf,
    rk: serde_bytes::ByteBuf,
}

/// One `add_ironwood_spend_signatures` entry from JS: `{ actionIndex, signature }`.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpendSignatureEntry {
    action_index: usize,
    signature: serde_bytes::ByteBuf,
}

/// One `ironwood_proof_request` randomizer from JS: `{ actionIndex, alpha }`.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofRequestAlpha {
    action_index: usize,
    alpha: serde_bytes::ByteBuf,
}

/// One shielded note to spend, as passed to `add_ironwood_shielded_spends`: the note's
/// plaintext, its Merkle witness (`{ position, authPath }`, re-validated against the bundle's
/// anchor at construction), and the nullifier.
impl TryFromJsValue for IronwoodKeylessSpendSpec {
    fn try_from_js_value(item: &JsValue) -> Result<Self, WasmUtxoError> {
        let witness = get_required_raw_field(item, "witness")?;
        let auth_path: [u8; IRONWOOD_MERKLE_DEPTH * 32] =
            required_fixed_bytes(&witness, "authPath")?;
        let mut path: WitnessAuthPath = [[0u8; 32]; IRONWOOD_MERKLE_DEPTH];
        for (node, chunk) in path.iter_mut().zip(auth_path.chunks_exact(32)) {
            node.copy_from_slice(chunk);
        }
        Ok(Self {
            recipient: required_fixed_bytes(item, "recipient")?,
            value: get_required_u64_field(item, "value")?,
            rho: required_fixed_bytes(item, "rho")?,
            rseed: required_fixed_bytes(item, "rseed")?,
            cmx: required_fixed_bytes(item, "cmx")?,
            witness: IronwoodWitness {
                position: get_field(&witness, "position")?,
                auth_path: path,
            },
            nullifier: required_fixed_bytes(item, "nullifier")?,
        })
    }
}

impl TryIntoJsValue for IronwoodActionMap {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        js_obj!(
            "spendActionIndices" => self.spend_action_indices().to_vec(),
            "outputActionIndices" => self.output_action_indices().to_vec(),
        )
    }
}

impl TryIntoJsValue for IronwoodShieldedStatus {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        let input_kind = match self.input_kind {
            IronwoodInputKind::Transparent => "transparent",
            IronwoodInputKind::Shielded => "shielded",
        };
        js_obj!(
            "inputKind" => input_kind.to_string(),
            "pendingOutCiphertexts" => self.pending_out_ciphertexts.clone(),
            "pendingRandomizers" => self.pending_randomizers.clone(),
            "pendingSpendSignatures" => self.pending_spend_signatures.clone(),
            "readyForProof" => self.ready_for_proof,
        )
    }
}

// =============================================================================
// IronwoodOutputRequest: one requested multi-recipient Ironwood shielded output
// =============================================================================

impl TryFromJsValue for IronwoodOutputRequest {
    fn try_from_js_value(item: &JsValue) -> Result<Self, WasmUtxoError> {
        let ovk: Option<Vec<u8>> = get_field(item, "ovk")?;
        Ok(IronwoodOutputRequest {
            recipient: required_fixed_bytes(item, "recipient")?,
            amount: get_required_u64_field(item, "amount")?,
            ovk: ovk.map(|ovk| fixed_bytes(&ovk, "ovk")).transpose()?,
            memo: required_fixed_bytes(item, "memo")?,
            unified_address: get_field(item, "unifiedAddress")?,
        })
    }
}

/// The Zcash parse, exposed to JS: a Zcash PSBT always routes here (the generic parse
/// refuses to drop the shielded side), so the returned object carries the additive
/// `inputKind` / `shieldedSpends` / `valueBalance` fields.
pub(crate) fn parse_transaction_with_wallet_keys(
    psbt: &crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt,
    wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
    replay_protection: &crate::fixed_script_wallet::ReplayProtection,
    paygo_pubkeys: &[miniscript::bitcoin::secp256k1::PublicKey],
) -> Result<JsValue, WasmUtxoError> {
    crate::fixed_script_wallet::bitgo_psbt::zcash::parse::parse_transaction_with_wallet_keys(
        psbt,
        wallet_keys,
        replay_protection,
        paygo_pubkeys,
    )?
    .try_to_js_value()
}

/// The Zcash outputs parse, exposed to JS (see [`parse_transaction_with_wallet_keys`]).
pub(crate) fn parse_outputs_with_wallet_keys(
    psbt: &crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt,
    wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
    paygo_pubkeys: &[miniscript::bitcoin::secp256k1::PublicKey],
) -> Result<JsValue, WasmUtxoError> {
    crate::fixed_script_wallet::bitgo_psbt::zcash::parse::parse_outputs_with_wallet_keys(
        psbt,
        wallet_keys,
        paygo_pubkeys,
    )?
    .try_to_js_value()
}

impl TryIntoJsValue for ZcashParsedInput {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        // Same shape as the generic input, plus the additive `isShielded: false`.
        let obj = self.base.try_to_js_value()?;
        js_sys::Reflect::set(&obj, &"isShielded".into(), &JsValue::FALSE)
            .map_err(|_| WasmUtxoError::new("Failed to set object property"))?;
        Ok(obj)
    }
}

impl TryIntoJsValue for ZcashParsedOutput {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        // Same shape as the generic output, plus the always-present `isShielded` and the
        // action index for shielded outputs (`null` for transparent ones).
        let obj = self.base.try_to_js_value()?;
        js_sys::Reflect::set(
            &obj,
            &"isShielded".into(),
            &self.is_shielded.try_to_js_value()?,
        )
        .map_err(|_| WasmUtxoError::new("Failed to set object property"))?;
        let action_index = match self.action_index {
            Some(index) => JsValue::from_f64(index as f64),
            None => JsValue::NULL,
        };
        js_sys::Reflect::set(&obj, &"actionIndex".into(), &action_index)
            .map_err(|_| WasmUtxoError::new("Failed to set object property"))?;
        Ok(obj)
    }
}

impl TryIntoJsValue for ZcashShieldedSpend {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        // `installed` means the signer replaced the Constructor's placeholder `rk`
        // (= the wallet `ak`).
        let randomizer = if self.rk_replaced {
            "installed"
        } else {
            "placeholder"
        };
        js_obj!(
            "actionIndex" => self.action_index,
            "value" => self.value,
            "recipient" => self.recipient.to_vec(),
            "nullifier" => self.nullifier.to_vec(),
            // Recomputed from the verified plaintext (the keyless verifier's `SpendWitness` check).
            "cmx" => self.cmx.to_vec(),
            "position" => self.position,
            "address" => self.address,
            "randomizer" => randomizer.to_string(),
            "signed" => self.signed,
        )
    }
}

impl TryIntoJsValue for ZcashParsedTransaction {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        let (input_kind, inputs, shielded_spends): (
            &str,
            Vec<ZcashParsedInput>,
            Vec<ZcashShieldedSpend>,
        ) = match &self.inputs {
            ZcashParsedInputs::Transparent(inputs) => ("transparent", inputs.clone(), Vec::new()),
            ZcashParsedInputs::Shielded(spends) => ("shielded", Vec::new(), spends.clone()),
        };
        // The Ironwood fields are additive and v6-only: a v4 parse keeps its existing shape.
        let ironwood = self.is_ironwood_v6;
        js_obj!(
            "inputs" => inputs,
            "outputs" => self.outputs.clone(),
            "spendAmount" => self.spend_amount,
            "minerFee" => self.miner_fee,
            "virtualSize" => self.virtual_size,
            ? "inputKind" => ironwood.then(|| input_kind.to_string()),
            ? "shieldedSpends" => ironwood.then_some(shielded_spends),
            ? "valueBalance" => ironwood.then_some(self.value_balance)
        )
    }
}
