//! Zcash v6 (Ironwood / NU6.3) transparent-input PSBT methods and wire format.
//!
//! Split verbatim out of the former monolithic `zcash_psbt.rs`.

// ---- Zcash v6 (Ironwood / NU6.3) ----
//
// A v6 PSBT keeps its transparent inputs/outputs in `psbt.unsigned_tx` (a version-6 rust-bitcoin
// `Transaction`) exactly like the v4 path, and carries the shielded side as an `orchard` PCZT in
// the proprietary map, under the `BITGO_ZEC_V6` namespace's `IronwoodPczt` subtype. The v6 header
// params (`version_group_id`, `expiry_height`) live under that same namespace's
// `VersionGroupId`/`ExpiryHeight` subtypes; `version_group_id`'s presence marks the PSBT as v6 so
// it round-trips through a plain PSBT serialization without the v4 tx-replacement dance.
//
// The lifecycle mirrors the microservice PSBT flow: the server builds (Constructor, no keys). For
// real spends, the signer then delivers each spend's randomized `rk`
// (`replace_ironwood_spend_rk`) before any sighash is fixed, and later its spend-auth signature
// (`apply_ironwood_spend_signature`). The client + HSM sign the transparent inputs over the
// ZIP-244 sighash this module exposes, the signed PSBT goes to the external proof service for the
// Halo2 `zkproof`, and `combine_ironwood_proof` finalizes the transparent inputs and splices in the
// proof + shielded bundle to produce the broadcast-ready v6 transaction. See
// `crate::zcash::ironwood_build` for the PCZT role bridge.

use miniscript::bitcoin::psbt::Psbt;
use miniscript::bitcoin::Transaction;

use super::{BitGoPsbt, ZcashBitGoPsbt, V6_NOT_SUPPORTED_BY_V4_PATH};
use crate::Network;

/// Errors produced while verifying a Zcash v6 (Ironwood) transparent-input signature.
///
/// The variant name is surfaced to JS as `err.code` (e.g. `"VerifyV6SignatureError.NotIronwoodV6"`)
/// via [`crate::error::WasmUtxoError`], so callers can branch on the error kind.
///
/// `Ok(false)` is reserved for "no signature exists for this key, or it fails cryptographic
/// verification"; everything that makes verification *unevaluable* is a typed variant here.
#[derive(Debug, strum::IntoStaticStr)]
pub enum VerifyV6SignatureError {
    /// The enum-level dispatch was handed a non-Zcash PSBT (Bitcoin/Dash/…).
    NotZcash,
    /// The PSBT is a Zcash PSBT but not v6 (Ironwood): the ZIP-244 transparent sighash only
    /// exists for v6, so verification cannot be evaluated.
    NotIronwoodV6,
    /// The requested input index does not exist.
    InputIndexOutOfRange { index: usize },
    /// The xpub could not be derived down the input's `bip32_derivation` path.
    Derivation(String),
    /// The Ironwood PCZT (whose shielded action data the ZIP-244 sighash commits) was added and
    /// then consumed by [`ZcashBitGoPsbt::combine_ironwood_proof`] — not simply never added,
    /// since a transparent-only v6 PSBT (no shielded output ever added) is verified against a
    /// bundle-less ZIP-244 digest instead, exactly like [`ZcashBitGoPsbt::unsigned_v6_txid`].
    MissingIronwoodPczt,
    /// The ZIP-244 transparent sighash could not be computed (structural input problem).
    Sighash(String),
}

impl std::fmt::Display for VerifyV6SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotZcash => write!(
                f,
                "verify-v6-signature: requires a Zcash v6 (Ironwood) PSBT, got a non-Zcash PSBT"
            ),
            Self::NotIronwoodV6 => write!(
                f,
                "verify-v6-signature: not a v6 (Ironwood) PSBT; use verify_signature_with_pub / verify_signature_with_xpub (ZIP-243) for v4/Sapling"
            ),
            Self::InputIndexOutOfRange { index } => {
                write!(f, "verify-v6-signature: input {index} out of range")
            }
            Self::Derivation(e) => write!(
                f,
                "verify-v6-signature: failed to derive the public key from the xpub: {e}"
            ),
            Self::MissingIronwoodPczt => write!(
                f,
                "verify-v6-signature: this PSBT's Ironwood PCZT has already been extracted (via combine_ironwood_proof); its shielded action data is gone, not merely absent"
            ),
            Self::Sighash(e) => write!(
                f,
                "verify-v6-signature: failed to compute the ZIP-244 transparent sighash: {e}"
            ),
        }
    }
}

crate::impl_wasm_error_code!(VerifyV6SignatureError);

impl ZcashBitGoPsbt {
    /// Create an empty Zcash **v6 (Ironwood)** shielding PSBT, with the consensus branch id resolved
    /// from `block_height`, which must be at or after NU6.3 activation.
    ///
    /// The height is checked against NU6.3 rather than merely Overwinter: a v6 transaction stamped
    /// with a pre-NU6.3 branch id is only rejected at broadcast, long after signing.
    pub fn new_v6_at_height(
        network: crate::Network,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        block_height: u32,
        lock_time: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Result<Self, String> {
        let is_mainnet = matches!(network, crate::Network::Zcash);
        let network_name = if is_mainnet { "mainnet" } else { "testnet" };
        let nu6_3 = crate::zcash::NetworkUpgrade::Nu6_3.activation_height(is_mainnet);
        if block_height < nu6_3 {
            return Err(format!(
                "Block height {block_height} is before NU6.3 (Ironwood) activation ({nu6_3}) on \
                 {network_name}; v6 transactions are not valid before then"
            ));
        }
        let consensus_branch_id = crate::zcash::branch_id_for_height(block_height, is_mainnet)
            .ok_or_else(|| {
                format!(
                    "Block height {} is before Overwinter activation on {}",
                    block_height,
                    if is_mainnet { "mainnet" } else { "testnet" }
                )
            })?;
        Ok(Self::new_v6(
            network,
            wallet_keys,
            consensus_branch_id,
            lock_time,
            expiry_height,
        ))
    }

    /// Create an empty Zcash **v6 (Ironwood)** shielding PSBT with an explicit consensus branch id.
    pub fn new_v6(
        network: crate::Network,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        consensus_branch_id: u32,
        lock_time: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Self {
        let version_group_id = crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID;
        let expiry_height = expiry_height.unwrap_or(0);
        let mut z = Self::new(
            network,
            wallet_keys,
            consensus_branch_id,
            Some(6),
            lock_time,
            Some(version_group_id),
            Some(expiry_height),
        );
        // v6 has no Sapling fields; the v6 codec writes the empty Sapling/Orchard slots itself.
        z.sapling_fields = Vec::new();
        super::propkv::set_zec_v6_params(&mut z.psbt, version_group_id, expiry_height);
        super::propkv::set_zec_v6_consensus_branch_id(&mut z.psbt, consensus_branch_id);
        z
    }

    /// Create an empty Zcash **v6 (Ironwood)** shielding PSBT without embedding any xpubs.
    ///
    /// [`Self::new_v6`] always stamps the PSBT with a [`RootWalletKeys`][crate::fixed_script_wallet::RootWalletKeys]'s
    /// xpubs, which standalone tooling (e.g. the CLI) that builds/signs one key at a time rather
    /// than through a fixed-script wallet has no use for and no wallet keys to supply. The xpubs
    /// are purely informational metadata — every other v6 method reads/writes only the
    /// proprietary-map fields this constructor also sets — so omitting them is safe.
    pub fn new_v6_bare(
        network: crate::Network,
        consensus_branch_id: u32,
        lock_time: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Self {
        use miniscript::bitcoin::absolute::LockTime;
        use miniscript::bitcoin::transaction::Version;

        let version_group_id = crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID;
        let expiry_height = expiry_height.unwrap_or(0);
        let tx = Transaction {
            version: Version(6),
            lock_time: LockTime::from_consensus(lock_time.unwrap_or(0)),
            input: vec![],
            output: vec![],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("empty transaction should be valid");
        super::propkv::set_zec_v6_params(&mut psbt, version_group_id, expiry_height);
        super::propkv::set_zec_v6_consensus_branch_id(&mut psbt, consensus_branch_id);
        Self {
            psbt,
            network,
            version_group_id: Some(version_group_id),
            expiry_height: Some(expiry_height),
            sapling_fields: Vec::new(),
        }
    }

    /// Whether this PSBT is a v6 (Ironwood) PSBT.
    pub fn is_ironwood_v6(&self) -> bool {
        self.version_group_id == Some(crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID)
    }

    /// Add a plain transparent output. Just `script`/`value` (`unified_address: None`) is exactly
    /// the legacy `add_output` behavior, unchanged, on either v4 or v6.
    ///
    /// If `unified_address` is given, this must be a legacy v4 PSBT — the UA is stored under the
    /// same `BITGO_ZEC_V6`-namespaced proprietary key space as the Ironwood UA storage, but that
    /// namespace name is historical, not a v6 requirement; a v6 PSBT's shielded-side UA already
    /// has its own path ([`Self::add_ironwood_output`]), so this one is reserved for legacy
    /// transparent-only PSBTs. `unified_address` must be a Unified Address whose transparent
    /// receiver is exactly `script` — mismatches are rejected rather than silently stored, the
    /// same contract `add_ironwood_output` applies to its Orchard receiver. It is then stored
    /// verbatim, keyed by this output's index in `unsigned_tx.output` (see
    /// [`super::propkv::set_transparent_output_unified_address`]), so
    /// [`Self::transparent_output_unified_address`] can later return the original UA string
    /// rather than just the bare scriptPubKey.
    pub fn add_transparent_output(
        &mut self,
        script: miniscript::bitcoin::ScriptBuf,
        value: u64,
        unified_address: Option<&str>,
    ) -> Result<usize, String> {
        let index = self.psbt.unsigned_tx.output.len();
        let Some(ua) = unified_address else {
            use miniscript::bitcoin::{Amount, TxOut};
            let tx_out = TxOut {
                value: Amount::from_sat(value),
                script_pubkey: script,
            };
            return crate::psbt_ops::insert_output(
                &mut self.psbt,
                index,
                tx_out,
                miniscript::bitcoin::psbt::Output::default(),
            );
        };

        if self.is_ironwood_v6() {
            return Err(
                "unified_address on a transparent output requires a legacy v4 PSBT".to_string(),
            );
        }

        let parsed =
            crate::zcash::unified_address::UnifiedAddress::parse(ua, self.network.to_coin_name())
                .map_err(|e| format!("invalid unified_address: {e}"))?;
        let transparent = parsed
            .transparent_script()
            .map_err(|e| format!("invalid unified_address: {e}"))?
            .ok_or_else(|| "unified_address has no transparent receiver".to_string())?;
        if transparent != script.as_bytes() {
            return Err("unified_address's transparent receiver does not match script".to_string());
        }

        super::propkv::set_transparent_output_unified_address(&mut self.psbt, index, ua);

        use miniscript::bitcoin::{Amount, TxOut};
        let tx_out = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script,
        };
        crate::psbt_ops::insert_output(
            &mut self.psbt,
            index,
            tx_out,
            miniscript::bitcoin::psbt::Output::default(),
        )?;
        Ok(index)
    }

    /// The Unified Address stored by [`Self::add_transparent_output`] for output `index`, if the
    /// caller supplied one — `None` if that output has no stored UA (including if it doesn't
    /// exist, or wasn't added via `add_transparent_output` at all).
    pub fn transparent_output_unified_address(&self, index: usize) -> Option<String> {
        super::propkv::get_transparent_output_unified_address(&self.psbt, index)
    }

    /// Sign every transparent input this key resolves a private key for, over the ZIP-244
    /// transparent sighash. Client-side counterpart to the generic `BitGoPsbt::sign()` (which
    /// rejects v6 PSBTs outright, since it only knows the ZIP-243 digest).
    ///
    /// If no transparent signature has been added to this PSBT yet, this is the first signing round.
    /// With a shielded output present, `xpriv` must be the wallet's user root key: it is used with
    /// `root_wallet_keys.bitgo_key()` to derive the wallet's `ovk` and finalize **every** action's
    /// `out_ciphertext` ([`Self::set_ironwood_out_ciphertext_for_user`], looped over the whole
    /// bundle, so multi-recipient builds are covered too) before any sighash is computed —
    /// `out_ciphertext` is sighash-committed, so it must be final before signing. Any other key
    /// signing first is **rejected**, rather than deriving an `ovk` from it that neither the user nor
    /// the server can reproduce; the user must sign first. Once a transparent signature exists (the
    /// expected shape: user first, then Bitgo), the step is skipped and any key may sign — so callers
    /// pass `root_wallet_keys` unconditionally on every round without needing to know which key is
    /// signing, and it is mandatory precisely so the step can never be silently skipped by omission.
    ///
    /// A consequence worth stating: a backup-key recovery cannot open the first signing round of a
    /// shielding transaction, since the user key is what defines its `ovk`.
    ///
    /// For a **transparent-only** v6 PSBT (no shielded output was ever added — see
    /// [`Self::require_no_shielded_output_ever_added`]), there is no `ovk`/`out_ciphertext` to
    /// finalize and nothing to commit to it, so this step — and the user-signs-first restriction
    /// that exists only to protect it — does not apply: any key may open the first round.
    ///
    /// Keys are resolved the same way `miniscript`'s own PSBT signer does for legacy scripts: via
    /// each input's `bip32_derivation` map (fingerprint + path) against `k.get_key(..)` — the same
    /// mechanism `sign_all_with_xpriv` relies on for v4/Sapling and other networks, reimplemented
    /// here because a v6 PSBT needs the ZIP-244 digest, which `miniscript`'s built-in signer does not
    /// know how to compute.
    ///
    /// Returns the indices of the transparent inputs that were signed.
    pub fn sign_ironwood_v6<C>(
        &mut self,
        xpriv: &miniscript::bitcoin::bip32::Xpriv,
        root_wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        secp: &miniscript::bitcoin::secp256k1::Secp256k1<C>,
    ) -> Result<Vec<usize>, String>
    where
        C: miniscript::bitcoin::secp256k1::Signing + miniscript::bitcoin::secp256k1::Verification,
    {
        use miniscript::bitcoin::psbt::GetKey;

        use miniscript::bitcoin::psbt::KeyRequest;
        use miniscript::bitcoin::secp256k1::{Message, PublicKey, SecretKey};

        if !self.is_ironwood_v6() {
            return Err(
                "sign_ironwood_v6 requires a v6 (Ironwood) PSBT; use the generic sign() for v4/Sapling"
                    .to_string(),
            );
        }

        // Resolve (input index, pubkey, privkey) for every transparent input this key can sign.
        let mut resolved: Vec<(usize, PublicKey, SecretKey)> = Vec::new();
        for (i, input) in self.psbt.inputs.iter().enumerate() {
            for (&pubkey, key_source) in input.bip32_derivation.iter() {
                let found = xpriv
                    .get_key(KeyRequest::Bip32(key_source.clone()), secp)
                    .map_err(|e| format!("input {i}: key lookup failed: {e:?}"))?;
                if let Some(private_key) = found {
                    if private_key.public_key(secp).inner == pubkey {
                        resolved.push((i, pubkey, private_key.inner));
                        break;
                    }
                }
            }
        }
        if resolved.is_empty() {
            return Ok(Vec::new());
        }

        let already_signed = self
            .psbt
            .inputs
            .iter()
            .any(|input| !input.partial_sigs.is_empty());
        // A bundle with real spends has its out_ciphertexts fixed under the spending FVK's ovk
        // (checked during construction, while the FVK was transient), so it skips the client-ovk
        // round. An absent PCZT counts as no real spends, so the round below fails loudly on it.
        let has_real_spends = match super::propkv::get_ironwood_pczt(&self.psbt) {
            Some(_) => Self::bundle_has_real_spends(&self.ironwood_pczt()?),
            None => false,
        };
        if !already_signed && !has_real_spends && !self.require_no_shielded_output_ever_added()? {
            // First signing round of a shielding build: finalize EVERY action's `out_ciphertext`
            // under this wallet's ovk before any sighash is computed — one wallet ovk covers the
            // whole bundle, and re-encrypting an action under the same ovk is deterministic
            // (same ovk ⇒ same bytes), so the loop is idempotent. Only the user key may open the
            // round — checked once, up front, so it holds regardless of the action count and
            // signing out of order fails loudly here instead of shipping an `out_ciphertext`
            // nobody can decrypt.
            Self::check_user_root_key(xpriv, root_wallet_keys, secp)
                .map_err(|e| format!("{e} (the user must sign a v6 shielding PSBT first)"))?;
            // Fail loud for a v6 PSBT with no actions: the first round must not sign a
            // transparent-only digest under the (shielded-only) ovk-derivation rules above.
            let action_count = self.ironwood_pczt()?.actions().len();
            if action_count == 0 {
                return Err("Ironwood PCZT has no actions".to_string());
            }
            for action_index in 0..action_count {
                self.set_ironwood_out_ciphertext_for_user(
                    action_index,
                    xpriv,
                    root_wallet_keys,
                    secp,
                )?;
            }
        }

        let mut signed = Vec::with_capacity(resolved.len());
        for (index, pubkey, privkey) in resolved {
            let sighash = self.v6_transparent_sighash(index)?;
            let msg = Message::from_digest(sighash);
            let mut der = secp.sign_ecdsa(&msg, &privkey).serialize_der().to_vec();
            const SIGHASH_ALL: u8 = miniscript::bitcoin::sighash::EcdsaSighashType::All as u8;
            der.push(SIGHASH_ALL);
            self.add_v6_transparent_signature(
                index,
                miniscript::bitcoin::PublicKey::new(pubkey),
                &der,
            )?;
            signed.push(index);
        }
        Ok(signed)
    }

    /// The ZIP-244 v6 txid (internal byte order — reverse for display) of the transaction as it
    /// currently stands: with a shielded output present, this commits to its action data (via
    /// [`Self::ironwood_action_data`]); for a transparent-only v6 PSBT (no shielded output ever
    /// added), it is the ZIP-244 txid of the transparent skeleton alone (`ironwood_bundle: None`
    /// is a valid ZIP-244 input) — identical to [`Self::unsigned_v6_txid`] in both cases. Errors
    /// only if a shielded output was added and then extracted via
    /// [`Self::combine_ironwood_proof`], since the action data an already-computed txid would
    /// commit to is then gone.
    pub fn v6_txid(&self) -> Result<[u8; 32], String> {
        let bundle = if self.require_no_shielded_output_ever_added()? {
            None
        } else {
            Some(self.ironwood_action_data()?)
        };
        let tx = self.to_v6_transaction(self.psbt.unsigned_tx.clone(), bundle)?;
        Ok(crate::zcash::v6::compute_v6_txid(&tx))
    }

    /// The unsigned ZIP-244 txid for this v6 (Ironwood) PSBT, whatever state it's in: with a
    /// shielded output present, this is [`Self::v6_txid`]; before one has been added, it is the
    /// ZIP-244 txid of the transparent-only skeleton (a bundle-less v6 tx is a valid ZIP-244
    /// input — `ironwood_bundle: None`).
    ///
    /// Exists so callers computing a general-purpose "unsigned txid" (like
    /// `PsbtAccess::unsigned_tx_id`) don't need to know whether a shielded output has been added
    /// yet — unlike [`Self::v6_txid`], this never errors just because one hasn't been.
    pub fn unsigned_v6_txid(&self) -> Result<[u8; 32], String> {
        let bundle = if self.require_no_shielded_output_ever_added()? {
            None
        } else {
            Some(self.ironwood_action_data()?)
        };
        let tx = self.to_v6_transaction(self.psbt.unsigned_tx.clone(), bundle)?;
        Ok(crate::zcash::v6::compute_v6_txid(&tx))
    }

    /// ZIP-244 per-input transparent sighash for transparent input `index` (SIGHASH_ALL) — the
    /// message the key controlling that input must sign.
    ///
    /// Works whether or not a shielded output has been added: with one, the digest commits to its
    /// action data (via [`Self::ironwood_action_data`]); without one — the transparent-only v6
    /// case — it commits to the bundle-less (`None`) ZIP-244 encoding instead, exactly as
    /// [`Self::unsigned_v6_txid`] does for the txid.
    pub fn v6_transparent_sighash(&self, index: usize) -> Result<[u8; 32], String> {
        let (amounts, scripts) = self.transparent_input_amounts_and_scripts()?;
        let bundle = if self.require_no_shielded_output_ever_added()? {
            None
        } else {
            Some(self.final_ironwood_action_data()?)
        };
        let tx = self.to_v6_transaction(self.psbt.unsigned_tx.clone(), bundle)?;
        let input = self
            .psbt
            .inputs
            .get(index)
            .ok_or_else(|| format!("input {index} out of range"))?;
        // Not used in the digest itself (ZIP-244 §S.2g.iii commits the spent scriptPubKey, not
        // the redeem/witness script — see `compute_v6_transparent_sighash`), but its presence
        // confirms the input is actually spendable before we hand back a sighash to sign.
        if input.witness_script.is_none() && input.redeem_script.is_none() {
            return Err(format!("input {index}: no redeem/witness script"));
        }
        crate::zcash::v6::compute_v6_transparent_sighash(&tx, index, &amounts, &scripts)
            .map_err(|e| e.to_string())
    }

    /// The ZIP-244 sig digest over the complete transaction (transparent I/O + shielded action
    /// data) — the message spend-auth signatures are computed over, and which
    /// [`Self::combine_ironwood_proof`] binds. Transparent inputs sign their own per-input digest
    /// ([`Self::v6_transparent_sighash`]), which commits the same shielded action data.
    ///
    /// Errors while any real spend's `rk` is still the placeholder — the digest must be final
    /// before it is signed.
    pub fn v6_sig_digest(&self) -> Result<[u8; 32], String> {
        let (amounts, scripts) = self.transparent_input_amounts_and_scripts()?;
        let bundle = self.final_ironwood_action_data()?;
        let tx = self.to_v6_transaction(self.psbt.unsigned_tx.clone(), Some(bundle))?;
        Ok(crate::zcash::v6::compute_v6_sig_digest(
            &tx, &amounts, &scripts,
        ))
    }

    /// Ingest a transparent-input signature returned by the client/HSM into `partial_sigs`, after
    /// verifying it against [`Self::v6_transparent_sighash`] for that input. `sig` is a DER ECDSA
    /// signature with the trailing SIGHASH_ALL byte (as it appears in a scriptSig).
    pub fn add_v6_transparent_signature(
        &mut self,
        index: usize,
        pubkey: miniscript::bitcoin::PublicKey,
        sig: &[u8],
    ) -> Result<(), String> {
        use miniscript::bitcoin::ecdsa::Signature as EcdsaSig;
        use miniscript::bitcoin::secp256k1::{Message, Secp256k1};

        // Reject a key the input's redeem script does not contain: such a signature would be
        // silently dropped at finalization, so fail at ingest where the caller can see it.
        let redeem_script = self
            .psbt
            .inputs
            .get(index)
            .ok_or_else(|| format!("input {index} out of range"))?
            .redeem_script
            .as_ref()
            .ok_or_else(|| format!("input {index}: no redeem script"))?;
        let script_pubkeys =
            crate::fixed_script_wallet::wallet_scripts::parse_multisig_script_2_of_3(redeem_script)
                .map_err(|e| format!("input {index}: {e}"))?;
        if !script_pubkeys
            .iter()
            .any(|pk| miniscript::bitcoin::PublicKey::from(*pk) == pubkey)
        {
            return Err(format!(
                "input {index}: pubkey is not one of the redeem script's keys"
            ));
        }

        let sighash = self.v6_transparent_sighash(index)?;
        let ecdsa_sig =
            EcdsaSig::from_slice(sig).map_err(|e| format!("input {index}: bad signature: {e}"))?;
        // `v6_transparent_sighash` always digests as SIGHASH_ALL; any other type byte would be
        // re-emitted verbatim by `finalized_transparent_tx`, producing a scriptSig whose signature
        // doesn't match the sighash a verifier recomputes for that type — fail at ingest instead.
        const SIGHASH_ALL: u32 = miniscript::bitcoin::sighash::EcdsaSighashType::All as u32;
        if ecdsa_sig.sighash_type != SIGHASH_ALL {
            return Err(format!(
                "input {index}: signature sighash type must be SIGHASH_ALL (0x{SIGHASH_ALL:02x}), got 0x{:02x}",
                ecdsa_sig.sighash_type
            ));
        }
        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest(sighash);
        secp.verify_ecdsa(&msg, &ecdsa_sig.signature, &pubkey.inner)
            .map_err(|e| {
                format!("input {index}: signature does not verify against v6 sighash: {e}")
            })?;
        self.psbt.inputs[index]
            .partial_sigs
            .insert(pubkey, ecdsa_sig);
        Ok(())
    }

    /// Verify if a valid signature exists for a given public key at the specified input index,
    /// computed over the ZIP-244 v6 (Ironwood) transparent sighash — the digest the key
    /// controlling the input actually signs (see [`Self::v6_transparent_sighash`]). The generic
    /// `verify_signature_with_pub` path digests ZIP-243 (Sapling) instead, so it would report
    /// `Ok(false)` for a valid v6 signature. v4/Sapling PSBTs are rejected outright.
    ///
    /// # Arguments
    /// - `secp`: Secp256k1 context for signature verification
    /// - `input_index`: The index of the input to check
    /// - `pubkey`: The secp256k1 public key
    ///
    /// # Returns
    /// - `Ok(true)` if a valid signature exists for the public key
    /// - `Ok(false)` if no signature exists for the public key
    /// - `Err(VerifyV6SignatureError)` if the input index is out of bounds, the PSBT is not v6,
    ///   a shielded output was added and then extracted, or the sighash cannot be computed
    pub fn verify_v6_signature_with_pub<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
        pubkey: &secp256k1::PublicKey,
    ) -> Result<bool, VerifyV6SignatureError> {
        use miniscript::bitcoin::secp256k1::Message;

        if !self.is_ironwood_v6() {
            return Err(VerifyV6SignatureError::NotIronwoodV6);
        }

        let input = self
            .psbt
            .inputs
            .get(input_index)
            .ok_or(VerifyV6SignatureError::InputIndexOutOfRange { index: input_index })?;

        // The ZIP-244 transparent sighash commits the PCZT's shielded action data if one was ever
        // added. A shielded output that was added and then consumed by `combine_ironwood_proof`
        // leaves that data unrecoverable, so the stored signature cannot be evaluated no matter
        // what. "Never added" is not an error, though — a transparent-only v6 PSBT is valid, and
        // `v6_transparent_sighash` below computes a bundle-less digest for it.
        if self.require_no_shielded_output_ever_added().is_err() {
            return Err(VerifyV6SignatureError::MissingIronwoodPczt);
        }

        let public_key = miniscript::bitcoin::PublicKey::new(*pubkey);
        let Some(ecdsa_sig) = input.partial_sigs.get(&public_key) else {
            return Ok(false); // No signature found for this public key
        };
        // `v6_transparent_sighash` always digests as SIGHASH_ALL; a different type byte would be
        // re-emitted verbatim by `finalized_transparent_tx`, exactly as `add_v6_transparent_signature`
        // rejects at ingest — so a stored sig with a foreign type reports as not verifying
        // (fail-closed) rather than as valid.
        const SIGHASH_ALL: u32 = miniscript::bitcoin::sighash::EcdsaSighashType::All as u32;
        if ecdsa_sig.sighash_type != SIGHASH_ALL {
            return Ok(false);
        }
        let msg = Message::from_digest(
            self.v6_transparent_sighash(input_index)
                .map_err(VerifyV6SignatureError::Sighash)?,
        );
        match secp.verify_ecdsa(&msg, &ecdsa_sig.signature, pubkey) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify if a valid signature exists for an extended public key at the specified input
    /// index, computed over the ZIP-244 v6 (Ironwood) transparent sighash — the v6 (Ironwood)
    /// counterpart to `verify_signature_with_xpub`, which digests ZIP-243 (Sapling) for Zcash
    /// PSBTs and would report `Ok(false)` for a valid v6 signature. v4/Sapling PSBTs are rejected
    /// outright.
    ///
    /// This method derives the public key from the xpub using the derivation path found in the
    /// PSBT input (the same `bip32_derivation`/`tap_key_origins` lookup the generic
    /// `verify_signature_with_xpub` uses), then delegates to
    /// [`Self::verify_v6_signature_with_pub`].
    ///
    /// # Arguments
    /// - `secp`: Secp256k1 context for signature verification and key derivation
    /// - `input_index`: The index of the input to check
    /// - `xpub`: The extended public key to derive from and verify the signature for
    ///
    /// # Returns
    /// - `Ok(true)` if a valid signature exists for the derived public key
    /// - `Ok(false)` if no matching derivation path exists, or no valid signature exists for the
    ///   derived public key
    /// - `Err(VerifyV6SignatureError)` if the input index is out of bounds, the PSBT is not v6,
    ///   derivation fails, a shielded output was added and then extracted, or the sighash cannot
    ///   be computed
    pub fn verify_v6_signature_with_xpub<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
        xpub: &miniscript::bitcoin::bip32::Xpub,
    ) -> Result<bool, VerifyV6SignatureError> {
        // Checked here, not only in the delegated `verify_v6_signature_with_pub`: a non-matching
        // xpub would otherwise exit at the derivation `None` arm below with Ok(false) before that
        // guard runs, silently answering on a PSBT whose ZIP-244 sighash does not exist.
        if !self.is_ironwood_v6() {
            return Err(VerifyV6SignatureError::NotIronwoodV6);
        }

        let input = self
            .psbt
            .inputs
            .get(input_index)
            .ok_or(VerifyV6SignatureError::InputIndexOutOfRange { index: input_index })?;

        // Derive the public key from the xpub using the derivation path in the PSBT input
        let derived_pubkey =
            match super::psbt_wallet_input::derive_pubkey_from_input(secp, xpub, input) {
                Err(e) => return Err(VerifyV6SignatureError::Derivation(e)),
                Ok(Some(pubkey)) => pubkey,
                Ok(None) => return Ok(false), // No matching derivation path for this xpub
            };

        self.verify_v6_signature_with_pub(secp, input_index, &derived_pubkey)
    }

    /// Build the finalized transparent transaction: clone the skeleton and fill each input's
    /// scriptSig from the collected `partial_sigs`, in the redeem script's pubkey order
    /// (`OP_0 <sig> <sig> <redeemScript>` for a 2-of-3 P2SH multisig). Zcash transparent inputs are
    /// non-segwit, so this produces a complete scriptSig with no witness.
    pub(crate) fn finalized_transparent_tx(&self) -> Result<Transaction, String> {
        use crate::fixed_script_wallet::wallet_scripts::parse_multisig_script_2_of_3;
        use miniscript::bitcoin::blockdata::opcodes::all::OP_PUSHBYTES_0;
        use miniscript::bitcoin::script::{Builder, PushBytesBuf};

        let mut tx = self.psbt.unsigned_tx.clone();
        for (i, txin) in tx.input.iter_mut().enumerate() {
            let input = self
                .psbt
                .inputs
                .get(i)
                .ok_or_else(|| format!("input {i}: no matching PSBT input"))?;
            let redeem_script = input
                .redeem_script
                .as_ref()
                .ok_or_else(|| format!("input {i}: no redeem script (expected P2SH multisig)"))?;
            let pubkeys = parse_multisig_script_2_of_3(redeem_script)
                .map_err(|e| format!("input {i}: {e}"))?;
            const REQUIRED_SIGS: usize = 2;

            // OP_0 (the multisig off-by-one dummy), then exactly REQUIRED_SIGS signatures in pubkey
            // order. Pushing every collected signature would break a 2-of-3 input signed by all
            // three keys: OP_CHECKMULTISIG pops exactly 2 and the extra push fails the script.
            let mut builder = Builder::new().push_opcode(OP_PUSHBYTES_0);
            let mut sig_count = 0usize;
            for pk in &pubkeys {
                if sig_count == REQUIRED_SIGS {
                    break;
                }
                if let Some(sig) = input
                    .partial_sigs
                    .get(&miniscript::bitcoin::PublicKey::from(*pk))
                {
                    let mut buf = PushBytesBuf::new();
                    buf.extend_from_slice(&sig.to_vec())
                        .map_err(|e| format!("input {i}: sig too large: {e}"))?;
                    builder = builder.push_slice(&buf);
                    sig_count += 1;
                }
            }
            if sig_count < REQUIRED_SIGS {
                return Err(format!(
                    "input {i}: only {sig_count} of {REQUIRED_SIGS} required signatures collected"
                ));
            }
            let mut rs = PushBytesBuf::new();
            rs.extend_from_slice(redeem_script.as_bytes())
                .map_err(|e| format!("input {i}: redeem script too large: {e}"))?;
            builder = builder.push_slice(&rs);
            txin.script_sig = builder.into_script();
        }
        Ok(tx)
    }

    /// Transaction Extractor role for a transparent-only v6 transaction: no shielded
    /// output was ever added to this PSBT, so there is no PCZT and nothing to combine an
    /// external proof into. Finalizes the transparent inputs (enforcing the same 2-of-3
    /// signature threshold [`Self::combine_ironwood_proof`] does) and encodes a v6 transaction
    /// with an empty (zero-action) Ironwood bundle slot — a structurally valid ZIP-244 encoding
    /// (see `zcash::v6::round_trip_empty_ironwood_slot`).
    ///
    /// Does not consume `self` and is not terminal: unlike [`Self::combine_ironwood_proof`],
    /// there is no stored PCZT to drop, so calling this more than once is safe and simply
    /// re-finalizes the same already-signed inputs.
    ///
    /// # Errors
    /// Returns an error if a shielded output was ever added to this PSBT — even one already
    /// extracted via [`Self::combine_ironwood_proof`] — since such a PSBT's ZIP-244 digest
    /// commits to real action data and must go through `combine_ironwood_proof` instead. Also
    /// errors if any transparent input is missing a required signature.
    pub fn extract_transparent_only_v6_tx(&self) -> Result<Vec<u8>, String> {
        if !self.require_no_shielded_output_ever_added()? {
            return Err(
                "this v6 PSBT carries a shielded output (or had one extracted); use \
                 combine_ironwood_proof instead"
                    .to_string(),
            );
        }
        let transparent = self.finalized_transparent_tx()?;
        let tx = self.to_v6_transaction(transparent, None)?;
        crate::zcash::v6::encode_v6_transaction(&tx).map_err(|e| e.to_string())
    }

    /// Serialize a v6 PSBT to bytes: a plain PSBT carrying the transparent skeleton in
    /// `unsigned_tx` and the shielded state (PCZT, branch id, v6 params) in the proprietary map.
    pub fn serialize_v6(&self) -> Vec<u8> {
        self.psbt.serialize()
    }

    /// Deserialize a v6 PSBT produced by [`Self::serialize_v6`], restoring the v6 header params from
    /// the proprietary map. Requires the Ironwood PCZT (i.e. [`Self::add_ironwood_output`] must
    /// already have been called) — use [`Self::deserialize_v6_pre_shield`] to load a v6 PSBT
    /// that doesn't have one yet.
    pub fn deserialize_v6(
        bytes: &[u8],
        network: crate::Network,
    ) -> Result<Self, super::DeserializeError> {
        Self::decode_v6(bytes, network, true)
    }

    /// Deserialize a v6 PSBT that may not yet carry its Ironwood PCZT — for tooling (e.g. the
    /// CLI) that builds the transparent skeleton (inputs/outputs) across separate
    /// serialize/deserialize round-trips before calling [`Self::add_ironwood_output`], unlike the
    /// in-process microservice flow [`Self::deserialize_v6`] otherwise assumes. Still validates
    /// the v6 params and consensus branch id, so a bare transparent skeleton round-trips exactly
    /// like a fully-shielded one.
    pub fn deserialize_v6_pre_shield(
        bytes: &[u8],
        network: crate::Network,
    ) -> Result<Self, super::DeserializeError> {
        Self::decode_v6(bytes, network, false)
    }

    fn decode_v6(
        bytes: &[u8],
        network: crate::Network,
        require_pczt: bool,
    ) -> Result<Self, super::DeserializeError> {
        let psbt = Psbt::deserialize(bytes)?;
        let (version_group_id, expiry_height) = super::propkv::get_zec_v6_params(&psbt)
            .ok_or_else(|| {
                super::DeserializeError::Network(
                    "PSBT is missing the ZecV6Params proprietary key (not a v6 PSBT)".to_string(),
                )
            })?;
        // Validate rather than trust: an unchecked version_group_id would leave
        // `is_ironwood_v6()` false on a PSBT that just came out of `deserialize_v6`, which would
        // then route `serialize` back down the v4 path.
        if version_group_id != crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID {
            return Err(super::DeserializeError::Network(format!(
                "PSBT declares version_group_id {:#010x}, expected the Ironwood id {:#010x}",
                version_group_id,
                crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID
            )));
        }
        // Defense-in-depth: a v6 PSBT missing these would otherwise deserialize fine and only fail
        // later, in v6_txid/combine_ironwood_proof, with a less obvious error.
        if super::propkv::get_zec_v6_consensus_branch_id(&psbt).is_none() {
            return Err(super::DeserializeError::Network(
                "v6 PSBT is missing its consensus branch id".to_string(),
            ));
        }
        if require_pczt && super::propkv::get_ironwood_pczt(&psbt).is_none() {
            return Err(super::DeserializeError::Network(
                "v6 PSBT is missing its Ironwood PCZT".to_string(),
            ));
        }
        if !require_pczt && super::propkv::is_ironwood_extracted(&psbt) {
            return Err(super::DeserializeError::Network(
                "v6 PSBT is missing its Ironwood PCZT after extraction".to_string(),
            ));
        }
        // Rule 0 (plan §3): a v6 PSBT carries either transparent inputs or shielded spends,
        // never both. The shielded side of the rule lives in
        // `add_shielded_spends` (transparent-input check) and the generic input adders'
        // Zcash arms; this closes the deserialize hole a PSBT could be edited through.
        if !psbt.inputs.is_empty() {
            if let Some(pczt_bytes) = super::propkv::get_ironwood_pczt(&psbt) {
                let pczt =
                    crate::zcash::ironwood_pczt::deserialize_pczt(&pczt_bytes).map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "v6 PSBT's Ironwood PCZT is invalid: {e}"
                        ))
                    })?;
                if Self::bundle_has_real_spends(&pczt) {
                    return Err(super::DeserializeError::Network(
                        "v6 PSBT mixes transparent inputs with shielded spends (one input \
                         kind per transaction)"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(ZcashBitGoPsbt {
            psbt,
            network,
            version_group_id: Some(version_group_id),
            expiry_height: Some(expiry_height),
            sapling_fields: Vec::new(),
        })
    }
}

impl BitGoPsbt {
    /// Reject v6 (Ironwood) PSBTs on the v4/Sapling-shaped paths, with a message explaining which
    /// dedicated method to use instead. [`Self::sign`] applies the same rule, but its `SignError`
    /// return type carries no message, so the `String`-returning wrappers check here as well.
    pub(crate) fn ensure_not_ironwood_v6(&self) -> Result<(), String> {
        match self {
            BitGoPsbt::Zcash(z, _) if z.is_ironwood_v6() => {
                Err(V6_NOT_SUPPORTED_BY_V4_PATH.to_string())
            }
            _ => Ok(()),
        }
    }
}

/// [`BitGoPsbt::new_zcash_v6`]: an empty v6 (Ironwood) PSBT with an explicit consensus branch
/// id. Delegates to [`ZcashBitGoPsbt::new_v6`].
pub(crate) fn new_bitgo_psbt_v6(
    network: Network,
    wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
    consensus_branch_id: u32,
    lock_time: Option<u32>,
    expiry_height: Option<u32>,
) -> BitGoPsbt {
    BitGoPsbt::Zcash(
        ZcashBitGoPsbt::new_v6(
            network,
            wallet_keys,
            consensus_branch_id,
            lock_time,
            expiry_height,
        ),
        network,
    )
}

/// [`BitGoPsbt::new_zcash_v6_at_height`]: an empty v6 (Ironwood) PSBT with the consensus branch
/// id resolved from block height. Delegates to [`ZcashBitGoPsbt::new_v6_at_height`].
pub(crate) fn new_bitgo_psbt_v6_at_height(
    network: Network,
    wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
    block_height: u32,
    lock_time: Option<u32>,
    expiry_height: Option<u32>,
) -> Result<BitGoPsbt, String> {
    Ok(BitGoPsbt::Zcash(
        ZcashBitGoPsbt::new_v6_at_height(
            network,
            wallet_keys,
            block_height,
            lock_time,
            expiry_height,
        )?,
        network,
    ))
}

/// The caller-supplied Unified Address for a transparent output, if `add_transparent_output`
/// was given one for `output_index` — `None` for non-Zcash PSBTs or outputs without one.
///
/// Mirrors the Zcash parse's treatment of shielded outputs' stored UAs: the
/// caller-supplied UA, not a bare address reconstructed from the scriptPubKey alone, is
/// what a client actually pasted in.
pub(crate) fn transparent_output_address_override(
    psbt: &BitGoPsbt,
    output_index: usize,
) -> Option<String> {
    let BitGoPsbt::Zcash(z, _) = psbt else {
        return None;
    };
    super::propkv::get_transparent_output_unified_address(&z.psbt, output_index)
}

/// The txid bytes of a Zcash PSBT's unsigned transaction: the ZIP-244 digest for a v6
/// (Ironwood) PSBT, the v4 wire-format hash otherwise.
pub(crate) fn unsigned_txid_bytes(zcash_psbt: &ZcashBitGoPsbt) -> [u8; 32] {
    // A v6 (Ironwood) PSBT's txid is the ZIP-244 digest over the transparent skeleton plus
    // shielded action data — the v4/Sapling path in the `else` branch builds an invalid
    // transaction for it (wrong wire format entirely), so it must not be used there.
    if zcash_psbt.is_ironwood_v6() {
        zcash_psbt
            .unsigned_v6_txid()
            .expect("Failed to compute v6 (Ironwood) txid")
    } else {
        zcash_psbt
            .compute_txid()
            .expect("Failed to compute Zcash txid")
    }
}
