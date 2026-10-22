//! Ironwood (shielded) PSBT methods: PCZT plumbing, out_ciphertexts, spend info,
//! ZIP-317 accounting and proof combination.
//!
//! Split verbatim out of the former monolithic `zcash_psbt.rs`.

use miniscript::bitcoin::Transaction;

use super::{BitGoPsbt, ZcashBitGoPsbt};

/// One requested Ironwood shielded output, as passed to
/// [`ZcashBitGoPsbt::add_ironwood_outputs`].
#[derive(Clone)]
pub struct IronwoodOutputRequest {
    /// 43-byte raw Orchard/Ironwood address.
    pub recipient: crate::zcash::ironwood_build::OrchardAddressBytes,
    /// Note value in zatoshi.
    pub amount: u64,
    /// Outgoing viewing key, if the output should be recoverable by the sender; `None` for a
    /// keyless build. Only survives if signatures are added directly via
    /// [`ZcashBitGoPsbt::add_v6_transparent_signature`]: [`ZcashBitGoPsbt::sign_ironwood_v6`]'s
    /// first round re-encrypts every action's `out_ciphertext` under the wallet `ovk`, replacing
    /// whatever this produced — in the normal signing flow it has no effect.
    pub ovk: Option<crate::zcash::ironwood_build::OvkBytes>,
    /// ZIP-302 memo field.
    pub memo: crate::zcash::ironwood_build::MemoBytes,
    /// Full Unified Address this output was addressed to, if the caller wants it preserved. If
    /// given, must be a Unified Address whose Orchard receiver is exactly `recipient` — it is
    /// stored verbatim, keyed by this output's action index (see
    /// [`super::propkv::set_ironwood_unified_address`]), so that output parsing can later return
    /// the original multi-receiver UA rather than reconstructing a single-receiver one from
    /// `recipient` alone, which drops any transparent/Sapling receiver the caller's UA carried.
    pub unified_address: Option<String>,
}

/// One Ironwood note to spend, as passed to
/// [`ZcashBitGoPsbt::add_ironwood_spends`]/[`ZcashBitGoPsbt::add_ironwood_actions`].
///
/// `recipient`/`value`/`rho`/`rseed`/`cmx` are note plaintext from the wallet's own note record;
/// `witness` comes from the note-commitment tree. The FVK is passed transiently to the Constructor
/// (to check note ownership and derive the nullifier) and omitted from the serialized PCZT; its
/// `ak` is used as the placeholder `rk` until the signer delivers the randomized one
/// (see [`ZcashBitGoPsbt::replace_ironwood_spend_rk`]).
#[derive(Clone)]
pub struct IronwoodSpendRequest {
    /// Raw full viewing key, 96 bytes: `ak ‖ nk ‖ rivk` (orchard's `FullViewingKey::to_bytes`
    /// layout). All spends in one bundle must share the same FVK.
    pub fvk: crate::zcash::ironwood_build::FvkBytes,
    /// The spent note's recipient: 43-byte raw Orchard/Ironwood address.
    pub recipient: crate::zcash::ironwood_build::OrchardAddressBytes,
    /// Note value in zatoshi.
    pub value: u64,
    /// The spent note's `rho` — the nullifier of the action that created the note.
    pub rho: [u8; 32],
    /// The spent note's random seed.
    pub rseed: [u8; 32],
    /// The note commitment the spent note's on-chain action carried; the reconstructed note must
    /// commit to exactly this.
    pub cmx: [u8; 32],
    /// Merkle witness for `cmx` at the bundle's anchor.
    pub witness: crate::zcash::ironwood_build::IronwoodWitness,
}

/// One real spend in the bundle, for the caller's accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IronwoodSpendInfo {
    /// Action index the spend landed at in the bundle.
    pub action_index: usize,
    /// Note value in zatoshi.
    pub value: u64,
    /// The nullifier this spend reveals (committed in the action data).
    pub nullifier: [u8; 32],
    /// Raw 43-byte Orchard recipient of the spent note.
    pub recipient: crate::zcash::ironwood_build::OrchardAddressBytes,
    /// Whether the signer replaced the Constructor's placeholder `rk` (the wire marker).
    pub rk_replaced: bool,
    /// Whether a spend-auth signature is installed.
    pub signed: bool,
}

impl From<&crate::zcash::ironwood_verify::VerifiedSpend> for IronwoodSpendInfo {
    fn from(spend: &crate::zcash::ironwood_verify::VerifiedSpend) -> Self {
        IronwoodSpendInfo {
            action_index: spend.action_index,
            value: spend.value,
            nullifier: spend.nullifier,
            recipient: spend.recipient,
            rk_replaced: spend.randomizer_installed,
            signed: spend.signed,
        }
    }
}

/// The spend/output/fee accounting view of the stored PCZT: real spends, real outputs, the
/// bundle's value balance, and the transaction-level fee.
///
/// `BundleType::UNPADDED` ⇒ no padding actions: each action pairs one real spend with one real
/// output, one real spend with a dummy output (spend-only), or a dummy spend with one real
/// output (output-only). A spend is fabricated iff it carries a `dummy_sk`; an output is
/// fabricated iff it is zero-valued and paired with a real spend (see
/// [`ZcashBitGoPsbt::ironwood_shielded_outputs_info`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IronwoodBundleInfo {
    pub spends: Vec<IronwoodSpendInfo>,
    /// `(action_index, value, recipient)` per real output — the same shape
    /// [`ZcashBitGoPsbt::ironwood_shielded_outputs_info`] returns.
    pub outputs: Vec<(
        usize,
        u64,
        crate::zcash::ironwood_build::OrchardAddressBytes,
    )>,
    /// The bundle's value balance in zatoshi: `Σv_spend − Σv_out` (negative when the shielded
    /// pool gains value).
    pub value_balance: i64,
    /// Total transparent-input value in zatoshi.
    pub transparent_in: i64,
    /// Total transparent-output value in zatoshi.
    pub transparent_out: i64,
    /// `(transparent_in + Σv_spend) − (transparent_out + Σv_out)` in zatoshi — the fee. A
    /// negative value means the transaction does not conserve value;
    /// [`ZcashBitGoPsbt::combine_ironwood_proof`] rejects it.
    pub fee: i64,
}

impl ZcashBitGoPsbt {
    /// Constructor role: build the shielded output(s) as a single orchard PCZT and store it in the
    /// PSBT. One Ironwood note is produced per entry of `requests`, each paired with a fabricated
    /// dummy spend; `anchor` (the current Ironwood note-commitment-tree root) is shared by all of
    /// them.
    ///
    /// Ordering relative to the transparent inputs/outputs does not matter — the shielded action
    /// data does not depend on them — but the sighash does, so all transparent I/O must be in place
    /// before signing.
    ///
    /// Only one call to this (or [`Self::add_ironwood_output`]) is supported per PSBT — calling it
    /// again is an error rather than a silent overwrite of the first batch (whose value the
    /// transparent side would still be funding). Multiple recipients in one transaction must
    /// therefore all be passed in a single `requests` slice.
    ///
    /// Returns the action index assigned to each request, in the same order as `requests` — the
    /// orchard builder pads/reorders actions, so request order does not equal action order. Any
    /// caller correlating per-action data (a stored Unified Address, an explicit
    /// [`Self::set_ironwood_out_ciphertext`] call) must use these indices, not the request index —
    /// though note [`Self::sign_ironwood_v6`]'s first round already patches every action's
    /// `out_ciphertext` with the wallet `ovk` on its own.
    pub fn add_ironwood_outputs<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        requests: &[IronwoodOutputRequest],
        anchor: &crate::zcash::ironwood_build::AnchorBytes,
        rng: R,
    ) -> Result<Vec<usize>, String> {
        if requests.is_empty() {
            return Err("at least one Ironwood output is required".to_string());
        }
        let action_map = self.add_ironwood_actions(&[], requests, anchor, rng)?;
        Ok(action_map.output_action_indices().to_vec())
    }

    /// Constructor role: build a single shielded output as an orchard PCZT and store it in the
    /// PSBT. A thin wrapper over [`Self::add_ironwood_outputs`]; see it for the general (and
    /// multi-recipient) contract, including the "only one call per PSBT" rule.
    #[allow(clippy::too_many_arguments)]
    pub fn add_ironwood_output<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        recipient: &crate::zcash::ironwood_build::OrchardAddressBytes,
        amount: u64,
        ovk: Option<crate::zcash::ironwood_build::OvkBytes>,
        anchor: &crate::zcash::ironwood_build::AnchorBytes,
        memo: &crate::zcash::ironwood_build::MemoBytes,
        unified_address: Option<&str>,
        rng: R,
    ) -> Result<usize, String> {
        let output_indices = self.add_ironwood_outputs(
            &[IronwoodOutputRequest {
                recipient: *recipient,
                amount,
                ovk,
                memo: *memo,
                unified_address: unified_address.map(str::to_string),
            }],
            anchor,
            rng,
        )?;
        Ok(output_indices[0])
    }

    /// Constructor role: build an orchard PCZT from real Ironwood spends and/or requested shielded
    /// outputs, and store it in the PSBT — the general form of [`Self::add_ironwood_outputs`],
    /// covering unshielding (spends only), shielded-to-shielded transfer, and shielding (outputs
    /// only — what [`Self::add_ironwood_outputs`] delegates to).
    ///
    /// Only one call to this (or [`Self::add_ironwood_outputs`]/[`Self::add_ironwood_spends`]) is
    /// supported per PSBT — calling it again is an error rather than a silent overwrite of the
    /// first batch (whose value the transparent side would still be funding). Multiple spends and
    /// outputs in one transaction must all be passed in this single call.
    ///
    /// The returned [`IronwoodActionMap`](crate::zcash::ironwood_build::IronwoodActionMap) gives,
    /// for each `spends[i]`/`outputs[i]`, the action index it landed at in the bundle — the
    /// orchard builder reorders actions (see
    /// [`crate::zcash::ironwood_build::construct_spend_pczt_multi`]), so request order does not
    /// equal action order.
    ///
    /// Real spends leave the placeholder `rk` (= the spend's `ak`) in the stored PCZT.
    pub fn add_ironwood_actions<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        spends: &[IronwoodSpendRequest],
        outputs: &[IronwoodOutputRequest],
        anchor: &crate::zcash::ironwood_build::AnchorBytes,
        rng: R,
    ) -> Result<crate::zcash::ironwood_build::IronwoodActionMap, String> {
        use crate::zcash::{ironwood_build, ironwood_pczt};

        if super::propkv::get_ironwood_pczt(&self.psbt).is_some() {
            return Err(
                "an Ironwood PCZT is already present; only one call is supported".to_string(),
            );
        }
        if spends.is_empty() && outputs.is_empty() {
            return Err("at least one Ironwood spend or output is required".to_string());
        }
        if !spends.is_empty() {
            for (i, req) in outputs.iter().enumerate() {
                if req.ovk.is_some() {
                    return Err(format!(
                        "output {i}: an explicit ovk is not supported in a bundle with real \
                         spends; the spending FVK's external ovk is used"
                    ));
                }
            }
        }
        for req in outputs {
            if let Some(ua) = &req.unified_address {
                self.check_unified_address_matches_recipient(ua, &req.recipient)?;
            }
        }

        let spend_specs: Vec<ironwood_build::IronwoodSpendSpec> = spends
            .iter()
            .map(|req| ironwood_build::IronwoodSpendSpec {
                fvk: req.fvk,
                recipient: req.recipient,
                value: req.value,
                rho: req.rho,
                rseed: req.rseed,
                cmx: req.cmx,
                witness: req.witness,
            })
            .collect();
        let output_specs: Vec<ironwood_build::IronwoodOutputSpec> = outputs
            .iter()
            .map(|req| ironwood_build::IronwoodOutputSpec {
                recipient: req.recipient,
                amount: req.amount,
                ovk: req.ovk,
                memo: req.memo,
            })
            .collect();
        let (pczt, action_map) =
            ironwood_build::construct_spend_pczt_multi(&spend_specs, &output_specs, anchor, rng)
                .map_err(|e| e.to_string())?;
        let bytes = ironwood_pczt::serialize_pczt(&pczt).map_err(|e| e.to_string())?;
        super::propkv::set_ironwood_pczt(&mut self.psbt, bytes);
        // Clear any UAs left over from a previous batch (this can run again on a PSBT whose PCZT
        // was previously extracted — mark_ironwood_extracted/take_ironwood_pczt drop only the
        // PCZT key, not these) before writing the new batch's, so a since-gone action index's
        // stale UA can never be silently misattributed to a different recipient in the new bundle.
        super::propkv::clear_ironwood_unified_addresses(&mut self.psbt);
        for (i, req) in outputs.iter().enumerate() {
            if let Some(ua) = &req.unified_address {
                let action_index = action_map
                    .output_action_index(i)
                    .ok_or_else(|| format!("output {i}: no action index"))?;
                super::propkv::set_ironwood_unified_address(&mut self.psbt, action_index, ua);
            }
        }
        Ok(action_map)
    }

    /// Reject a caller-supplied Unified Address whose Orchard receiver is not exactly `recipient`:
    /// it is stored verbatim and later returned by output parsing in place of `recipient`.
    fn check_unified_address_matches_recipient(
        &self,
        ua: &str,
        recipient: &crate::zcash::ironwood_build::OrchardAddressBytes,
    ) -> Result<(), String> {
        let parsed =
            crate::zcash::unified_address::UnifiedAddress::parse(ua, self.network.to_coin_name())
                .map_err(|e| format!("invalid unified_address: {e}"))?;
        let orchard = parsed
            .orchard_receiver()
            .map_err(|e| format!("invalid unified_address: {e}"))?
            .ok_or_else(|| {
                "unified_address has no Orchard receiver, but recipient is an Orchard address"
                    .to_string()
            })?;
        if orchard.as_slice() != recipient.as_slice() {
            return Err("unified_address's Orchard receiver does not match recipient".to_string());
        }
        Ok(())
    }

    /// Constructor role: build real Ironwood spends (no shielded outputs) as an orchard PCZT and
    /// store it in the PSBT. A thin wrapper over [`Self::add_ironwood_actions`]; see it for the
    /// general contract, including the "only one call per PSBT" rule.
    pub fn add_ironwood_spends<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        requests: &[IronwoodSpendRequest],
        anchor: &crate::zcash::ironwood_build::AnchorBytes,
        rng: R,
    ) -> Result<Vec<usize>, String> {
        if requests.is_empty() {
            return Err("at least one Ironwood spend is required".to_string());
        }
        let action_map = self.add_ironwood_actions(requests, &[], anchor, rng)?;
        Ok(action_map.spend_action_indices().to_vec())
    }

    /// Deserialize the stored orchard PCZT.
    pub(crate) fn ironwood_pczt(&self) -> Result<orchard::pczt::Bundle, String> {
        let bytes = super::propkv::get_ironwood_pczt(&self.psbt)
            .ok_or_else(|| "no Ironwood PCZT stored in PSBT".to_string())?;
        crate::zcash::ironwood_pczt::deserialize_pczt(&bytes).map_err(|e| e.to_string())
    }

    /// The raw serialized orchard PCZT bytes stored in the proprietary map, or `None` if absent
    /// (before [`Self::add_ironwood_output`], or after [`Self::combine_ironwood_proof`] drops it).
    pub fn raw_ironwood_pczt_bytes(&self) -> Option<Vec<u8>> {
        super::propkv::get_ironwood_pczt(&self.psbt)
    }

    /// The number of real (non-dummy) Ironwood spends and outputs in the stored PCZT; `(0, 0)`
    /// when no shielded spend or output was ever added.
    ///
    /// The Constructor builds `BundleType::UNPADDED` bundles, so the action count is
    /// `max(spends, outputs)`. Once the PCZT has been extracted (see
    /// [`Self::mark_ironwood_extracted`]) the counts recorded at extraction are returned, so a
    /// finalized PSBT still reports its actions.
    pub fn ironwood_real_spend_and_output_counts(&self) -> Result<(usize, usize), String> {
        if !super::propkv::has_ironwood_pczt(&self.psbt)
            && super::propkv::is_ironwood_extracted(&self.psbt)
        {
            let (spends, outputs) = super::propkv::get_ironwood_extracted_counts(&self.psbt)
                .ok_or_else(|| {
                    "this PSBT's Ironwood PCZT was extracted without recording its action counts"
                        .to_string()
                })?;
            return Ok((spends as usize, outputs as usize));
        }
        if self.require_no_shielded_output_ever_added()? {
            return Ok((0, 0));
        }
        self.pczt_real_spend_and_output_counts()
    }

    fn pczt_real_spend_and_output_counts(&self) -> Result<(usize, usize), String> {
        let report = self.keyless_verify_info()?;
        Ok((report.spends.len(), report.outputs.len()))
    }

    /// Client-managed `ovk`, raw-key form: re-encrypt the Ironwood output's `out_ciphertext` under
    /// an `ovk` derived as the ECDH agreement of `bitgo_pubkey` and `user_privkey`. The `ovk` never
    /// leaves this call — it is not returned and not persisted anywhere.
    ///
    /// Prefer [`Self::set_ironwood_out_ciphertext_for_user`], which is the same operation with the
    /// key pair taken from the wallet's own keys and validated. This raw form cannot check that the
    /// bytes it was handed are the canonical pair (the BitGo *root* pubkey and the user *root*
    /// privkey — see [`crate::zcash::ironwood_build::derive_client_ovk`]), so passing anything else
    /// yields an `ovk` the server cannot re-derive and the user cannot recover the note with, with
    /// no error at any layer.
    ///
    /// `out_ciphertext` is committed by the ZIP-244 sighash, so this must run **before** any
    /// transparent signature is collected: once a signature exists, changing `out_ciphertext` would
    /// silently invalidate it (the signature would no longer match the sighash a verifier
    /// recomputes), so this rejects rather than allowing that. Call this immediately after
    /// [`Self::add_ironwood_output`]/[`Self::deserialize_v6`] and before
    /// [`Self::v6_transparent_sighash`]/[`Self::add_v6_transparent_signature`].
    ///
    /// Normally you do not call this per action at all: [`Self::sign_ironwood_v6`]'s first round
    /// patches **every** action's `out_ciphertext` with the wallet `ovk` automatically (and
    /// idempotently — same ovk ⇒ same bytes). An explicit call is only needed to pre-finalize under
    /// a different `ovk`, and note that a first-round `sign_ironwood_v6` then overwrites it; a
    /// custom-`ovk` ciphertext can only survive if signatures are added directly via
    /// [`Self::add_v6_transparent_signature`], bypassing `sign_ironwood_v6`.
    ///
    /// `action_index` is the index a shielded output landed at in the bundle — for a
    /// multi-recipient build via [`Self::add_ironwood_outputs`], this is the value returned
    /// alongside it by [`Self::ironwood_shielded_outputs_info`], not necessarily the position the
    /// output was passed in at (see [`crate::zcash::ironwood_build::construct_shield_pczt_multi`]
    /// for why actions get reordered).
    pub fn set_ironwood_out_ciphertext(
        &mut self,
        action_index: usize,
        bitgo_pubkey: &[u8],
        user_privkey: &[u8],
    ) -> Result<(), String> {
        use crate::zcash::{ironwood_build, ironwood_pczt};

        if self
            .psbt
            .inputs
            .iter()
            .any(|input| !input.partial_sigs.is_empty())
        {
            return Err(
                "cannot set out_ciphertext after a transparent signature has been collected: \
                 out_ciphertext is sighash-committed, so this would invalidate it; call \
                 set_ironwood_out_ciphertext before signing"
                    .to_string(),
            );
        }

        let bytes = super::propkv::get_ironwood_pczt(&self.psbt)
            .ok_or_else(|| "no Ironwood PCZT stored in PSBT".to_string())?;
        let pczt = ironwood_pczt::deserialize_pczt(&bytes).map_err(|e| e.to_string())?;
        let ovk = ironwood_build::derive_client_ovk(bitgo_pubkey, user_privkey)
            .map_err(|e| e.to_string())?;
        let out_ciphertext = ironwood_build::compute_out_ciphertext(
            &pczt,
            action_index,
            ovk,
            &mut rand::rngs::OsRng,
        )
        .map_err(|e| e.to_string())?;

        let patched = ironwood_pczt::with_out_ciphertext(&bytes, action_index, out_ciphertext)
            .map_err(|e| e.to_string())?;
        super::propkv::set_ironwood_pczt(&mut self.psbt, patched);
        Ok(())
    }

    /// Client-managed `ovk`, wallet-key form: re-encrypt the Ironwood output's `out_ciphertext`
    /// under the `ovk` for *this wallet*, derived as
    /// `ECDH(root_wallet_keys.bitgo_key(), user_xpriv)` — both root keys, so the `ovk` does not
    /// depend on which inputs the transaction spends, and the server can re-derive the identical
    /// value from `ECDH(bitgo_root_privkey, user_root_pubkey)` in order to validate
    /// `out_ciphertext` before it countersigns.
    ///
    /// `user_xpriv` must be the wallet's user root key: this rejects any other key (the backup or
    /// BitGo key, or an unrelated xpriv) rather than deriving an `ovk` from it, since such an `ovk`
    /// is one neither the user nor the server can reproduce and the mistake is otherwise invisible —
    /// the transaction still broadcasts, and the outgoing note is simply never recoverable.
    ///
    /// See [`Self::set_ironwood_out_ciphertext`] for the sighash-ordering constraint, which applies
    /// here too.
    pub fn set_ironwood_out_ciphertext_for_user<C>(
        &mut self,
        action_index: usize,
        user_xpriv: &miniscript::bitcoin::bip32::Xpriv,
        root_wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        secp: &miniscript::bitcoin::secp256k1::Secp256k1<C>,
    ) -> Result<(), String>
    where
        C: miniscript::bitcoin::secp256k1::Signing,
    {
        use zeroize::Zeroizing;

        Self::check_user_root_key(user_xpriv, root_wallet_keys, secp)?;
        let bitgo_pubkey = root_wallet_keys.bitgo_key().public_key.serialize();
        let user_privkey = Zeroizing::new(user_xpriv.private_key.secret_bytes());
        self.set_ironwood_out_ciphertext(action_index, &bitgo_pubkey, user_privkey.as_slice())
    }

    /// Reject any `user_xpriv` that is not this wallet's user root key — the only key whose ECDH
    /// agreement with the BitGo root key yields an `ovk` both the user and the server can reproduce.
    pub(crate) fn check_user_root_key<C>(
        user_xpriv: &miniscript::bitcoin::bip32::Xpriv,
        root_wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        secp: &miniscript::bitcoin::secp256k1::Secp256k1<C>,
    ) -> Result<(), String>
    where
        C: miniscript::bitcoin::secp256k1::Signing,
    {
        use miniscript::bitcoin::bip32::Xpub;

        let expected = root_wallet_keys.user_key().public_key;
        if Xpub::from_priv(secp, user_xpriv).public_key != expected {
            return Err(
                "out_ciphertext's ovk must be derived from this wallet's user root key: the key \
                 given is not it (the backup and BitGo keys derive an ovk neither the user nor the \
                 server can reproduce, which would leave the shielded output permanently \
                 unrecoverable)"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Whether `pczt` has real spends. Real spends have no `dummy_sk`; the builder marks
    /// fabricated padding spends with one. Other note plaintext fields may also be present on
    /// dummies, so they are not reliable discriminators.
    pub(crate) fn bundle_has_real_spends(pczt: &orchard::pczt::Bundle) -> bool {
        pczt.actions()
            .iter()
            .any(|a| a.spend().dummy_sk().is_none())
    }

    /// Render an Ironwood signing-hook error, naming the action for an out-of-range index.
    fn ironwood_action_error(
        action_index: usize,
    ) -> impl Fn(crate::zcash::ironwood_build::IronwoodBuildError) -> String {
        move |e| match e {
            crate::zcash::ironwood_build::IronwoodBuildError::ActionIndexOutOfRange => {
                format!("action {action_index} out of range")
            }
            e => e.to_string(),
        }
    }

    /// Ingest the randomized `rk = ak.randomize(alpha)` for one real spend, replacing the
    /// placeholder the Constructor left in the stored PCZT.
    ///
    /// Must run before any signature over the ZIP-244 digest exists — the digest commits `rk` — so
    /// this is rejected once a transparent signature has been collected (the same ordering
    /// contract [`Self::set_ironwood_out_ciphertext`] enforces) or a spend-auth signature has been
    /// applied. Re-delivering the same `rk` is idempotent; delivering the placeholder itself (the
    /// spend's unrandomized `ak`) is rejected. The bundle-level rules are shared with
    /// [`crate::zcash::ironwood_build::set_spend_auth_randomizer`].
    pub fn replace_ironwood_spend_rk(
        &mut self,
        action_index: usize,
        rk: [u8; 32],
    ) -> Result<(), String> {
        use crate::zcash::{ironwood_build, ironwood_pczt};

        if self
            .psbt
            .inputs
            .iter()
            .any(|input| !input.partial_sigs.is_empty())
        {
            return Err(
                "cannot replace a spend's rk after a transparent signature has been collected: \
                 rk is sighash-committed, so this would invalidate it"
                    .to_string(),
            );
        }

        let bytes = super::propkv::get_ironwood_pczt(&self.psbt)
            .ok_or_else(|| "no Ironwood PCZT stored in PSBT".to_string())?;
        let pczt = ironwood_pczt::deserialize_pczt(&bytes).map_err(|e| e.to_string())?;
        ironwood_build::check_spend_rk_replaceable(&pczt, action_index, &rk)
            .map_err(Self::ironwood_action_error(action_index))?;

        let patched =
            ironwood_pczt::with_spend_rk(&bytes, action_index, rk).map_err(|e| e.to_string())?;
        super::propkv::set_ironwood_pczt(&mut self.psbt, patched);
        Ok(())
    }

    /// Apply the RedPallas `spend_auth_sig` for one real spend, after verifying
    /// it against that spend's (already replaced) `rk` over the ZIP-244 sig digest. A rejected
    /// signature is not stored.
    pub fn apply_ironwood_spend_signature(
        &mut self,
        action_index: usize,
        sig: [u8; 64],
    ) -> Result<(), String> {
        use crate::zcash::{ironwood_build, ironwood_pczt};

        let bytes = super::propkv::get_ironwood_pczt(&self.psbt)
            .ok_or_else(|| "no Ironwood PCZT stored in PSBT".to_string())?;
        let mut pczt = ironwood_pczt::deserialize_pczt(&bytes).map_err(|e| e.to_string())?;
        // Gate before the sighash: it is not final while any real spend's rk is the placeholder.
        ironwood_build::require_spend_rks_replaced(&pczt).map_err(|e| e.to_string())?;

        let (amounts, scripts) = self.transparent_input_amounts_and_scripts()?;
        let bundle = ironwood_build::pczt_action_data(&pczt).map_err(|e| e.to_string())?;
        let tx = self.to_v6_transaction(self.psbt.unsigned_tx.clone(), Some(bundle))?;
        let sighash = crate::zcash::v6::compute_v6_sig_digest(&tx, &amounts, &scripts);

        // The shared signing-time role: re-checks the placeholder gate (a RedPallas signature
        // made with alpha = 0 verifies against rk = ak) and runs orchard's verify-before-store.
        ironwood_build::apply_spend_signature(&mut pczt, action_index, sighash, &sig)
            .map_err(Self::ironwood_action_error(action_index))?;

        let patched = ironwood_pczt::serialize_pczt(&pczt).map_err(|e| e.to_string())?;
        super::propkv::set_ironwood_pczt(&mut self.psbt, patched);
        Ok(())
    }

    /// The shielded action-data view of the stored PCZT (commitments/ciphertexts/flags/value/anchor;
    /// no proof or signatures). This is what the ZIP-244 txid and sighash commit to.
    pub fn ironwood_action_data(&self) -> Result<crate::zcash::v6::IronwoodBundle, String> {
        crate::zcash::ironwood_build::pczt_action_data(&self.ironwood_pczt()?)
            .map_err(|e| e.to_string())
    }

    /// [`Self::ironwood_action_data`], but only once it is final enough to sign: errors while any
    /// real spend's `rk` is still the Constructor's placeholder, since the ZIP-244 digest commits
    /// `rk`.
    pub(crate) fn final_ironwood_action_data(
        &self,
    ) -> Result<crate::zcash::v6::IronwoodBundle, String> {
        use crate::zcash::ironwood_build::{self, IronwoodBuildError};

        let pczt = self.ironwood_pczt()?;
        match ironwood_build::require_spend_rks_replaced(&pczt) {
            Ok(()) => {}
            Err(IronwoodBuildError::PlaceholderRkNotReplaced) => {
                return Err(
                    "this PSBT spends real Ironwood notes whose rk is still the placeholder: the \
                     signer must deliver the randomized rk (replace_ironwood_spend_rk) \
                     before any sighash is computed — the ZIP-244 digest commits rk"
                        .to_string(),
                )
            }
            Err(e) => return Err(e.to_string()),
        }
        ironwood_build::pczt_action_data(&pczt).map_err(|e| e.to_string())
    }

    /// Distinguishes "no shielded output has ever been added" (`Ok(true)`) from "a shielded output
    /// is currently present" (`Ok(false)`) from "one was added and then extracted via
    /// [`Self::combine_ironwood_proof`]/`mark_ironwood_extracted`" (`Err`) — the latter two look
    /// identical as bare PCZT-presence (`None` either way), but only "never added" is safe to
    /// treat as "there is no shielded output here". Call this before trusting an absent PCZT to
    /// mean that.
    pub(crate) fn require_no_shielded_output_ever_added(&self) -> Result<bool, String> {
        if super::propkv::has_ironwood_pczt(&self.psbt) {
            return Ok(false);
        }
        if super::propkv::is_ironwood_extracted(&self.psbt) {
            return Err(
                "this PSBT's Ironwood PCZT has already been extracted (via combine_ironwood_proof); \
                 its shielded output data is gone, not merely absent"
                    .to_string(),
            );
        }
        Ok(true)
    }

    /// The keyless verification of the stored PCZT (plan §5): run every check a party
    /// without viewing keys can run before surfacing any plaintext value, so a tampered
    /// bundle fails loudly with the failing check instead of leaking unverified plaintext.
    /// Verification only reads the PCZT: its plaintext stays in place for the prover.
    ///
    /// The stored spend-validating key (plan PR 5's `0x08` key) is passed through when
    /// present; until then the `Rk` check is skipped and only the key-free checks run.
    pub(crate) fn keyless_verify(
        &self,
        pczt: &orchard::pczt::Bundle,
    ) -> Result<
        crate::zcash::ironwood_verify::IronwoodVerificationReport,
        crate::zcash::ironwood_build::IronwoodVerifyError,
    > {
        let ctx = crate::zcash::ironwood_verify::KeylessVerifyContext {
            stored_ak: super::propkv::get_ironwood_spend_validating_key(&self.psbt),
            ..Default::default()
        };
        crate::zcash::ironwood_verify::verify_bundle_without_keys(pczt, &ctx)
    }

    /// The String-flavored keyless verification of the stored PCZT the info accessors use;
    /// the Zcash parse calls [`Self::keyless_verify`] to keep the failing check's error code.
    fn keyless_verify_info(
        &self,
    ) -> Result<crate::zcash::ironwood_verify::IronwoodVerificationReport, String> {
        self.keyless_verify(&self.ironwood_pczt()?)
            .map_err(|e| e.to_string())
    }

    /// The action index, value (zatoshi), and raw 43-byte recipient of every shielded Ironwood
    /// output added via [`Self::add_ironwood_output`]/[`Self::add_ironwood_outputs`] — empty if no
    /// shielded output is present yet.
    ///
    /// The shielded side lives in a proprietary-map PCZT rather than `unsigned_tx.output`, so
    /// transparent-only output parsing (`ParsedOutput`/`sum_output_values`) never sees it; this is
    /// how callers surface it explicitly for spend/fee accounting.
    ///
    /// The recipient is readable here — unlike the on-wire `IronwoodAction`
    /// ([`crate::zcash::ironwood_build::action_to_ironwood`], which only carries the *encrypted*
    /// note — because the PCZT keeps the Constructor's plaintext `recipient`/`value` fields
    /// in-memory for the Prover/Signer roles; nothing needs decrypting.
    ///
    /// Only real requested outputs are returned. Bundles are built with `BundleType::UNPADDED`, so
    /// (per `orchard`'s cross-address-disabled pairing) a shielding-only bundle pairs a fabricated
    /// *dummy spend* with every real output, while a bundle with more real spends than outputs
    /// pairs the surplus spends with fabricated zero-valued *dummy outputs* — those are filtered
    /// out (a zero-valued output paired with a real spend). Use
    /// [`Self::ironwood_shielded_spends_info`] for the spend side.
    ///
    /// The returned action index is what [`super::propkv::get_ironwood_unified_address`] is keyed
    /// by, for callers that want the original Unified Address (if one was stored) rather than just
    /// the raw recipient.
    ///
    /// Errors (rather than returning empty) if the PCZT is absent because it was already
    /// extracted — see [`Self::require_no_shielded_output_ever_added`].
    pub fn ironwood_shielded_outputs_info(
        &self,
    ) -> Result<
        Vec<(
            usize,
            u64,
            crate::zcash::ironwood_build::OrchardAddressBytes,
        )>,
        String,
    > {
        if self.require_no_shielded_output_ever_added()? {
            return Ok(Vec::new());
        }
        let report = self.keyless_verify_info()?;
        Ok(report
            .outputs
            .into_iter()
            .map(|output| (output.action_index, output.value, output.recipient))
            .collect())
    }

    /// The action index, value (zatoshi), and nullifier of every real Ironwood spend added via
    /// [`Self::add_ironwood_spends`]/[`Self::add_ironwood_actions`] — empty if no shielded data is
    /// present yet (or the bundle only shields).
    ///
    /// Like the outputs, the spends live in the proprietary-map PCZT rather than
    /// `unsigned_tx.input`, so transparent-only input parsing never sees them; callers fold these
    /// values into their input totals for fee accounting.
    ///
    /// Errors (rather than returning empty) if the PCZT is absent because it was already
    /// extracted — see [`Self::require_no_shielded_output_ever_added`].
    pub fn ironwood_shielded_spends_info(&self) -> Result<Vec<IronwoodSpendInfo>, String> {
        if self.require_no_shielded_output_ever_added()? {
            return Ok(Vec::new());
        }
        let report = self.keyless_verify_info()?;
        Ok(report.spends.iter().map(IronwoodSpendInfo::from).collect())
    }

    /// The spend/output/fee accounting for the bundle behind this PSBT — see
    /// [`IronwoodBundleInfo`]. `value_balance`/`fee` come from the bundle's committed
    /// `value_sum`, cross-checked against the plaintext note values. Errors if the PCZT is
    /// absent (no spend/output was ever added, or it was already extracted).
    pub fn ironwood_bundle_info(&self) -> Result<IronwoodBundleInfo, String> {
        if self.require_no_shielded_output_ever_added()? {
            return Err("no Ironwood PCZT stored in PSBT".to_string());
        }
        // The keyless verifier (plan §5) runs every key-free check — including `ValueSum`,
        // which cross-checks the committed `value_sum` against the plaintext note values —
        // before any accounting flows out of here. The plaintext note values are NOT bound
        // after deserialization: the proofs bind only `cv_net`/`cm`.
        let report = self.keyless_verify_info()?;
        let spends = report
            .spends
            .iter()
            .map(IronwoodSpendInfo::from)
            .collect::<Vec<_>>();
        let outputs = report
            .outputs
            .iter()
            .map(|output| (output.action_index, output.value, output.recipient))
            .collect::<Vec<_>>();
        // The bundle's committed value balance (the wire `value_sum`): the quantity the IO
        // Finalizer enforces against the proof-bound `cv_net`s and the ZIP-244 digest commits.
        let value_balance = report.value_balance;
        let transparent_in = self
            .transparent_input_amounts_and_scripts()?
            .0
            .iter()
            .sum::<i64>();
        let transparent_out = self
            .psbt
            .unsigned_tx
            .output
            .iter()
            .map(|o| {
                i64::try_from(o.value.to_sat())
                    .map_err(|_| "transparent output value exceeds i64 range".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .sum::<i64>();
        // The fee composes the committed shielded balance with the transparent sides, in checked
        // arithmetic: consensus-impossible magnitudes error instead of wrapping.
        let fee = transparent_in
            .checked_sub(transparent_out)
            .and_then(|net| net.checked_add(value_balance))
            .ok_or_else(|| "transaction value magnitudes exceed the i64 fee range".to_string())?;
        Ok(IronwoodBundleInfo {
            spends,
            outputs,
            value_balance,
            transparent_in,
            transparent_out,
            fee,
        })
    }

    /// Fail before the (expensive) shielded finalize/proof/combine when the transaction doesn't
    /// conserve value: a negative fee means outputs exceed inputs. Anchored to the bundle's
    /// committed `value_sum` — see [`Self::ironwood_bundle_info`].
    fn check_ironwood_value_conservation(&self) -> Result<(), String> {
        let info = self.ironwood_bundle_info()?;
        if info.fee < 0 {
            return Err(format!(
                "transaction does not conserve value: fee {} zatoshi < 0",
                info.fee
            ));
        }
        Ok(())
    }

    /// The ZIP-317 transparent terms `(tx_in_total_size, tx_out_total_size)`: the estimated
    /// **final** serialized sizes of the transparent inputs (each carrying the scriptSig the
    /// PSBT's scripts will produce, see [`estimated_script_sig_len`]) and the exact serialized
    /// sizes of the transparent outputs.
    pub fn zip317_transparent_sizes(&self) -> (u64, u64) {
        let tx_in_total_size = self
            .psbt
            .inputs
            .iter()
            .map(|input| {
                crate::zcash::zip317::transparent_input_size(estimated_script_sig_len(input))
            })
            .sum();
        let tx_out_total_size = self
            .psbt
            .unsigned_tx
            .output
            .iter()
            .map(|output| crate::zcash::zip317::transparent_output_size(output.script_pubkey.len()))
            .sum();
        (tx_in_total_size, tx_out_total_size)
    }

    /// The ZIP-317 logical-action counts for this PSBT — see [`crate::zcash::zip317`].
    ///
    /// The transparent terms come from [`Self::zip317_transparent_sizes`]. The shielded term is
    /// the Ironwood action count, `max(real spends, real outputs)` of the stored PCZT (zero when
    /// none is stored); v6 transactions have no Sapling or JoinSplit components.
    pub fn zip317_action_counts(&self) -> Result<crate::zcash::zip317::Zip317ActionCounts, String> {
        let (tx_in_total_size, tx_out_total_size) = self.zip317_transparent_sizes();
        let (spends, outputs) = self.ironwood_real_spend_and_output_counts()?;
        Ok(crate::zcash::zip317::Zip317ActionCounts {
            tx_in_total_size,
            tx_out_total_size,
            n_actions_ironwood: spends.max(outputs) as u64,
            ..Default::default()
        })
    }

    /// The ZIP-317 conventional fee (zatoshi) for this PSBT's shape. Opt-in: nothing in the
    /// transparent-only fee path calls it.
    pub fn zip317_conventional_fee(&self) -> Result<u64, String> {
        Ok(crate::zcash::zip317::conventional_fee(
            &self.zip317_action_counts()?,
        ))
    }

    /// The spent-output value (zatoshi, as i64) and scriptPubKey of every transparent input, in
    /// input order — the amounts/scripts ZIP-244 commits to.
    pub(crate) fn transparent_input_amounts_and_scripts(
        &self,
    ) -> Result<(Vec<i64>, Vec<miniscript::bitcoin::ScriptBuf>), String> {
        let mut amounts = Vec::with_capacity(self.psbt.inputs.len());
        let mut scripts = Vec::with_capacity(self.psbt.inputs.len());
        for (i, input) in self.psbt.inputs.iter().enumerate() {
            // `psbt.inputs` and `unsigned_tx.input` are parallel vectors by PSBT invariant, but a
            // skew here would be a WASM abort rather than a JS exception, so surface it as an error.
            let prevout = self
                .psbt
                .unsigned_tx
                .input
                .get(i)
                .ok_or_else(|| format!("input {i}: no matching tx input"))?
                .previous_output;
            let (script, value) =
                super::psbt_wallet_input::get_output_script_and_value(input, prevout)
                    .map_err(|e| format!("input {i}: missing UTXO value/script: {e}"))?;
            amounts.push(
                i64::try_from(value.to_sat())
                    .map_err(|_| format!("input {i}: transparent value out of i64 range"))?,
            );
            scripts.push(script.clone());
        }
        Ok((amounts, scripts))
    }

    /// Assemble a [`ZcashV6Transaction`] from the transparent skeleton plus the given Ironwood
    /// bundle (action-data-only for digests, or fully authorized for extraction).
    pub(crate) fn to_v6_transaction(
        &self,
        transparent: Transaction,
        ironwood_bundle: Option<crate::zcash::v6::IronwoodBundle>,
    ) -> Result<crate::zcash::v6::ZcashV6Transaction, String> {
        let consensus_branch_id = super::propkv::get_zec_v6_consensus_branch_id(&self.psbt)
            .ok_or_else(|| "missing consensus_branch_id".to_string())?;
        Ok(crate::zcash::v6::ZcashV6Transaction {
            version_group_id: crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID,
            consensus_branch_id,
            transparent,
            expiry_height: self.expiry_height.unwrap_or(0),
            sapling_value_balance: 0,
            ironwood_bundle,
        })
    }

    /// Transaction Extractor role: given the external prover's `proof` bytes, finalize the
    /// transparent inputs, apply the shielded binding signature, and produce the broadcast-ready v6
    /// transaction bytes.
    ///
    /// The PSBT must already carry every transparent input's signatures (via
    /// [`Self::add_v6_transparent_signature`]) and the PCZT (from [`Self::add_ironwood_output`]).
    /// `rng` seeds both the dummy spend-auth signature (in the IO finalizer) and the binding
    /// signature (in the Transaction Extractor). Consumes `self`.
    pub fn combine_ironwood_proof<R: rand::RngCore + rand::CryptoRng>(
        self,
        proof: Vec<u8>,
        mut rng: R,
    ) -> Result<Vec<u8>, String> {
        use crate::zcash::{ironwood_build, ironwood_pczt};

        // Finalize the transparent inputs first: it enforces the 2-of-3 signature threshold, so an
        // under-signed PSBT fails here instead of after the (expensive) shielded finalize/combine.
        let transparent = self.finalized_transparent_tx()?;

        // The shielded binding signature signs the ZIP-244 sig digest over the complete tx
        // (transparent I/O + shielded action data). Signatures/proof are excluded from that digest,
        // so it is stable regardless of transparent-input signing.
        let (amounts, scripts) = self.transparent_input_amounts_and_scripts()?;
        let action_bundle = self.ironwood_action_data()?;
        let sig_tx = self.to_v6_transaction(self.psbt.unsigned_tx.clone(), Some(action_bundle))?;
        let sighash = crate::zcash::v6::compute_v6_sig_digest(&sig_tx, &amounts, &scripts);

        // Pre-flight value-conservation guard, shared with the local-combine path.
        self.check_ironwood_value_conservation()?;

        // Signer + IO finalizer: sign the dummy spend(s) and derive the binding signing key.
        let mut pczt = self.ironwood_pczt()?;
        ironwood_build::finalize_shield_io(&mut pczt, sighash, &mut rng)
            .map_err(|e| e.to_string())?;

        // Splice in the external proof, then run the Transaction Extractor.
        let signed_bytes = ironwood_pczt::serialize_pczt(&pczt).map_err(|e| e.to_string())?;
        let proven = ironwood_pczt::deserialize_pczt(
            &ironwood_pczt::with_zkproof(&signed_bytes, proof).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let full_bundle =
            ironwood_build::combine(&proven, sighash, &mut rng).map_err(|e| e.to_string())?;

        let tx = self.to_v6_transaction(transparent, Some(full_bundle))?;
        crate::zcash::v6::encode_v6_transaction(&tx).map_err(|e| e.to_string())
    }

    /// Like [`Self::combine_ironwood_proof`], but produces the `zkproof` itself (via
    /// [`crate::zcash::ironwood_build::create_proof`]) rather than requiring it from an external
    /// proof service. Behind the `orchard-proving` feature — standalone tooling (e.g. the CLI)
    /// that has no external proof service to call can enable it; the shipped WASM build must not,
    /// since it would link the halo2 circuit into every consumer. Consumes `self`.
    #[cfg(feature = "orchard-proving")]
    pub fn combine_ironwood_proof_locally<R: rand::RngCore + rand::CryptoRng>(
        self,
        rng: R,
    ) -> Result<Vec<u8>, String> {
        self.combine_ironwood_proof_locally_with_alphas(&[], None, rng)
    }

    /// Spend-bundle variant of [`Self::combine_ironwood_proof_locally`]: the Prover role derives
    /// `rk` inside the circuit from `ak` + `alpha`, so proving a bundle with real spends requires
    /// each spend's `alpha` — delivered here as `(action_index, alpha)` pairs — and the spending
    /// FVK, which the Constructor scrubbed from the stored PCZT ("the FVK never leaves its
    /// holder": the local prover *is* the holder, so it passes its own FVK here; a remote keyed
    /// prover supplies the equivalent out-of-band). Both are patched into the in-memory PCZT
    /// only and never reach the PSBT or the produced transaction.
    #[cfg(feature = "orchard-proving")]
    pub fn combine_ironwood_proof_locally_with_alphas<R: rand::RngCore + rand::CryptoRng>(
        self,
        alphas: &[(usize, [u8; 32])],
        spending_fvk: Option<&crate::zcash::ironwood_build::FvkBytes>,
        mut rng: R,
    ) -> Result<Vec<u8>, String> {
        use crate::zcash::{ironwood_build, ironwood_pczt};

        let transparent = self.finalized_transparent_tx()?;

        let (amounts, scripts) = self.transparent_input_amounts_and_scripts()?;
        let action_bundle = self.ironwood_action_data()?;
        let sig_tx = self.to_v6_transaction(self.psbt.unsigned_tx.clone(), Some(action_bundle))?;
        let sighash = crate::zcash::v6::compute_v6_sig_digest(&sig_tx, &amounts, &scripts);

        // Same pre-flight guard as the external-proof path: fail before the (expensive) local
        // proof generation when the transaction doesn't conserve value.
        self.check_ironwood_value_conservation()?;

        // Patch the alphas into the wire form (transiently — the result is consumed in-memory
        // and never stored back into the PSBT).
        let mut bytes = super::propkv::get_ironwood_pczt(&self.psbt)
            .ok_or_else(|| "no Ironwood PCZT stored in PSBT".to_string())?;
        for (action_index, alpha) in alphas {
            bytes = ironwood_pczt::with_spend_alpha(&bytes, *action_index, Some(*alpha))
                .map_err(|e| e.to_string())?;
        }
        if let Some(fvk) = spending_fvk {
            // The prover needs the FVK on every real spend to derive `ak`/`nk`; dummy spends
            // keep their fabricating FVK (the IO Finalizer signs them with it).
            bytes = ironwood_pczt::with_spend_fvk_on_real_spends(&bytes, *fvk)
                .map_err(|e| e.to_string())?;
        }
        let mut pczt = ironwood_pczt::deserialize_pczt(&bytes).map_err(|e| e.to_string())?;

        ironwood_build::finalize_shield_io(&mut pczt, sighash, &mut rng)
            .map_err(|e| e.to_string())?;
        ironwood_build::create_proof(&mut pczt, &mut rng).map_err(|e| e.to_string())?;
        let full_bundle =
            ironwood_build::combine(&pczt, sighash, &mut rng).map_err(|e| e.to_string())?;

        let tx = self.to_v6_transaction(transparent, Some(full_bundle))?;
        crate::zcash::v6::encode_v6_transaction(&tx).map_err(|e| e.to_string())
    }

    /// Mark this v6 PSBT as extracted by dropping its PCZT, making [`Self::combine_ironwood_proof`]
    /// terminal for callers that cannot consume the PSBT by value (the wasm bindings, which must
    /// clone). Any later Ironwood operation then fails with "no Ironwood PCZT stored in PSBT"
    /// instead of silently re-running against already-extracted state — and because the PCZT is
    /// gone from the bytes too, that holds across a `serialize`/`deserialize` round-trip.
    ///
    /// The PCZT's real spend/output counts are recorded first, so ZIP-317 fee estimation
    /// ([`Self::zip317_action_counts`]) keeps working on the extracted PSBT.
    ///
    /// Returns whether a PCZT was present.
    pub fn mark_ironwood_extracted(&mut self) -> bool {
        if let Ok((spends, outputs)) = self.pczt_real_spend_and_output_counts() {
            super::propkv::set_ironwood_extracted_counts(
                &mut self.psbt,
                spends as u32,
                outputs as u32,
            );
        }
        super::propkv::take_ironwood_pczt(&mut self.psbt)
    }
}

/// The estimated length of the FINAL scriptSig a transparent input will carry, for ZIP-317's
/// size-based input accounting — exact once the input is finalized.
///
/// BitGo wallet inputs are P2SH 2-of-3 multisig: the scriptSig is
/// `OP_0 <sig> <sig> <redeemScript>`, so it is sized from the actual redeem script. A P2SH-P2PK
/// replay-protection input (redeem script `<pubkey> OP_CHECKSIG`) carries `<sig> <redeemScript>`
/// instead. See [`crate::zcash::zip317`] for the signature-size convention.
pub(crate) fn estimated_script_sig_len(input: &crate::bitcoin::psbt::Input) -> usize {
    use crate::zcash::zip317;
    // A finalized input carries its real scriptSig (and the finalizer clears `redeem_script`).
    if let Some(script_sig) = &input.final_script_sig {
        return script_sig.len();
    }
    match &input.redeem_script {
        Some(redeem) if BitGoPsbt::extract_pubkey_from_p2pk_redeem_script(redeem).is_ok() => {
            zip317::p2sh_p2pk_script_sig_len(redeem.len())
        }
        Some(redeem) => zip317::p2sh_multisig_script_sig_len(redeem.len()),
        None => zip317::p2pkh_script_sig_len(),
    }
}
