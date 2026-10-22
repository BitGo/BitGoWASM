//! The Ironwood **spend** PSBT workflow: the keyless Constructor entry point
//! ([`ZcashBitGoPsbt::add_shielded_spends`]) and the one-input-kind rule.
//!
//! The build service (IMS) selects notes and calls [`ZcashBitGoPsbt::add_shielded_spends`]
//! with the notes' plaintext, their witnesses, the KMS-derived nullifiers, the requested
//! outputs and the wallet's spend-validating key `ak` — and no viewing key. The constructed
//! PCZT is stored in the PSBT together with `ak` (proprietary key `0x08`), which the key-free
//! verifier reads for the `Rk` check, and the per-output Unified Addresses.
//!
//! One input kind: a v6 PSBT spends **either** transparent inputs (transparent v6 or
//! shielding) **or** shielded notes (deshield / shielded→shielded), never both. The shielded
//! side enforces it here ([`ZcashBitGoPsbt::add_shielded_spends`] rejects transparent
//! inputs); the transparent side enforces it in
//! [`ZcashBitGoPsbt::reject_transparent_input_with_spend_bundle`], which the generic input
//! adders call for their Zcash arms, and in `decode_v6` at deserialize time.

use super::error::IronwoodPsbtError;
use super::{IronwoodOutputRequest, ZcashBitGoPsbt};

impl ZcashBitGoPsbt {
    /// Constructor role: build the shielded spends (and optionally shielded outputs) as a
    /// single **keyless** orchard PCZT and store it in the PSBT — the deshield and
    /// shielded→shielded Constructor for a build service that holds no viewing keys.
    ///
    /// Each entry of `spends` carries the spent note's plaintext (`recipient`/`value`/`rho`/
    /// `rseed`/`cmx`), its Merkle witness, and the nullifier (from the note store, or from
    /// KMS's `generate-nullifiers`). Each entry of `outputs` is a requested shielded output
    /// (its `ovk` must be `None`: KMS owns encryption in the spend flow). The bundle has
    /// `max(spends, outputs)` actions; the actions are shuffled, so the returned
    /// [`IronwoodActionMap`](crate::zcash::ironwood_build::IronwoodActionMap) gives, for each
    /// `spends[i]`/`outputs[i]`, the action index it landed at.
    ///
    /// Every real spend carries the wallet's `ak` as the placeholder `rk` and no `alpha`; the
    /// signer installs `alpha` and the matching `rk = ak.randomize(alpha)` before any sighash
    /// is computed. Every output's `out_ciphertext` is a random placeholder —
    /// KMS replaces it under its FVK `ovk`. No FVK ever enters the stored
    /// PCZT.
    ///
    /// Rules enforced here:
    /// - **one input kind** — rejected when the PSBT already carries transparent inputs
    ///   ([`IronwoodPsbtError::MixedInputKinds`]);
    /// - **one call per PSBT** — a second call would silently overwrite the first batch
    ///   ([`IronwoodPsbtError::AlreadyAdded`]).
    ///
    /// Also stored: the caller's `ak` (proprietary key `0x08`) — the key-free verifier's `Rk`
    /// check reads it — each output's Unified Address, keyed by its action index, and the
    /// all-clear `out_ciphertext` bitset (proprietary key `0x09`).
    pub fn add_shielded_spends<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        spends: &[crate::zcash::ironwood_construct::IronwoodKeylessSpendSpec],
        outputs: &[IronwoodOutputRequest],
        anchor: &crate::zcash::ironwood_build::AnchorBytes,
        ak: &[u8; 32],
        rng: R,
    ) -> Result<crate::zcash::ironwood_build::IronwoodActionMap, IronwoodPsbtError> {
        use crate::zcash::{ironwood_build, ironwood_construct};

        // One input kind: a spend PSBT has no transparent inputs — the shielded side funds itself.
        if !self.psbt.inputs.is_empty() {
            return Err(IronwoodPsbtError::MixedInputKinds);
        }
        // One call per PSBT: a second batch would overwrite the first one's value.
        if super::propkv::get_ironwood_pczt(&self.psbt).is_some() {
            return Err(IronwoodPsbtError::AlreadyAdded);
        }
        for req in outputs {
            if let Some(ua) = &req.unified_address {
                self.check_unified_address_matches_recipient(ua, &req.recipient)
                    .map_err(IronwoodPsbtError::BadUnifiedAddress)?;
            }
        }

        let output_specs: Vec<ironwood_build::IronwoodOutputSpec> = outputs
            .iter()
            .map(|req| ironwood_build::IronwoodOutputSpec {
                recipient: req.recipient,
                amount: req.amount,
                ovk: req.ovk,
                memo: req.memo,
            })
            .collect();
        let (pczt, action_map) = ironwood_construct::construct_spend_pczt_keyless(
            spends,
            &output_specs,
            anchor,
            ak,
            rng,
        )?;
        let action_count = pczt.actions().len();
        let action_map =
            self.store_ironwood_pczt_and_unified_addresses(pczt, action_map, outputs)?;
        // The wallet's spend-validating key, for the key-free verifier's `Rk` check.
        super::propkv::set_ironwood_spend_validating_key(&mut self.psbt, ak);
        // Every real output starts pending its `out_ciphertext`: the
        // little-endian bitset over the bundle's actions starts all-clear, so
        // `pending_out_ciphertexts` reports the full request until KMS's ciphertexts land.
        super::propkv::set_ironwood_out_ciphertexts_set(
            &mut self.psbt,
            vec![0u8; action_count.div_ceil(8)],
        );
        Ok(action_map)
    }

    /// The one-input-kind rule on the transparent side: reject adding a transparent input to a PSBT
    /// whose stored Ironwood bundle already spends real (non-dummy) notes.
    ///
    /// A stored PCZT with only dummy spends — the **shielding** flow — is fine: transparent
    /// inputs funding shielded outputs is exactly what that flow builds. Called by the
    /// generic input adders' Zcash arms ([`super::super::BitGoPsbt::add_input_at_index`],
    /// `add_wallet_input_at_index`, `add_replay_protection_input_at_index`).
    pub(crate) fn reject_transparent_input_with_spend_bundle(&self) -> Result<(), String> {
        let Some(bytes) = super::propkv::get_ironwood_pczt(&self.psbt) else {
            return Ok(());
        };
        let pczt = crate::zcash::ironwood_pczt::deserialize_pczt(&bytes).map_err(|e| {
            format!(
                "cannot check the one-input-kind rule: the stored Ironwood PCZT is invalid: {e}"
            )
        })?;
        if Self::bundle_has_real_spends(&pczt) {
            return Err(
                "cannot add a transparent input to a v6 PSBT that already spends shielded \
                 notes (one input kind per transaction); build the shielded spend in a PSBT \
                 without transparent inputs"
                    .to_string(),
            );
        }
        Ok(())
    }

    // ---- The KMS out_ciphertext / proof workflow ----

    /// The stored PCZT, raw and deserialized, or [`IronwoodPsbtError::NotSpendBundle`] if
    /// absent.
    fn stored_ironwood_pczt(&self) -> Result<(Vec<u8>, orchard::pczt::Bundle), IronwoodPsbtError> {
        let bytes = super::propkv::get_ironwood_pczt(&self.psbt)
            .ok_or(IronwoodPsbtError::NotSpendBundle)?;
        let pczt = crate::zcash::ironwood_pczt::deserialize_pczt(&bytes)?;
        Ok((bytes, pczt))
    }

    /// The action indices of every real (requested, non-dummy) output, classified from the
    /// plaintext the way the key-free verifier does: a dummy spend's output is always real,
    /// and a real spend's output is real unless it is the fabricated value-0 one. An output
    /// with no plaintext value counts as real, so the ciphertexts-first gate fails closed.
    ///
    /// The ciphertexts-first gate runs on bundles mid-way through the signer's randomizer writes,
    /// which the full verifier rejects, so it uses this classification alone; the paths that hand
    /// data to KMS run the verifier first.
    fn real_output_indices(pczt: &orchard::pczt::Bundle) -> Vec<usize> {
        pczt.actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| {
                action.spend().dummy_sk().is_some()
                    || action
                        .output()
                        .value()
                        .as_ref()
                        .is_none_or(|value| value.inner() != 0)
            })
            .map(|(action_index, _)| action_index)
            .collect()
    }

    /// [`Self::pending_out_ciphertexts`] over an already-deserialized PCZT.
    ///
    /// Only spend bundles are tracked: shielding finalizes its ciphertexts at signing. A spend
    /// bundle without the [`ZecV6KeySubtype::IronwoodOutCiphertextsSet`] bitset counts every real
    /// output as pending — both Constructors always write it, so a missing bitset means the key was
    /// stripped, and failing closed keeps the ciphertexts-first gate from being skipped that way.
    ///
    /// [`ZecV6KeySubtype::IronwoodOutCiphertextsSet`]: super::propkv::ZecV6KeySubtype::IronwoodOutCiphertextsSet
    fn pending_out_ciphertexts_in(
        &self,
        pczt: &orchard::pczt::Bundle,
    ) -> Result<Vec<usize>, IronwoodPsbtError> {
        if !Self::bundle_has_real_spends(pczt) {
            return Ok(Vec::new());
        }
        let bits = super::propkv::get_ironwood_out_ciphertexts_set(&self.psbt).unwrap_or_default();
        Ok(Self::real_output_indices(pczt)
            .into_iter()
            .filter(|&action_index| !bitset_contains(&bits, action_index))
            .collect())
    }

    /// The real outputs whose `out_ciphertext` is still pending. Empty for a
    /// bundle with no real spends (shielding).
    pub fn pending_out_ciphertexts(&self) -> Result<Vec<usize>, IronwoodPsbtError> {
        let (_, pczt) = self.stored_ironwood_pczt()?;
        self.pending_out_ciphertexts_in(&pczt)
    }

    /// The KMS out-ciphertext request: the raw PCZT bytes plus the real
    /// outputs still pending their `out_ciphertext`. KMS decrypts nothing here — it
    /// re-encrypts each pending output under its FVK `ovk` and returns one 80-byte
    /// ciphertext per action index, applied with [`Self::add_out_ciphertexts`].
    ///
    /// Errors with [`IronwoodPsbtError::NotSpendBundle`] when no PCZT is stored or the
    /// bundle is not a spend bundle, and with [`IronwoodPsbtError::NothingPending`] when
    /// every real output is already set (or there are none, as in a pure deshield).
    pub fn out_ciphertext_request(&self) -> Result<(Vec<u8>, Vec<usize>), IronwoodPsbtError> {
        let (bytes, pczt) = self.stored_ironwood_pczt()?;
        if !Self::bundle_has_real_spends(&pczt) {
            return Err(IronwoodPsbtError::NotSpendBundle);
        }
        self.keyless_verify(&pczt)
            .map_err(IronwoodPsbtError::Verify)?;
        let pending = self.pending_out_ciphertexts_in(&pczt)?;
        if pending.is_empty() {
            return Err(IronwoodPsbtError::NothingPending);
        }
        Ok((bytes, pending))
    }

    /// The ciphertexts-first gate for the sighash, randomizer and proof paths: every real output
    /// of a spend bundle must have its `out_ciphertext` installed before anything commits
    /// the action data (the ZIP-244 digest commits `out_ciphertext`).
    ///
    /// No PCZT (a transparent-only v6 PSBT, or one already extracted) passes: the caller
    /// that needs a PCZT surfaces its own, more specific error.
    pub(crate) fn require_out_ciphertexts_set(&self) -> Result<(), IronwoodPsbtError> {
        match self.stored_ironwood_pczt() {
            Ok((_, pczt)) => self.require_out_ciphertexts_set_in(&pczt),
            Err(IronwoodPsbtError::NotSpendBundle) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// [`Self::require_out_ciphertexts_set`] over an already-deserialized PCZT.
    pub(crate) fn require_out_ciphertexts_set_in(
        &self,
        pczt: &orchard::pczt::Bundle,
    ) -> Result<(), IronwoodPsbtError> {
        let pending = self.pending_out_ciphertexts_in(pczt)?;
        if pending.is_empty() {
            return Ok(());
        }
        Err(IronwoodPsbtError::OutCiphertextPending {
            action_indices: pending,
        })
    }

    /// Randomizers installed: every real spend's randomized `rk` must be installed — the ZIP-244
    /// digest and the proof both commit to `rk`.
    fn require_randomizers_installed(
        pczt: &orchard::pczt::Bundle,
    ) -> Result<(), IronwoodPsbtError> {
        use crate::zcash::ironwood_build::IronwoodBuildError;

        let mut pending = Vec::new();
        for (action_index, action) in pczt.actions().iter().enumerate() {
            let spend = action.spend();
            if spend.dummy_sk().is_some() {
                continue;
            }
            if !crate::zcash::ironwood_pczt::spend_rk_replaced(spend)
                .map_err(IronwoodBuildError::PcztWire)?
            {
                pending.push(action_index);
            }
        }
        if pending.is_empty() {
            return Ok(());
        }
        Err(IronwoodPsbtError::RandomizerPending {
            action_indices: pending,
        })
    }

    /// The bundle is frozen once a spend-auth signature exists — or, as
    /// defense in depth, once any transparent input carries a partial signature.
    fn require_unfrozen(&self, pczt: &orchard::pczt::Bundle) -> Result<(), IronwoodPsbtError> {
        let spend_signed = pczt
            .actions()
            .iter()
            .any(|action| action.spend().spend_auth_sig().is_some());
        let transparent_signed = self
            .psbt
            .inputs
            .iter()
            .any(|input| !input.partial_sigs.is_empty());
        if spend_signed || transparent_signed {
            return Err(IronwoodPsbtError::AlreadySigned);
        }
        Ok(())
    }

    /// Apply the KMS out-ciphertext response: one `(action_index,
    /// out_ciphertext)` pair per pending real output. **Atomic** — every entry is validated
    /// before anything is written, so one bad entry stores nothing.
    ///
    /// Each index must exist ([`IronwoodPsbtError::UnknownAction`]) and name a real output
    /// ([`IronwoodPsbtError::DummyAction`]). Re-delivering the bytes already installed — before
    /// this call or earlier in the same batch — is accepted; different bytes for an index that
    /// already has a ciphertext are rejected ([`IronwoodPsbtError::OutCiphertextConflict`]). Frozen
    /// once signed: rejected once any signature exists ([`IronwoodPsbtError::AlreadySigned`]). Only
    /// spend bundles take ciphertexts here ([`IronwoodPsbtError::NotSpendBundle`]).
    pub fn add_out_ciphertexts(
        &mut self,
        entries: &[(usize, crate::zcash::ironwood_build::OutCiphertextBytes)],
    ) -> Result<(), IronwoodPsbtError> {
        use crate::zcash::ironwood_build::OutCiphertextBytes;
        use crate::zcash::ironwood_pczt::with_out_ciphertext;

        let (bytes, pczt) = self.stored_ironwood_pczt()?;
        self.require_unfrozen(&pczt)?;
        if !Self::bundle_has_real_spends(&pczt) {
            return Err(IronwoodPsbtError::NotSpendBundle);
        }
        if entries.is_empty() {
            return Err(IronwoodPsbtError::NothingPending);
        }
        self.keyless_verify(&pczt)
            .map_err(IronwoodPsbtError::Verify)?;
        let real_outputs = Self::real_output_indices(&pczt);
        let mut bits =
            super::propkv::get_ironwood_out_ciphertexts_set(&self.psbt).unwrap_or_default();

        // Validate everything first: unknown, dummy, and conflicting entries reject the
        // whole batch without touching the PSBT.
        let mut installs: Vec<(usize, OutCiphertextBytes)> = Vec::new();
        for &(action_index, out_ciphertext) in entries {
            if action_index >= pczt.actions().len() {
                return Err(IronwoodPsbtError::UnknownAction);
            }
            if !real_outputs.contains(&action_index) {
                return Err(IronwoodPsbtError::DummyAction);
            }
            let installed = installs
                .iter()
                .find(|(index, _)| *index == action_index)
                .map(|(_, ciphertext)| *ciphertext)
                .or_else(|| {
                    bitset_contains(&bits, action_index).then(|| {
                        pczt.actions()[action_index]
                            .output()
                            .encrypted_note()
                            .out_ciphertext
                    })
                });
            match installed {
                Some(installed) if installed != out_ciphertext => {
                    return Err(IronwoodPsbtError::OutCiphertextConflict { action_index });
                }
                // Identical bytes: nothing to patch.
                Some(_) => {}
                None => installs.push((action_index, out_ciphertext)),
            }
        }
        if installs.is_empty() {
            return Ok(());
        }

        let mut patched = bytes;
        for (action_index, out_ciphertext) in installs {
            patched = with_out_ciphertext(&patched, action_index, out_ciphertext)?;
            bitset_set(&mut bits, action_index);
        }
        super::propkv::set_ironwood_pczt(&mut self.psbt, patched);
        super::propkv::set_ironwood_out_ciphertexts_set(&mut self.psbt, bits);
        Ok(())
    }

    /// Signed before proven: every real spend's `spend_auth_sig` must be installed — the proof is
    /// requested only once the wallet has signed, as shielding requests it only after its
    /// transparent signing rounds.
    fn require_spend_signatures(pczt: &orchard::pczt::Bundle) -> Result<(), IronwoodPsbtError> {
        let pending: Vec<usize> = pczt
            .actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| {
                action.spend().dummy_sk().is_none() && action.spend().spend_auth_sig().is_none()
            })
            .map(|(action_index, _)| action_index)
            .collect();
        if pending.is_empty() {
            return Ok(());
        }
        Err(IronwoodPsbtError::SpendSignaturePending {
            action_indices: pending,
        })
    }

    /// The proof request: the raw PCZT bytes, handed to the keyed prover at
    /// finalize time. The returned proof goes straight to [`Self::combine_ironwood_proof`];
    /// it is never stored in the PSBT.
    ///
    /// Every real output's `out_ciphertext`, every real spend's randomized `rk`, and every
    /// real spend's `spend_auth_sig` must be installed first. Signing
    /// freezes the bundle, so the proof is always made over the final action data. A
    /// shielding bundle has none of these, so it is served as-is.
    pub fn proof_request(&self) -> Result<Vec<u8>, IronwoodPsbtError> {
        let (bytes, pczt) = self.stored_ironwood_pczt()?;
        self.require_out_ciphertexts_set_in(&pczt)?;
        Self::require_randomizers_installed(&pczt)?;
        Self::require_spend_signatures(&pczt)?;
        Ok(bytes)
    }
}

/// Whether the little-endian bitset has bit `index` set (bit `i` = byte `i / 8`, mask
/// `1 << (i % 8)`); bytes beyond the stored length read as clear.
fn bitset_contains(bits: &[u8], index: usize) -> bool {
    bits.get(index / 8)
        .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
}

/// Set bit `index` in the little-endian bitset, growing it if needed.
fn bitset_set(bits: &mut Vec<u8>, index: usize) {
    if bits.len() <= index / 8 {
        bits.resize(index / 8 + 1, 0);
    }
    bits[index / 8] |= 1 << (index % 8);
}
