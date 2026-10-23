//! The Ironwood **spend** PSBT workflow: the keyless Constructor entry point
//! ([`ZcashBitGoPsbt::add_shielded_spends`]) and the one-input-kind rule.
//!
//! The caller selects notes and calls [`ZcashBitGoPsbt::add_shielded_spends`] with the notes'
//! plaintext, their witnesses, their nullifiers and the requested outputs — and no key at
//! all. The constructed PCZT is stored in the PSBT together with the
//! per-output Unified Addresses.
//!
//! The PSBT never carries the wallet's spend-validating key `ak`, nor the spends' randomizers
//! `alpha` (with the randomized `rk` an `alpha` would reveal `ak`): real spends start with the
//! fixed [`PLACEHOLDER_RK`](crate::zcash::ironwood_build::PLACEHOLDER_RK), the signer installs
//! only the randomized `rk` ([`ZcashBitGoPsbt::add_spend_randomizers`]), and the alphas reach
//! the prover out of band ([`ZcashBitGoPsbt::proof_request`]).
//!
//! One input kind: a v6 PSBT spends **either** transparent inputs (transparent v6 or
//! shielding) **or** shielded notes (deshield / shielded→shielded), never both. The shielded
//! side enforces it here ([`ZcashBitGoPsbt::add_shielded_spends`] rejects transparent
//! inputs); the transparent side enforces it in
//! [`ZcashBitGoPsbt::reject_transparent_input_with_spend_bundle`], which the generic input
//! adders call for their Zcash arms, and in `decode_v6` at deserialize time.

use super::error::IronwoodPsbtError;
use super::parse::ZcashShieldedSpend;
use super::{IronwoodOutputRequest, ZcashBitGoPsbt};

impl ZcashBitGoPsbt {
    /// Constructor role: build the shielded spends (and optionally shielded outputs) as a
    /// single **keyless** orchard PCZT and store it in the PSBT — the deshield and
    /// shielded→shielded Constructor for a caller that holds no viewing keys.
    ///
    /// Each entry of `spends` carries the spent note's plaintext (`recipient`/`value`/`rho`/
    /// `rseed`/`cmx`), its Merkle witness, and the nullifier (from the note store, or derived
    /// by the viewing-key holder). Each entry of `outputs` is a requested shielded output
    /// (its `ovk` must be `None`: encryption belongs to the viewing-key holder in the spend
    /// flow). The bundle has
    /// `max(spends, outputs)` actions; the actions are shuffled, so the returned
    /// [`IronwoodActionMap`](crate::zcash::ironwood_build::IronwoodActionMap) gives, for each
    /// `spends[i]`/`outputs[i]`, the action index it landed at.
    ///
    /// Every real spend carries [`PLACEHOLDER_RK`](crate::zcash::ironwood_build::PLACEHOLDER_RK)
    /// as its `rk` and no `alpha`; the signer installs the randomized `rk = ak.randomize(alpha)`
    /// before any sighash is computed. Every output's `out_ciphertext` is a random placeholder,
    /// replaced under the FVK's `ovk`. No FVK ever enters the stored
    /// PCZT.
    ///
    /// Rules enforced here:
    /// - **one input kind** — rejected when the PSBT already carries transparent inputs
    ///   ([`IronwoodPsbtError::MixedInputKinds`]);
    /// - **one call per PSBT** — a second call would silently overwrite the first batch
    ///   ([`IronwoodPsbtError::AlreadyAdded`]).
    ///
    /// Also stored: each output's Unified Address, keyed by its action index, and the
    /// all-clear `out_ciphertext` bitset (proprietary key `0x09`).
    pub fn add_shielded_spends<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        spends: &[crate::zcash::ironwood_construct::IronwoodKeylessSpendSpec],
        outputs: &[IronwoodOutputRequest],
        anchor: &crate::zcash::ironwood_build::AnchorBytes,
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
        let (pczt, action_map) =
            ironwood_construct::construct_spend_pczt_keyless(spends, &output_specs, anchor, rng)?;
        let action_count = pczt.actions().len();
        let action_map =
            self.store_ironwood_pczt_and_unified_addresses(pczt, action_map, outputs)?;
        // Every real output starts pending its `out_ciphertext`: the
        // little-endian bitset over the bundle's actions starts all-clear, so
        // `pending_out_ciphertexts` reports the full request until the ciphertexts land.
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

    // ---- The out_ciphertext / proof workflow ----

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
    /// the PCZT out run the verifier first.
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

    /// The out-ciphertext request: the raw PCZT bytes plus the real outputs still pending
    /// their `out_ciphertext`. The viewing-key holder decrypts nothing here — it re-encrypts each pending output under its FVK `ovk` and returns one 80-byte
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

    /// The real spends whose `rk` is still the placeholder.
    fn pending_randomizers_in(pczt: &orchard::pczt::Bundle) -> Vec<usize> {
        use crate::zcash::ironwood_build::spend_rk_is_placeholder;

        pczt.actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| {
                action.spend().dummy_sk().is_none() && spend_rk_is_placeholder(action.spend())
            })
            .map(|(action_index, _)| action_index)
            .collect()
    }

    /// Randomizers installed: every real spend's randomized `rk` must be installed before any
    /// sighash — the ZIP-244 digest and the proof both commit to `rk`.
    fn require_randomizers_installed(
        pczt: &orchard::pczt::Bundle,
    ) -> Result<(), IronwoodPsbtError> {
        let pending = Self::pending_randomizers_in(pczt);
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

    /// Apply the out-ciphertext response: one `(action_index,
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

    /// The real spends with no `spend_auth_sig` yet.
    fn pending_spend_signatures_in(pczt: &orchard::pczt::Bundle) -> Vec<usize> {
        pczt.actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| {
                action.spend().dummy_sk().is_none() && action.spend().spend_auth_sig().is_none()
            })
            .map(|(action_index, _)| action_index)
            .collect()
    }

    /// Signed before proven: every real spend's `spend_auth_sig` must be installed — the proof is
    /// requested only once the wallet has signed, as shielding requests it only after its
    /// transparent signing rounds.
    pub(crate) fn require_spend_signatures(
        pczt: &orchard::pczt::Bundle,
    ) -> Result<(), IronwoodPsbtError> {
        let pending = Self::pending_spend_signatures_in(pczt);
        if pending.is_empty() {
            return Ok(());
        }
        Err(IronwoodPsbtError::SpendSignaturePending {
            action_indices: pending,
        })
    }

    /// The proof request: the PCZT bytes handed to the keyed prover at finalize time, with
    /// each real spend's randomizer `alpha` patched in. The returned proof goes straight to
    /// [`Self::combine_ironwood_proof`]; it is never stored in the PSBT.
    ///
    /// Every real output's `out_ciphertext`, every real spend's randomized `rk`, and every
    /// real spend's `spend_auth_sig` must be installed first. Signing freezes the bundle, so
    /// the proof is always made over the final action data.
    ///
    /// The PSBT never stores `alpha` (with `rk` it would reveal the wallet's `ak`), so the
    /// caller supplies exactly one `(action_index, alpha)` per real spend: each index must
    /// exist ([`IronwoodPsbtError::UnknownAction`]), name a real spend
    /// ([`IronwoodPsbtError::DummyAction`]) and appear once
    /// ([`IronwoodPsbtError::DuplicateAction`]), every real spend must be covered
    /// ([`IronwoodPsbtError::RandomizerMissing`]), and each `alpha` must be a canonical,
    /// non-zero scalar. The alphas are written only to the returned bytes. A shielding bundle
    /// takes no alphas and is served as-is.
    pub fn proof_request(
        &self,
        alphas: &[(usize, [u8; 32])],
    ) -> Result<Vec<u8>, IronwoodPsbtError> {
        let (bytes, pczt) = self.stored_ironwood_pczt()?;
        self.require_out_ciphertexts_set_in(&pczt)?;
        Self::require_randomizers_installed(&pczt)?;
        Self::require_spend_signatures(&pczt)?;

        for &(action_index, _) in alphas {
            Self::require_real_spend(&pczt, action_index)?;
        }
        Self::require_distinct_actions(alphas.iter().map(|&(action_index, _)| action_index))?;
        let missing: Vec<usize> = pczt
            .actions()
            .iter()
            .enumerate()
            .filter(|&(action_index, action)| {
                action.spend().dummy_sk().is_none()
                    && !alphas.iter().any(|&(index, _)| index == action_index)
            })
            .map(|(action_index, _)| action_index)
            .collect();
        if !missing.is_empty() {
            return Err(IronwoodPsbtError::RandomizerMissing {
                action_indices: missing,
            });
        }
        if alphas.is_empty() {
            return Ok(bytes);
        }
        let with_alphas = crate::zcash::ironwood_build::with_spend_alphas(&pczt, alphas)?;
        Ok(crate::zcash::ironwood_pczt::serialize_pczt(&with_alphas)?)
    }

    /// The action exists ([`IronwoodPsbtError::UnknownAction`]) and is a real spend
    /// ([`IronwoodPsbtError::DummyAction`]).
    fn require_real_spend(
        pczt: &orchard::pczt::Bundle,
        action_index: usize,
    ) -> Result<(), IronwoodPsbtError> {
        let action = pczt
            .actions()
            .get(action_index)
            .ok_or(IronwoodPsbtError::UnknownAction)?;
        if action.spend().dummy_sk().is_some() {
            return Err(IronwoodPsbtError::DummyAction);
        }
        Ok(())
    }

    /// Reject a batch that names an action more than once.
    fn require_distinct_actions(
        indices: impl Iterator<Item = usize>,
    ) -> Result<(), IronwoodPsbtError> {
        let mut seen = Vec::new();
        for action_index in indices {
            if seen.contains(&action_index) {
                return Err(IronwoodPsbtError::DuplicateAction { action_index });
            }
            seen.push(action_index);
        }
        Ok(())
    }

    // ---- The randomizer / spend-signature path ----

    /// Install the signer's randomized `rk`s: one `(action_index, alpha, rk)` entry per real
    /// spend, with `rk = ak.randomize(alpha)`. **Only `rk` is stored** — the PSBT never carries
    /// `alpha` or `ak` (with `rk`, an `alpha` would reveal `ak`). **Atomic** — every entry is
    /// validated and installed on a working copy first, so one bad entry stores nothing.
    ///
    /// Each index must exist ([`IronwoodPsbtError::UnknownAction`]), name a real spend
    /// ([`IronwoodPsbtError::DummyAction`]) and appear once
    /// ([`IronwoodPsbtError::DuplicateAction`]). `alpha` must be a canonical, non-zero scalar
    /// and `rk` a canonical key other than the placeholder; given the wallet's `ak`, the pair
    /// must satisfy `rk == ak.randomize(alpha)` ([`IronwoodPsbtError::Build`] wrapping the
    /// [`crate::zcash::ironwood_build::IronwoodBuildError`] variants). Without `ak` the pair is
    /// checked later, by the client's key-free verifier and by the keyed prover.
    ///
    /// Ciphertexts first: rejected while any real output's `out_ciphertext` is pending. Frozen
    /// once signed: rejected once any signature exists ([`IronwoodPsbtError::AlreadySigned`]).
    /// Only spend bundles take randomizers ([`IronwoodPsbtError::NotSpendBundle`]), and the
    /// batch must not be empty ([`IronwoodPsbtError::NothingPending`]). Re-delivering an
    /// installed `rk` is accepted: no sighash is final until every real spend has one.
    pub fn add_spend_randomizers(
        &mut self,
        entries: &[(usize, [u8; 32], [u8; 32])],
        ak: Option<&[u8; 32]>,
    ) -> Result<(), IronwoodPsbtError> {
        use crate::zcash::ironwood_build::{set_spend_auth_randomizer, IronwoodBuildError};
        use orchard::primitives::redpallas::{SpendAuth, VerificationKey};

        let (_, mut pczt) = self.stored_ironwood_pczt()?;
        if !Self::bundle_has_real_spends(&pczt) {
            return Err(IronwoodPsbtError::NotSpendBundle);
        }
        if entries.is_empty() {
            return Err(IronwoodPsbtError::NothingPending);
        }
        self.require_unfrozen(&pczt)?;
        self.require_out_ciphertexts_set_in(&pczt)?;
        Self::require_distinct_actions(entries.iter().map(|&(action_index, _, _)| action_index))?;
        // The identity encodes as all zeros: it randomizes to a key anyone can sign for.
        let ak = ak
            .map(|ak| {
                if *ak == [0u8; 32] {
                    return Err(IronwoodBuildError::BadSpendValidatingKey);
                }
                VerificationKey::<SpendAuth>::try_from(*ak)
                    .map_err(|_| IronwoodBuildError::BadSpendValidatingKey)
            })
            .transpose()?;

        // Validate-and-install on the working copy: the PSBT is replaced only on full success.
        for &(action_index, alpha, rk) in entries {
            Self::require_real_spend(&pczt, action_index)?;
            set_spend_auth_randomizer(&mut pczt, action_index, &alpha, &rk, ak.as_ref())?;
        }

        let patched = crate::zcash::ironwood_pczt::serialize_pczt(&pczt)?;
        super::propkv::set_ironwood_pczt(&mut self.psbt, patched);
        Ok(())
    }

    /// The ZIP-244 sig digest the real spends' `spend_auth_sig`s are computed over. Every real
    /// output's `out_ciphertext` and every real spend's randomizer must be installed first —
    /// the digest commits both the ciphertexts and the randomized `rk`s.
    pub fn spend_sighash(&self) -> Result<[u8; 32], IronwoodPsbtError> {
        use crate::zcash::ironwood_build::IronwoodBuildError;

        let (_, pczt) = self.stored_ironwood_pczt()?;
        self.require_out_ciphertexts_set_in(&pczt)?;
        Self::require_randomizers_installed(&pczt)?;
        self.v6_sig_digest()
            .map_err(|e| IronwoodPsbtError::Build(IronwoodBuildError::Verify(e)))
    }

    /// Apply the signer's spend-auth signatures: one `(action_index, sig)` entry per real
    /// spend, each verified against that spend's installed `rk` over [`Self::spend_sighash`]
    /// before it is stored. **Atomic** — every signature is verified on a working copy, so one
    /// bad entry stores nothing.
    ///
    /// Each index must exist ([`IronwoodPsbtError::UnknownAction`]), name a real spend
    /// ([`IronwoodPsbtError::DummyAction`]) and appear once
    /// ([`IronwoodPsbtError::DuplicateAction`]). Only spend bundles take spend signatures
    /// ([`IronwoodPsbtError::NotSpendBundle`]), and the batch must not be empty
    /// ([`IronwoodPsbtError::NothingPending`]). Rejected while any real output's
    /// `out_ciphertext` is pending or any real spend's randomized `rk` is not installed.
    /// Signing does not freeze this method: every spend-auth signature is over the same
    /// digest, so signatures may arrive in several batches.
    pub fn add_spend_signatures(
        &mut self,
        entries: &[(usize, [u8; 64])],
    ) -> Result<(), IronwoodPsbtError> {
        use crate::zcash::ironwood_build::apply_spend_signature;

        let (_, mut pczt) = self.stored_ironwood_pczt()?;
        if !Self::bundle_has_real_spends(&pczt) {
            return Err(IronwoodPsbtError::NotSpendBundle);
        }
        if entries.is_empty() {
            return Err(IronwoodPsbtError::NothingPending);
        }
        let sighash = self.spend_sighash()?;
        Self::require_distinct_actions(entries.iter().map(|&(action_index, _)| action_index))?;

        // Verify-and-apply on the working copy: the PSBT is replaced only on full success.
        for &(action_index, sig) in entries {
            Self::require_real_spend(&pczt, action_index)?;
            apply_spend_signature(&mut pczt, action_index, sighash, &sig)?;
        }

        let patched = crate::zcash::ironwood_pczt::serialize_pczt(&pczt)?;
        super::propkv::set_ironwood_pczt(&mut self.psbt, patched);
        Ok(())
    }

    /// The orchestration view of the shielded workflow: the input kind, what is still pending
    /// at each stage, and whether the PSBT is ready for its proof. A PSBT without a PCZT is a
    /// transparent one with nothing pending and nothing to prove; errors only when the stored
    /// PCZT does not deserialize.
    pub fn shielded_status(&self) -> Result<IronwoodShieldedStatus, IronwoodPsbtError> {
        let Some(bytes) = super::propkv::get_ironwood_pczt(&self.psbt) else {
            return Ok(IronwoodShieldedStatus {
                input_kind: IronwoodInputKind::Transparent,
                pending_out_ciphertexts: Vec::new(),
                pending_randomizers: Vec::new(),
                pending_spend_signatures: Vec::new(),
                ready_for_proof: false,
            });
        };
        let pczt = crate::zcash::ironwood_pczt::deserialize_pczt(&bytes)?;
        let input_kind = if Self::bundle_has_real_spends(&pczt) {
            IronwoodInputKind::Shielded
        } else {
            IronwoodInputKind::Transparent
        };
        let pending_out_ciphertexts = self.pending_out_ciphertexts_in(&pczt)?;
        let pending_randomizers = Self::pending_randomizers_in(&pczt);
        let pending_spend_signatures = Self::pending_spend_signatures_in(&pczt);
        let ready_for_proof = match input_kind {
            IronwoodInputKind::Shielded => {
                pending_out_ciphertexts.is_empty()
                    && pending_randomizers.is_empty()
                    && pending_spend_signatures.is_empty()
            }
            // Shielding requests its proof once its transparent inputs are signed; the dummy
            // spends are signed by the IO Finalizer during combine.
            IronwoodInputKind::Transparent => self.finalized_transparent_tx().is_ok(),
        };

        Ok(IronwoodShieldedStatus {
            input_kind,
            pending_out_ciphertexts,
            pending_randomizers,
            pending_spend_signatures,
            ready_for_proof,
        })
    }

    /// The client's key-free verification of the stored shielded bundle, driven by the
    /// caller's own expectations — the PSBT is never trusted for who a spend belongs to.
    ///
    /// This runs [`verify_bundle_without_keys`] over the stored PCZT with
    /// the caller's spend-validating key `ak` and its signer's `(action, alpha, rk)`
    /// triples; nothing is read back from the PSBT for the `Rk` check. When every real
    /// spend's randomized `rk` is installed, the ZIP-244 sig digest is computed here and any
    /// present spend-auth signature is verified over it; a mid-flow bundle (placeholder
    /// `rk`s still pending) verifies without the signature check instead. On success the
    /// returned report carries the verified plaintext values: the only transaction the
    /// client can sign over this bundle that verifies on-chain is one that moves exactly the
    /// values shown.
    ///
    /// A PSBT without a stored PCZT fails with [`IronwoodPsbtError::NotSpendBundle`]. A
    /// shielding bundle (dummy spends only) verifies with no spends and its shielded outputs
    /// in the report.
    ///
    /// [`verify_bundle_without_keys`]: crate::zcash::ironwood_verify::verify_bundle_without_keys
    pub fn verify_shielded_bundle(
        &self,
        ak: Option<&[u8; 32]>,
        randomizers: &[(usize, [u8; 32], [u8; 32])],
    ) -> Result<IronwoodVerifiedBundle, IronwoodPsbtError> {
        use crate::zcash::ironwood_verify::{verify_bundle_without_keys, KeylessVerifyContext};

        let (_, pczt) = self.stored_ironwood_pczt()?;
        // Only real spends carry spend-auth signatures to check, and the digest is only
        // well-defined once every real spend's randomized `rk` is installed (and every real
        // output's `out_ciphertext` is set); `spend_sighash` enforces both.
        let sighash = if Self::bundle_has_real_spends(&pczt)
            && Self::pending_randomizers_in(&pczt).is_empty()
        {
            Some(self.spend_sighash()?)
        } else {
            None
        };
        let report = verify_bundle_without_keys(
            &pczt,
            &KeylessVerifyContext {
                expected_ak: ak.copied(),
                expected_randomizers: randomizers.to_vec(),
                sighash,
            },
        )
        .map_err(IronwoodPsbtError::Verify)?;
        let spends = report
            .spends
            .iter()
            .map(|spend| {
                ZcashShieldedSpend::from_verified(spend, self.network().to_coin_name())
                    .map_err(|e| IronwoodPsbtError::BadUnifiedAddress(e.to_string()))
            })
            .collect::<Result<Vec<_>, IronwoodPsbtError>>()?;
        Ok(IronwoodVerifiedBundle {
            spends,
            outputs: report.outputs,
            value_balance: report.value_balance,
            anchor: report.anchor,
        })
    }
}

/// Which input kind a v6 PSBT carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IronwoodInputKind {
    /// Transparent inputs (a transparent v6 or shielding transaction).
    Transparent,
    /// Shielded note spends (a deshield or shielded→shielded transaction).
    Shielded,
}

/// The orchestration view of the shielded workflow, from
/// [`ZcashBitGoPsbt::shielded_status`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IronwoodShieldedStatus {
    /// The PSBT's input kind.
    pub input_kind: IronwoodInputKind,
    /// The real outputs still pending their `out_ciphertext`.
    pub pending_out_ciphertexts: Vec<usize>,
    /// The real spends still pending their randomized `rk`.
    pub pending_randomizers: Vec<usize>,
    /// The real spends still pending their `spend_auth_sig`.
    pub pending_spend_signatures: Vec<usize>,
    /// Whether the PSBT is ready for its proof: [`ZcashBitGoPsbt::proof_request`] succeeds
    /// (given the alphas), and [`ZcashBitGoPsbt::combine_ironwood_proof`] then needs only the
    /// proof.
    pub ready_for_proof: bool,
}

/// The client-facing verified view of the stored shielded bundle, from
/// [`ZcashBitGoPsbt::verify_shielded_bundle`] — the key-free verifier's report with each
/// spend's Unified Address filled in.
#[derive(Clone, Debug)]
pub struct IronwoodVerifiedBundle {
    /// The bundle's real spends, as verified, in the parse's [`ZcashShieldedSpend`] shape.
    pub spends: Vec<ZcashShieldedSpend>,
    /// The bundle's real outputs, as verified.
    pub outputs: Vec<crate::zcash::ironwood_verify::VerifiedOutput>,
    /// The bundle's value balance (Σv_spend − Σv_out).
    pub value_balance: i64,
    /// The anchor the spends' witnesses commit to.
    pub anchor: [u8; 32],
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
