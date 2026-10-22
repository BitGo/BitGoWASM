//! The Ironwood **spend** PSBT workflow (plan §4/§6.2): the keyless Constructor entry point
//! ([`ZcashBitGoPsbt::add_shielded_spends`]) and the one-input-kind rule (plan rule 0).
//!
//! The build service (IMS) selects notes and calls [`ZcashBitGoPsbt::add_shielded_spends`]
//! with the notes' plaintext, their witnesses, the KMS-derived nullifiers, the requested
//! outputs and the wallet's spend-validating key `ak` — and no viewing key. The constructed
//! PCZT is stored in the PSBT together with `ak` (proprietary key `0x08`), which the key-free
//! verifier (plan §5) reads for the `Rk` check, and the per-output Unified Addresses.
//!
//! Rule 0 (plan §3): a v6 PSBT spends **either** transparent inputs (transparent v6 or
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
    /// shielded→shielded Constructor for a build service that holds no viewing keys (plan §4).
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
    /// is computed (plan rule 2). Every output's `out_ciphertext` is a random placeholder —
    /// KMS replaces it under its FVK `ovk` (plan §2 step 3). No FVK ever enters the stored
    /// PCZT.
    ///
    /// Rules enforced here (plan §3):
    /// - **rule 0** — rejected when the PSBT already carries transparent inputs
    ///   ([`IronwoodPsbtError::MixedInputKinds`]);
    /// - **one call per PSBT** — a second call would silently overwrite the first batch
    ///   ([`IronwoodPsbtError::AlreadyAdded`]).
    ///
    /// Also stored: the caller's `ak` (proprietary key `0x08`) — the key-free verifier's `Rk`
    /// check reads it — and each output's Unified Address, keyed by its action index.
    pub fn add_shielded_spends<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        spends: &[crate::zcash::ironwood_construct::IronwoodKeylessSpendSpec],
        outputs: &[IronwoodOutputRequest],
        anchor: &crate::zcash::ironwood_build::AnchorBytes,
        ak: &[u8; 32],
        rng: R,
    ) -> Result<crate::zcash::ironwood_build::IronwoodActionMap, IronwoodPsbtError> {
        use crate::zcash::{ironwood_build, ironwood_construct};

        // Rule 0: a spend PSBT has no transparent inputs — the shielded side funds itself.
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
        let action_map =
            self.store_ironwood_pczt_and_unified_addresses(pczt, action_map, outputs)?;
        // The wallet's spend-validating key, for the key-free verifier's `Rk` check (plan §5).
        super::propkv::set_ironwood_spend_validating_key(&mut self.psbt, ak);
        Ok(action_map)
    }

    /// Rule 0 on the transparent side: reject adding a transparent input to a PSBT whose
    /// stored Ironwood bundle already spends real (non-dummy) notes.
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
}
