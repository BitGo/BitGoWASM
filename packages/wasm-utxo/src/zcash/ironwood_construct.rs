//! The **keyless** Ironwood spend Constructor: build a deshield or
//! shielded→shielded bundle from real spends and requested outputs without any viewing key.
//!
//! The keyed constructor ([`construct_spend_pczt_multi`]) needs each spend's FVK — the orchard
//! [`Builder`](orchard::builder::Builder) derives the nullifier and checks note ownership with
//! it — but the builder holds no keys. This module assembles the same actions field by
//! field instead:
//!
//! - each real spend carries its **note plaintext** (`recipient`/`value`/`rho`/`rseed`/`cmx`), a
//!   **witness** and a caller-supplied **nullifier** (from the note store, or derived by the viewing-key holder);
//! - each real output carries its recipient, value and memo; its note (and therefore
//!   `cmx`/`enc_ciphertext`) is fabricated here, keyed to the paired spend's nullifier;
//! - every action's `rcv`/`cv_net` pair is sampled here, and the bundle's committed
//!   `value_sum` is `Σ(v_spend − v_out)`;
//! - `rk` is the fixed [`PLACEHOLDER_RK`], with no `alpha` — the FROST signer installs the
//!   randomized `rk` ([`set_spend_auth_randomizer`]); the wallet's `ak` never enters the bundle;
//! - no FVK ever enters the constructed bundle: real spends carry `fvk = None`, so the wire
//!   form stays keyless by construction;
//! - each output's `out_ciphertext` is a random **placeholder** (encrypted under `ovk = ⊥`):
//!   the viewing-key holder re-encrypts it under its FVK `ovk` and splices the real one in via
//!   [`with_out_ciphertext`](super::ironwood_pczt::with_out_ciphertext).
//!
//! Surplus outputs (more outputs than spends) are fabricated as **dummy-spend** actions by an
//! outputs-only [`Builder`] — reusing orchard's own dummy-spend fabrication (its `dummy_sk`,
//! fabricating FVK, `alpha`/`rk` and dummy witness) — and moved into the combined bundle
//! through the wire form. Surplus spends (more spends than outputs) are paired with **dummy
//! outputs**: value-0 notes to a fresh random address, the shape the orchard builder itself
//! fabricates for an unpaired spend.
//!
//! After assembly the bundle is shuffled (action order leaks nothing about the request order)
//! and run through the key-free verifier ([`verify_bundle_without_keys`]) as a self-check: the
//! Constructor's own output must satisfy every check the client will later run on it.
//!
//! [`construct_spend_pczt_multi`]: super::ironwood_build::construct_spend_pczt_multi
//! [`set_spend_auth_randomizer`]: super::ironwood_build::set_spend_auth_randomizer
//! [`PLACEHOLDER_RK`]: super::ironwood_build::PLACEHOLDER_RK
//! [`verify_bundle_without_keys`]: super::ironwood_verify::verify_bundle_without_keys

use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};

use orchard::bundle::BundleVersion;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, Note, NoteVersion, Nullifier, RandomSeed, Rho};
use orchard::pczt::Bundle as PcztBundle;
use orchard::tree::Anchor;
use orchard::value::{NoteValue, ValueCommitTrapdoor, ValueCommitment};
use orchard::Address;

use super::ironwood_build::{
    build_ironwood_witness, construct_shield_pczt_multi, AnchorBytes, IronwoodActionMap,
    IronwoodBuildError, IronwoodOutputSpec, IronwoodWitness, MemoBytes, OrchardAddressBytes,
    CMX_PROPRIETARY_KEY, MEMO_SIZE, PLACEHOLDER_RK,
};
use super::ironwood_pczt::{ActionWire, OutputWire, SpendWire, WitnessWire};
use super::ironwood_verify::{verify_bundle_without_keys, KeylessVerifyContext};

/// Zcash `MAX_MONEY`: 21 000 000 ZEC in zatoshi. No note, output or bundle total can exceed it.
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// One Ironwood note to spend, as passed to [`construct_spend_pczt_keyless`].
///
/// Everything here is the note's plaintext from the wallet's own note record (or a
/// derived nullifier): the reconstructed note must commit to `cmx`, and the witness must
/// recompute to the bundle's anchor. The **nullifier is not verified here** — that needs the
/// FVK, which the builder does not hold. A wrong nullifier only produces an invalid
/// transaction: the proof fails, and a prover that re-derives every nullifier rejects the
/// bundle before proving.
#[derive(Clone, Copy, Debug)]
pub struct IronwoodKeylessSpendSpec {
    /// The spent note's recipient: 43-byte raw Orchard/Ironwood address.
    pub recipient: OrchardAddressBytes,
    /// Note value in zatoshi.
    pub value: u64,
    /// The spent note's `rho` — the nullifier of the action that created the note.
    pub rho: [u8; 32],
    /// The spent note's random seed.
    pub rseed: [u8; 32],
    /// The note commitment the spent note's on-chain action carried; the reconstructed note
    /// must commit to exactly this.
    pub cmx: [u8; 32],
    /// Merkle witness for `cmx` at the bundle's anchor.
    pub witness: IronwoodWitness,
    /// The nullifier this spend reveals, from the note store or the viewing-key holder. Installed verbatim:
    /// a wrong value fails the proof, never misdirects value.
    pub nullifier: [u8; 32],
}

/// Where a constructed action's request-side data came from, for the [`IronwoodActionMap`].
///
/// An action pairs one spend with one output, so a paired action carries both origins; a
/// surplus action carries only the side it was fabricated for (a surplus real spend gets a
/// dummy output, a dummy spend carries a surplus real output).
#[derive(Clone, Copy)]
struct ActionOrigin {
    spend: Option<usize>,
    output: Option<usize>,
}

/// Constructor: build a keyless Ironwood spend bundle as an orchard PCZT from real spends
/// and/or requested outputs — the deshield and shielded→shielded Constructor for a build
/// service that holds no viewing keys.
///
/// The bundle has `max(spends.len(), outputs.len())` actions (cross-address transfers are
/// enabled in the bundle's flags, so a spend and an output share an action): where one side
/// runs out, the missing half is a protocol dummy — a value-0 output to a fresh random address
/// for surplus spends, an orchard-`Builder`-fabricated dummy spend for surplus outputs. At
/// least one real spend is required: output-only bundles are *shielding* builds
/// ([`construct_shield_pczt_multi`]).
///
/// No key material is needed or carried: every real spend's `rk` is [`PLACEHOLDER_RK`]
/// (replaced by the signer's randomized `rk` later), and real spends carry no FVK, `ak` or
/// `alpha`.
///
/// Every output must have `ovk: None` and a positive amount: encryption belongs to the
/// viewing-key holder in the spend flow, and a zero-valued output is how a bundle marks fabricated dummies.
///
/// The returned [`IronwoodActionMap`] gives, for each `spends[i]`/`outputs[i]`, the action
/// index it landed at in the bundle — the actions are shuffled, so request order does not
/// equal action order.
///
/// [`construct_shield_pczt_multi`]: super::ironwood_build::construct_shield_pczt_multi
pub fn construct_spend_pczt_keyless<R: RngCore + CryptoRng>(
    spends: &[IronwoodKeylessSpendSpec],
    outputs: &[IronwoodOutputSpec],
    anchor: &AnchorBytes,
    mut rng: R,
) -> Result<(PcztBundle, IronwoodActionMap), IronwoodBuildError> {
    // At least one real spend: output-only bundles are shielding builds.
    if spends.is_empty() {
        return Err(IronwoodBuildError::NoSpends);
    }
    Option::<Anchor>::from(Anchor::from_bytes(*anchor)).ok_or(IronwoodBuildError::BadAnchor)?;

    // Validate every caller input before anything is built, so a bad request fails
    // atomically instead of halfway through construction.
    let note_version = BundleVersion::ironwood_v3().note_version();
    for (spend_index, spec) in spends.iter().enumerate() {
        validate_keyless_spend_note(spec, spend_index, anchor, note_version)?;
    }
    let mut recipients = Vec::with_capacity(outputs.len());
    for (output_index, spec) in outputs.iter().enumerate() {
        // Encryption belongs to the viewing-key holder in the spend flow — no caller-chosen `ovk`.
        if spec.ovk.is_some() {
            return Err(IronwoodBuildError::OvkNotAllowed { output_index });
        }
        // A zero-valued output is how a bundle marks fabricated dummies.
        if spec.amount == 0 {
            return Err(IronwoodBuildError::ZeroValueOutput { output_index });
        }
        if spec.amount > MAX_MONEY {
            return Err(IronwoodBuildError::ValueOutOfRange);
        }
        recipients.push(
            Option::from(Address::from_raw_address_bytes(&spec.recipient))
                .ok_or(IronwoodBuildError::BadRecipient)?,
        );
    }
    // Each value is ≤ MAX_MONEY, so these sums cannot overflow a u64; a total above
    // MAX_MONEY can never appear in a valid transaction.
    let spend_total: u64 = spends.iter().map(|s| s.value).sum();
    let output_total: u64 = outputs.iter().map(|o| o.amount).sum();
    if spend_total > MAX_MONEY || output_total > MAX_MONEY {
        return Err(IronwoodBuildError::ValueOutOfRange);
    }

    // Surplus outputs (more outputs than spends) are fabricated as dummy-spend actions by an
    // outputs-only Builder — orchard's own dummy-spend fabrication (`dummy_sk`, fabricating
    // FVK, alpha/rk, dummy witness), which cannot be reproduced from public APIs. Each
    // surplus action carries the request index of the output it was fabricated for.
    let surplus_start = spends.len().min(outputs.len());
    let surplus = &outputs[surplus_start..];
    let surplus_actions = builder_dummy_spend_actions(surplus, surplus_start, anchor, &mut rng)?;

    let mut actions = Vec::with_capacity(spends.len().max(outputs.len()));
    for (i, spend_spec) in spends.iter().enumerate() {
        // Per action: sample the value-commitment trapdoor, derive `cv_net` from the action's
        // net value, then build both halves against it — the output's placeholder
        // `out_ciphertext` commits `cv_net`, mirroring the orchard builder.
        let output_value = if i < outputs.len() {
            outputs[i].amount
        } else {
            0
        };
        let rcv = sample_rcv(&mut rng);
        let v_net = NoteValue::from_raw(spend_spec.value) - NoteValue::from_raw(output_value);
        let cv_net = ValueCommitment::derive(v_net, rcv.clone());

        // The output note keys to the paired spend's nullifier — the request-supplied one.
        let paired_nullifier = spend_spec.nullifier;
        let (output, has_real_output) = if i < outputs.len() {
            (
                real_output_wire(
                    &outputs[i],
                    recipients[i],
                    paired_nullifier,
                    &cv_net,
                    note_version,
                    &mut rng,
                )?,
                true,
            )
        } else {
            // A dummy output on a surplus real spend: value 0, a fresh random address, a
            // ZIP-302 no-memo — the shape the orchard builder fabricates for an unpaired
            // spend.
            let (recipient, memo) = dummy_output(&mut rng);
            (
                dummy_output_wire(
                    recipient,
                    memo,
                    paired_nullifier,
                    &cv_net,
                    note_version,
                    &mut rng,
                )?,
                false,
            )
        };
        actions.push((
            ActionWire {
                cv_net: cv_net.to_bytes(),
                rcv: Some(rcv.to_bytes()),
                spend: real_spend_wire(spend_spec),
                output,
            },
            ActionOrigin {
                spend: Some(i),
                output: has_real_output.then_some(i),
            },
        ));
    }
    actions.extend(surplus_actions);

    // Shuffle so the action order leaks nothing about the request order, then record where
    // each requested spend/output landed.
    let (wires, action_map) = shuffle_actions(actions, spends.len(), outputs.len(), &mut rng);

    // The bundle's committed value balance: Σ(v_spend − v_out) over the real sides (dummies
    // carry value 0, so they contribute nothing), as (magnitude, is_negative). Both totals
    // are ≤ MAX_MONEY (checked above), well inside orchard's ±2^63−1 value-sum range.
    let value_sum = if spend_total >= output_total {
        (spend_total - output_total, false)
    } else {
        (output_total - spend_total, true)
    };

    let bundle = assemble_bundle(wires, value_sum, anchor, !outputs.is_empty())?;

    // Self-check: the Constructor's own output must pass every key-free
    // check the client will later run on it — note commitments, value commitments, the
    // value sum, the witnesses, the placeholder-rk state, and no leaked viewing keys.
    let report = verify_bundle_without_keys(&bundle, &KeylessVerifyContext::default())
        .map_err(IronwoodBuildError::SelfCheck)?;
    debug_assert_eq!(
        report.spends.len(),
        spends.len(),
        "every requested spend is reported as a real spend"
    );
    debug_assert_eq!(
        report.outputs.len(),
        outputs.len(),
        "every requested output is reported as a real output"
    );

    Ok((bundle, action_map))
}

/// Validate one keyless spend's note data: the reconstructed note
/// must be internally valid, must commit to exactly `cmx`, and its witness must recompute to
/// the bundle's anchor. The nullifier's *value* is deliberately NOT checked — that needs the
/// FVK — only that it is a canonical encoding.
fn validate_keyless_spend_note(
    spec: &IronwoodKeylessSpendSpec,
    spend_index: usize,
    anchor: &AnchorBytes,
    note_version: NoteVersion,
) -> Result<(), IronwoodBuildError> {
    if spec.value > MAX_MONEY {
        return Err(IronwoodBuildError::ValueOutOfRange);
    }
    // Only the encoding is checkable without the FVK; it must parse, because it keys the
    // paired output note's `rho` and is installed verbatim on the wire.
    Option::<Nullifier>::from(Nullifier::from_bytes(&spec.nullifier))
        .ok_or(IronwoodBuildError::BadNullifier { spend_index })?;
    let recipient = Option::from(Address::from_raw_address_bytes(&spec.recipient))
        .ok_or(IronwoodBuildError::BadRecipient)?;
    let rho = Option::from(Rho::from_bytes(&spec.rho)).ok_or(IronwoodBuildError::InvalidNote)?;
    let rseed = Option::from(RandomSeed::from_bytes(spec.rseed, &rho))
        .ok_or(IronwoodBuildError::InvalidNote)?;
    let note: Note = Option::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(spec.value),
        rho,
        rseed,
        note_version,
    ))
    .ok_or(IronwoodBuildError::InvalidNote)?;
    if ExtractedNoteCommitment::from(note.commitment()).to_bytes() != spec.cmx {
        return Err(IronwoodBuildError::NoteCommitmentMismatch);
    }
    build_ironwood_witness(
        &spec.cmx,
        spec.witness.position,
        &spec.witness.auth_path,
        anchor,
    )?;
    Ok(())
}

/// The wire spend half of one real spend: note plaintext, the witness, [`PLACEHOLDER_RK`] as
/// `rk`, no `alpha`, no FVK, and the note's `cmx` recorded for reconciliation.
fn real_spend_wire(spec: &IronwoodKeylessSpendSpec) -> SpendWire {
    SpendWire {
        nullifier: spec.nullifier,
        rk: PLACEHOLDER_RK,
        spend_auth_sig: None,
        recipient: Some(spec.recipient.to_vec()),
        value: Some(spec.value),
        rho: Some(spec.rho),
        rseed: Some(spec.rseed),
        // The FVK never enters the PCZT: the Constructor is keyless by design.
        fvk: None,
        witness: Some(WitnessWire {
            position: spec.witness.position,
            auth_path: spec.witness.auth_path.to_vec(),
        }),
        alpha: None,
        dummy_sk: None,
        proprietary: [(CMX_PROPRIETARY_KEY.to_string(), spec.cmx.to_vec())].into(),
    }
}

/// Rejection-sample an output note's `rseed` for `rho`: a random 32-byte seed is
/// only usable when `RandomSeed::from_bytes` accepts it.
fn sample_rseed<R: RngCore>(rng: &mut R, rho: &Rho) -> RandomSeed {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Some(rseed) = RandomSeed::from_bytes(bytes, rho).into_option() {
            return rseed;
        }
    }
}

/// Rejection-sample the action's value-commitment trapdoor: a random 32-byte
/// scalar is only usable when it is a canonical field-element encoding.
fn sample_rcv<R: RngCore>(rng: &mut R) -> ValueCommitTrapdoor {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Some(rcv) = ValueCommitTrapdoor::from_bytes(bytes).into_option() {
            return rcv;
        }
    }
}

/// Build the output note for `rho` (the paired spend's nullifier) with a fresh
/// rejection-sampled `rseed`, returning the note and its extracted commitment.
///
/// `Note::from_parts` also rejects (with negligible probability) an `rseed` whose note
/// commitment is degenerate; that is resampled too, as orchard's own `Note::new` does, so a
/// valid request never fails here.
fn build_output_note<R: RngCore>(
    recipient: Address,
    value: NoteValue,
    rho: Rho,
    note_version: NoteVersion,
    rng: &mut R,
) -> (Note, ExtractedNoteCommitment) {
    loop {
        let rseed = sample_rseed(rng, &rho);
        if let Some(note) =
            Note::from_parts(recipient, value, rho, rseed, note_version).into_option()
        {
            let cmx = ExtractedNoteCommitment::from(note.commitment());
            return (note, cmx);
        }
    }
}

/// The wire output half of one real output, keyed to the paired spend's nullifier.
fn real_output_wire<R: RngCore>(
    spec: &IronwoodOutputSpec,
    recipient: Address,
    paired_nullifier: [u8; 32],
    cv_net: &ValueCommitment,
    note_version: NoteVersion,
    rng: &mut R,
) -> Result<OutputWire, IronwoodBuildError> {
    output_wire_from_note(
        recipient,
        NoteValue::from_raw(spec.amount),
        &spec.memo,
        paired_nullifier,
        cv_net,
        note_version,
        rng,
    )
}

/// Encrypt an output note: the real `enc_ciphertext` (recoverable by whoever holds the
/// recipient's `ivk`) and the ephemeral key it rode in on, plus a placeholder `out_ciphertext`
/// under `ovk = ⊥` — random bytes, replaced by the real one later.
fn encrypt_output<R: RngCore>(
    note: Note,
    memo: &MemoBytes,
    cv_net: &ValueCommitment,
    cmx: &ExtractedNoteCommitment,
    rng: &mut R,
) -> ([u8; 32], [u8; 580], [u8; 80]) {
    use orchard::note_encryption::IronwoodDomain;
    use zcash_note_encryption::NoteEncryption;

    let enc = NoteEncryption::<IronwoodDomain>::new(None, note, *memo);
    let enc_ciphertext = enc.encrypt_note_plaintext();
    let out_ciphertext = enc.encrypt_outgoing_plaintext(cv_net, cmx, rng);
    (
        <IronwoodDomain as zcash_note_encryption::Domain>::epk_bytes(enc.epk()).0,
        enc_ciphertext,
        out_ciphertext,
    )
}

/// The wire output half of one dummy output: value 0, a fresh random address, a ZIP-302
/// no-memo — the shape the orchard builder fabricates for an unpaired real spend.
fn dummy_output_wire<R: RngCore>(
    recipient: OrchardAddressBytes,
    memo: MemoBytes,
    paired_nullifier: [u8; 32],
    cv_net: &ValueCommitment,
    note_version: NoteVersion,
    rng: &mut R,
) -> Result<OutputWire, IronwoodBuildError> {
    let recipient = Option::from(Address::from_raw_address_bytes(&recipient))
        .ok_or(IronwoodBuildError::BadRecipient)?;
    output_wire_from_note(
        recipient,
        NoteValue::ZERO,
        &memo,
        paired_nullifier,
        cv_net,
        note_version,
        rng,
    )
}

/// Shared body of [`real_output_wire`]/[`dummy_output_wire`]: build the note against `rho`
/// (the paired spend's nullifier), commit it, encrypt it, and return the wire output.
#[allow(clippy::too_many_arguments)]
fn output_wire_from_note<R: RngCore>(
    recipient: Address,
    value: NoteValue,
    memo: &MemoBytes,
    paired_nullifier: [u8; 32],
    cv_net: &ValueCommitment,
    note_version: NoteVersion,
    rng: &mut R,
) -> Result<OutputWire, IronwoodBuildError> {
    let rho =
        Option::from(Rho::from_bytes(&paired_nullifier)).ok_or(IronwoodBuildError::InvalidNote)?;
    let (note, cmx) = build_output_note(recipient, value, rho, note_version, rng);
    let (ephemeral_key, enc_ciphertext, out_ciphertext) =
        encrypt_output(note, memo, cv_net, &cmx, rng);
    Ok(OutputWire {
        cmx: cmx.to_bytes(),
        ephemeral_key,
        enc_ciphertext: enc_ciphertext.to_vec(),
        out_ciphertext: out_ciphertext.to_vec(),
        recipient: Some(recipient.to_raw_address_bytes().to_vec()),
        value: Some(value.inner()),
        rseed: Some(*note.rseed().as_bytes()),
        ock: None,
        user_address: None,
        proprietary: Default::default(),
    })
}

/// A fresh random address (a random `SpendingKey`'s external address at diversifier 0) and the
/// ZIP-302 no-memo field — the dummy output's recipient and memo.
fn dummy_output<R: RngCore>(rng: &mut R) -> (OrchardAddressBytes, MemoBytes) {
    let mut memo = [0u8; MEMO_SIZE];
    memo[0] = 0xf6; // ZIP-302 "no memo"
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes)) {
            let fvk = FullViewingKey::from(&sk);
            return (
                fvk.address_at(0u32, Scope::External).to_raw_address_bytes(),
                memo,
            );
        }
    }
}

/// Fabricate the dummy-spend actions for surplus outputs with an outputs-only orchard
/// [`Builder`](orchard::builder::Builder) — the existing shielding path, which needs no key —
/// and return their wire actions paired with the surplus output's request-relative index.
///
/// This reuses orchard's own dummy-spend fabrication (a fabricated zero-value note with its
/// `dummy_sk`, a fabricating FVK, a builder-chosen `alpha`/`rk`, and a dummy Merkle witness):
/// the IO Finalizer signs those dummies from their stored `alpha`/`dummy_sk` at
/// [`finalize_shield_io`](super::ironwood_build::finalize_shield_io) time.
fn builder_dummy_spend_actions<R: RngCore + CryptoRng>(
    surplus_outputs: &[IronwoodOutputSpec],
    // The request-relative index of `surplus_outputs[0]` — origins are request-relative so
    // the shuffled map lines up with the caller's `outputs` slice.
    output_offset: usize,
    anchor: &AnchorBytes,
    mut rng: R,
) -> Result<Vec<(ActionWire, ActionOrigin)>, IronwoodBuildError> {
    if surplus_outputs.is_empty() {
        return Ok(Vec::new());
    }
    let (surplus_bundle, surplus_map) =
        construct_shield_pczt_multi(surplus_outputs, anchor, &mut rng)?;
    let wires = super::ironwood_pczt::bundle_actions_to_wire(&surplus_bundle);
    let output_indices = surplus_map.output_action_indices();
    Ok(wires
        .into_iter()
        .enumerate()
        .map(|(action_index, wire)| {
            // Which surplus output this action was fabricated for.
            let surplus_output = output_indices
                .iter()
                .position(|&index| index == action_index)
                .map(|k| output_offset + k);
            (
                wire,
                ActionOrigin {
                    spend: None,
                    output: surplus_output,
                },
            )
        })
        .collect())
}

/// Shuffle the constructed actions so their order leaks nothing about the request order, and
/// record where each requested spend/output landed.
fn shuffle_actions<R: RngCore>(
    actions: Vec<(ActionWire, ActionOrigin)>,
    spend_count: usize,
    output_count: usize,
    rng: &mut R,
) -> (Vec<ActionWire>, IronwoodActionMap) {
    let mut shuffled = actions;
    shuffled.shuffle(rng);
    let mut spend_action_indices = vec![usize::MAX; spend_count];
    let mut output_action_indices = vec![usize::MAX; output_count];
    for (position, (_, origin)) in shuffled.iter().enumerate() {
        if let Some(i) = origin.spend {
            spend_action_indices[i] = position;
        }
        if let Some(j) = origin.output {
            output_action_indices[j] = position;
        }
    }
    (
        shuffled.into_iter().map(|(wire, _)| wire).collect(),
        IronwoodActionMap::from_parts(spend_action_indices, output_action_indices),
    )
}

/// Assemble the wire actions into an Ironwood V3 bundle with the given committed `value_sum`
/// — the same parse a serialized PCZT takes on the way back in, including the
/// duplicate-nullifier guard.
fn assemble_bundle(
    actions: Vec<ActionWire>,
    value_sum: (u64, bool),
    anchor: &AnchorBytes,
    has_outputs: bool,
) -> Result<PcztBundle, IronwoodBuildError> {
    // The keyless constructor always carries real spends; outputs are enabled iff any were
    // requested. The fabricated halves on the surplus side (value-0 dummies) satisfy the
    // disabled bit.
    let flags = super::ironwood_build::ironwood_flag_byte(true, has_outputs);
    let wire = super::ironwood_pczt::BundleWire {
        flags,
        value_pool: 1,       // Ironwood
        protocol_version: 2, // V3
        value_sum_magnitude: value_sum.0,
        value_sum_negative: value_sum.1,
        anchor: *anchor,
        zkproof: None,
        bsk: None,
        actions,
    };
    super::ironwood_pczt::bundle_from_wire(wire).map_err(|e| match e {
        // Surface the wire parse's duplicate-nullifier guard as the typed
        // Constructor error (the index is the post-shuffle action index).
        super::ironwood_pczt::IronwoodPcztError::DuplicateNullifier { action_index } => {
            IronwoodBuildError::DuplicateNullifier { action_index }
        }
        other => IronwoodBuildError::PcztWire(other.to_string()),
    })
}

/// Shared keyless-spend test fixture (also used by the PSBT-level spend tests).
#[cfg(test)]
pub(crate) mod test_util {
    use super::*;
    use crate::zcash::ironwood_build::test_field_bytes as field_bytes;
    use crate::zcash::ironwood_build::test_util::{real_two_leaf_tree, RealLeaf};

    /// Two real notes (100M and 80M zatoshi) of one wallet under a real two-leaf tree, as the
    /// keyless Constructor receives them (nullifiers as the note store would report
    /// them), plus the anchor, the wallet's FVK (the test oracle's key holder, standing in for
    /// the viewing-key holder) and its spend-validating key `ak` (the client's key, never passed to the
    /// Constructor).
    pub(crate) fn keyless_fixture() -> (
        Vec<IronwoodKeylessSpendSpec>,
        AnchorBytes,
        FullViewingKey,
        [u8; 32],
    ) {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let (anchor, leaves) = real_two_leaf_tree(
            &fvk,
            [
                (100_000_000u64, field_bytes(200), [52u8; 32]),
                (80_000_000u64, field_bytes(201), [53u8; 32]),
            ],
        );
        let ak: [u8; 32] = fvk.to_bytes()[..32].try_into().unwrap();
        let spec = |leaf: &RealLeaf| {
            let address =
                Option::<Address>::from(Address::from_raw_address_bytes(&leaf.recipient)).unwrap();
            let rho = Option::<Rho>::from(Rho::from_bytes(&leaf.rho)).unwrap();
            let rseed =
                Option::<RandomSeed>::from(RandomSeed::from_bytes(leaf.rseed, &rho)).unwrap();
            let note = Option::<Note>::from(Note::from_parts(
                address,
                NoteValue::from_raw(leaf.value),
                rho,
                rseed,
                BundleVersion::ironwood_v3().note_version(),
            ))
            .unwrap();
            IronwoodKeylessSpendSpec {
                recipient: leaf.recipient,
                value: leaf.value,
                rho: leaf.rho,
                rseed: leaf.rseed,
                cmx: leaf.cmx,
                witness: leaf.witness,
                nullifier: note.nullifier(&fvk).to_bytes(),
            }
        };
        (vec![spec(&leaves[0]), spec(&leaves[1])], anchor, fvk, ak)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zcash::ironwood_build::compute_out_ciphertext;
    use crate::zcash::ironwood_build::test_field_bytes as field_bytes;
    use crate::zcash::ironwood_pczt::{deserialize_pczt, serialize_pczt, with_out_ciphertext};
    use ff::{Field, PrimeField};
    use orchard::keys::SpendAuthorizingKey;
    use orchard::primitives::redpallas::{SpendAuth, VerificationKey};
    use rand::rngs::OsRng;

    use super::test_util::keyless_fixture as fixture;

    /// A requested output back to the wallet itself, at the given diversifier and amount.
    fn wallet_output(fvk: &FullViewingKey, diversifier: u32, amount: u64) -> IronwoodOutputSpec {
        IronwoodOutputSpec {
            recipient: fvk
                .address_at(diversifier, Scope::External)
                .to_raw_address_bytes(),
            amount,
            ovk: None,
            memo: [0u8; 512],
        }
    }

    /// Patch every requested output's `out_ciphertext` to the real encryption under `ovk` —
    /// what the viewing-key holder does in the production flow.
    fn patch_out_ciphertexts(
        bundle: &PcztBundle,
        output_indices: &[usize],
        ovk: [u8; 32],
    ) -> PcztBundle {
        let mut bytes = serialize_pczt(bundle).unwrap();
        for &idx in output_indices {
            let expected = compute_out_ciphertext(bundle, idx, ovk, &mut OsRng).unwrap();
            bytes = with_out_ciphertext(&bytes, idx, expected).unwrap();
        }
        deserialize_pczt(&bytes).unwrap()
    }

    /// The oracle round trip: a bundle built by the keyless Constructor
    /// behaves exactly like one built by the keyed oracle — the real `out_ciphertext`s splice in,
    /// the FROST randomizers install, the keyed verifier and the key-free verifier both pass,
    /// and the FROST stand-in signatures verify.
    fn oracle_round_trip(spends: usize, outputs: usize) -> (PcztBundle, IronwoodActionMap) {
        let (specs, anchor, fvk, ak) = fixture();
        let specs = &specs[..spends];
        let outs: Vec<IronwoodOutputSpec> = (0..outputs)
            .map(|j| wallet_output(&fvk, 100 + j as u32, 90_000_000))
            .collect();
        let (bundle, map) = construct_spend_pczt_keyless(specs, &outs, &anchor, OsRng).unwrap();

        // Shape: UNPADDED means exactly max(S, O) actions.
        assert_eq!(bundle.actions().len(), spends.max(outputs));

        // The out_ciphertext round: every requested output gets its real ciphertext.
        let ovk = *fvk.to_ovk(Scope::External).as_ref();
        let bundle = patch_out_ciphertexts(&bundle, map.output_action_indices(), ovk);

        // FROST round: install a real randomizer per real spend.
        let ask = SpendAuthorizingKey::from(
            &Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap(),
        );
        let ak_key = VerificationKey::<SpendAuth>::try_from(ak).unwrap();
        let mut randomizers = Vec::new();
        let mut bundle = bundle;
        for action_index in map.spend_action_indices() {
            let alpha = pasta_curves::pallas::Scalar::random(&mut OsRng);
            let rk = <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&ask.randomize(&alpha)));
            crate::zcash::ironwood_build::set_spend_auth_randomizer(
                &mut bundle,
                *action_index,
                &alpha.to_repr(),
                &rk,
                Some(&ak_key),
            )
            .unwrap();
            randomizers.push((*action_index, alpha.to_repr(), rk));
        }

        // Only the randomized rk is stored: alpha stays with the signer.
        for action_index in map.spend_action_indices() {
            assert!(bundle.actions()[*action_index].spend().alpha().is_none());
        }

        // The keyed oracle verifier passes (the FVK holder's view, alphas out of band)…
        let alphas: Vec<(usize, [u8; 32])> = randomizers
            .iter()
            .map(|(action_index, alpha, _)| (*action_index, *alpha))
            .collect();
        crate::zcash::ironwood_build::verify_ironwood_spends(&bundle, &fvk.to_bytes(), &alphas)
            .unwrap();

        // …and the key-free verifier passes with the caller's own expectations.
        let report = verify_bundle_without_keys(
            &bundle,
            &KeylessVerifyContext {
                expected_ak: Some(ak),
                expected_randomizers: randomizers.clone(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(report.spends.len(), spends);
        assert_eq!(report.outputs.len(), outputs);

        // Sign with the FROST stand-in key; the signatures verify against the installed rks.
        let sighash = [9u8; 32];
        for ((action_index, alpha_repr, _), _) in randomizers.iter().zip(0..) {
            let alpha = pasta_curves::pallas::Scalar::from_repr(*alpha_repr).unwrap();
            let sig = ask.randomize(&alpha).sign(OsRng, &sighash);
            crate::zcash::ironwood_build::apply_spend_signature(
                &mut bundle,
                *action_index,
                sighash,
                &<[u8; 64]>::from(&sig),
            )
            .unwrap();
        }
        verify_bundle_without_keys(
            &bundle,
            &KeylessVerifyContext {
                sighash: Some(sighash),
                ..Default::default()
            },
        )
        .unwrap();
        (bundle, map)
    }

    #[test]
    fn oracle_round_trip_one_spend_no_outputs() {
        oracle_round_trip(1, 0);
    }

    #[test]
    fn oracle_round_trip_one_to_one() {
        oracle_round_trip(1, 1);
    }

    #[test]
    fn oracle_round_trip_two_spends_one_output() {
        oracle_round_trip(2, 1);
    }

    #[test]
    fn oracle_round_trip_one_spend_two_outputs() {
        oracle_round_trip(1, 2);
    }

    #[test]
    fn oracle_round_trip_two_to_two() {
        oracle_round_trip(2, 2);
    }

    /// Shape checks: the action map points at the right actions after the shuffle; surplus
    /// real spends carry value-0 dummy outputs; `value_sum` is positive for a deshield.
    #[test]
    fn action_map_and_dummy_outputs_follow_the_shapes() {
        let (specs, anchor, fvk, _ak) = fixture();

        // 2 spends → 1 output: the surplus spend carries a dummy output (value 0).
        let (bundle, map) = construct_spend_pczt_keyless(
            &specs,
            &[wallet_output(&fvk, 100, 90_000_000)],
            &anchor,
            OsRng,
        )
        .unwrap();
        assert_eq!(bundle.actions().len(), 2);
        let real_outputs: Vec<_> = map
            .output_action_indices()
            .iter()
            .map(|&idx| {
                let output = bundle.actions()[idx].output();
                (
                    output.value().map(|v| v.inner()),
                    output.recipient().map(|a| a.to_raw_address_bytes()),
                )
            })
            .collect();
        assert_eq!(
            real_outputs,
            vec![(
                Some(90_000_000),
                Some(
                    fvk.address_at(100u32, Scope::External)
                        .to_raw_address_bytes()
                )
            )]
        );
        // The other action's output is the dummy: value 0.
        let dummy_index = (0..2)
            .find(|&idx| !map.output_action_indices().contains(&idx))
            .unwrap();
        assert_eq!(
            bundle.actions()[dummy_index]
                .output()
                .value()
                .map(|v| v.inner()),
            Some(0)
        );
        // Two 100M/80M spends pay out 90M: valueBalance is +90M (positive: a deshield).
        let report = verify_bundle_without_keys(&bundle, &KeylessVerifyContext::default()).unwrap();
        assert_eq!(report.value_balance, 90_000_000);

        // 1 spend → 2 outputs: the surplus output rides a dummy spend.
        let (specs, anchor, fvk, _ak) = fixture();
        let (bundle, map) = construct_spend_pczt_keyless(
            &specs[..1],
            &[
                wallet_output(&fvk, 100, 40_000_000),
                wallet_output(&fvk, 101, 50_000_000),
            ],
            &anchor,
            OsRng,
        )
        .unwrap();
        assert_eq!(bundle.actions().len(), 2);
        for j in 0..2 {
            let idx = map.output_action_index(j).unwrap();
            let action = &bundle.actions()[idx];
            // Output 0 pairs the real spend; surplus output 1 rides a dummy spend.
            assert_eq!(
                action.spend().dummy_sk().is_some(),
                j == 1,
                "output {j}: unexpected spend kind"
            );
            assert_eq!(
                action.output().value().map(|v| v.inner()),
                Some(40_000_000 + 10_000_000 * j as u64)
            );
        }
        let report = verify_bundle_without_keys(&bundle, &KeylessVerifyContext::default()).unwrap();
        // 100M spent − 90M outputs = +10M (positive: a deshield pays out).
        assert_eq!(report.value_balance, 10_000_000);
    }

    /// Negative tests, one per constructor invariant.
    #[test]
    fn rejects_bad_requests() {
        let (specs, anchor, fvk, _ak) = fixture();

        // At least one spend.
        assert!(matches!(
            construct_spend_pczt_keyless(&[], &[], &anchor, OsRng),
            Err(IronwoodBuildError::NoSpends)
        ));

        // No caller-chosen ovk.
        let mut bad_ovk = wallet_output(&fvk, 100, 90_000_000);
        bad_ovk.ovk = Some([3u8; 32]);
        assert!(matches!(
            construct_spend_pczt_keyless(&specs, &[bad_ovk], &anchor, OsRng),
            Err(IronwoodBuildError::OvkNotAllowed { output_index: 0 })
        ));

        // Zero-valued outputs are the dummy marker.
        assert!(matches!(
            construct_spend_pczt_keyless(&specs, &[wallet_output(&fvk, 100, 0)], &anchor, OsRng),
            Err(IronwoodBuildError::ZeroValueOutput { output_index: 0 })
        ));

        // The note must commit to its recorded cmx.
        let mut bad_cmx = specs[0];
        bad_cmx.cmx = field_bytes(999);
        assert!(matches!(
            construct_spend_pczt_keyless(&[bad_cmx], &[], &anchor, OsRng),
            Err(IronwoodBuildError::NoteCommitmentMismatch)
        ));

        // The note plaintext must be internally valid (non-canonical rho).
        let mut bad_rho = specs[0];
        bad_rho.rho = [0xffu8; 32];
        assert!(matches!(
            construct_spend_pczt_keyless(&[bad_rho], &[], &anchor, OsRng),
            Err(IronwoodBuildError::InvalidNote)
        ));

        // The witness must recompute to the anchor.
        assert!(matches!(
            construct_spend_pczt_keyless(
                &specs,
                &[],
                &crate::zcash::ironwood_build::test_util::real_two_leaf_tree(
                    &fvk,
                    [
                        (1u64, field_bytes(1), [1u8; 32]),
                        (2u64, field_bytes(2), [2u8; 32])
                    ]
                )
                .0,
                OsRng
            ),
            Err(IronwoodBuildError::WitnessAnchorMismatch)
        ));

        // Duplicate nullifiers are rejected, as the typed Constructor error.
        let mut dup = specs[1];
        dup.nullifier = specs[0].nullifier;
        assert!(matches!(
            construct_spend_pczt_keyless(&[specs[0], dup], &[], &anchor, OsRng),
            Err(IronwoodBuildError::DuplicateNullifier { .. })
        ));

        // A non-canonical anchor encoding.
        assert!(matches!(
            construct_spend_pczt_keyless(&specs, &[], &[0xffu8; 32], OsRng),
            Err(IronwoodBuildError::BadAnchor)
        ));

        // A non-canonical nullifier encoding names the offending spend.
        let mut bad_nf = specs[1];
        bad_nf.nullifier = [0xffu8; 32];
        assert!(matches!(
            construct_spend_pczt_keyless(&[specs[0], bad_nf], &[], &anchor, OsRng),
            Err(IronwoodBuildError::BadNullifier { spend_index: 1 })
        ));

        // Values above MAX_MONEY: an output amount, and a total of in-range outputs.
        assert!(matches!(
            construct_spend_pczt_keyless(
                &specs,
                &[wallet_output(&fvk, 100, MAX_MONEY + 1)],
                &anchor,
                OsRng
            ),
            Err(IronwoodBuildError::ValueOutOfRange)
        ));
        assert!(matches!(
            construct_spend_pczt_keyless(
                &specs,
                &[
                    wallet_output(&fvk, 100, MAX_MONEY),
                    wallet_output(&fvk, 101, 1)
                ],
                &anchor,
                OsRng
            ),
            Err(IronwoodBuildError::ValueOutOfRange)
        ));
    }

    /// No FVK reaches the constructed PCZT: every real spend's `fvk`
    /// is absent, and the wallet FVK's secret-ish half (`nk ‖ rivk`) appears nowhere in the
    /// serialized bytes. Neither does its `ak`: the placeholder `rk` is [`PLACEHOLDER_RK`].
    #[test]
    fn constructed_pczt_carries_no_wallet_fvk() {
        let (specs, anchor, fvk, _ak) = fixture();
        for (spends, outputs) in [(1usize, 0usize), (2, 1), (1, 2), (2, 2)] {
            let outs: Vec<IronwoodOutputSpec> = (0..outputs)
                .map(|j| wallet_output(&fvk, 100 + j as u32, 30_000_000))
                .collect();
            let (bundle, map) =
                construct_spend_pczt_keyless(&specs[..spends], &outs, &anchor, OsRng).unwrap();
            for &idx in map.spend_action_indices() {
                let spend = bundle.actions()[idx].spend();
                assert!(spend.fvk().is_none(), "real spend {idx} carries an fvk");
                assert!(spend.zip32_derivation().is_none());
                assert!(
                    spend.alpha().is_none(),
                    "no alpha before the signer installs one"
                );
                assert_eq!(<[u8; 32]>::from(spend.rk()), PLACEHOLDER_RK);
            }
            let bytes = serialize_pczt(&bundle).unwrap();
            let fvk_bytes = fvk.to_bytes();
            let nk_rivk = &fvk_bytes[32..];
            assert!(
                !bytes.windows(nk_rivk.len()).any(|w| w == nk_rivk),
                "{spends}→{outputs}: the wallet FVK's nk‖rivk leaked into the PCZT"
            );
            for half in [&fvk_bytes[..32], &fvk_bytes[32..64], &fvk_bytes[64..96]] {
                assert!(
                    !bytes.windows(32).any(|w| w == half),
                    "{spends}→{outputs}: a wallet FVK component leaked into the PCZT"
                );
            }
        }
    }

    /// Randomness: two builds of the same request produce different action orders, `rcv`s
    /// and `rseed`s — linkability hinges on the Constructor randomizing everything it can.
    #[test]
    fn two_builds_randomize_order_rcvs_and_rseeds() {
        let (specs, anchor, fvk, _ak) = fixture();
        let outs = [
            wallet_output(&fvk, 100, 30_000_000),
            wallet_output(&fvk, 101, 30_000_000),
        ];
        let build = || {
            let (bundle, map) =
                construct_spend_pczt_keyless(&specs, &outs, &anchor, OsRng).unwrap();
            (serialize_pczt(&bundle).unwrap(), map)
        };
        // The action ORDER differs: the maps disagree on where spend 0 landed. 2! orders are
        // possible (a collision has probability 1/2 per pair), so retry a few times.
        let mut order_differs = false;
        let mut first: Option<(Vec<u8>, IronwoodActionMap)> = None;
        for _ in 0..8 {
            let (bytes, map) = build();
            if let Some((_, ref map_a)) = first {
                if (0..2).any(|i| map_a.spend_action_index(i) != map.spend_action_index(i))
                    || (0..2).any(|i| map_a.output_action_index(i) != map.output_action_index(i))
                {
                    order_differs = true;
                }
            } else {
                first = Some((bytes, map));
            }
        }
        assert!(
            order_differs,
            "the shuffle must reorder actions across builds"
        );
        // The rseeds differ regardless of order: compare the ciphertexts of two builds.
        let (a, _) = build();
        let (b, _) = build();
        assert_ne!(
            a, b,
            "two builds of the same request must differ byte-for-byte"
        );
    }
}
