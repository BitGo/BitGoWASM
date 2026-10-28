//! The key-free verifier for Ironwood (Zcash v6) PCZT bundles.
//!
//! A party without viewing keys — the client co-signing, or a keyless builder — cannot check
//! nullifier ownership or decrypt anything, but it CAN check that the transaction it is
//! asked to sign moves exactly the values it was shown:
//!
//! - `NoteCommitment`: every output's plaintext note produces its committed `cmx`;
//! - `CvNet`: every action's `cv_net` commits to its plaintext net value;
//! - every action keeps its full plaintext (note recipient/value/rho/rseed, `rcv`): the
//!   prover needs it, and it is what lets anyone reading the PSBT see what moves where;
//! - `ValueSum`: the bundle's committed `value_sum` equals `Σ(v_spend − v_out)` over exactly the
//!   reported spends and outputs — dummy spends carry value 0, so nothing moves unseen;
//! - `SpendWitness`: every real spend's rebuilt note commits to a leaf under the bundle's anchor
//!   and matches the spend's recorded `cmx`;
//! - `Rk`: every real spend's `rk` is either [`PLACEHOLDER_RK`] or a randomized key; given the
//!   caller's own `ak` and FROST randomizers, each randomized `rk` is `ak.randomize(alpha)`;
//! - `ViewingKeyPresent`: no viewing-key material (`fvk`, ZIP-32 derivation) leaks on a real spend;
//! - `RandomizerPresent`: no real spend carries its `alpha`, which with `rk` reveals `ak`;
//! - `BundleVersion`: the bundle is an Ironwood V3 bundle;
//! - `Flags`: the bundle's flags match its contents (spends enabled iff a real spend is
//!   present, outputs iff a real output is, cross-address always enabled);
//! - `ZeroValueOutput`: value-0 (dummy) outputs only sit on actions with a real spend;
//! - `SpendSignature`: every present spend-auth signature verifies against the spend's `rk` over
//!   the caller's sighash.
//!
//! Duplicate nullifiers are not re-checked here: `deserialize_pczt` already rejects them.
//!
//! Failures surface as [`IronwoodVerifyError::Action`] carrying an
//! [`IronwoodVerifyCheck`], so the JS error code is `IronwoodVerifyError.<check>` — the
//! same shape the keyed verifier uses.
//!
//! [`PLACEHOLDER_RK`]: super::ironwood_build::PLACEHOLDER_RK

use ff::Field;
use orchard::{
    bundle::BundleVersion,
    note::Note,
    pczt::Bundle as PcztBundle,
    primitives::redpallas::{SpendAuth, VerificationKey},
    value::NoteValue,
};

use super::ironwood_build::{
    ironwood_flag_byte, spend_rk_is_placeholder, IronwoodVerifyCheck, IronwoodVerifyError,
    OrchardAddressBytes, CMX_PROPRIETARY_KEY,
};
use super::ironwood_pczt::PcztSpend;

/// The caller's own expectations for the keyless verification.
#[derive(Debug, Clone, Default)]
pub struct KeylessVerifyContext {
    /// The caller's own spend-validating key (`ak`) — never read from the PSBT, which does not
    /// carry it. When given, every randomized real spend must have an entry in
    /// `expected_randomizers` whose `rk` is `ak.randomize(alpha)`: the client checks it is
    /// signing for its own wallet.
    pub expected_ak: Option<[u8; 32]>,
    /// The `(action, alpha, rk)` triples the caller's FROST round produced: when given, each
    /// spend on those actions must carry exactly that randomized `rk`.
    pub expected_randomizers: Vec<(usize, [u8; 32], [u8; 32])>,
    /// The ZIP-244 shielded sig digest to verify present spend-auth signatures against
    /// (`SpendSignature`); `None` skips the check.
    pub sighash: Option<[u8; 32]>,
}

/// One real spend, as verified by [`verify_bundle_without_keys`].
#[derive(Debug, Clone)]
pub struct VerifiedSpend {
    /// The spend's action index in the bundle.
    pub action_index: usize,
    /// Note value in zatoshi.
    pub value: u64,
    /// Raw Orchard recipient (43 bytes).
    pub recipient: OrchardAddressBytes,
    /// The nullifier this spend reveals.
    pub nullifier: [u8; 32],
    /// The note commitment recomputed from the verified plaintext.
    pub cmx: [u8; 32],
    /// The witness's leaf position in the commitment tree.
    pub position: u32,
    /// Whether the signer replaced the Constructor's [`PLACEHOLDER_RK`] with a randomized `rk`.
    ///
    /// [`PLACEHOLDER_RK`]: super::ironwood_build::PLACEHOLDER_RK
    pub randomizer_installed: bool,
    /// Whether a spend-auth signature is present.
    pub signed: bool,
}

/// One real output, as verified by [`verify_bundle_without_keys`].
#[derive(Debug, Clone)]
pub struct VerifiedOutput {
    /// The output's action index in the bundle.
    pub action_index: usize,
    /// Output value in zatoshi.
    pub value: u64,
    /// Raw Orchard recipient (43 bytes).
    pub recipient: OrchardAddressBytes,
}

/// The verified view of a bundle: the real spends and outputs with their plaintext values,
/// the bundle's committed value balance, and the anchor the spends commit under.
#[derive(Debug, Clone)]
pub struct IronwoodVerificationReport {
    pub spends: Vec<VerifiedSpend>,
    pub outputs: Vec<VerifiedOutput>,
    /// The bundle's committed value balance (Σv_spend − Σv_out, negative when the shielded
    /// pool gains value).
    pub value_balance: i64,
    /// The anchor every real spend's witness commits to.
    pub anchor: [u8; 32],
}

/// Verify an Ironwood PCZT bundle without any viewing keys.
///
/// On success the bundle's values are exactly what the plaintext fields say they are, and
/// every real spend commits to a leaf under the bundle's anchor: the only transaction a
/// client can sign over this bundle that verifies on-chain is one that moves exactly the
/// values shown. What a keyless party cannot check (note ownership, nullifier validity, a
/// fresh anchor) can only make the transaction invalid, never misdirected.
pub fn verify_bundle_without_keys(
    bundle: &PcztBundle,
    ctx: &KeylessVerifyContext,
) -> Result<IronwoodVerificationReport, IronwoodVerifyError> {
    // `BundleVersion`: the bundle must be an Ironwood V3 bundle. Its flags are checked against
    // the bundle's contents after the action scan below.
    let ironwood_v3 = BundleVersion::ironwood_v3();
    if *bundle.bundle_version() != ironwood_v3 {
        return Err(action_error(
            0,
            IronwoodVerifyCheck::BundleVersion,
            format!(
                "bundle version is {:?}, expected Ironwood V3",
                bundle.bundle_version()
            ),
        ));
    }

    let expected_ak = expected_spend_validating_key(ctx)?;

    let mut spends = Vec::new();
    let mut outputs = Vec::new();
    for (action_index, action) in bundle.actions().iter().enumerate() {
        let spend = action.spend();
        let output = action.output();
        let is_real_spend = spend.dummy_sk().is_none();

        // Every action keeps its full plaintext — the prover needs it to build the
        // proof, and it is what lets anyone reading the PSBT see exactly what moves where.
        // A missing field could otherwise hide a value from the checks below.
        let (spend_value, output_value, output_recipient) = action_plaintext(action_index, action)?;

        // `NoteCommitment`: the output's plaintext note must produce its committed `cmx`.
        output.verify_note_commitment(spend).map_err(|e| {
            action_error(
                action_index,
                IronwoodVerifyCheck::NoteCommitment,
                e.to_string(),
            )
        })?;

        // `CvNet`: `cv_net` must commit to the action's plaintext net value — no FVK is
        // needed for this.
        action
            .verify_cv_net()
            .map_err(|e| action_error(action_index, IronwoodVerifyCheck::CvNet, e.to_string()))?;

        if !is_real_spend {
            // A fabricated (dummy) spend never moves value: one that carried some would fund
            // the bundle invisibly, since dummy spends stay out of the reported spends.
            if spend_value != 0 {
                return Err(action_error(
                    action_index,
                    IronwoodVerifyCheck::DummySpendValue,
                    format!("a dummy spend carries a non-zero value ({spend_value} zatoshi)"),
                ));
            }
            // `ZeroValueOutput`: a value-0 output may only sit on an action with a real spend — a
            // value-0 output on a dummy-spend action would be indistinguishable from a fabricated
            // one in the value-based accounting. The dummy spend's paired output is a REAL output
            // (the shielding pairing: dummy spend carries the real output).
            if output_value == 0 {
                return Err(action_error(
                    action_index,
                    IronwoodVerifyCheck::ZeroValueOutput,
                    "a value-0 output is paired with a dummy spend".to_string(),
                ));
            }
            outputs.push(VerifiedOutput {
                action_index,
                value: output_value,
                recipient: output_recipient,
            });
            continue;
        }

        spends.push(verify_real_spend(
            bundle,
            action_index,
            spend,
            ctx,
            expected_ak.as_ref(),
        )?);
        // The fabricated zero-valued outputs the Constructor pairs with surplus real
        // spends stay out of the reported outputs; everything else is a real output.
        if output_value != 0 {
            outputs.push(VerifiedOutput {
                action_index,
                value: output_value,
                recipient: output_recipient,
            });
        }
    }

    // `Flags`: the bundle must enable exactly what it carries — the spends flag iff a
    // real spend exists, the outputs flag iff a real output exists (cross-address transfers are
    // always enabled for Ironwood V3). This is a canonical-form policy, not a value check: a
    // disabled flag only adds a value-0 constraint, and the commitment checks above already pin
    // every value. Pinning one flag byte per bundle shape keeps every party agreeing on the
    // exact bytes (and so the txid) the Constructor produced.
    let expected_flags = ironwood_flag_byte(!spends.is_empty(), !outputs.is_empty());
    if bundle.flag_byte() != expected_flags {
        return Err(action_error(
            0,
            IronwoodVerifyCheck::Flags,
            format!(
                "flag byte {:#04x} does not match the bundle's contents ({} real spends, {} real \
                 outputs; expected {:#04x})",
                bundle.flag_byte(),
                spends.len(),
                outputs.len(),
                expected_flags,
            ),
        ));
    }

    // Every caller-expected randomizer must land on a real spend: one aimed at a dummy or a
    // missing action would otherwise be silently ignored.
    for (action_index, _, _) in &ctx.expected_randomizers {
        if !spends
            .iter()
            .any(|spend| spend.action_index == *action_index)
        {
            return Err(action_error(
                *action_index,
                IronwoodVerifyCheck::Rk,
                "an expected randomizer targets an action without a real spend".to_string(),
            ));
        }
    }

    // `ValueSum`: the committed value_sum must equal Σ(v_spend − v_out) over exactly the reported
    // spends and outputs. Everything left out of the report is value-0 (dummy spends and
    // fabricated outputs are checked above), so the reported values are the whole bundle:
    // nothing moves that the caller is not shown.
    let value_balance = super::ironwood_build::pczt_action_data(bundle)
        .map_err(|e| action_error(0, IronwoodVerifyCheck::ValueSum, e.to_string()))?
        .value_balance;
    let spend_total = spends.iter().map(|s| s.value as i128).sum::<i128>();
    let output_total = outputs.iter().map(|o| o.value as i128).sum::<i128>();
    if spend_total - output_total != value_balance as i128 {
        return Err(action_error(
            0,
            IronwoodVerifyCheck::ValueSum,
            format!(
                "plaintext note values are inconsistent with the bundle's committed value_sum: \
                 spends {spend_total} - outputs {output_total} != value_balance {value_balance}"
            ),
        ));
    }

    Ok(IronwoodVerificationReport {
        spends,
        outputs,
        value_balance,
        anchor: bundle.anchor().to_bytes(),
    })
}

/// `Rk` setup: the caller's own `ak`, parsed as a canonical, non-identity verification key.
fn expected_spend_validating_key(
    ctx: &KeylessVerifyContext,
) -> Result<Option<VerificationKey<SpendAuth>>, IronwoodVerifyError> {
    let Some(bytes) = ctx.expected_ak else {
        return Ok(None);
    };
    // The identity point encodes as all zeros; it randomizes to a key anyone can sign for.
    if bytes == [0u8; 32] {
        return Err(action_error(
            0,
            IronwoodVerifyCheck::Rk,
            "the expected spend-validating key is the identity".to_string(),
        ));
    }
    VerificationKey::<SpendAuth>::try_from(bytes)
        .map(Some)
        .map_err(|e| {
            action_error(
                0,
                IronwoodVerifyCheck::Rk,
                format!("the expected spend-validating key is not a canonical point: {e}"),
            )
        })
}

/// The action's plaintext: `(spend value, output value, output recipient)`, after checking
/// that every plaintext field the checks and the prover rely on is present — spend
/// recipient/value/rho/rseed, output recipient/value/rseed, and the value-commitment
/// trapdoor.
fn action_plaintext(
    action_index: usize,
    action: &orchard::pczt::Action,
) -> Result<(u64, u64, OrchardAddressBytes), IronwoodVerifyError> {
    let missing = |field: &str| {
        action_error(
            action_index,
            IronwoodVerifyCheck::MissingPlaintext,
            format!("the action is missing its plaintext {field}"),
        )
    };
    let spend = action.spend();
    let output = action.output();
    if spend.recipient().is_none() {
        return Err(missing("spend recipient"));
    }
    if spend.rho().is_none() {
        return Err(missing("spend rho"));
    }
    if spend.rseed().is_none() {
        return Err(missing("spend rseed"));
    }
    if output.rseed().is_none() {
        return Err(missing("output rseed"));
    }
    if action.rcv().is_none() {
        return Err(missing("value-commitment trapdoor (rcv)"));
    }
    let spend_value = spend
        .value()
        .map(|v| v.inner())
        .ok_or_else(|| missing("spend value"))?;
    let output_value = output
        .value()
        .map(|v| v.inner())
        .ok_or_else(|| missing("output value"))?;
    let output_recipient = output
        .recipient()
        .map(|address| address.to_raw_address_bytes())
        .ok_or_else(|| missing("output recipient"))?;
    Ok((spend_value, output_value, output_recipient))
}

/// Run the real-spend-only checks (`SpendWitness`, `Rk`, `ViewingKeyPresent`, `SpendSignature`) on
/// one action and return its verified data.
fn verify_real_spend(
    bundle: &PcztBundle,
    action_index: usize,
    spend: &PcztSpend,
    ctx: &KeylessVerifyContext,
    expected_ak: Option<&VerificationKey<SpendAuth>>,
) -> Result<VerifiedSpend, IronwoodVerifyError> {
    // `SpendWitness`: rebuild the note from plaintext and check it against the witness and the
    // recorded `cmx`.
    let recipient = spend.recipient().ok_or_else(|| {
        action_error(
            action_index,
            IronwoodVerifyCheck::SpendWitness,
            "real spend is missing its plaintext recipient".to_string(),
        )
    })?;
    let value = spend.value().ok_or_else(|| {
        action_error(
            action_index,
            IronwoodVerifyCheck::SpendWitness,
            "real spend is missing its plaintext value".to_string(),
        )
    })?;
    let rseed = spend.rseed().ok_or_else(|| {
        action_error(
            action_index,
            IronwoodVerifyCheck::SpendWitness,
            "real spend is missing its plaintext rseed".to_string(),
        )
    })?;
    let path = spend.witness().as_ref().ok_or_else(|| {
        action_error(
            action_index,
            IronwoodVerifyCheck::SpendWitness,
            "real spend is missing its witness".to_string(),
        )
    })?;
    let position = path.position();

    let nf = spend.nullifier();
    // The spend's own `rho` (the spent note's nullifier seed) and `rseed` are Constructor
    // plaintext — NOT derived from the nullifier (the nullifier is derived FROM the note).
    let rho = spend.rho().ok_or_else(|| {
        action_error(
            action_index,
            IronwoodVerifyCheck::SpendWitness,
            "real spend is missing its plaintext rho".to_string(),
        )
    })?;
    let note = Option::<Note>::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(value.inner()),
        rho,
        rseed,
        bundle.bundle_version().note_version(),
    ))
    .ok_or_else(|| {
        action_error(
            action_index,
            IronwoodVerifyCheck::SpendWitness,
            "the spend's plaintext fields do not form a valid note".to_string(),
        )
    })?;
    let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
    let cmx_bytes = cmx.to_bytes();
    if spend.proprietary().get(CMX_PROPRIETARY_KEY) != Some(&cmx_bytes.to_vec()) {
        return Err(action_error(
            action_index,
            IronwoodVerifyCheck::SpendWitness,
            "the rebuilt note's cmx does not match the spend's recorded cmx".to_string(),
        ));
    }
    if path.root(cmx) != *bundle.anchor() {
        return Err(action_error(
            action_index,
            IronwoodVerifyCheck::SpendWitness,
            "the rebuilt note does not commit to a leaf under the bundle's anchor".to_string(),
        ));
    }

    // `ViewingKeyPresent`: no viewing-key material may leak on a real spend.
    if spend.fvk().is_some() || spend.zip32_derivation().is_some() {
        return Err(action_error(
            action_index,
            IronwoodVerifyCheck::ViewingKeyPresent,
            "a real spend carries viewing-key material (fvk or ZIP-32 derivation)".to_string(),
        ));
    }

    // `RandomizerPresent`: `alpha` never rides the PSBT — with the randomized `rk` it would
    // reveal the wallet's `ak`.
    if spend.alpha().is_some() {
        return Err(action_error(
            action_index,
            IronwoodVerifyCheck::RandomizerPresent,
            "a real spend carries its randomizer (alpha), which with rk reveals ak".to_string(),
        ));
    }

    // `Rk`: the `rk` is the placeholder until the signer installs its randomized one; the
    // caller checks a randomized `rk` against its own `ak` and FROST randomizers.
    let randomizer_installed = !spend_rk_is_placeholder(spend);
    let expected = ctx
        .expected_randomizers
        .iter()
        .find(|(action, _, _)| *action == action_index);
    match expected {
        Some((_, expected_alpha, expected_rk)) => {
            if !randomizer_installed || <[u8; 32]>::from(spend.rk()) != *expected_rk {
                return Err(action_error(
                    action_index,
                    IronwoodVerifyCheck::Rk,
                    "the spend's rk does not match the caller's expected rk".to_string(),
                ));
            }
            if let Some(ak) = expected_ak {
                let alpha = Option::<pasta_curves::pallas::Scalar>::from(
                    <pasta_curves::pallas::Scalar as ff::PrimeField>::from_repr(*expected_alpha),
                )
                .filter(|alpha| !bool::from(alpha.is_zero()))
                .ok_or_else(|| {
                    action_error(
                        action_index,
                        IronwoodVerifyCheck::Rk,
                        "the caller's expected alpha is zero or not a canonical scalar".to_string(),
                    )
                })?;
                if ak.randomize(&alpha) != *spend.rk() {
                    return Err(action_error(
                        action_index,
                        IronwoodVerifyCheck::Rk,
                        "the spend's rk is not ak.randomize(alpha) for the caller's \
                         spend-validating key"
                            .to_string(),
                    ));
                }
            }
        }
        None if randomizer_installed && expected_ak.is_some() => {
            return Err(action_error(
                action_index,
                IronwoodVerifyCheck::Rk,
                "the spend's randomized rk cannot be checked against the caller's \
                 spend-validating key without its expected randomizer"
                    .to_string(),
            ));
        }
        None => {}
    }

    // `SpendSignature`: any present spend-auth signature must verify against the spend's `rk` over
    // the caller's sighash.
    if let (Some(sighash), Some(sig)) = (ctx.sighash, spend.spend_auth_sig()) {
        spend.rk().verify(sighash.as_slice(), sig).map_err(|e| {
            action_error(
                action_index,
                IronwoodVerifyCheck::SpendSignature,
                e.to_string(),
            )
        })?;
    }

    Ok(VerifiedSpend {
        action_index,
        value: value.inner(),
        recipient: recipient.to_raw_address_bytes(),
        nullifier: nf.to_bytes(),
        cmx: cmx_bytes,
        position,
        randomizer_installed,
        signed: spend.spend_auth_sig().is_some(),
    })
}

/// A check failure on one action, with the check name carried for the error code.
fn action_error(
    action_index: usize,
    check: IronwoodVerifyCheck,
    detail: String,
) -> IronwoodVerifyError {
    IronwoodVerifyError::Action {
        action_index,
        check,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        verify_bundle_without_keys, IronwoodVerificationReport, IronwoodVerifyCheck,
        IronwoodVerifyError, KeylessVerifyContext,
    };
    use crate::zcash::ironwood_build::{
        construct_spend_pczt_multi, test_field_bytes as field_bytes, IronwoodOutputSpec,
        IronwoodSpendSpec, OrchardAddressBytes, WitnessAuthPath, ANCHOR_SIZE,
    };
    use crate::zcash::ironwood_pczt::{
        deserialize_pczt, serialize_pczt, with_action_rewrite_for_test, with_flags_for_test,
        with_output_recipient_for_test, with_spend_alpha, with_spend_auth_sig, with_spend_fvk,
        with_spend_rk, with_spend_value, with_spend_witness_for_test, with_value_sum_for_test,
        without_output_recipient_for_test, ActionRewriteForTest,
    };
    use ff::{Field, PrimeField};
    use orchard::{
        bundle::BundleVersion,
        keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
        note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
        primitives::redpallas::{self, SpendAuth, VerificationKey},
        tree::{MerkleHashOrchard, MerklePath},
        value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    };
    use rand::rngs::OsRng;

    /// A deterministic 43-byte Orchard recipient derived from a fixed spending key.
    fn test_recipient() -> OrchardAddressBytes {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        FullViewingKey::from(&sk)
            .address_at(0u32, Scope::External)
            .to_raw_address_bytes()
    }

    /// A self-consistent real-spend fixture: the note reconstructed from the plaintext fields
    /// commits to `cmx`, and the witness anchors `cmx` under the returned root.
    fn test_spend_spec() -> (IronwoodSpendSpec, [u8; ANCHOR_SIZE]) {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let rho = Option::<Rho>::from(Rho::from_bytes(&field_bytes(100))).unwrap();
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes([42u8; 32], &rho)).unwrap();
        let address =
            Option::<orchard::Address>::from(orchard::Address::from_raw_address_bytes(&recipient))
                .unwrap();
        let note = Option::<Note>::from(Note::from_parts(
            address,
            NoteValue::from_raw(100_000_000),
            rho,
            rseed,
            BundleVersion::ironwood_v3().note_version(),
        ))
        .unwrap();
        let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();

        let position = 5u32;
        let auth_path: WitnessAuthPath = std::array::from_fn(|i| field_bytes(i as u64 + 1));
        let sibling_hashes: [MerkleHashOrchard; 32] =
            auth_path.map(|s| Option::from(MerkleHashOrchard::from_bytes(&s)).unwrap());
        let anchor = MerklePath::from_parts(position, sibling_hashes)
            .root(
                Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&cmx))
                    .unwrap(),
            )
            .to_bytes();

        (
            IronwoodSpendSpec {
                fvk: fvk.to_bytes(),
                recipient,
                value: 100_000_000,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                cmx,
                witness: crate::zcash::ironwood_build::IronwoodWitness {
                    position,
                    auth_path,
                },
            },
            anchor,
        )
    }

    /// A real-spend bundle with one real output, in wire form (placeholder `rk` installed,
    /// FVK scrubbed — the serialized state).
    fn test_bundle() -> (Vec<u8>, [u8; ANCHOR_SIZE], OrchardAddressBytes) {
        let (spec, anchor) = test_spend_spec();
        let (bundle, _) = construct_spend_pczt_multi(
            &[spec],
            &[IronwoodOutputSpec {
                recipient: test_recipient(),
                amount: 90_000_000,
                ovk: None,
                memo: [0u8; 512],
            }],
            &anchor,
            OsRng,
        )
        .unwrap();
        let bytes = serialize_pczt(&bundle).unwrap();
        (bytes, anchor, test_recipient())
    }

    /// Verify the wire bundle, mapping the failure to its check name.
    fn verify_check(
        bytes: &[u8],
        ctx: &KeylessVerifyContext,
    ) -> Result<IronwoodVerificationReport, IronwoodVerifyCheck> {
        match verify_bundle_without_keys(&deserialize_pczt(bytes).unwrap(), ctx) {
            Ok(report) => Ok(report),
            Err(IronwoodVerifyError::Action { check, .. }) => Err(check),
            Err(other) => panic!("expected an Action failure, got {other:?}"),
        }
    }

    /// The context the tests verify with: no caller `ak` or randomizers, so `Rk` only checks
    /// each real spend's state.
    fn ctx() -> KeylessVerifyContext {
        KeylessVerifyContext::default()
    }

    /// The test wallet's spend authorizing key (`ask`), matching [`test_spend_spec`]'s note.
    fn test_ask() -> SpendAuthorizingKey {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        SpendAuthorizingKey::from(&sk)
    }

    /// The wallet's public spend-validating key (`ak`) — the client's own key, never in the
    /// PSBT.
    fn test_ak() -> [u8; 32] {
        // `ask.randomize(0)` is `ask` itself as a RedPallas signing key.
        let ask = test_ask().randomize(&pasta_curves::pallas::Scalar::ZERO);
        <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&ask))
    }

    /// A valid spend-validating key that belongs to some other wallet.
    fn foreign_ak() -> [u8; 32] {
        let signing_key = redpallas::SigningKey::<SpendAuth>::try_from(field_bytes(55)).unwrap();
        <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&signing_key))
    }

    /// Install the randomized `rk = ak.randomize(alpha)` on action 0 (the test bundle's only
    /// real spend) — `rk` only, as the signer does. Returns the patched bytes, the signing key
    /// and the `rk`.
    fn with_installed_randomizer(
        bytes: &[u8],
        alpha: pasta_curves::pallas::Scalar,
    ) -> (Vec<u8>, redpallas::SigningKey<SpendAuth>, [u8; 32]) {
        let rsk = test_ask().randomize(&alpha);
        let rk = <[u8; 32]>::from(VerificationKey::<SpendAuth>::from(&rsk));
        (with_spend_rk(bytes, 0, rk).unwrap(), rsk, rk)
    }

    #[test]
    fn honest_bundle_verifies_and_keeps_its_plaintext() {
        let (bytes, anchor, recipient) = test_bundle();
        let report = verify_check(&bytes, &ctx()).unwrap();
        assert_eq!(report.spends.len(), 1);
        assert_eq!(report.spends[0].value, 100_000_000);
        assert_eq!(report.outputs.len(), 1);
        assert_eq!(report.outputs[0].value, 90_000_000);
        assert_eq!(report.outputs[0].recipient, recipient);
        // 100_000_000 − 90_000_000
        assert_eq!(report.value_balance, 10_000_000);
        assert_eq!(report.anchor, anchor);
        assert!(!report.spends[0].randomizer_installed);
        assert!(!report.spends[0].signed);
        // Verification only reads: the plaintext the prover needs is still on the wire.
        let bundle = deserialize_pczt(&bytes).unwrap();
        for action in bundle.actions() {
            assert!(action.spend().value().is_some() && action.spend().recipient().is_some());
            assert!(action.output().value().is_some() && action.output().recipient().is_some());
            assert!(action.rcv().is_some());
        }
        assert_eq!(serialize_pczt(&bundle).unwrap(), bytes);
    }

    #[test]
    fn honest_shielding_bundle_verifies() {
        let shield = crate::zcash::ironwood_build::construct_shield_pczt(
            &test_recipient(),
            1_000,
            None,
            &test_bundle().1,
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        let report = verify_bundle_without_keys(&shield, &ctx()).unwrap();
        assert!(report.spends.is_empty());
        assert_eq!(report.outputs.len(), 1);
        assert_eq!(report.outputs[0].value, 1_000);
        assert_eq!(report.value_balance, -1_000);
    }

    /// A spends-only (deshield) bundle in wire form — one real spend, no outputs.
    fn test_deshield_bundle() -> Vec<u8> {
        let (spec, anchor) = test_spend_spec();
        let (bundle, _) = construct_spend_pczt_multi(&[spec], &[], &anchor, OsRng).unwrap();
        serialize_pczt(&bundle).unwrap()
    }

    #[test]
    fn honest_deshield_bundle_verifies_with_spends_only_flags() {
        let bytes = test_deshield_bundle();
        let report = verify_check(&bytes, &ctx()).unwrap();
        assert_eq!(report.spends.len(), 1);
        assert!(report.outputs.is_empty());
        // The deshield's flags enable spends but not outputs: spends | cross-address.
        assert_eq!(deserialize_pczt(&bytes).unwrap().flag_byte(), 0x05);
    }

    /// A flag that lies in either direction fails `Flags`: enabling outputs on an output-free
    /// bundle, disabling spends while a real spend is present, or clearing cross-address.
    #[test]
    fn flags_disagreeing_with_the_real_sides_fail_flags() {
        let bytes = test_deshield_bundle();
        for lying_flags in [0x01, 0x04, 0x06, 0x07] {
            let patched = with_flags_for_test(&bytes, lying_flags).unwrap();
            assert_eq!(
                verify_check(&patched, &ctx()).unwrap_err(),
                IronwoodVerifyCheck::Flags,
                "flag byte {:#04x} must be rejected",
                lying_flags
            );
        }
    }

    /// A transfer (real spend and real output) must enable both sides, and a shielding bundle
    /// (dummy spends only) must leave spends disabled; both keep cross-address enabled.
    #[test]
    fn transfer_and_shield_flags_must_match_their_real_sides() {
        let (transfer, anchor, _) = test_bundle();
        assert_eq!(deserialize_pczt(&transfer).unwrap().flag_byte(), 0x07);
        for lying_flags in [0x03, 0x04, 0x05, 0x06] {
            let patched = with_flags_for_test(&transfer, lying_flags).unwrap();
            assert_eq!(
                verify_check(&patched, &ctx()).unwrap_err(),
                IronwoodVerifyCheck::Flags,
                "transfer flag byte {:#04x} must be rejected",
                lying_flags
            );
        }

        let shield = crate::zcash::ironwood_build::construct_shield_pczt(
            &test_recipient(),
            1_000,
            None,
            &anchor,
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        let shield = serialize_pczt(&shield).unwrap();
        assert_eq!(deserialize_pczt(&shield).unwrap().flag_byte(), 0x06);
        for lying_flags in [0x02, 0x04, 0x05, 0x07] {
            let patched = with_flags_for_test(&shield, lying_flags).unwrap();
            assert_eq!(
                verify_check(&patched, &ctx()).unwrap_err(),
                IronwoodVerifyCheck::Flags,
                "shield flag byte {:#04x} must be rejected",
                lying_flags
            );
        }
    }

    #[test]
    fn recipient_swapped_at_equal_value_fails_note_commitment() {
        let (bytes, _anchor, _recipient) = test_bundle();
        // A *valid* but different recipient (a different key's address): orchard rejects an
        // invalid encoding at parse, so the tamper must keep the field well-formed.
        let other_recipient = {
            let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([9u8; 32])).unwrap();
            FullViewingKey::from(&sk)
                .address_at(0u32, Scope::External)
                .to_raw_address_bytes()
        };
        let tampered = with_output_recipient_for_test(&bytes, 0, &other_recipient).unwrap();
        assert_eq!(
            verify_check(&tampered, &ctx()).unwrap_err(),
            IronwoodVerifyCheck::NoteCommitment
        );
    }

    /// An output whose recipient is withheld would otherwise skip `NoteCommitment` and drop out of
    /// the report while its value still balanced `ValueSum`: funds to a recipient nobody is shown.
    #[test]
    fn output_without_its_recipient_fails_missing_plaintext() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let tampered = without_output_recipient_for_test(&bytes, 0).unwrap();
        assert_eq!(
            verify_check(&tampered, &ctx()).unwrap_err(),
            IronwoodVerifyCheck::MissingPlaintext
        );
    }

    /// Two self-consistent real-spend fixtures from ONE wallet that are true siblings in one
    /// Merkle tree: leaf A (100 ztk) at position 0, leaf B (40 ztk) at position 1.
    fn test_sibling_specs() -> (IronwoodSpendSpec, IronwoodSpendSpec, [u8; ANCHOR_SIZE]) {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let make = |diversifier: u32, value: u64, rho_seed: u64, rseed: [u8; 32]| {
            let recipient = fvk
                .address_at(diversifier, Scope::External)
                .to_raw_address_bytes();
            let rho = Option::<Rho>::from(Rho::from_bytes(&field_bytes(rho_seed))).unwrap();
            let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed, &rho)).unwrap();
            let address = Option::<orchard::Address>::from(
                orchard::Address::from_raw_address_bytes(&recipient),
            )
            .unwrap();
            let note = Option::<Note>::from(Note::from_parts(
                address,
                NoteValue::from_raw(value),
                rho,
                rseed,
                BundleVersion::ironwood_v3().note_version(),
            ))
            .unwrap();
            (
                recipient,
                rho,
                rseed,
                ExtractedNoteCommitment::from(note.commitment()),
            )
        };
        let (recipient_a, rho_a, rseed_a, cmx_a) = make(0, 100_000_000, 100, [42u8; 32]);
        let (recipient_b, rho_b, rseed_b, cmx_b) = make(1, 40_000_000, 101, [43u8; 32]);

        // True siblings at the tree's bottom level: positions 0 and 1.
        let mut path_a = [MerkleHashOrchard::from_cmx(&cmx_a); 32];
        let mut path_b = [MerkleHashOrchard::from_cmx(&cmx_a); 32];
        // Level-0 siblings are each other; levels 1..31 are shared filler siblings.
        path_a[0] = MerkleHashOrchard::from_cmx(&cmx_b);
        path_b[0] = MerkleHashOrchard::from_cmx(&cmx_a);
        for (dst, i) in path_a.iter_mut().skip(1).zip(0u64..) {
            *dst = Option::from(MerkleHashOrchard::from_bytes(&field_bytes(i + 2))).unwrap();
            path_b[1 + i as usize] = *dst;
        }
        let anchor = MerklePath::from_parts(0, path_a).root(cmx_a).to_bytes();

        let spec = |recipient: OrchardAddressBytes,
                    rho: Rho,
                    rseed: RandomSeed,
                    cmx: ExtractedNoteCommitment,
                    value: u64,
                    position: u32,
                    path: [MerkleHashOrchard; 32]| {
            IronwoodSpendSpec {
                fvk: fvk.to_bytes(),
                recipient,
                value,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                cmx: cmx.to_bytes(),
                witness: crate::zcash::ironwood_build::IronwoodWitness {
                    position,
                    auth_path: path.map(|h| h.to_bytes()),
                },
            }
        };
        (
            spec(recipient_a, rho_a, rseed_a, cmx_a, 100_000_000, 0, path_a),
            spec(recipient_b, rho_b, rseed_b, cmx_b, 40_000_000, 1, path_b),
            anchor,
        )
    }

    #[test]
    fn values_swapped_between_two_actions_fail_cv_net() {
        let (spec, second, anchor) = test_sibling_specs();
        let (bundle, action_map) = construct_spend_pczt_multi(
            &[spec, second],
            &[
                IronwoodOutputSpec {
                    recipient: test_recipient(),
                    amount: 30_000_000,
                    ovk: None,
                    memo: [0u8; 512],
                },
                IronwoodOutputSpec {
                    recipient: test_recipient(),
                    amount: 110_000_000,
                    ovk: None,
                    memo: [0u8; 512],
                },
            ],
            &anchor,
            OsRng,
        )
        .unwrap();
        let bytes = serialize_pczt(&bundle).unwrap();
        // Swap the two real spends' plaintext values (via the action map, so each spec's own
        // action gets the other's value): each action's `cv_net` no longer commits to its net
        // value, while the bundle totals stay equal, so only `CvNet` can catch it.
        let action_a = action_map.spend_action_index(0).unwrap();
        let action_b = action_map.spend_action_index(1).unwrap();
        let spend_a = with_spend_value(&bytes, action_a, 40_000_000).unwrap();
        let spend_b = with_spend_value(&spend_a, action_b, 100_000_000).unwrap();
        assert_eq!(
            verify_check(&spend_b, &ctx()).unwrap_err(),
            IronwoodVerifyCheck::CvNet
        );
    }

    #[test]
    fn forged_value_sum_fails_value_sum() {
        let (bytes, _anchor, _recipient) = test_bundle();
        // Committed sum: 100_000_000 − 90_000_000 = 10_000_000. Forge 20_000_000.
        let tampered = with_value_sum_for_test(&bytes, 20_000_000, false).unwrap();
        assert_eq!(
            verify_check(&tampered, &ctx()).unwrap_err(),
            IronwoodVerifyCheck::ValueSum
        );
    }

    #[test]
    fn witness_for_a_different_leaf_fails_spend_witness() {
        let (bytes, _anchor, _recipient) = test_bundle();
        // Same shape, wrong leaf position: the root no longer anchors the spend's note.
        let auth_path: WitnessAuthPath = std::array::from_fn(|i| field_bytes(i as u64 + 1));
        let tampered = with_spend_witness_for_test(&bytes, 0, 6, &auth_path).unwrap();
        assert_eq!(
            verify_check(&tampered, &ctx()).unwrap_err(),
            IronwoodVerifyCheck::SpendWitness
        );
    }

    #[test]
    fn placeholder_rk_verifies_with_the_callers_ak() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let ctx = KeylessVerifyContext {
            expected_ak: Some(test_ak()),
            ..Default::default()
        };
        let report = verify_check(&bytes, &ctx).unwrap();
        assert!(!report.spends[0].randomizer_installed);
    }

    #[test]
    fn identity_expected_ak_fails_rk() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let ctx = KeylessVerifyContext {
            expected_ak: Some([0u8; 32]),
            ..Default::default()
        };
        assert_eq!(
            verify_check(&bytes, &ctx).unwrap_err(),
            IronwoodVerifyCheck::Rk
        );
    }

    #[test]
    fn installed_randomizer_verifies_against_the_callers_ak() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let alpha = pasta_curves::pallas::Scalar::random(OsRng);
        let (installed, _rsk, rk) = with_installed_randomizer(&bytes, alpha);
        let ctx = KeylessVerifyContext {
            expected_ak: Some(test_ak()),
            expected_randomizers: vec![(0, alpha.to_repr(), rk)],
            ..Default::default()
        };
        let report = verify_check(&installed, &ctx).unwrap();
        assert!(report.spends[0].randomizer_installed);
        // Without the caller's expectations the installed state is still reported.
        let report = verify_check(&installed, &KeylessVerifyContext::default()).unwrap();
        assert!(report.spends[0].randomizer_installed);
    }

    #[test]
    fn foreign_expected_ak_fails_rk() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let alpha = pasta_curves::pallas::Scalar::random(OsRng);
        let (installed, _rsk, rk) = with_installed_randomizer(&bytes, alpha);
        let ctx = KeylessVerifyContext {
            expected_ak: Some(foreign_ak()),
            expected_randomizers: vec![(0, alpha.to_repr(), rk)],
            ..Default::default()
        };
        assert_eq!(
            verify_check(&installed, &ctx).unwrap_err(),
            IronwoodVerifyCheck::Rk
        );
    }

    #[test]
    fn expected_alpha_that_does_not_produce_the_rk_fails_rk() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let (installed, _rsk, rk) =
            with_installed_randomizer(&bytes, pasta_curves::pallas::Scalar::random(OsRng));
        // The installed `rk`, but a different claimed `alpha`.
        let other_alpha = pasta_curves::pallas::Scalar::random(OsRng).to_repr();
        let ctx = KeylessVerifyContext {
            expected_ak: Some(test_ak()),
            expected_randomizers: vec![(0, other_alpha, rk)],
            ..Default::default()
        };
        assert_eq!(
            verify_check(&installed, &ctx).unwrap_err(),
            IronwoodVerifyCheck::Rk
        );
    }

    #[test]
    fn expected_rk_that_differs_from_the_installed_one_fails_rk() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let alpha = pasta_curves::pallas::Scalar::random(OsRng);
        let (installed, _rsk, _rk) = with_installed_randomizer(&bytes, alpha);
        let (_, _, other_rk) =
            with_installed_randomizer(&bytes, pasta_curves::pallas::Scalar::random(OsRng));
        let ctx = KeylessVerifyContext {
            expected_randomizers: vec![(0, alpha.to_repr(), other_rk)],
            ..Default::default()
        };
        assert_eq!(
            verify_check(&installed, &ctx).unwrap_err(),
            IronwoodVerifyCheck::Rk
        );
        // An expected randomizer on a spend still at the placeholder fails too.
        assert_eq!(
            verify_check(&bytes, &ctx).unwrap_err(),
            IronwoodVerifyCheck::Rk
        );
    }

    #[test]
    fn expected_ak_without_the_randomizer_of_an_installed_spend_fails_rk() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let (installed, _rsk, _rk) =
            with_installed_randomizer(&bytes, pasta_curves::pallas::Scalar::random(OsRng));
        let ctx = KeylessVerifyContext {
            expected_ak: Some(test_ak()),
            ..Default::default()
        };
        assert_eq!(
            verify_check(&installed, &ctx).unwrap_err(),
            IronwoodVerifyCheck::Rk
        );
    }

    #[test]
    fn zero_expected_alpha_fails_rk() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let ctx = KeylessVerifyContext {
            expected_ak: Some(test_ak()),
            expected_randomizers: vec![(0, [0u8; 32], test_ak())],
            ..Default::default()
        };
        let tampered = with_spend_rk(&bytes, 0, test_ak()).unwrap();
        assert_eq!(
            verify_check(&tampered, &ctx).unwrap_err(),
            IronwoodVerifyCheck::Rk
        );
    }

    #[test]
    fn alpha_on_a_real_spend_fails_randomizer_present() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let alpha = pasta_curves::pallas::Scalar::random(OsRng);
        let (installed, _rsk, _rk) = with_installed_randomizer(&bytes, alpha);
        let tampered = with_spend_alpha(&installed, 0, Some(alpha.to_repr())).unwrap();
        assert_eq!(
            verify_check(&tampered, &ctx()).unwrap_err(),
            IronwoodVerifyCheck::RandomizerPresent
        );
    }

    #[test]
    fn expected_randomizer_for_an_action_without_a_real_spend_fails_rk() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let ctx = KeylessVerifyContext {
            expected_randomizers: vec![(7, [1u8; 32], test_ak())],
            ..Default::default()
        };
        assert_eq!(
            verify_check(&bytes, &ctx).unwrap_err(),
            IronwoodVerifyCheck::Rk
        );
    }

    #[test]
    fn fvk_left_on_a_real_spend_fails_viewing_key_present() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let fvk = {
            let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
            FullViewingKey::from(&sk).to_bytes()
        };
        let tampered = with_spend_fvk(&bytes, 0, fvk).unwrap();
        assert_eq!(
            verify_check(&tampered, &ctx()).unwrap_err(),
            IronwoodVerifyCheck::ViewingKeyPresent
        );
    }

    #[test]
    fn valid_spend_auth_sig_verifies_and_is_reported() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let (installed, rsk, _rk) =
            with_installed_randomizer(&bytes, pasta_curves::pallas::Scalar::random(OsRng));
        let sighash = field_bytes(66);
        let sig = <[u8; 64]>::from(&rsk.sign(OsRng, &sighash));
        let signed = with_spend_auth_sig(&installed, 0, sig).unwrap();
        let ctx = KeylessVerifyContext {
            sighash: Some(sighash),
            ..Default::default()
        };
        let report = verify_check(&signed, &ctx).unwrap();
        assert!(report.spends[0].signed);
    }

    #[test]
    fn invalid_spend_auth_sig_fails_spend_signature() {
        let (bytes, _anchor, _recipient) = test_bundle();
        let (installed, _rsk, _rk) =
            with_installed_randomizer(&bytes, pasta_curves::pallas::Scalar::random(OsRng));
        let tampered = with_spend_auth_sig(&installed, 0, [9u8; 64]).unwrap();
        let ctx = KeylessVerifyContext {
            sighash: Some(field_bytes(66)),
            ..Default::default()
        };
        assert_eq!(
            verify_check(&tampered, &ctx).unwrap_err(),
            IronwoodVerifyCheck::SpendSignature
        );
    }

    /// A shielding bundle and the index of its (only) dummy-spend action.
    fn shielding_bundle() -> (Vec<u8>, orchard::pczt::Bundle, usize) {
        let shield = crate::zcash::ironwood_build::construct_shield_pczt(
            &test_recipient(),
            1_000,
            None,
            &test_bundle().1,
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        let dummy_action = shield
            .actions()
            .iter()
            .position(|a| a.spend().dummy_sk().is_some())
            .unwrap();
        (serialize_pczt(&shield).unwrap(), shield, dummy_action)
    }

    /// `cv_net` committing to `spend_value − output_value` under a fixed trapdoor.
    fn net_commitment(spend_value: u64, output_value: u64) -> ([u8; 32], [u8; 32]) {
        let rcv = Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(
            field_bytes(1_500),
        ))
        .unwrap();
        let net = NoteValue::from_raw(spend_value) - NoteValue::from_raw(output_value);
        (
            ValueCommitment::derive(net, rcv.clone()).to_bytes(),
            rcv.to_bytes(),
        )
    }

    #[test]
    fn zero_value_output_on_a_dummy_spend_fails_zero_value_output() {
        // A shielding bundle's dummy spend carries a real output; rewrite that output to a value-0
        // one with a consistent note commitment, `cv_net` and committed sum, so the verifier
        // reaches `ZeroValueOutput` instead of tripping on the `NoteCommitment`, `CvNet` or
        // `ValueSum` checks: the accounting could no longer tell it apart from a fabricated dummy
        // output.
        let (bytes, shield, dummy_action) = shielding_bundle();
        // The output note's rho is the paired SPEND's nullifier (`Rho::from_nf_old`).
        let rho = Option::<Rho>::from(Rho::from_bytes(
            &shield.actions()[dummy_action]
                .spend()
                .nullifier()
                .to_bytes(),
        ))
        .unwrap();
        let recipient = Option::<orchard::Address>::from(orchard::Address::from_raw_address_bytes(
            &test_recipient(),
        ))
        .unwrap();
        let (rseed, cmx) = (0u64..)
            .find_map(|i| {
                let candidate = field_bytes(1_000 + i);
                let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(candidate, &rho))?;
                let note = Option::<Note>::from(Note::from_parts(
                    recipient,
                    NoteValue::from_raw(0),
                    rho,
                    rseed,
                    BundleVersion::ironwood_v3().note_version(),
                ))?;
                Some((
                    candidate,
                    ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
                ))
            })
            .unwrap();
        let (cv_net, rcv) = net_commitment(0, 0);
        let tampered = with_action_rewrite_for_test(
            &bytes,
            &ActionRewriteForTest {
                action_index: dummy_action,
                output_value: 0,
                output_rseed: rseed,
                output_cmx: cmx,
                spend_value: None,
                cv_net,
                rcv,
                value_sum_magnitude: 0,
                value_sum_negative: false,
            },
        )
        .unwrap();
        assert_eq!(
            verify_check(&tampered, &ctx()).unwrap_err(),
            IronwoodVerifyCheck::ZeroValueOutput
        );
    }

    /// A dummy spend that claims value would fund the bundle without ever appearing among
    /// the reported spends, so the shown fee would differ from the real one.
    #[test]
    fn dummy_spend_with_a_value_fails_dummy_spend_value() {
        let (bytes, shield, dummy_action) = shielding_bundle();
        let output = shield.actions()[dummy_action].output();
        let output_value = output.value().unwrap().inner();
        let (cv_net, rcv) = net_commitment(5_000, output_value);
        let tampered = with_action_rewrite_for_test(
            &bytes,
            &ActionRewriteForTest {
                action_index: dummy_action,
                output_value,
                output_rseed: *output.rseed().unwrap().as_bytes(),
                output_cmx: output.cmx().to_bytes(),
                spend_value: Some(5_000),
                cv_net,
                rcv,
                // 5_000 − 1_000 entering the transparent side.
                value_sum_magnitude: 4_000,
                value_sum_negative: false,
            },
        )
        .unwrap();
        assert_eq!(
            verify_check(&tampered, &ctx()).unwrap_err(),
            IronwoodVerifyCheck::DummySpendValue
        );
    }
}
