//! Bridge between the `orchard` PCZT roles and the v6 [`IronwoodBundle`] wire type.
//!
//! For an Ironwood bundle — shielding (outputs only), unshielding (spends only), or shielded
//! transfer — `wasm-utxo` plays three of the four `orchard` PCZT roles; the fourth (Prover) runs
//! in an external service:
//!
//! - **Constructor** ([`construct_spend_pczt_multi`]): builds the bundle from real spends (each
//!   carrying its full note plaintext) and/or requested outputs (each padded with a dummy spend)
//!   as an `orchard::pczt::Bundle` with no proof or signatures yet. All action data (value
//!   commitments, note commitments, ciphertexts) is fixed here, and it is exactly what the
//!   ZIP-244 shielded sighash commits to. Real spends carry only a placeholder `rk` and no
//!   `alpha` — the signer owns both — and no FVK (it is used only during construction).
//! - **IO Finalizer / Signer** ([`finalize_shield_io`]): derives the binding signing key (`bsk`)
//!   and signs the dummy spends over the now-fixed shielded sighash.
//! - **Transaction Extractor** ([`combine`]): given the signed PCZT with the prover's `zkproof`
//!   spliced in ([`super::ironwood_pczt::with_zkproof`]), verifies the spend-auth signatures,
//!   applies the binding signature, and maps the authorized orchard bundle to an [`IronwoodBundle`]
//!   ready for [`encode_v6_transaction`](super::v6::encode_v6_transaction).
//!
//! The **Prover** role (halo2) is intentionally absent — proving is delegated to an external
//! service so the shipped WASM never links the circuit.
//!
//! ## Why the proof can be filled in after signing
//!
//! A v6 transparent signature commits (via the ZIP-244 sighash) to the shielded *action data*
//! (`ironwood_digest`), but not to the `proof`, `anchor`, or `binding_sig` (those live in the
//! authorizing digest, which the sighash excludes). So the order is: fix action data at build,
//! compute the sighash, sign (transparent inputs + dummy spends), then prove, then combine. The
//! binding signature — applied during [`combine`] — signs the same build-time sighash and has no
//! dependency on the transparent signatures.

use rand::{CryptoRng, RngCore};

use orchard::builder::{Builder, BundleType};
use orchard::bundle::{BundleVersion, Flags};
#[cfg(any(test, feature = "orchard-proving"))]
use orchard::keys::Scope;
use orchard::keys::{FullViewingKey, OutgoingViewingKey};
use orchard::note::ExtractedNoteCommitment;
#[cfg(any(test, feature = "orchard-proving"))]
use orchard::note::{Note, NoteVersion, RandomSeed, Rho};
use orchard::pczt::Bundle as PcztBundle;
use orchard::primitives::redpallas::{SpendAuth, VerificationKey};
use orchard::tree::{Anchor, MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use orchard::{Action as OrchardAction, Address};

use incrementalmerkletree::{Address as MerkleAddress, Hashable, Level, Position};
use shardtree::{LocatedPrunableTree, Node, PrunableTree, RetentionFlags, Tree};
use std::sync::Arc;

use super::v6::{IronwoodAction, IronwoodBundle};

/// Length of a raw Orchard/Ironwood receiver (`Address`) in bytes.
pub const ORCHARD_ADDRESS_SIZE: usize = 43;
/// Length of an Ironwood note-commitment-tree root (`Anchor`) in bytes.
pub const ANCHOR_SIZE: usize = 32;
/// Length of an outgoing viewing key in bytes.
pub const OVK_SIZE: usize = 32;
/// Length of the ZIP-302 memo field in bytes.
pub const MEMO_SIZE: usize = 512;
/// The ZIP-302 "no memo" memo field: the `0xf6` marker followed by zeros.
pub const ZIP302_NO_MEMO: [u8; MEMO_SIZE] = {
    let mut memo = [0u8; MEMO_SIZE];
    memo[0] = 0xf6;
    memo
};

/// Length of an Orchard/Ironwood full viewing key in bytes (`ak ‖ nk ‖ rivk`).
pub const FVK_SIZE: usize = 96;
/// A raw Orchard/Ironwood receiver.
pub type OrchardAddressBytes = [u8; ORCHARD_ADDRESS_SIZE];
/// An Ironwood note-commitment-tree root.
pub type AnchorBytes = [u8; ANCHOR_SIZE];
/// A raw outgoing viewing key.
pub type OvkBytes = [u8; OVK_SIZE];
/// A ZIP-302 memo field.
pub type MemoBytes = [u8; MEMO_SIZE];
/// A raw Orchard/Ironwood full viewing key.
pub type FvkBytes = [u8; FVK_SIZE];
/// Proprietary key under which a real spend's on-chain note commitment (`cmx`) is recorded in its
/// action's proprietary map (reconciliation/audit; the PCZT spend side has no dedicated cmx field).
pub const CMX_PROPRIETARY_KEY: &str = "cmx";

/// The `rk` every real spend carries until the signer installs its randomized one: the Pallas
/// point `hash_to_curve("BitGo-Ironwood")(b"placeholder-rk")`, whose discrete log nobody knows,
/// so no signature verifies against it.
///
/// A real spend is unrandomized exactly when its `rk` is this point, so the randomizer state is
/// read from the committed `rk` itself. It is deliberately not the wallet's `ak`: the PSBT never
/// carries `ak`.
pub const PLACEHOLDER_RK: [u8; 32] = [
    0xc9, 0xf6, 0x55, 0x48, 0xf6, 0x26, 0x83, 0x02, 0x08, 0x17, 0x96, 0xa7, 0x05, 0x63, 0x14, 0x1d,
    0x16, 0xf5, 0x35, 0x69, 0xda, 0xe4, 0xe9, 0xe9, 0xd4, 0x63, 0xfa, 0xbe, 0x57, 0x12, 0x21, 0x8e,
];

/// Merkle depth of the Ironwood/Orchard note commitment tree.
pub const IRONWOOD_MERKLE_DEPTH: usize = 32;

/// Raw sibling hashes for one Merkle authentication path (leaf → anchor), caller-supplied,
/// leaf-to-root order.
pub type WitnessAuthPath = [[u8; 32]; IRONWOOD_MERKLE_DEPTH];

/// A validated Merkle witness for a note commitment, installable into a real spend via
/// `Builder::add_spend` (see [`construct_spend_pczt_multi`]).
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct IronwoodWitness {
    pub position: u32,
    pub auth_path: WitnessAuthPath,
}

/// Height (in levels) of a caller-supplied shard: its root sits at this level, so it spans up to
/// `2^shard_height` leaves. `0` means `shard` is just the target leaf itself and all 32 auth-path
/// entries come from `cap`.
pub type ShardHeight = u8;

/// A node of a pruned Orchard note-commitment (sub)tree, mirroring `shardtree::PrunableTree`:
/// caller-supplied shard/cap data for [`build_ironwood_witness_from_shard`] is expressed in this
/// shape rather than as a dense leaf array, so it matches what a real pruned tree store (e.g.
/// `wasm-privacy-coin`'s `ShardTree`) actually holds — most of a shard's leaves are never
/// individually retained, only enough annotated hashes to reproduce any witness.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type")]
pub enum ShardTreeNode {
    /// No information available for this (sub)tree.
    Nil,
    /// A single known hash: either a real leaf commitment, or the precomputed root of an entirely
    /// pruned subtree (a `Leaf` can appear at any level, not just level 0).
    Leaf {
        #[serde(with = "serde_bytes")]
        hash: [u8; 32],
    },
    /// Two children, optionally annotated with this node's own precomputed root — the annotation
    /// lets a caller omit detail below a pruned branch while still supplying enough to compute
    /// sibling roots elsewhere in the tree.
    Parent {
        #[serde(with = "serde_bytes", default)]
        hash: Option<[u8; 32]>,
        left: Box<ShardTreeNode>,
        right: Box<ShardTreeNode>,
    },
}

/// Caller-supplied shard/cap data for `build_ironwood_witness_from_shard`.
pub struct ShardWitnessInput<'a> {
    /// The leaf's position in the whole note-commitment tree.
    pub position: u32,
    pub shard_height: ShardHeight,
    /// Total number of leaves committed to the tree as of `expected_anchor` — the truncation
    /// boundary beyond which unpopulated positions are treated as canonically empty rather than
    /// as missing data (the note-commitment tree only ever grows, so this is well-defined for any
    /// anchor the caller has actually observed).
    pub leaf_count: u64,
    /// The commitment being witnessed — the leaf at `position`.
    pub cmx: &'a [u8; 32],
    /// The pruned shard subtree containing `position`, rooted at level `shard_height`.
    pub shard: &'a ShardTreeNode,
    /// The pruned "cap": the tree above every shard, down to (and including) shard-root nodes.
    /// Only the nodes on the path from `position`'s shard up to the overall root need be present.
    pub cap: &'a ShardTreeNode,
}

/// Errors produced while constructing or combining an Ironwood shielded bundle.
///
/// The variant name is surfaced to JS as `err.code` (e.g. `"IronwoodBuildError.BadRecipient"`)
/// via [`crate::error::WasmUtxoError`].
#[derive(Debug, strum::IntoStaticStr)]
pub enum IronwoodBuildError {
    /// The recipient bytes are not a valid Orchard/Ironwood raw address.
    BadRecipient,
    /// The anchor bytes are not a valid Ironwood note-commitment-tree root.
    BadAnchor,
    /// An Ironwood output must carry a positive value: a zero-valued output is how the
    /// construction marks fabricated dummy outputs, so accepting one from a caller would
    /// make real and fabricated outputs indistinguishable.
    ZeroValueOutput { output_index: usize },
    /// The orchard builder rejected the bundle parameters.
    Builder(String),
    /// The orchard builder rejected the output.
    Output(String),
    /// IO finalization (bsk derivation / dummy-spend signing) failed.
    Finalize(String),
    /// The Transaction Extractor rejected the PCZT (missing proof/sig/bsk, or a non-canonical proof).
    Extract(String),
    /// The bundle had no spends and no outputs.
    EmptyBundle,
    /// Binding the bundle failed: either the spend-auth signatures didn't verify against the
    /// sighash, or `bsk` (set by [`finalize_shield_io`]) is missing or does not match the bundle's
    /// value commitments.
    BindingSignatureFailed,
    /// The requested action index does not exist in the bundle.
    ActionIndexOutOfRange,
    /// The PCZT output is missing a field ([`recipient`](orchard::pczt::Output::recipient),
    /// [`value`](orchard::pczt::Output::value), or [`rseed`](orchard::pczt::Output::rseed)) needed
    /// to reconstruct the note and recompute `out_ciphertext`.
    MissingOutputFields,
    /// The reconstructed note is not internally valid (e.g. a corrupted `rseed`/`rho` pair).
    InvalidNote,
    /// The note reconstructed from the PCZT output's fields does not commit to the `cmx` the action
    /// already carries, so recomputing `out_ciphertext` from it would encrypt an `esk` inconsistent
    /// with the action's fixed `ephemeral_key`.
    NoteCommitmentMismatch,
    /// A constructed output's `out_ciphertext` does not match the expected outgoing viewing key.
    OutCiphertextMismatch,
    /// The bitgo/user key bytes are not a valid secp256k1 public/private key.
    BadKey(String),
    /// Local proof generation (`orchard-proving` feature) failed.
    Prove(String),
    /// A witness `cmx` or `auth_path` entry is not a canonical Pallas field element.
    BadWitnessPath,
    /// The witness recomputed a root that does not match the expected anchor.
    WitnessAnchorMismatch,
    /// `shard_height` exceeds `IRONWOOD_MERKLE_DEPTH` (32).
    ShardHeightOutOfRange,
    /// `shard` does not have enough detail to witness `position` as of `leaf_count` (e.g. a `Nil`
    /// or pruned `Leaf` node lies on the path to it), or `position`'s shard-local index is not
    /// within `leaf_count`.
    ShardWitnessUnavailable,
    /// `cap` does not have enough detail to compute a sibling root above the shard (e.g. a `Nil`
    /// or pruned `Leaf` node covers a range that a witness sibling needs to be split out of).
    CapNodeMissing,
    /// The full viewing key bytes are not a valid Orchard/Ironwood FVK.
    BadFvk,
    /// The bundle's spends use more than one full viewing key; one wallet (one FVK) per bundle,
    /// because the output `ovk` defaults to the spending FVK's own.
    MixedSpendingFvks,
    /// Two of the bundle's spends derive the same nullifier. Orchard does not check this, and
    /// consensus rejects a transaction with a repeated nullifier, so the duplicate must be caught
    /// at construction instead of dying on-chain.
    DuplicateNullifier {
        /// The later action whose nullifier repeats an earlier spend's.
        action_index: usize,
    },
    /// The orchard PCZT Updater role rejected an update (e.g. an action index out of range).
    Updater(String),
    /// The PCZT wire round-trip (serialize/patch/deserialize) failed.
    PcztWire(String),
    /// The orchard PCZT Verifier rejected the bundle, with the failing check/action as context.
    Verify(String),
    /// A provided spend-auth signature is not valid for the action's `rk` (and sighash).
    InvalidExternalSignature,
    /// The orchard PCZT Signer role rejected the signature for a reason other than
    /// [`InvalidExternalSignature`](Self::InvalidExternalSignature).
    Signer(String),
    /// A spend's `rk` cannot be (re)installed once any action in the bundle carries a
    /// spend-auth signature: the ZIP-244 sighash commits every action's `rk`, so replacing any
    /// of them would invalidate every signature already made.
    SpendSignatureAlreadyPresent,
    /// `set_spend_fvk` was called on a dummy spend: a dummy's FVK belongs to its fabricating
    /// builder (the IO Finalizer signs the dummy with it) and must not be overwritten.
    SetFvkOnDummySpend,
    /// A spend's `rk` (and `alpha`) replacement targeted a dummy spend: a dummy's `alpha`/`rk`
    /// were fabricated with its `dummy_sk`, which the IO Finalizer signs with, so replacing them
    /// would break that signature.
    RandomizerOnDummySpend,
    /// The randomizer pair would leave the spend's `rk` unrandomized: `alpha` is zero (so
    /// `rk = ak.randomize(alpha)` is the wallet's own, linkable `ak`), or `rk` is
    /// [`PLACEHOLDER_RK`].
    UnrandomizedRk,
    /// The keyless spend constructor was called without any real spend:
    /// an output-only bundle is a *shielding* build — use [`construct_shield_pczt_multi`]
    /// for it.
    NoSpends,
    /// An output passed to the keyless spend constructor carried an explicit `ovk`: in the
    /// spend flow encryption belongs to the viewing-key holder, so the PSBT side may not
    /// choose one. The placeholder `out_ciphertext` the constructor installs is replaced by
    /// the real `out_ciphertext` later.
    OvkNotAllowed {
        /// The offending output's position in the `outputs` slice.
        output_index: usize,
    },
    /// The caller-supplied spend-validating key (`ak`) is not a canonical, non-identity
    /// RedPallas verification key, so no randomizer pair can be checked against it.
    BadSpendValidatingKey,
    /// The randomizer pair is inconsistent with the caller's spend-validating key: `rk` is not
    /// `ak.randomize(alpha)`, or `rk` is not a canonical verification key.
    RandomizerMismatch,
    /// A real spend's `rk` is still [`PLACEHOLDER_RK`]: the ZIP-244 digest commits `rk`, so no
    /// sighash computed before every randomizer is installed is final.
    RandomizersNotInstalled,
    /// A randomizer `alpha` is not a canonical Pallas scalar encoding.
    BadAlpha {
        /// The action the randomizer targets.
        action_index: usize,
    },
    /// The prover or keyed verifier was given no `alpha` for this real spend: the PSBT never
    /// stores one, so every real spend's `alpha` must be supplied out of band.
    RandomizerMissing {
        /// The real spend without an `alpha`.
        action_index: usize,
    },
    /// Two randomizers target the same action.
    DuplicateRandomizer {
        /// The repeated action index.
        action_index: usize,
    },
    /// A keyless spend's caller-supplied nullifier is not a canonical Pallas base-field
    /// encoding. The nullifier is installed verbatim and keys the paired output note's `rho`.
    BadNullifier {
        /// The offending spend's position in the `spends` slice.
        spend_index: usize,
    },
    /// A note or output value, or the spend/output total, exceeds Zcash `MAX_MONEY`
    /// (21 000 000 ZEC): no such value can appear in a valid transaction.
    ValueOutOfRange,
    /// The keyless spend constructor's own output failed the key-free verifier — an
    /// internal inconsistency; the wrapped error names the failing check.
    SelfCheck(IronwoodVerifyError),
}

/// Which Verifier check failed — its name is the error code callers key their diagnostics on
/// (`IronwoodVerifyError.<check>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr)]
pub enum IronwoodVerifyCheck {
    /// The note's plaintext fields do not produce the recorded nullifier under this FVK (or
    /// the FVK does not own the note).
    Nullifier,
    /// `rk` is not `ak.randomize(alpha)` for this FVK (or `alpha` is not installed).
    Rk,
    /// `cv_net` does not commit to the action's net value with its `rcv`.
    CvNet,
    /// The output note does not produce the committed `cmx`.
    NoteCommitment,
    /// The bundle's committed `value_sum` does not equal the plaintext
    /// `Σ(v_spend − v_out)`.
    ValueSum,
    /// The real spend's rebuilt note does not commit to a leaf under the bundle's anchor
    /// (or does not match the spend's recorded `cmx`).
    SpendWitness,
    /// A real spend leaks viewing-key material (`fvk` or a ZIP-32 derivation) on the wire.
    ViewingKeyPresent,
    /// A real spend carries its randomizer `alpha` on the wire: with `rk` it reveals the
    /// wallet's `ak` (`ak = rk − [alpha]·G`).
    RandomizerPresent,
    /// The bundle is not an Ironwood V3 bundle.
    BundleVersion,
    /// The bundle's flags do not match its contents (spends enabled iff a real spend is
    /// present, outputs iff a real output is, cross-address always enabled).
    Flags,
    /// A value-0 (dummy) output is paired with a dummy spend, so the value-based
    /// accounting cannot distinguish it from a real output.
    ZeroValueOutput,
    /// A spend-auth signature does not verify against the spend's `rk` over the caller's
    /// sighash.
    SpendSignature,
    /// An action is missing a plaintext field (note recipient/value/rho/rseed or the
    /// value-commitment trapdoor) that the checks and the prover rely on.
    MissingPlaintext,
    /// A fabricated (dummy) spend carries a non-zero value.
    DummySpendValue,
    /// An output's `ephemeral_key`/`enc_ciphertext` do not carry its plaintext note: the
    /// ciphertext does not decrypt under the note's own `esk` and recipient `pk_d` to exactly
    /// the shown note, so the recipient could never find it.
    EncCiphertext,
}

/// The full orchard Verifier role's failure modes (see [`verify_ironwood_spends`]).
#[derive(Debug, strum::IntoStaticStr)]
pub enum IronwoodVerifyError {
    /// The supplied FVK bytes are not a valid Orchard/Ironwood full viewing key.
    BadFvk,
    /// The bundle violates the cross-address restriction.
    CrossAddressRestriction(String),
    /// A per-action check failed; `check` says which, `detail` carries the orchard error.
    Action {
        /// The action the failing check ran on.
        action_index: usize,
        /// Which check failed.
        check: IronwoodVerifyCheck,
        /// The orchard `VerifyError` detail.
        detail: String,
    },
}

impl core::fmt::Display for IronwoodVerifyCheck {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::Nullifier => "nullifier",
            Self::Rk => "rk",
            Self::CvNet => "cv_net",
            Self::NoteCommitment => "note commitment",
            Self::ValueSum => "value sum",
            Self::SpendWitness => "spend witness",
            Self::ViewingKeyPresent => "viewing key present",
            Self::RandomizerPresent => "randomizer present",
            Self::BundleVersion => "bundle version",
            Self::Flags => "flags",
            Self::ZeroValueOutput => "zero-value output",
            Self::SpendSignature => "spend signature",
            Self::MissingPlaintext => "missing plaintext",
            Self::DummySpendValue => "dummy spend value",
            Self::EncCiphertext => "enc ciphertext",
        };
        f.write_str(s)
    }
}

impl core::fmt::Display for IronwoodVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadFvk => write!(f, "ironwood-verify: invalid full viewing key bytes"),
            Self::CrossAddressRestriction(e) => {
                write!(f, "ironwood-verify: cross-address restriction: {e}")
            }
            Self::Action {
                action_index,
                check,
                detail,
            } => write!(
                f,
                "ironwood-verify: action {action_index} failed the {check} check: {detail}"
            ),
        }
    }
}

impl std::error::Error for IronwoodVerifyError {}

/// Per-action failures surface the failing check as the code (`IronwoodVerifyError.Rk`, …), not
/// the shared `Action` variant name, so callers can key on which check failed.
impl crate::error::WasmErrorCode for IronwoodVerifyError {
    fn code(&self) -> String {
        let name: &'static str = match self {
            Self::Action { check, .. } => check.into(),
            other => other.into(),
        };
        format!("IronwoodVerifyError.{name}")
    }
}

impl core::fmt::Display for IronwoodBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadRecipient => write!(f, "ironwood-build: invalid recipient address bytes"),
            Self::BadAnchor => write!(f, "ironwood-build: invalid anchor bytes"),
            Self::Builder(e) => write!(f, "ironwood-build: builder error: {e}"),
            Self::Output(e) => write!(f, "ironwood-build: output error: {e}"),
            Self::ZeroValueOutput { output_index } => write!(
                f,
                "ironwood-build: output {output_index} has a zero value; Ironwood outputs \
                 must carry a positive value"
            ),
            Self::Finalize(e) => write!(f, "ironwood-build: IO finalization failed: {e}"),
            Self::Extract(e) => write!(f, "ironwood-build: extractor error: {e}"),
            Self::EmptyBundle => write!(f, "ironwood-build: bundle has no actions"),
            Self::BindingSignatureFailed => {
                write!(
                    f,
                    "ironwood-build: failed to bind the bundle (invalid spend-auth signatures, \
                     or a missing/invalid binding signing key)"
                )
            }
            Self::ActionIndexOutOfRange => write!(f, "ironwood-build: action index out of range"),
            Self::MissingOutputFields => write!(
                f,
                "ironwood-build: output is missing recipient/value/rseed; cannot recompute \
                 out_ciphertext"
            ),
            Self::InvalidNote => write!(
                f,
                "ironwood-build: reconstructed note is not internally valid"
            ),
            Self::NoteCommitmentMismatch => write!(
                f,
                "ironwood-build: the note reconstructed from the output's recipient/value/rseed does \
                 not commit to the action's cmx; refusing to recompute out_ciphertext from it"
            ),
            Self::OutCiphertextMismatch => write!(
                f,
                "ironwood-build: output out_ciphertext does not match the expected ovk"
            ),
            Self::BadKey(e) => write!(f, "ironwood-build: invalid key: {e}"),
            Self::Prove(e) => write!(f, "ironwood-build: proof generation failed: {e}"),
            Self::BadWitnessPath => write!(
                f,
                "ironwood-build: invalid witness path (cmx or an auth_path entry is not a \
                 canonical field element)"
            ),
            Self::WitnessAnchorMismatch => write!(
                f,
                "ironwood-build: witness path does not recompute to the expected anchor"
            ),
            Self::ShardHeightOutOfRange => write!(
                f,
                "ironwood-build: shard_height exceeds the tree depth ({IRONWOOD_MERKLE_DEPTH})"
            ),
            Self::ShardWitnessUnavailable => write!(
                f,
                "ironwood-build: shard does not have enough detail to witness the target position"
            ),
            Self::CapNodeMissing => write!(
                f,
                "ironwood-build: cap does not have enough detail to compute a sibling root"
            ),
            Self::BadFvk => write!(f, "ironwood-build: invalid full viewing key bytes"),
            Self::DuplicateNullifier { action_index } => write!(
                f,
                "ironwood-build: duplicate nullifier across spend actions (action {action_index} \
                 repeats an earlier spend's nullifier)"
            ),
            Self::MixedSpendingFvks => write!(
                f,
                "ironwood-build: all spends in one bundle must share one full viewing key"
            ),
            Self::Updater(e) => write!(f, "ironwood-build: PCZT updater error: {e}"),
            Self::PcztWire(e) => write!(f, "ironwood-build: PCZT wire error: {e}"),
            Self::Verify(e) => write!(f, "ironwood-build: PCZT verification failed: {e}"),
            Self::InvalidExternalSignature => write!(
                f,
                "ironwood-build: spend-auth signature is not valid for the action's rk and \
                 sighash"
            ),
            Self::Signer(e) => write!(f, "ironwood-build: PCZT signer error: {e}"),
            Self::SpendSignatureAlreadyPresent => write!(
                f,
                "ironwood-build: a spend's randomizer cannot be installed after a \
                 spend-auth signature exists (the sighash commits every action's rk)"
            ),
            Self::SetFvkOnDummySpend => write!(
                f,
                "ironwood-build: a dummy spend's fvk belongs to its fabricating builder and \
                 must not be overwritten"
            ),
            Self::RandomizerOnDummySpend => write!(
                f,
                "ironwood-build: a dummy spend's alpha/rk belong to its fabricating builder and \
                 must not be replaced"
            ),
            Self::UnrandomizedRk => write!(
                f,
                "ironwood-build: the randomizer leaves the spend's rk unrandomized (alpha is \
                 zero, or rk is the placeholder)"
            ),
            Self::NoSpends => write!(
                f,
                "ironwood-build: a spend bundle needs at least one real spend; outputs-only \
                 bundles are shielding builds"
            ),
            Self::OvkNotAllowed { output_index } => write!(
                f,
                "ironwood-build: output {output_index} carries an explicit ovk; the keyless \
                 spend constructor leaves encryption to the viewing-key holder"
            ),
            Self::BadSpendValidatingKey => write!(
                f,
                "ironwood-build: the spend-validating key is not a canonical RedPallas \
                 verification key"
            ),
            Self::BadNullifier { spend_index } => write!(
                f,
                "ironwood-build: spend {spend_index}'s nullifier is not a canonical field \
                 element"
            ),
            Self::RandomizerMismatch => write!(
                f,
                "ironwood-build: the randomizer pair does not match the spend-validating key \
                 (rk must equal ak.randomize(alpha))"
            ),
            Self::RandomizersNotInstalled => write!(
                f,
                "ironwood-build: cannot compute a sighash or apply a signature while a real \
                 spend's rk is still the placeholder"
            ),
            Self::BadAlpha { action_index } => write!(
                f,
                "ironwood-build: action {action_index}'s alpha is not a canonical scalar"
            ),
            Self::RandomizerMissing { action_index } => write!(
                f,
                "ironwood-build: no alpha was supplied for the real spend at action \
                 {action_index}"
            ),
            Self::DuplicateRandomizer { action_index } => write!(
                f,
                "ironwood-build: more than one randomizer targets action {action_index}"
            ),
            Self::ValueOutOfRange => write!(
                f,
                "ironwood-build: a value or the spend/output total exceeds MAX_MONEY"
            ),
            Self::SelfCheck(e) => write!(
                f,
                "ironwood-build: the constructed bundle failed its key-free self-check: {e}"
            ),
        }
    }
}

crate::impl_wasm_error_code!(IronwoodBuildError);

/// One requested Ironwood shielded output, as passed to [`construct_spend_pczt_multi`].
#[derive(Clone, Copy)]
pub struct IronwoodOutputSpec {
    /// 43-byte raw Orchard/Ironwood address.
    pub recipient: OrchardAddressBytes,
    /// Note value in zatoshi.
    pub amount: u64,
    /// Outgoing viewing key, if the output should be recoverable by the sender; `None` for a
    /// keyless build, or in a bundle with real spends (the spending FVK's external `ovk` is then
    /// used).
    pub ovk: Option<OvkBytes>,
    /// ZIP-302 memo field.
    pub memo: MemoBytes,
}

/// One Ironwood note to spend, as passed to [`construct_spend_pczt_multi`].
///
/// Everything except the witness is the note's plaintext from the wallet's own note record: the
/// FVK must own the note, the reconstructed note must commit to `cmx`, and the witness must
/// recompute to the bundle's anchor. The FVK is used only during construction (ownership check,
/// nullifier derivation, and the construction-time verifier) and is omitted from the serialized
/// PCZT; its public `ak` doubles as the placeholder `rk` until the signer replaces it.
///
/// The keyed (FVK-carrying) spend spec — the **test oracle** for the keyless constructor
/// (`ironwood_construct::construct_spend_pczt_keyless`). Production builds never see the FVK:
/// the PSBT is built keyless, and the shipped WASM must not carry this path.
#[cfg(any(test, feature = "orchard-proving"))]
#[derive(Clone, Copy, Debug)]
pub struct IronwoodSpendSpec {
    /// Raw full viewing key, 96 bytes: `ak ‖ nk ‖ rivk` (orchard's `FullViewingKey::to_bytes`
    /// layout). All spends in one bundle must share the same FVK.
    pub fvk: FvkBytes,
    /// The spent note's recipient: 43-byte raw Orchard/Ironwood address.
    pub recipient: OrchardAddressBytes,
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
    pub witness: IronwoodWitness,
}

/// Maps each caller-supplied spend/output position to the action index it landed at in the
/// constructed bundle. The builder reorders actions (see `orchard::builder::BundleMetadata`), so
/// callers that associate per-spend or per-output data with an action must go through this
/// mapping rather than assuming index `i`.
#[derive(Clone, Debug)]
pub struct IronwoodActionMap {
    spend_action_indices: Vec<usize>,
    output_action_indices: Vec<usize>,
}

impl IronwoodActionMap {
    /// The action index `spends[i]` landed at.
    pub fn spend_action_index(&self, i: usize) -> Option<usize> {
        self.spend_action_indices.get(i).copied()
    }

    /// The action index `outputs[i]` landed at.
    pub fn output_action_index(&self, i: usize) -> Option<usize> {
        self.output_action_indices.get(i).copied()
    }

    /// The action index of every requested spend, in request order.
    pub fn spend_action_indices(&self) -> &[usize] {
        &self.spend_action_indices
    }

    /// The action index of every requested output, in request order.
    pub fn output_action_indices(&self) -> &[usize] {
        &self.output_action_indices
    }
}

impl IronwoodActionMap {
    /// Assemble a map from already-shuffled action indices — the keyless spend
    /// constructor's shuffle produces them directly, without a builder.
    pub(crate) fn from_parts(
        spend_action_indices: Vec<usize>,
        output_action_indices: Vec<usize>,
    ) -> Self {
        Self {
            spend_action_indices,
            output_action_indices,
        }
    }
}

/// The Ironwood bundle flags for a build with the given real sides: spends are enabled iff the
/// bundle carries real spends, outputs iff it carries real outputs, and cross-address transfers
/// are always enabled (the least-restrictive value the Ironwood V3 version permits). Fabricated
/// value-0 halves — the dummy spends on shielding builds, the dummy outputs on deshields —
/// satisfy the disabled bits: the action circuit only forbids non-zero value on a disabled side.
pub(crate) fn ironwood_flags(has_spends: bool, has_outputs: bool) -> Flags {
    // Flag-byte layout (Zcash §7.1): bit 0 enables spends, bit 1 outputs, and bit 2
    // (`enableCrossAddress`) is set on every Ironwood V3 bundle.
    let byte = 0b100 | u8::from(has_spends) | (u8::from(has_outputs) << 1);
    Flags::from_byte(byte, BundleVersion::ironwood_v3())
        .expect("the Ironwood V3 flag byte is always representable")
}

/// The wire byte of [`ironwood_flags`].
pub(crate) fn ironwood_flag_byte(has_spends: bool, has_outputs: bool) -> u8 {
    let bundle_version = BundleVersion::ironwood_v3();
    ironwood_flags(has_spends, has_outputs)
        .to_byte(bundle_version)
        .expect("the Ironwood V3 flag byte is always representable")
}

/// Constructor: build an Ironwood bundle as an orchard PCZT from real spends and/or requested
/// outputs — the general Constructor for the shielding (outputs only), unshielding (spends only),
/// and shielded-transfer flows.
///
/// `BundleType::UNPADDED` ⇒ exactly `max(spends.len(), outputs.len())` actions, no additional
/// padding; where an action pairs a real side with a missing one, the missing side is the
/// protocol's dummy (a fabricated zero-value spend for shielding, a dummy output description for
/// spend-only actions).
///
/// Every spend must share one full viewing key (one wallet per bundle), because an output's `ovk`
/// defaults to that FVK's own external `ovk` (`fvk.to_ovk(Scope::External)`) — so an output with
/// `ovk: None` in a bundle with real spends gets its `out_ciphertext` finalized at construction;
/// in the spend-free (shielding) case `None` still means a keyless build.
///
/// `anchor` is the Ironwood note-commitment-tree root every spend's witness must recompute to.
/// `rng` must be a CSPRNG — it seeds the builder's internal randomness.
///
/// Actions are randomized (reordered) relative to the `spends`/`outputs` order (see
/// `orchard::builder::BundleMetadata`), so the returned [`IronwoodActionMap`] gives, for each
/// `spends[i]`/`outputs[i]`, the action index it landed at in the bundle — callers that need to
/// associate per-spend or per-output data with the right action must go through the map rather
/// than assuming index `i`.
///
/// The returned PCZT carries no signatures or proof yet. Real spends carry the note plaintext
/// (recipient/value/rho/rseed/witness) but no FVK, only a placeholder `rk` (the spend's `ak`), and
/// no `alpha`; see [`scrub_spend_randomizers`]. Run [`finalize_shield_io`] once the sighash is
/// known, then hand the PCZT to the prover and [`combine`].
///
/// This is the oracle path: keyed construction through the orchard `Builder`, available only
/// under `test` / `orchard-proving`. The production deshield/shielded→shielded
/// Constructor is [`crate::zcash::ironwood_construct::construct_spend_pczt_keyless`].
#[cfg(any(test, feature = "orchard-proving"))]
pub fn construct_spend_pczt_multi<R: RngCore + CryptoRng>(
    spends: &[IronwoodSpendSpec],
    outputs: &[IronwoodOutputSpec],
    anchor: &AnchorBytes,
    mut rng: R,
) -> Result<(PcztBundle, IronwoodActionMap), IronwoodBuildError> {
    if spends.is_empty() && outputs.is_empty() {
        return Err(IronwoodBuildError::EmptyBundle);
    }
    let anchor_root =
        Option::from(Anchor::from_bytes(*anchor)).ok_or(IronwoodBuildError::BadAnchor)?;

    let bundle_version = BundleVersion::ironwood_v3();
    let mut builder = Builder::new(
        BundleType::UNPADDED,
        bundle_version,
        ironwood_flags(!spends.is_empty(), !outputs.is_empty()),
        anchor_root,
    )
    .map_err(|e| IronwoodBuildError::Builder(e.to_string()))?;

    // Parse and validate every spend's note data before touching the builder: typed errors here
    // instead of the builder's opaque SpendError strings.
    let parsed: Vec<ParsedSpend> = spends
        .iter()
        .map(|spec| parse_spend_spec(spec, anchor, bundle_version.note_version()))
        .collect::<Result<_, _>>()?;
    // One wallet = one FVK per bundle; a differing FVK is rejected before the note-ownership
    // check in the builder (which would fail anyway with the wrong FVK).
    if let Some(first) = parsed.first() {
        if parsed
            .iter()
            .any(|p| p.fvk.to_bytes() != first.fvk.to_bytes())
        {
            return Err(IronwoodBuildError::MixedSpendingFvks);
        }
    }
    let default_ovk = parsed
        .first()
        .map(|p| *p.fvk.to_ovk(Scope::External).as_ref());
    for ParsedSpend {
        fvk,
        note,
        merkle_path,
    } in parsed
    {
        builder
            .add_spend(fvk, note, merkle_path)
            .map_err(|e| IronwoodBuildError::Builder(e.to_string()))?;
    }

    for (output_index, spec) in outputs.iter().enumerate() {
        if spec.amount == 0 {
            return Err(IronwoodBuildError::ZeroValueOutput { output_index });
        }
        let recipient = Option::from(Address::from_raw_address_bytes(&spec.recipient))
            .ok_or(IronwoodBuildError::BadRecipient)?;
        let ovk = spec.ovk.or(default_ovk).map(OutgoingViewingKey::from);
        builder
            .add_output(ovk, recipient, NoteValue::from_raw(spec.amount), spec.memo)
            .map_err(|e| IronwoodBuildError::Output(e.to_string()))?;
    }
    let (bundle, meta) = builder
        .build_for_pczt(&mut rng)
        .map_err(|e| IronwoodBuildError::Builder(e.to_string()))?;
    let action_map = IronwoodActionMap {
        spend_action_indices: (0..spends.len())
            .map(|i| {
                meta.spend_action_index(i)
                    .ok_or(IronwoodBuildError::ActionIndexOutOfRange)
            })
            .collect::<Result<Vec<_>, _>>()?,
        output_action_indices: (0..outputs.len())
            .map(|i| {
                meta.output_action_index(i)
                    .ok_or(IronwoodBuildError::ActionIndexOutOfRange)
            })
            .collect::<Result<Vec<_>, _>>()?,
    };

    // Validate FVK-dependent invariants while the constructor still has the transient FVKs.
    verify_spend_pczt(&bundle)?;
    validate_constructed_out_ciphertexts(
        &bundle,
        outputs,
        action_map.output_action_indices(),
        default_ovk,
        &mut rng,
    )?;

    // Record each spent note's cmx for reconciliation, then strip what the signer owns:
    // the builder bakes a random `alpha` and a randomized `rk` into every real spend at build time,
    // but `alpha` is derived at signing — the persisted PCZT carries only the placeholder. The FVK
    // is stripped too: it is used only during construction. Dummy spends are untouched (the IO
    // Finalizer signs them from their stored alpha/dummy_sk).
    let mut bundle = bundle;
    for (i, spec) in spends.iter().enumerate() {
        // The map covers every requested spend by construction (it was built from the same len).
        let idx = action_map
            .spend_action_index(i)
            .expect("map covers every requested spend");
        bundle
            .update_with(|mut u| {
                u.update_action_with(idx, |mut a| {
                    a.set_spend_proprietary(CMX_PROPRIETARY_KEY.to_string(), spec.cmx.to_vec());
                    Ok(())
                })
            })
            .map_err(|e| IronwoodBuildError::Updater(e.to_string()))?;
    }
    let bundle = scrub_spend_randomizers(&bundle, action_map.spend_action_indices())?;
    Ok((bundle, action_map))
}

/// Check that every real output whose `ovk` is known at construction time (an explicit one, or the
/// spending FVK's default) got an `out_ciphertext` under exactly that `ovk`: with real spends the
/// signing round never re-encrypts it, so a mismatch here would ship unrecoverable outgoing data.
/// Encryption under a known `ovk` is deterministic, so `rng` is not actually consumed.
fn validate_constructed_out_ciphertexts<R: RngCore + CryptoRng>(
    bundle: &PcztBundle,
    outputs: &[IronwoodOutputSpec],
    output_indices: &[usize],
    default_ovk: Option<OvkBytes>,
    rng: &mut R,
) -> Result<(), IronwoodBuildError> {
    for (output, &action_index) in outputs.iter().zip(output_indices) {
        if output.amount == 0 {
            continue;
        }
        let Some(ovk) = output.ovk.or(default_ovk) else {
            continue;
        };
        let expected = compute_out_ciphertext(bundle, action_index, ovk, rng)?;
        if bundle.actions()[action_index]
            .output()
            .encrypted_note()
            .out_ciphertext
            != expected
        {
            return Err(IronwoodBuildError::OutCiphertextMismatch);
        }
    }
    Ok(())
}

/// Constructor: build a transparent → Ironwood shielding bundle (no real spends) as an orchard
/// PCZT, for one or more outputs. Each output rides an orchard-`Builder`-fabricated dummy spend
/// (`BundleType::UNPADDED`, so exactly one action per output); no key is needed.
/// The bundle's flags disable spends: the fabricated dummy spends are declared dummies, not
/// real spends.
///
/// Also the dummy-spend fabricator the keyless spend constructor
/// ([`crate::zcash::ironwood_construct::construct_spend_pczt_keyless`]) reuses for surplus
/// outputs: it moves the fabricated actions into its own bundle through the wire form.
pub fn construct_shield_pczt_multi<R: RngCore + CryptoRng>(
    outputs: &[IronwoodOutputSpec],
    anchor: &AnchorBytes,
    mut rng: R,
) -> Result<(PcztBundle, IronwoodActionMap), IronwoodBuildError> {
    if outputs.is_empty() {
        return Err(IronwoodBuildError::EmptyBundle);
    }
    let anchor_root =
        Option::from(Anchor::from_bytes(*anchor)).ok_or(IronwoodBuildError::BadAnchor)?;
    let bundle_version = BundleVersion::ironwood_v3();
    let mut builder = Builder::new(
        BundleType::UNPADDED,
        bundle_version,
        ironwood_flags(false, true),
        anchor_root,
    )
    .map_err(|e| IronwoodBuildError::Builder(e.to_string()))?;
    for (output_index, spec) in outputs.iter().enumerate() {
        if spec.amount == 0 {
            return Err(IronwoodBuildError::ZeroValueOutput { output_index });
        }
        let recipient = Option::from(Address::from_raw_address_bytes(&spec.recipient))
            .ok_or(IronwoodBuildError::BadRecipient)?;
        builder
            .add_output(
                spec.ovk.map(OutgoingViewingKey::from),
                recipient,
                NoteValue::from_raw(spec.amount),
                spec.memo,
            )
            .map_err(|e| IronwoodBuildError::Output(e.to_string()))?;
    }
    let (bundle, meta) = builder
        .build_for_pczt(&mut rng)
        .map_err(|e| IronwoodBuildError::Builder(e.to_string()))?;
    let action_map = IronwoodActionMap::from_parts(
        Vec::new(),
        (0..outputs.len())
            .map(|i| {
                meta.output_action_index(i)
                    .ok_or(IronwoodBuildError::ActionIndexOutOfRange)
            })
            .collect::<Result<Vec<_>, _>>()?,
    );
    verify_spend_pczt(&bundle)?;
    validate_constructed_out_ciphertexts(
        &bundle,
        outputs,
        action_map.output_action_indices(),
        None,
        &mut rng,
    )?;
    Ok((bundle, action_map))
}

/// The parsed-and-validated values one real spend contributes to the builder.
#[cfg(any(test, feature = "orchard-proving"))]
struct ParsedSpend {
    fvk: FullViewingKey,
    note: Note,
    merkle_path: MerklePath,
}

/// Parse and validate one real spend's note data — typed errors instead of the builder's opaque
/// `SpendError` strings:
///
/// - the FVK bytes must parse as an Orchard/Ironwood full viewing key
///   ([`IronwoodBuildError::BadFvk`]);
/// - the recipient bytes must be a valid raw address ([`IronwoodBuildError::BadRecipient`]);
/// - the note reconstructed from (`recipient`, `value`, `rho`, `rseed`) must be internally valid
///   ([`IronwoodBuildError::InvalidNote`]) and must commit to exactly `spec.cmx`
///   ([`IronwoodBuildError::NoteCommitmentMismatch`]);
/// - the witness must recompute to the bundle's anchor (the `build_ironwood_witness` errors).
#[cfg(any(test, feature = "orchard-proving"))]
fn parse_spend_spec(
    spec: &IronwoodSpendSpec,
    anchor: &AnchorBytes,
    note_version: NoteVersion,
) -> Result<ParsedSpend, IronwoodBuildError> {
    let fvk = FullViewingKey::from_bytes(&spec.fvk).ok_or(IronwoodBuildError::BadFvk)?;
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

    let mut sibling_hashes = [MerkleHashOrchard::empty_leaf(); IRONWOOD_MERKLE_DEPTH];
    for (to, from) in sibling_hashes.iter_mut().zip(spec.witness.auth_path.iter()) {
        *to = parse_hash(from)?;
    }
    Ok(ParsedSpend {
        fvk,
        note,
        merkle_path: MerklePath::from_parts(spec.witness.position, sibling_hashes),
    })
}

/// Strip builder-generated spend authorizing data from every real spend, through the wire form
/// (the only place a built PCZT's `alpha`/`rk` are writable): clear `alpha` and install
/// [`PLACEHOLDER_RK`] — the builder's randomized `rk` together with its `alpha` would reveal the
/// spend's `ak`. Dummy spends are untouched: their stored `alpha`/`dummy_sk` are what the IO
/// Finalizer signs with.
#[cfg(any(test, feature = "orchard-proving"))]
fn scrub_spend_randomizers(
    bundle: &PcztBundle,
    spend_indices: &[usize],
) -> Result<PcztBundle, IronwoodBuildError> {
    use super::ironwood_pczt::{
        deserialize_pczt, serialize_pczt, with_spend_alpha, with_spend_fvk_cleared, with_spend_rk,
        IronwoodPcztError,
    };
    let map = |e: IronwoodPcztError| IronwoodBuildError::PcztWire(e.to_string());

    let mut bytes = serialize_pczt(bundle).map_err(map)?;
    for &idx in spend_indices {
        bytes = with_spend_alpha(&bytes, idx, None).map_err(map)?;
        bytes = with_spend_rk(&bytes, idx, PLACEHOLDER_RK).map_err(map)?;
        // The caller-supplied FVK is constructor-only: it must never ride the
        // serialized PCZT past this point. Dummy fvks (shielding builds) are
        // untouched — `create_proof` requires an fvk on every spend.
        bytes = with_spend_fvk_cleared(&bytes, idx).map_err(map)?;
    }
    deserialize_pczt(&bytes).map_err(map)
}

/// Verifier: run the orchard PCZT checks that are meaningful while their fields are present.
/// The Constructor calls this before serialization, while the transient FVK is available for
/// nullifier and value-commitment checks; serialized PCZTs intentionally omit that FVK.
///
/// - spends with an FVK — re-derive and check the note nullifier;
/// - outputs with a recipient — verify the note commitment;
/// - actions with both sides' fields present — verify the value commitment;
/// - every spend's nullifier is unique across the bundle (orchard does not check this; consensus
///   rejects a transaction with a repeated nullifier).
///
/// `verify_rk` is deliberately skipped: it requires `alpha`, which real spends do not carry.
pub fn verify_spend_pczt(bundle: &PcztBundle) -> Result<(), IronwoodBuildError> {
    bundle
        .verify_cross_address_restriction()
        .map_err(|e| IronwoodBuildError::Verify(e.to_string()))?;
    if let Some(action_index) = super::ironwood_pczt::duplicate_nullifier_index(bundle) {
        return Err(IronwoodBuildError::DuplicateNullifier { action_index });
    }
    for (i, action) in bundle.actions().iter().enumerate() {
        let spend = action.spend();
        let output = action.output();
        if spend.fvk().is_some() {
            spend.verify_nullifier(None).map_err(|e| {
                IronwoodBuildError::Verify(format!("spend action {i}: nullifier: {e}"))
            })?;
        }
        if output.recipient().is_some() {
            output.verify_note_commitment(spend).map_err(|e| {
                IronwoodBuildError::Verify(format!("output action {i}: note commitment: {e}"))
            })?;
        }
        // `cv_net` commits to the plaintext net value — no FVK is needed for that,
        // so the check runs whenever both sides carry their values.
        if spend.value().is_some() && output.value().is_some() {
            action.verify_cv_net().map_err(|e| {
                IronwoodBuildError::Verify(format!("action {i}: value commitment: {e}"))
            })?;
        }
    }
    Ok(())
}

/// Signing time: install the signer's randomized `rk` on one real spend, replacing
/// [`PLACEHOLDER_RK`]. Only `rk` is written: `alpha` stays out of the PCZT (with `rk` it would
/// reveal the wallet's `ak`) and is delivered to the prover out of band ([`with_spend_alphas`]).
/// The bundle is replaced only on full success.
///
/// `alpha` must be a canonical, non-zero scalar, and `rk` a canonical verification key other
/// than [`PLACEHOLDER_RK`]. When the caller supplies the wallet's `ak`, the pair is checked
/// (`rk == ak.randomize(alpha)`), so a randomizer for a foreign wallet fails here; without it
/// the pair is checked by the client's key-free verifier and by the keyed prover.
///
/// Rejected when any action in the bundle carries a spend-auth signature (the digest commits
/// every action's `rk`, so installing any one invalidates them all) and when the target is a
/// dummy spend (its `alpha`/`rk` belong to its fabricating builder). Re-delivering the
/// installed `rk` is accepted (a no-op rewrite).
pub fn set_spend_auth_randomizer(
    bundle: &mut PcztBundle,
    action_index: usize,
    alpha: &[u8; 32],
    rk: &[u8; 32],
    ak: Option<&VerificationKey<SpendAuth>>,
) -> Result<(), IronwoodBuildError> {
    use super::ironwood_pczt::{
        deserialize_pczt, serialize_pczt, with_spend_rk, IronwoodPcztError,
    };
    let map = |e: IronwoodPcztError| IronwoodBuildError::PcztWire(e.to_string());

    let spend = bundle
        .actions()
        .get(action_index)
        .ok_or(IronwoodBuildError::ActionIndexOutOfRange)?
        .spend();
    if bundle
        .actions()
        .iter()
        .any(|a| a.spend().spend_auth_sig().is_some())
    {
        return Err(IronwoodBuildError::SpendSignatureAlreadyPresent);
    }
    if spend.dummy_sk().is_some() {
        return Err(IronwoodBuildError::RandomizerOnDummySpend);
    }
    let alpha_scalar = parse_alpha(action_index, alpha)?;
    if *rk == PLACEHOLDER_RK {
        return Err(IronwoodBuildError::UnrandomizedRk);
    }
    let rk_key = VerificationKey::<SpendAuth>::try_from(*rk)
        .map_err(|_| IronwoodBuildError::RandomizerMismatch)?;
    if let Some(ak) = ak {
        if ak.randomize(&alpha_scalar) != rk_key {
            return Err(IronwoodBuildError::RandomizerMismatch);
        }
    }

    let bytes = serialize_pczt(bundle).map_err(map)?;
    let bytes = with_spend_rk(&bytes, action_index, *rk).map_err(map)?;
    *bundle = deserialize_pczt(&bytes).map_err(map)?;
    Ok(())
}

/// Parse a randomizer `alpha`: a canonical, non-zero Pallas scalar. A zero `alpha` randomizes
/// `ak` to itself, leaving a linkable `rk`.
fn parse_alpha(
    action_index: usize,
    alpha: &[u8; 32],
) -> Result<pasta_curves::pallas::Scalar, IronwoodBuildError> {
    use ff::{Field, PrimeField};

    let alpha = Option::<pasta_curves::pallas::Scalar>::from(
        pasta_curves::pallas::Scalar::from_repr(*alpha),
    )
    .ok_or(IronwoodBuildError::BadAlpha { action_index })?;
    if bool::from(alpha.is_zero()) {
        return Err(IronwoodBuildError::UnrandomizedRk);
    }
    Ok(alpha)
}

/// Whether a real spend's `rk` is still [`PLACEHOLDER_RK`].
pub(crate) fn spend_rk_is_placeholder(spend: &super::ironwood_pczt::PcztSpend) -> bool {
    <[u8; 32]>::from(spend.rk()) == PLACEHOLDER_RK
}

/// Errors with [`IronwoodBuildError::RandomizersNotInstalled`] while any real spend's `rk` is
/// still [`PLACEHOLDER_RK`]: the ZIP-244 digest commits every action's `rk`, so no sighash
/// computed before every randomizer is installed is final.
pub fn require_spend_randomizers_installed(bundle: &PcztBundle) -> Result<(), IronwoodBuildError> {
    for action in bundle.actions().iter() {
        let spend = action.spend();
        if spend.dummy_sk().is_some() {
            continue;
        }
        if spend_rk_is_placeholder(spend) {
            return Err(IronwoodBuildError::RandomizersNotInstalled);
        }
    }
    Ok(())
}

/// A working copy of `bundle` with every real spend's `alpha` installed, for the roles that
/// need it (the Prover, and the keyed Verifier's `verify_rk`). The PSBT never stores `alpha`, so
/// it is supplied here out of band and the copy must not be written back.
///
/// `alphas` holds exactly one `(action_index, alpha)` per real spend: an out-of-range index
/// ([`IronwoodBuildError::ActionIndexOutOfRange`]), a dummy spend
/// ([`IronwoodBuildError::RandomizerOnDummySpend`]), a repeated index
/// ([`IronwoodBuildError::DuplicateRandomizer`]), a non-canonical or zero `alpha`, and a real
/// spend left without one ([`IronwoodBuildError::RandomizerMissing`]) are rejected.
pub fn with_spend_alphas(
    bundle: &PcztBundle,
    alphas: &[(usize, [u8; 32])],
) -> Result<PcztBundle, IronwoodBuildError> {
    use super::ironwood_pczt::{
        deserialize_pczt, serialize_pczt, with_spend_alpha, IronwoodPcztError,
    };
    let map = |e: IronwoodPcztError| IronwoodBuildError::PcztWire(e.to_string());

    let mut seen = Vec::with_capacity(alphas.len());
    for (action_index, alpha) in alphas {
        let action = bundle
            .actions()
            .get(*action_index)
            .ok_or(IronwoodBuildError::ActionIndexOutOfRange)?;
        if action.spend().dummy_sk().is_some() {
            return Err(IronwoodBuildError::RandomizerOnDummySpend);
        }
        if seen.contains(action_index) {
            return Err(IronwoodBuildError::DuplicateRandomizer {
                action_index: *action_index,
            });
        }
        parse_alpha(*action_index, alpha)?;
        seen.push(*action_index);
    }
    if let Some(action_index) = bundle
        .actions()
        .iter()
        .enumerate()
        .find(|(i, a)| a.spend().dummy_sk().is_none() && !seen.contains(i))
        .map(|(i, _)| i)
    {
        return Err(IronwoodBuildError::RandomizerMissing { action_index });
    }

    let mut bytes = serialize_pczt(bundle).map_err(map)?;
    for (action_index, alpha) in alphas {
        bytes = with_spend_alpha(&bytes, *action_index, Some(*alpha)).map_err(map)?;
    }
    deserialize_pczt(&bytes).map_err(map)
}

/// Signing time: apply an externally produced spend-auth signature (orchard verifies it against
/// the action's `rk` before storing).
///
/// The sighash must be the ZIP-244 digest computed over the CURRENT action data — a signature
/// over a pre-installation digest fails `rk` verification here. Rejected while any real
/// spend's `rk` is still [`PLACEHOLDER_RK`] ([`require_spend_randomizers_installed`]): the
/// digest is not final until every randomized `rk` is installed.
pub fn apply_spend_signature(
    bundle: &mut PcztBundle,
    action_index: usize,
    sighash: [u8; 32],
    sig: &[u8; 64],
) -> Result<(), IronwoodBuildError> {
    use orchard::primitives::redpallas::{self, SpendAuth};

    if action_index >= bundle.actions().len() {
        return Err(IronwoodBuildError::ActionIndexOutOfRange);
    }
    require_spend_randomizers_installed(bundle)?;
    bundle.actions_mut()[action_index]
        .apply_signature(sighash, redpallas::Signature::<SpendAuth>::from(*sig))
        .map_err(|e| match e {
            orchard::pczt::SignerError::InvalidExternalSignature => {
                IronwoodBuildError::InvalidExternalSignature
            }
            other => IronwoodBuildError::Signer(other.to_string()),
        })
}

/// Fill in a real spend's `fvk` so the Prover and Verifier can use it.
///
/// The Constructor scrubs the FVK from the persisted PCZT ("the FVK never leaves its holder");
/// this installs the holder's copy on one action. Rejected on dummy spends: a dummy's FVK
/// belongs to its fabricating builder and the IO Finalizer signs the dummy with it.
pub fn set_spend_fvk(
    bundle: &mut PcztBundle,
    action_index: usize,
    fvk: &FvkBytes,
) -> Result<(), IronwoodBuildError> {
    use super::ironwood_pczt::{
        deserialize_pczt, serialize_pczt, with_spend_fvk, IronwoodPcztError,
    };
    let map = |e: IronwoodPcztError| IronwoodBuildError::PcztWire(e.to_string());

    let action = bundle
        .actions()
        .get(action_index)
        .ok_or(IronwoodBuildError::ActionIndexOutOfRange)?;
    if action.spend().dummy_sk().is_some() {
        return Err(IronwoodBuildError::SetFvkOnDummySpend);
    }
    let bytes = serialize_pczt(bundle).map_err(map)?;
    let bytes = with_spend_fvk(&bytes, action_index, *fvk).map_err(map)?;
    *bundle = deserialize_pczt(&bytes).map_err(map)?;
    Ok(())
}

/// The full orchard Verifier role over every action — the checks an FVK holder runs before
/// signing or proving a PCZT that arrived over the wire.
///
/// All checks take the caller's own key as `expected_fvk` (the note-level checks ignore it for
/// dummy spends, which carry their fabricating FVK):
///
/// - `Spend::verify_nullifier` — the plaintext fields produce the recorded nullifier under
///   this FVK, and the FVK owns the note;
/// - `Spend::verify_rk` — `ak.randomize(alpha) == rk`, with each real spend's `alpha` taken
///   from `alphas` (the PSBT never stores it; see [`with_spend_alphas`]);
/// - `Action::verify_cv_net` — the value commitment matches the action's net value;
/// - `Output::verify_note_commitment` — the output note produces the committed `cmx`;
/// - `Bundle::verify_cross_address_restriction` — structural.
///
/// Each failure maps to a distinct [`IronwoodVerifyCheck`] so callers can tell which check failed.
pub fn verify_ironwood_spends(
    bundle: &PcztBundle,
    fvk: &FvkBytes,
    alphas: &[(usize, [u8; 32])],
) -> Result<(), IronwoodVerifyError> {
    let fvk = FullViewingKey::from_bytes(fvk).ok_or(IronwoodVerifyError::BadFvk)?;
    let bundle = &with_spend_alphas(bundle, alphas).map_err(|e| {
        let action_index = match e {
            IronwoodBuildError::RandomizerMissing { action_index }
            | IronwoodBuildError::DuplicateRandomizer { action_index }
            | IronwoodBuildError::BadAlpha { action_index } => action_index,
            _ => 0,
        };
        IronwoodVerifyError::Action {
            action_index,
            check: IronwoodVerifyCheck::Rk,
            detail: e.to_string(),
        }
    })?;
    bundle
        .verify_cross_address_restriction()
        .map_err(|e| IronwoodVerifyError::CrossAddressRestriction(e.to_string()))?;
    for (i, action) in bundle.actions().iter().enumerate() {
        let spend = action.spend();
        spend
            .verify_nullifier(Some(&fvk))
            .map_err(|e| IronwoodVerifyError::Action {
                action_index: i,
                check: IronwoodVerifyCheck::Nullifier,
                detail: e.to_string(),
            })?;
        spend
            .verify_rk(Some(&fvk))
            .map_err(|e| IronwoodVerifyError::Action {
                action_index: i,
                check: IronwoodVerifyCheck::Rk,
                detail: e.to_string(),
            })?;
        action
            .verify_cv_net()
            .map_err(|e| IronwoodVerifyError::Action {
                action_index: i,
                check: IronwoodVerifyCheck::CvNet,
                detail: e.to_string(),
            })?;
        action
            .output()
            .verify_note_commitment(spend)
            .map_err(|e| IronwoodVerifyError::Action {
                action_index: i,
                check: IronwoodVerifyCheck::NoteCommitment,
                detail: e.to_string(),
            })?;
    }
    Ok(())
}

/// Constructor: build a transparent → Ironwood shielding bundle as an orchard PCZT, for a single
/// output. A thin wrapper over [`construct_shield_pczt_multi`]; see it for the general (and
/// multi-output) contract.
pub fn construct_shield_pczt<R: RngCore + CryptoRng>(
    recipient: &OrchardAddressBytes,
    amount: u64,
    ovk: Option<OvkBytes>,
    anchor: &AnchorBytes,
    memo: &MemoBytes,
    rng: R,
) -> Result<PcztBundle, IronwoodBuildError> {
    let (bundle, _) = construct_shield_pczt_multi(
        &[IronwoodOutputSpec {
            recipient: *recipient,
            amount,
            ovk,
            memo: *memo,
        }],
        anchor,
        rng,
    )?;
    Ok(bundle)
}

/// Build and validate a Merkle witness for note commitment `cmx` at `position` with sibling
/// hashes `auth_path`, checking it recomputes to `expected_anchor`.
///
/// This crate has no chain state (no note-commitment-tree, no lightwalletd connection), so the raw
/// sibling-hash path must always be supplied by the caller. This function only builds and validates
/// the witness structure from those caller-supplied details — it does not install the witness
/// anywhere (see module docs).
///
/// Returns [`IronwoodBuildError::BadWitnessPath`] if `cmx` or any `auth_path` entry is not a
/// canonical field element, [`IronwoodBuildError::BadAnchor`] if `expected_anchor` isn't canonical,
/// or [`IronwoodBuildError::WitnessAnchorMismatch`] if the recomputed root doesn't match
/// `expected_anchor` — catching a bad caller-supplied path immediately rather than failing later at
/// the external prover.
pub fn build_ironwood_witness(
    cmx: &[u8; 32],
    position: u32,
    auth_path: &WitnessAuthPath,
    expected_anchor: &AnchorBytes,
) -> Result<IronwoodWitness, IronwoodBuildError> {
    let cmx_parsed =
        Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(cmx))
            .ok_or(IronwoodBuildError::BadWitnessPath)?;
    let anchor =
        Option::from(Anchor::from_bytes(*expected_anchor)).ok_or(IronwoodBuildError::BadAnchor)?;

    let mut auth_path_hashes = [MerkleHashOrchard::from_cmx(&cmx_parsed); IRONWOOD_MERKLE_DEPTH];
    for (dst, src) in auth_path_hashes.iter_mut().zip(auth_path.iter()) {
        *dst = Option::from(MerkleHashOrchard::from_bytes(src))
            .ok_or(IronwoodBuildError::BadWitnessPath)?;
    }

    let path = MerklePath::from_parts(position, auth_path_hashes);
    if path.root(cmx_parsed) != anchor {
        return Err(IronwoodBuildError::WitnessAnchorMismatch);
    }

    Ok(IronwoodWitness {
        position,
        auth_path: *auth_path,
    })
}

/// Build and validate an Ironwood witness from a pruned shard + cap, instead of a
/// caller-precomputed full 32-entry path. Uses `shardtree`'s own pruning-aware
/// `LocatedPrunableTree::witness`/`PrunableTree::root_hash` to do the Merkle folding — the same
/// algorithm a real note-commitment-tree store (e.g. `wasm-privacy-coin`'s `ShardTree`) uses to
/// answer witness queries — then delegates all canonical-encoding and anchor checks to
/// `build_ironwood_witness`; no validation is duplicated.
pub fn build_ironwood_witness_from_shard(
    input: &ShardWitnessInput,
    expected_anchor: &AnchorBytes,
) -> Result<IronwoodWitness, IronwoodBuildError> {
    if input.shard_height as usize > IRONWOOD_MERKLE_DEPTH {
        return Err(IronwoodBuildError::ShardHeightOutOfRange);
    }
    let depth = Level::from(IRONWOOD_MERKLE_DEPTH as u8);
    let position = Position::from(input.position as u64);
    let truncate_at = Position::from(input.leaf_count);

    let shard_addr = MerkleAddress::from_parts(
        Level::from(input.shard_height),
        (input.position as u64) >> input.shard_height,
    );

    // shard_height == 0 means `shard_addr` is the target leaf itself: there is no sub-tree to
    // witness within it (all 32 auth-path entries come from `cap`), and
    // `LocatedPrunableTree::witness` isn't defined for a level-0 root address.
    let mut path: Vec<MerkleHashOrchard> = if input.shard_height == 0 {
        Vec::new()
    } else {
        let shard_tree = to_prunable_tree(input.shard)?;
        LocatedPrunableTree::from_parts(shard_addr, shard_tree)
            .map_err(|_| IronwoodBuildError::ShardWitnessUnavailable)?
            .witness(position, truncate_at)
            .map_err(|_| IronwoodBuildError::ShardWitnessUnavailable)?
    };

    let cap_root_addr = MerkleAddress::from_parts(depth, 0);
    let cap_tree = to_prunable_tree(input.cap)?;
    let located_cap = LocatedPrunableTree::from_parts(cap_root_addr, cap_tree)
        .map_err(|_| IronwoodBuildError::CapNodeMissing)?;
    let mut cur_addr = shard_addr;
    while cur_addr.level() < depth {
        let sibling = cap_root_hash(
            located_cap.root(),
            cap_root_addr,
            cur_addr.sibling(),
            truncate_at,
        )?;
        path.push(sibling);
        cur_addr = cur_addr.parent();
    }

    let full_path: Vec<[u8; 32]> = path.iter().map(MerkleHashOrchard::to_bytes).collect();
    let full_path: WitnessAuthPath = full_path.try_into().expect(
        "shard witness + cap walk together always produce exactly IRONWOOD_MERKLE_DEPTH entries",
    );

    build_ironwood_witness(input.cmx, input.position, &full_path, expected_anchor)
}

/// Convert a caller-supplied [`ShardTreeNode`] into a real `shardtree::PrunableTree`.
///
/// Leaves are tagged `RetentionFlags::MARKED`: `LocatedPrunableTree::witness` only trusts a
/// sibling leaf that is marked (that flag exists so a *persisted, evolving* store knows which
/// leaves it must keep for future witnessing). We have no such store or pruning schedule — every
/// leaf the caller bothered to supply here is, by construction, needed for this one witness — so
/// marking them all is the correct (and only) way to make that check pass.
fn to_prunable_tree(
    node: &ShardTreeNode,
) -> Result<PrunableTree<MerkleHashOrchard>, IronwoodBuildError> {
    Ok(match node {
        ShardTreeNode::Nil => Tree::empty(),
        ShardTreeNode::Leaf { hash } => Tree::leaf((parse_hash(hash)?, RetentionFlags::MARKED)),
        ShardTreeNode::Parent { hash, left, right } => {
            let ann = hash.as_ref().map(parse_hash).transpose()?.map(Arc::new);
            Tree::parent(ann, to_prunable_tree(left)?, to_prunable_tree(right)?)
        }
    })
}

fn parse_hash(bytes: &[u8; 32]) -> Result<MerkleHashOrchard, IronwoodBuildError> {
    Option::from(MerkleHashOrchard::from_bytes(bytes)).ok_or(IronwoodBuildError::BadWitnessPath)
}

/// Compute the root hash of the node at `target_addr` within `tree` (rooted at `tree_addr`,
/// `tree_addr` containing `target_addr`), by navigating down to it and then delegating to
/// `PrunableTree::root_hash` — which itself recurses further as needed and returns cached
/// annotated hashes for pruned branches.
///
/// Applies the same "beyond `truncate_at` ⇒ canonically empty" shortcut `root_hash` uses
/// internally, but keyed on `target_addr` (not `tree_addr`) and *before* requiring an exact
/// address match: a `Nil` far to the right of all real data can appear at any ancestor level (real
/// trees don't pad every level down to the target's own level with empty `Parent` nodes), and
/// that's still a legitimate "definitely empty" answer, not missing data — checking against
/// `tree_addr` instead would only catch this once traversal happened to reach `target_addr`
/// exactly, which a `Nil`/`Leaf` dead end higher up prevents.
fn cap_root_hash(
    tree: &PrunableTree<MerkleHashOrchard>,
    tree_addr: MerkleAddress,
    target_addr: MerkleAddress,
    truncate_at: Position,
) -> Result<MerkleHashOrchard, IronwoodBuildError> {
    if truncate_at <= target_addr.position_range_start() {
        return Ok(MerkleHashOrchard::empty_root(target_addr.level()));
    }
    if tree_addr == target_addr {
        return tree
            .root_hash(tree_addr, truncate_at)
            .map_err(|_| IronwoodBuildError::CapNodeMissing);
    }
    match &**tree {
        Node::Parent { left, right, .. } => {
            let (l_addr, r_addr) = tree_addr
                .children()
                .expect("a Parent node's address always has children");
            if l_addr.contains(&target_addr) {
                cap_root_hash(left, l_addr, target_addr, truncate_at)
            } else {
                cap_root_hash(right, r_addr, target_addr, truncate_at)
            }
        }
        _ => Err(IronwoodBuildError::CapNodeMissing),
    }
}

/// IO Finalizer / Signer: derive the binding signing key and sign the dummy spends.
///
/// `sighash` is the ZIP-244 shielded sig digest computed over the *complete* v6 transaction
/// (transparent inputs/outputs plus this bundle's action data); it must not change afterwards, since
/// the binding signature applied in [`combine`] signs the same value.
pub fn finalize_shield_io<R: RngCore + CryptoRng>(
    bundle: &mut PcztBundle,
    sighash: [u8; 32],
    rng: R,
) -> Result<(), IronwoodBuildError> {
    bundle
        .finalize_io(sighash, rng)
        .map_err(|e| IronwoodBuildError::Finalize(e.to_string()))
}

/// Prover: attach a real Halo2 proof to the PCZT bundle in place, using a freshly-built proving
/// key for the bundle's own circuit version.
///
/// Behind the `orchard-proving` feature (pulls in halo2's circuit/proving-key machinery — heavy,
/// so it's opt-in). Building the proving key is expensive; callers proving many bundles in one
/// process should build it once via `orchard::circuit::ProvingKey::build` and call
/// `bundle.create_proof` directly rather than this convenience wrapper.
///
/// Order relative to [`finalize_shield_io`] does not matter — the two set disjoint PCZT fields
/// (`zkproof` here, `spend_auth_sig`/`bsk` there) — but both must run before [`combine`].
#[cfg(feature = "orchard-proving")]
pub fn create_proof<R: RngCore + CryptoRng>(
    bundle: &mut PcztBundle,
    rng: R,
) -> Result<(), IronwoodBuildError> {
    use orchard::circuit::ProvingKey;

    let pk = ProvingKey::build(BundleVersion::ironwood_v3().circuit_version());
    bundle
        .create_proof(&pk, rng)
        .map_err(|e| IronwoodBuildError::Prove(e.to_string()))
}

/// Map an orchard action (in any authorization state) to the v6 wire action.
///
/// The action-data fields are authorization-independent, so this serves both the effects-only
/// (action-data) view and the fully-authorized combine output.
fn action_to_ironwood<A>(a: &OrchardAction<A>) -> IronwoodAction {
    let enc = a.encrypted_note();
    IronwoodAction {
        cv: a.cv_net().to_bytes(),
        // The action's on-wire `nullifier` field doubles as the paired output note's `rho`.
        nullifier: a.nullifier().to_bytes(),
        rk: <[u8; 32]>::from(a.rk()),
        cmx: a.cmx().to_bytes(),
        ephemeral_key: enc.epk_bytes,
        enc_ciphertext: enc.enc_ciphertext,
        out_ciphertext: enc.out_ciphertext,
    }
}

/// Action-data view of the PCZT: the [`IronwoodBundle`] fields the ZIP-244 sighash and txid commit
/// to (commitments, ciphertexts, flags, value balance, anchor).
///
/// `proof`, `spend_auth_sigs`, and `binding_sig` are left empty — the result is meant for computing
/// digests, NOT for [`encode_v6_transaction`](super::v6::encode_v6_transaction) (which requires one
/// spend-auth signature per action). Use [`combine`] to produce an encodable bundle.
pub fn pczt_action_data(bundle: &PcztBundle) -> Result<IronwoodBundle, IronwoodBuildError> {
    let effects = bundle
        .extract_effects::<i64>()
        .map_err(|e| IronwoodBuildError::Extract(e.to_string()))?
        .ok_or(IronwoodBuildError::EmptyBundle)?;
    Ok(IronwoodBundle {
        actions: effects.actions().iter().map(action_to_ironwood).collect(),
        flags: effects.flag_byte(),
        value_balance: *effects.value_balance(),
        anchor: effects.anchor().to_bytes(),
        proof: Vec::new(),
        spend_auth_sigs: Vec::new(),
        binding_sig: [0u8; 64],
    })
}

/// Transaction Extractor: turn a signed + proven PCZT into a fully-authorized [`IronwoodBundle`].
///
/// `bundle` must already carry every `spend_auth_sig` (from [`finalize_shield_io`]), the binding
/// signing key `bsk` (also set by [`finalize_shield_io`]), and a canonical `zkproof` (from the proof
/// service, spliced in via [`super::ironwood_pczt::with_zkproof`]). `sighash` must equal the shielded
/// sig digest used when finalizing IO: it is what the binding signature signs and what every
/// spend-auth signature is verified against. `rng` seeds the (randomized) binding signature.
pub fn combine<R: RngCore + CryptoRng>(
    bundle: &PcztBundle,
    sighash: [u8; 32],
    rng: R,
) -> Result<IronwoodBundle, IronwoodBuildError> {
    let unbound = bundle
        .extract::<i64>()
        .map_err(|e| IronwoodBuildError::Extract(e.to_string()))?
        .ok_or(IronwoodBuildError::EmptyBundle)?;
    let authorized = unbound
        .apply_binding_signature(sighash, rng)
        .ok_or(IronwoodBuildError::BindingSignatureFailed)?;

    let spend_auth_sigs = authorized
        .actions()
        .iter()
        .map(|a| <[u8; 64]>::from(a.authorization()))
        .collect();
    Ok(IronwoodBundle {
        actions: authorized
            .actions()
            .iter()
            .map(action_to_ironwood)
            .collect(),
        flags: authorized.flag_byte(),
        value_balance: *authorized.value_balance(),
        anchor: authorized.anchor().to_bytes(),
        proof: authorized.authorization().proof().as_ref().to_vec(),
        spend_auth_sigs,
        binding_sig: <[u8; 64]>::from(authorized.authorization().binding_signature()),
    })
}

/// Length of the Ironwood/orchard `out_ciphertext` field in bytes (`OUT_PLAINTEXT_SIZE` + AEAD tag).
pub const OUT_CIPHERTEXT_SIZE: usize = zcash_note_encryption::OUT_CIPHERTEXT_SIZE;
/// An Ironwood/orchard `out_ciphertext`.
pub type OutCiphertextBytes = [u8; OUT_CIPHERTEXT_SIZE];

/// Client-managed `ovk`: derive a 32-byte outgoing viewing key as the ECDH shared secret
/// between the BitGo cosigner's secp256k1 public key and the user's secp256k1 private key.
///
/// This never touches the server: the server-side (keyless) build in [`construct_shield_pczt`]
/// passes `ovk = None`, and the client calls this — with a key pair it alone can complete an ECDH
/// with — to derive an `ovk` the server never sees, then splices the resulting `out_ciphertext` in
/// via [`compute_out_ciphertext`] and [`super::ironwood_pczt::with_out_ciphertext`].
///
/// **The canonical key pair is the two *root* wallet keys**: `bitgo_pubkey` is
/// `RootWalletKeys::bitgo_key()`'s raw pubkey and `user_privkey` is the user root `Xpriv`'s secret
/// key — never a `(chain, index)`-derived leaf key. Both sides of the agreement are therefore
/// transaction-independent, so the `ovk` does not depend on which inputs a transaction happens to
/// spend or the order they appear in, and the server can re-derive it from
/// `ECDH(bitgo_root_privkey, user_root_pubkey)` — the same shared secret from the other side —
/// knowing only the wallet's keys. Callers should go through
/// [`ZcashBitGoPsbt::set_ironwood_out_ciphertext_for_user`], which enforces this pairing;
/// see also the `server_can_independently_derive_ovk_and_validate_out_ciphertext_before_signing`
/// test for the validation the server runs before countersigning.
///
/// Because both inputs are long-term keys, the resulting `ovk` is a long-term *wallet* key — the
/// same value for every transaction of a given wallet — exactly as an `ovk` is treated in Zcash
/// generally. It is not, and is not intended to be, per-transaction.
///
/// `secp256k1`'s ECDH (SHA-256 of the compressed shared point, its default hashing) already yields a
/// uniformly random 32-byte value suitable as a raw `ovk` directly — no separate KDF step is needed.
///
/// [`ZcashBitGoPsbt::set_ironwood_out_ciphertext_for_user`]: crate::fixed_script_wallet::bitgo_psbt::zcash_psbt::ZcashBitGoPsbt::set_ironwood_out_ciphertext_for_user
pub fn derive_client_ovk(
    bitgo_pubkey: &[u8],
    user_privkey: &[u8],
) -> Result<OvkBytes, IronwoodBuildError> {
    let pk = secp256k1::PublicKey::from_slice(bitgo_pubkey)
        .map_err(|e| IronwoodBuildError::BadKey(format!("bitgo pubkey: {e}")))?;
    let sk = secp256k1::SecretKey::from_slice(user_privkey)
        .map_err(|e| IronwoodBuildError::BadKey(format!("user private key: {e}")))?;
    let shared = secp256k1::ecdh::SharedSecret::new(&pk, &sk);
    Ok(shared.secret_bytes())
}

/// Recompute `out_ciphertext` for one action of a PCZT under a client-supplied `ovk`, reconstructing
/// the output note from the Constructor-set PCZT fields (`recipient`, `value`, `rseed`, and `rho`
/// derived from the paired spend's `nullifier`). Reuses the note's ZIP-212-derived `esk`/`epk`, so
/// the result is consistent with the action's already-fixed `cv`/`cmx`/`ephemeral_key`/
/// `enc_ciphertext` — only `out_ciphertext` changes.
///
/// The reconstructed note is checked against the action's already-committed `cmx` before it is
/// used: `out_ciphertext` carries `pk_d || esk`, so a note reconstructed from stale or corrupted
/// fields would produce a ciphertext whose `esk` does not match the action's fixed `ephemeral_key`
/// — ciphertext that encrypts and splices in cleanly, and only reveals itself as garbage when
/// someone later tries to recover the note. Failing here turns that into
/// [`IronwoodBuildError::NoteCommitmentMismatch`].
///
/// The caller (see [`super::ironwood_pczt::with_out_ciphertext`]) is responsible for splicing the
/// returned bytes into the PCZT wire form; this function only computes them.
pub fn compute_out_ciphertext<R: RngCore + CryptoRng>(
    pczt: &PcztBundle,
    action_index: usize,
    ovk: OvkBytes,
    rng: &mut R,
) -> Result<OutCiphertextBytes, IronwoodBuildError> {
    use orchard::note::Rho;
    use orchard::note_encryption::IronwoodDomain;
    use orchard::Note;
    use zcash_note_encryption::NoteEncryption;

    let action = pczt
        .actions()
        .get(action_index)
        .ok_or(IronwoodBuildError::ActionIndexOutOfRange)?;
    let output = action.output();
    let recipient = output
        .recipient()
        .as_ref()
        .ok_or(IronwoodBuildError::MissingOutputFields)?;
    let value = output
        .value()
        .as_ref()
        .ok_or(IronwoodBuildError::MissingOutputFields)?;
    let rseed = output
        .rseed()
        .as_ref()
        .ok_or(IronwoodBuildError::MissingOutputFields)?;
    let rho = Option::<Rho>::from(Rho::from_bytes(&action.spend().nullifier().to_bytes()))
        .ok_or(IronwoodBuildError::InvalidNote)?;
    let note: Note = Option::from(Note::from_parts(
        *recipient,
        *value,
        rho,
        *rseed,
        *output.note_version(),
    ))
    .ok_or(IronwoodBuildError::InvalidNote)?;

    // The note we just rebuilt must be the note this action already commits to — otherwise the
    // `esk` we are about to encrypt belongs to a different note than the action's `ephemeral_key`,
    // and the resulting `out_ciphertext` is unrecoverable garbage that nothing downstream checks.
    let committed_cmx = output.cmx();
    if orchard::note::ExtractedNoteCommitment::from(note.commitment()) != *committed_cmx {
        return Err(IronwoodBuildError::NoteCommitmentMismatch);
    }

    // The memo only affects `enc_ciphertext` (already fixed at build time), not
    // `outgoing_plaintext_bytes` (pk_d || esk) — unused here, so a placeholder is fine.
    let placeholder_memo = [0u8; 512];
    let enc = NoteEncryption::<IronwoodDomain>::new(
        Some(orchard::keys::OutgoingViewingKey::from(ovk)),
        note,
        placeholder_memo,
    );
    Ok(enc.encrypt_outgoing_plaintext(action.cv_net(), committed_cmx, rng))
}

/// An arbitrary canonical Pallas field element keyed off `seed` — a test stand-in for a leaf
/// commitment, sibling hash, or note `rho`.
#[cfg(test)]
pub(crate) fn test_field_bytes(seed: u64) -> [u8; 32] {
    use ff::PrimeField;
    pasta_curves::pallas::Base::from(seed).to_repr()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zcash::ironwood_pczt::{
        deserialize_pczt, serialize_pczt, with_out_ciphertext, with_output_rseed_for_test,
        with_zkproof,
    };
    use crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID;
    use crate::zcash::v6::{
        compute_v6_sig_digest, compute_v6_txid, decode_v6_transaction, encode_v6_transaction,
        ZcashV6Transaction,
    };
    use miniscript::bitcoin::hashes::Hash;
    use miniscript::bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use orchard::note::{Note, RandomSeed, Rho};
    use orchard::Proof;
    use rand::rngs::OsRng;

    const NU6_3_BRANCH_ID: u32 = 0x37a5165b;

    /// A deterministic Ironwood receiver derived from a fixed spending key, for building test PCZTs.
    fn test_recipient() -> [u8; ORCHARD_ADDRESS_SIZE] {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        fvk.address_at(0u32, Scope::External).to_raw_address_bytes()
    }

    /// A single-P2PKH-input, no-output transparent skeleton to hang the Ironwood bundle on.
    fn transparent_skeleton() -> Transaction {
        Transaction {
            version: miniscript::bitcoin::transaction::Version::non_standard(6),
            input: vec![TxIn {
                // A non-zero prevout: an all-zeros hash would be read as a coinbase input.
                previous_output: OutPoint::new(Txid::from_byte_array([0x11u8; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from(vec![0x76u8, 0xa9, 0x14]),
            }],
            lock_time: miniscript::bitcoin::locktime::absolute::LockTime::from_consensus(0),
        }
    }

    fn v6_tx(transparent: Transaction, bundle: Option<IronwoodBundle>) -> ZcashV6Transaction {
        ZcashV6Transaction {
            version_group_id: ZCASH_IRONWOOD_VERSION_GROUP_ID,
            consensus_branch_id: NU6_3_BRANCH_ID,
            transparent,
            expiry_height: 0,
            sapling_value_balance: 0,
            ironwood_bundle: bundle,
        }
    }

    #[test]
    fn construct_yields_single_action_shielding_amount() {
        let amount = 100_000_000u64;
        let pczt = construct_shield_pczt(
            &test_recipient(),
            amount,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        let data = pczt_action_data(&pczt).unwrap();
        assert_eq!(data.actions.len(), 1, "UNPADDED single output ⇒ one action");
        // A shielding bundle disables spends (its only spend is the fabricated dummy):
        // outputs | cross-address.
        assert_eq!(data.flags, 0x06);
        // A pure output bundle (dummy spend has value 0): value_balance = 0 - amount.
        assert_eq!(data.value_balance, -(amount as i64));
    }

    // ---- Witness builder ----

    // [`build_ironwood_witness`] only cares that its inputs are canonical field elements, not that
    // they come from a real note-commitment tree, so synthesized `field_bytes` values work just as
    // well as ones derived from a real note for these tests.
    use super::test_field_bytes as field_bytes;

    /// A self-consistent `(cmx, position, auth_path, anchor)` fixture: `anchor` is computed via
    /// `orchard`'s own `MerklePath::root`, the same primitive [`build_ironwood_witness`] wraps.
    fn witness_fixture(position: u32) -> ([u8; 32], WitnessAuthPath, AnchorBytes) {
        let cmx = field_bytes(0);
        let auth_path: WitnessAuthPath = std::array::from_fn(|i| field_bytes(i as u64 + 1));

        let cmx_parsed =
            Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&cmx))
                .unwrap();
        let sibling_hashes: [MerkleHashOrchard; IRONWOOD_MERKLE_DEPTH] =
            auth_path.map(|s| Option::from(MerkleHashOrchard::from_bytes(&s)).unwrap());
        let anchor = MerklePath::from_parts(position, sibling_hashes)
            .root(cmx_parsed)
            .to_bytes();

        (cmx, auth_path, anchor)
    }

    #[test]
    fn build_ironwood_witness_accepts_a_self_consistent_path() {
        let (cmx, auth_path, anchor) = witness_fixture(5);
        let witness = build_ironwood_witness(&cmx, 5, &auth_path, &anchor).unwrap();
        assert_eq!(
            witness,
            IronwoodWitness {
                position: 5,
                auth_path
            }
        );
    }

    #[test]
    fn build_ironwood_witness_rejects_a_corrupted_auth_path_entry() {
        let (cmx, mut auth_path, anchor) = witness_fixture(5);
        auth_path[0] = field_bytes(999);
        assert!(matches!(
            build_ironwood_witness(&cmx, 5, &auth_path, &anchor),
            Err(IronwoodBuildError::WitnessAnchorMismatch)
        ));
    }

    #[test]
    fn build_ironwood_witness_rejects_the_wrong_anchor() {
        let (cmx, auth_path, _anchor) = witness_fixture(5);
        let wrong_anchor = Anchor::empty_tree().to_bytes();
        assert!(matches!(
            build_ironwood_witness(&cmx, 5, &auth_path, &wrong_anchor),
            Err(IronwoodBuildError::WitnessAnchorMismatch)
        ));
    }

    #[test]
    fn build_ironwood_witness_rejects_non_canonical_cmx() {
        let (_cmx, auth_path, anchor) = witness_fixture(5);
        let non_canonical = [0xffu8; 32];
        assert!(matches!(
            build_ironwood_witness(&non_canonical, 5, &auth_path, &anchor),
            Err(IronwoodBuildError::BadWitnessPath)
        ));
    }

    #[test]
    fn build_ironwood_witness_rejects_non_canonical_auth_path_entry() {
        let (cmx, mut auth_path, anchor) = witness_fixture(5);
        auth_path[3] = [0xffu8; 32];
        assert!(matches!(
            build_ironwood_witness(&cmx, 5, &auth_path, &anchor),
            Err(IronwoodBuildError::BadWitnessPath)
        ));
    }

    #[test]
    fn build_ironwood_witness_rejects_non_canonical_anchor() {
        let (cmx, auth_path, _anchor) = witness_fixture(5);
        let non_canonical_anchor = [0xffu8; 32];
        assert!(matches!(
            build_ironwood_witness(&cmx, 5, &auth_path, &non_canonical_anchor),
            Err(IronwoodBuildError::BadAnchor)
        ));
    }

    // ---- Shard witness builder ----

    /// Build a dense `ShardTreeNode` of `height` levels from `leaves` (real leaf hashes,
    /// left-to-right): any position at or beyond `leaves.len()` is `Nil` — genuinely
    /// not-yet-committed, not a canonical empty-leaf placeholder — matching how a real pruned
    /// store represents "nothing here yet" and relying on `truncate_at` (not tree contents) to
    /// tell `witness`/`root_hash` that's expected.
    fn dense_shard(height: u8, leaves: &[[u8; 32]]) -> ShardTreeNode {
        fn go(height: u8, start: usize, leaves: &[[u8; 32]]) -> ShardTreeNode {
            if start >= leaves.len() {
                return ShardTreeNode::Nil;
            }
            if height == 0 {
                return ShardTreeNode::Leaf {
                    hash: leaves[start],
                };
            }
            let half = 1usize << (height - 1);
            ShardTreeNode::Parent {
                hash: None,
                left: Box::new(go(height - 1, start, leaves)),
                right: Box::new(go(height - 1, start + half, leaves)),
            }
        }
        go(height, 0, leaves)
    }

    /// A cap spanning levels `shard_height..IRONWOOD_MERKLE_DEPTH` with exactly one known node —
    /// `known_hash`, the precomputed root of the shard at `known_shard_index` — and `Nil`
    /// elsewhere, exercising a *pruned* branch (no full detail, just an annotated hash) rather
    /// than dense structure all the way down.
    fn cap_with_one_known_shard(
        shard_height: u8,
        known_shard_index: u64,
        known_hash: [u8; 32],
    ) -> ShardTreeNode {
        fn go(
            level: u8,
            index: u64,
            shard_height: u8,
            known_shard_index: u64,
            known_hash: [u8; 32],
        ) -> ShardTreeNode {
            if level == shard_height {
                return if index == known_shard_index {
                    ShardTreeNode::Leaf { hash: known_hash }
                } else {
                    ShardTreeNode::Nil
                };
            }
            let span = 1u64 << (level - shard_height);
            let start = index * span;
            if known_shard_index < start || known_shard_index >= start + span {
                return ShardTreeNode::Nil;
            }
            ShardTreeNode::Parent {
                hash: None,
                left: Box::new(go(
                    level - 1,
                    index * 2,
                    shard_height,
                    known_shard_index,
                    known_hash,
                )),
                right: Box::new(go(
                    level - 1,
                    index * 2 + 1,
                    shard_height,
                    known_shard_index,
                    known_hash,
                )),
            }
        }
        go(
            IRONWOOD_MERKLE_DEPTH as u8,
            0,
            shard_height,
            known_shard_index,
            known_hash,
        )
    }

    /// Fold a dense, contiguous `leaves` prefix (a `2^height`-leaf shard) bottom-up — independent
    /// of `build_ironwood_witness_from_shard`'s own `shardtree`-backed folding — returning `(this
    /// shard's own root hash, the height sibling hashes on the path to local_position)`.
    fn fold_shard(
        height: u8,
        leaves: &[[u8; 32]],
        mut local_position: usize,
    ) -> (MerkleHashOrchard, Vec<MerkleHashOrchard>) {
        let mut level: Vec<MerkleHashOrchard> = leaves
            .iter()
            .map(|b| Option::from(MerkleHashOrchard::from_bytes(b)).unwrap())
            .collect();
        let mut path = Vec::with_capacity(height as usize);
        for l in 0..height {
            let lvl = Level::from(l);
            let sibling_idx = local_position ^ 1;
            path.push(
                level
                    .get(sibling_idx)
                    .copied()
                    .unwrap_or_else(|| MerkleHashOrchard::empty_root(lvl)),
            );
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let right = pair
                    .get(1)
                    .copied()
                    .unwrap_or_else(|| MerkleHashOrchard::empty_root(lvl));
                next.push(MerkleHashOrchard::combine(lvl, &pair[0], &right));
            }
            level = next;
            local_position >>= 1;
        }
        (level[0], path)
    }

    /// Root a full 32-entry auth path against `cmx`/`position`, via the same primitive
    /// `build_ironwood_witness` wraps — independent of `build_ironwood_witness_from_shard`.
    fn root_full_path(
        position: u32,
        cmx: [u8; 32],
        full_path: Vec<MerkleHashOrchard>,
    ) -> AnchorBytes {
        let cmx_parsed =
            Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&cmx))
                .unwrap();
        let sibling_hashes: [MerkleHashOrchard; IRONWOOD_MERKLE_DEPTH] =
            full_path.try_into().unwrap();
        MerklePath::from_parts(position, sibling_hashes)
            .root(cmx_parsed)
            .to_bytes()
    }

    /// A self-consistent fixture: a single shard (index 0) holding `populated` real leaves (out of
    /// `2^shard_height`), nothing else in the tree — so `cap` is entirely `Nil` and `leaf_count`
    /// (the truncation boundary) equals `populated`.
    fn single_shard_fixture(
        shard_height: u8,
        populated: usize,
        position: u32,
    ) -> (ShardTreeNode, ShardTreeNode, u64, [u8; 32], AnchorBytes) {
        let leaves: Vec<[u8; 32]> = (0..populated)
            .map(|i| field_bytes(i as u64 + 100))
            .collect();
        let (_, bottom) = fold_shard(shard_height, &leaves, position as usize);

        let mut full_path = bottom;
        for l in shard_height..(IRONWOOD_MERKLE_DEPTH as u8) {
            full_path.push(MerkleHashOrchard::empty_root(Level::from(l)));
        }

        let cmx = leaves[position as usize];
        let anchor = root_full_path(position, cmx, full_path);
        let shard = dense_shard(shard_height, &leaves);
        (shard, ShardTreeNode::Nil, populated as u64, cmx, anchor)
    }

    /// A self-consistent fixture with *two* shards: shard 0 is fully populated (its root hash is
    /// known only as a pruned `Leaf` annotation in `cap`, not full detail), shard 1 holds
    /// `position_in_shard1 + 1` real leaves and contains the target position. Exercises the cap
    /// traversal / pruned-annotation path `single_shard_fixture` (empty cap) never touches.
    fn two_shard_fixture(
        shard_height: u8,
        position_in_shard1: u32,
    ) -> (ShardTreeNode, ShardTreeNode, u64, [u8; 32], AnchorBytes) {
        let shard_capacity = 1usize << shard_height;
        let shard0_leaves: Vec<[u8; 32]> = (0..shard_capacity)
            .map(|i| field_bytes(i as u64 + 100))
            .collect();
        let (shard0_root, _) = fold_shard(shard_height, &shard0_leaves, 0);

        let populated1 = position_in_shard1 as usize + 1;
        let shard1_leaves: Vec<[u8; 32]> = (0..populated1)
            .map(|i| field_bytes(i as u64 + 5000))
            .collect();
        let (_, bottom) = fold_shard(shard_height, &shard1_leaves, position_in_shard1 as usize);

        let mut full_path = bottom;
        full_path.push(shard0_root); // shard 1's sibling at the shard-root level is shard 0.
        for l in (shard_height + 1)..(IRONWOOD_MERKLE_DEPTH as u8) {
            full_path.push(MerkleHashOrchard::empty_root(Level::from(l)));
        }

        let global_position = shard_capacity as u32 + position_in_shard1;
        let cmx = shard1_leaves[position_in_shard1 as usize];
        let anchor = root_full_path(global_position, cmx, full_path);

        let shard = dense_shard(shard_height, &shard1_leaves);
        let cap = cap_with_one_known_shard(shard_height, 0, shard0_root.to_bytes());
        let leaf_count = (shard_capacity + populated1) as u64;
        (shard, cap, leaf_count, cmx, anchor)
    }

    #[test]
    fn build_ironwood_witness_from_shard_full_shard_interior_position() {
        let (shard, cap, leaf_count, cmx, anchor) = single_shard_fixture(4, 16, 7);
        let witness = build_ironwood_witness_from_shard(
            &ShardWitnessInput {
                position: 7,
                shard_height: 4,
                leaf_count,
                cmx: &cmx,
                shard: &shard,
                cap: &cap,
            },
            &anchor,
        )
        .unwrap();
        assert_eq!(witness.position, 7);
    }

    #[test]
    fn build_ironwood_witness_from_shard_edge_positions() {
        for position in [0u32, 15u32] {
            let (shard, cap, leaf_count, cmx, anchor) = single_shard_fixture(4, 16, position);
            build_ironwood_witness_from_shard(
                &ShardWitnessInput {
                    position,
                    shard_height: 4,
                    leaf_count,
                    cmx: &cmx,
                    shard: &shard,
                    cap: &cap,
                },
                &anchor,
            )
            .unwrap();
        }
    }

    #[test]
    fn build_ironwood_witness_from_shard_partial_shard_tip() {
        // 10 of 16 possible leaves; target the last populated leaf, so some low-level siblings
        // fall in the empty tail (index 9's sibling, 8, is real) while others don't (index 9 at
        // the next level up pairs with an as-yet-uncommitted, `Nil` slot).
        let (shard, cap, leaf_count, cmx, anchor) = single_shard_fixture(4, 10, 9);
        build_ironwood_witness_from_shard(
            &ShardWitnessInput {
                position: 9,
                shard_height: 4,
                leaf_count,
                cmx: &cmx,
                shard: &shard,
                cap: &cap,
            },
            &anchor,
        )
        .unwrap();
    }

    #[test]
    fn build_ironwood_witness_from_shard_height_zero_degenerates_to_full_path() {
        let (_shard, cap, leaf_count, cmx, anchor) = single_shard_fixture(0, 1, 0);
        // shard_height == 0: `cap` alone must carry the full 32-entry path (`shard` is unused).
        let unused_shard = ShardTreeNode::Nil;
        let via_shard = build_ironwood_witness_from_shard(
            &ShardWitnessInput {
                position: 0,
                shard_height: 0,
                leaf_count,
                cmx: &cmx,
                shard: &unused_shard,
                cap: &cap,
            },
            &anchor,
        )
        .unwrap();
        assert_eq!(via_shard.position, 0);
    }

    #[test]
    fn build_ironwood_witness_from_shard_two_shards_with_pruned_cap_annotation() {
        // shard 1 (containing the target) is witnessed against a cap that only knows shard 0's
        // precomputed root — not its full contents — exercising the pruned-annotation path in
        // `cap_root_hash`/`PrunableTree::root_hash`.
        let (shard, cap, leaf_count, cmx, anchor) = two_shard_fixture(4, 3);
        let witness = build_ironwood_witness_from_shard(
            &ShardWitnessInput {
                position: 16 + 3, // shard 1, local position 3
                shard_height: 4,
                leaf_count,
                cmx: &cmx,
                shard: &shard,
                cap: &cap,
            },
            &anchor,
        )
        .unwrap();
        assert_eq!(witness.position, 19);
    }

    #[test]
    fn build_ironwood_witness_from_shard_rejects_shard_height_out_of_range() {
        assert!(matches!(
            build_ironwood_witness_from_shard(
                &ShardWitnessInput {
                    position: 0,
                    shard_height: 33,
                    leaf_count: 0,
                    cmx: &[0u8; 32],
                    shard: &ShardTreeNode::Nil,
                    cap: &ShardTreeNode::Nil,
                },
                &[0u8; 32],
            ),
            Err(IronwoodBuildError::ShardHeightOutOfRange)
        ));
    }

    #[test]
    fn build_ironwood_witness_from_shard_rejects_insufficient_shard_detail() {
        // `leaf_count` claims position 9 is populated, but `shard` is entirely `Nil`.
        let (_shard, cap, leaf_count, cmx, anchor) = single_shard_fixture(4, 10, 9);
        assert!(matches!(
            build_ironwood_witness_from_shard(
                &ShardWitnessInput {
                    position: 9,
                    shard_height: 4,
                    leaf_count,
                    cmx: &cmx,
                    shard: &ShardTreeNode::Nil,
                    cap: &cap,
                },
                &anchor,
            ),
            Err(IronwoodBuildError::ShardWitnessUnavailable)
        ));
    }

    #[test]
    fn build_ironwood_witness_from_shard_rejects_missing_cap_node() {
        // Two-shard fixture, but `cap` is replaced with `Nil` — shard 0's root is no longer
        // available, and `leaf_count` says it's real data (not "beyond truncate_at"), so the
        // sibling lookup must fail rather than silently treating it as empty.
        let (shard, _cap, leaf_count, cmx, anchor) = two_shard_fixture(4, 3);
        assert!(matches!(
            build_ironwood_witness_from_shard(
                &ShardWitnessInput {
                    position: 19,
                    shard_height: 4,
                    leaf_count,
                    cmx: &cmx,
                    shard: &shard,
                    cap: &ShardTreeNode::Nil,
                },
                &anchor,
            ),
            Err(IronwoodBuildError::CapNodeMissing)
        ));
    }

    #[test]
    fn build_ironwood_witness_from_shard_rejects_non_canonical_shard_hash() {
        let (_shard, cap, leaf_count, cmx, anchor) = single_shard_fixture(4, 16, 7);
        let bad_shard = ShardTreeNode::Leaf { hash: [0xffu8; 32] };
        assert!(matches!(
            build_ironwood_witness_from_shard(
                &ShardWitnessInput {
                    position: 7,
                    shard_height: 4,
                    leaf_count,
                    cmx: &cmx,
                    shard: &bad_shard,
                    cap: &cap,
                },
                &anchor,
            ),
            Err(IronwoodBuildError::BadWitnessPath)
        ));
    }

    #[test]
    fn build_ironwood_witness_from_shard_rejects_non_canonical_cap_annotation() {
        let (shard, _cap, leaf_count, cmx, anchor) = two_shard_fixture(4, 3);
        let bad_cap = ShardTreeNode::Parent {
            hash: Some([0xffu8; 32]),
            left: Box::new(ShardTreeNode::Nil),
            right: Box::new(ShardTreeNode::Nil),
        };
        assert!(matches!(
            build_ironwood_witness_from_shard(
                &ShardWitnessInput {
                    position: 19,
                    shard_height: 4,
                    leaf_count,
                    cmx: &cmx,
                    shard: &shard,
                    cap: &bad_cap,
                },
                &anchor,
            ),
            Err(IronwoodBuildError::BadWitnessPath)
        ));
    }

    #[test]
    fn build_ironwood_witness_from_shard_rejects_wrong_anchor() {
        let (shard, cap, leaf_count, cmx, _anchor) = single_shard_fixture(4, 16, 7);
        let wrong_anchor = Anchor::empty_tree().to_bytes();
        assert!(matches!(
            build_ironwood_witness_from_shard(
                &ShardWitnessInput {
                    position: 7,
                    shard_height: 4,
                    leaf_count,
                    cmx: &cmx,
                    shard: &shard,
                    cap: &cap,
                },
                &wrong_anchor,
            ),
            Err(IronwoodBuildError::WitnessAnchorMismatch)
        ));
    }

    #[test]
    fn build_ironwood_witness_from_shard_rejects_non_canonical_anchor() {
        let (shard, cap, leaf_count, cmx, _anchor) = single_shard_fixture(4, 16, 7);
        let non_canonical_anchor = [0xffu8; 32];
        assert!(matches!(
            build_ironwood_witness_from_shard(
                &ShardWitnessInput {
                    position: 7,
                    shard_height: 4,
                    leaf_count,
                    cmx: &cmx,
                    shard: &shard,
                    cap: &cap,
                },
                &non_canonical_anchor,
            ),
            Err(IronwoodBuildError::BadAnchor)
        ));
    }

    /// End-to-end (build → sighash → sign dummy spend → inject proof → combine), no circuit:
    /// the resulting v6 tx round-trips through the codec and its txid is stable. A canonical-length
    /// placeholder proof stands in for the external prover (the codec/txid never inspect proof
    /// bytes, and the Extractor only length-checks them).
    #[test]
    fn build_finalize_combine_produces_encodable_tx() {
        let amount = 100_000_000u64;
        let mut pczt = construct_shield_pczt(
            &test_recipient(),
            amount,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();

        // Fix the transaction structure, then compute the shielded sighash it commits to.
        let transparent = transparent_skeleton();
        let input_amounts = [200_000_000i64];
        let input_scripts = [ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac])];
        let tx_for_sighash = v6_tx(transparent.clone(), Some(pczt_action_data(&pczt).unwrap()));
        let sighash = compute_v6_sig_digest(&tx_for_sighash, &input_amounts, &input_scripts);

        // Signer + IO finalizer (dummy spend-auth signature + bsk).
        finalize_shield_io(&mut pczt, sighash, OsRng).unwrap();

        // Round-trip through the proof-service wire path: serialize, splice a canonical-length
        // placeholder proof, deserialize.
        let signed_bytes = serialize_pczt(&pczt).unwrap();
        let proof = vec![0u8; Proof::expected_proof_size(1)];
        let proven = deserialize_pczt(&with_zkproof(&signed_bytes, proof).unwrap()).unwrap();

        // Combine → fully-authorized bundle.
        let bundle = combine(&proven, sighash, OsRng).unwrap();
        assert_eq!(bundle.actions.len(), 1);
        assert_eq!(bundle.spend_auth_sigs.len(), 1);
        assert_eq!(bundle.proof.len(), Proof::expected_proof_size(1));
        assert_eq!(bundle.flags, 0x06);

        // The action data survived unchanged from build → combine (digests are stable).
        assert_eq!(
            bundle.actions,
            tx_for_sighash.ironwood_bundle.unwrap().actions
        );

        // The assembled tx encodes and round-trips, with a stable txid.
        let tx = v6_tx(transparent, Some(bundle));
        let bytes = encode_v6_transaction(&tx).unwrap();
        let decoded = decode_v6_transaction(&bytes).unwrap();
        assert_eq!(decoded, tx);
        assert_eq!(compute_v6_txid(&decoded), compute_v6_txid(&tx));
    }

    /// Cross-check the combined transaction against `zebra-chain` (an independent NU6.3
    /// implementation): zebra must decode our bytes, see a v6 tx, and agree on the ZIP-244 txid
    /// and structure. This proves our Constructor → [`IronwoodBundle`] → wire mapping is canonical.
    /// (zebra parses but does not verify the proof on deserialize, so the placeholder proof is fine.)
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn combined_tx_matches_zebra() {
        use zebra_chain::serialization::ZcashDeserialize;
        use zebra_chain::transaction::Transaction as ZebraTx;

        let amount = 100_000_000u64;
        let mut pczt = construct_shield_pczt(
            &test_recipient(),
            amount,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        let transparent = transparent_skeleton();
        let input_amounts = [200_000_000i64];
        let input_scripts = [ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac])];
        let sighash = compute_v6_sig_digest(
            &v6_tx(transparent.clone(), Some(pczt_action_data(&pczt).unwrap())),
            &input_amounts,
            &input_scripts,
        );
        finalize_shield_io(&mut pczt, sighash, OsRng).unwrap();
        let signed_bytes = serialize_pczt(&pczt).unwrap();
        let proven = deserialize_pczt(
            &with_zkproof(&signed_bytes, vec![0u8; Proof::expected_proof_size(1)]).unwrap(),
        )
        .unwrap();
        let bundle = combine(&proven, sighash, OsRng).unwrap();

        let tx = v6_tx(transparent, Some(bundle));
        let bytes = encode_v6_transaction(&tx).unwrap();

        let zebra = ZebraTx::zcash_deserialize(&bytes[..]).expect("zebra decodes our v6 tx");
        assert_eq!(zebra.version(), 6);
        assert_eq!(zebra.ironwood_actions().count(), 1);
        assert_eq!(zebra.inputs().len(), tx.transparent.input.len());
        assert_eq!(zebra.outputs().len(), tx.transparent.output.len());

        let mut our_txid = compute_v6_txid(&tx);
        our_txid.reverse();
        assert_eq!(
            zebra.hash().to_string(),
            hex::encode(our_txid),
            "zebra txid == ours"
        );
    }

    /// Load a Zcash test fixture's contents from `test/fixtures/zcash/`.
    #[cfg(not(target_arch = "wasm32"))]
    fn load_zcash_fixture(name: &str) -> String {
        crate::fixed_script_wallet::test_utils::fixtures::load_fixture(&format!("zcash/{}", name))
            .unwrap_or_else(|e| panic!("failed to load fixture {}: {}", name, e))
    }

    /// Golden shielded-sighash oracle, using the real on-chain `shield1zec` transaction.
    ///
    /// The transaction's Ironwood bundle carries a real RedPallas dummy spend-auth signature and a
    /// real binding signature, both produced by an external Ironwood signer over the ZIP-244
    /// *shielded* sig digest. We reconstruct the orchard bundle from the on-wire action data and
    /// verify **both** real signatures against the digest [`compute_v6_sig_digest`] computes. If
    /// they verify, our shielded sig digest is byte-correct — the shielded twin of the transparent
    /// golden test in `v6.rs`, and an independent check since neither signature was produced by this
    /// code.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn golden_shield1zec_shielded_signatures_verify() {
        use nonempty::NonEmpty;
        use orchard::bundle::{Bundle as OrchardBundle, EffectsOnly};
        use orchard::note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext};
        use orchard::primitives::redpallas::{Binding, Signature, SpendAuth, VerificationKey};
        use orchard::value::ValueCommitment;

        let raw = hex::decode(load_zcash_fixture("v6_shield1zec_rawtx.hex").trim()).unwrap();
        let tx = decode_v6_transaction(&raw).unwrap();
        let bundle = tx.ironwood_bundle.clone().expect("ironwood bundle present");

        // Spent output committed by ZIP-244 (from the reference that built this tx; see the
        // transparent golden test in v6.rs).
        let prevout_value: i64 = 313_990_000;
        let prevout_script = ScriptBuf::from(
            hex::decode("76a9147c6b843a25873c036aff575516e3802bcc47f63488ac").unwrap(),
        );
        assert_eq!(tx.transparent.input.len(), 1);
        let sighash =
            compute_v6_sig_digest(&tx, &[prevout_value], std::slice::from_ref(&prevout_script));

        // Reconstruct the orchard EffectsOnly bundle from the on-wire action data, so we can derive
        // the binding validating key and verify the real signatures.
        let actions = bundle
            .actions
            .iter()
            .map(|a| {
                let cv_net =
                    Option::from(ValueCommitment::from_bytes(&a.cv)).expect("valid cv_net");
                let rk = VerificationKey::<SpendAuth>::try_from(a.rk).expect("valid rk");
                let cmx =
                    Option::from(ExtractedNoteCommitment::from_bytes(&a.cmx)).expect("valid cmx");
                let nf = Option::from(Nullifier::from_bytes(&a.nullifier)).expect("valid nf");
                let encrypted_note = TransmittedNoteCiphertext {
                    epk_bytes: a.ephemeral_key,
                    enc_ciphertext: a.enc_ciphertext,
                    out_ciphertext: a.out_ciphertext,
                };
                OrchardAction::from_parts(nf, rk, cmx, encrypted_note, cv_net, ())
                    .expect("valid action")
            })
            .collect::<Vec<_>>();
        let actions = NonEmpty::from_vec(actions).expect("at least one action");

        let orchard_bundle = OrchardBundle::<EffectsOnly, i64>::from_parts(
            actions,
            Flags::from_byte(bundle.flags, BundleVersion::ironwood_v3()).expect("valid flags"),
            bundle.value_balance,
            Option::from(Anchor::from_bytes(bundle.anchor)).expect("valid anchor"),
            EffectsOnly,
            BundleVersion::ironwood_v3(),
        )
        .expect("valid bundle");
        assert_eq!(orchard_bundle.flag_byte(), bundle.flags);

        // The real dummy spend-auth signature verifies against our shielded sig digest.
        let spend_auth_sig = Signature::<SpendAuth>::from(bundle.spend_auth_sigs[0]);
        orchard_bundle.actions()[0]
            .rk()
            .verify(&sighash, &spend_auth_sig)
            .expect("real spend-auth signature verifies against compute_v6_sig_digest");

        // The real binding signature verifies against our shielded sig digest.
        let binding_sig = Signature::<Binding>::from(bundle.binding_sig);
        orchard_bundle
            .binding_validating_key()
            .verify(&sighash, &binding_sig)
            .expect("real binding signature verifies against compute_v6_sig_digest");
    }

    /// Golden `out_ciphertext` oracle, using the real on-chain `shield1zec` transaction's note
    /// (`cv`, `cmx`, `epk`, and the confidential `rseed`/`recipient`/`value` build inputs — not
    /// on-chain, but known out-of-band for this reference transaction) together with the real `ovk`
    /// derived from that note's own spending key.
    ///
    /// The on-chain `out_ciphertext` for this particular reference transaction was itself built
    /// **keyless** (`ovk = None`, the random-placeholder path every other build/test in this crate
    /// also exercises) — confirmed here by demonstrating that `try_output_recovery_with_ovk` cannot
    /// decrypt it under *any* real `ovk` derived from the note's own key material (neither
    /// `Scope::External` nor `Scope::Internal`), even though every other field of the note
    /// (`recipient`, `value`, `rseed`, hence `cmx`, hence `enc_ciphertext`) is independently
    /// confirmed correct against the chain. So there is no real on-chain `out_ciphertext` for this
    /// fixture to byte-match against — instead, this pins that our own [`compute_out_ciphertext`]
    /// (fed the real `cv`/`cmx`/rho from the chain and the real `ovk` from the note's key material)
    /// produces ciphertext that is itself correctly recoverable, end to end, on genuine on-chain
    /// note data rather than a self-built one.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn golden_shield1zec_out_ciphertext_round_trips_on_real_on_chain_note_data() {
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};
        use orchard::note::{
            ExtractedNoteCommitment, NoteVersion, Nullifier, RandomSeed, Rho,
            TransmittedNoteCiphertext,
        };
        use orchard::note_encryption::IronwoodDomain;
        use orchard::primitives::redpallas::{SpendAuth, VerificationKey};
        use orchard::value::ValueCommitment;
        use orchard::{Address, Note};
        use zcash_note_encryption::{try_output_recovery_with_ovk, NoteEncryption};

        // Confidential build inputs for this reference transaction (not on-chain; known out-of-band
        // for this fixture only).
        let recipient_hex =
            "d632c28aa0831d671be17709a42c9627e2eb687a1b2a55768ea470c9bae7499cd0bd3d0eb0484e307236b5";
        let rseed_hex = "ecbb65cca04f6701f4a96c3d7b9edc5ecf421451fef4350978e84066c841d2d3";
        let spending_key_hex = "9d451e17e1c0874374dcdb64d3d8e151b26f346a1a227d7b7b7f18bbc6c9cb40";
        let value_zat: u64 = 100_000_000;

        let raw = hex::decode(load_zcash_fixture("v6_shield1zec_rawtx.hex").trim()).unwrap();
        let tx = decode_v6_transaction(&raw).unwrap();
        let bundle = tx.ironwood_bundle.expect("ironwood bundle present");
        let action = &bundle.actions[0];

        // Reconstruct the real output note and confirm it commits to the real on-chain cmx.
        let recipient_bytes: [u8; ORCHARD_ADDRESS_SIZE] =
            hex::decode(recipient_hex).unwrap().try_into().unwrap();
        let recipient =
            Option::<Address>::from(Address::from_raw_address_bytes(&recipient_bytes)).unwrap();
        let rseed_bytes: [u8; 32] = hex::decode(rseed_hex).unwrap().try_into().unwrap();
        // The action's on-wire `nullifier` field doubles as the paired output note's `rho` (see
        // `action_to_ironwood`).
        let rho = Option::<Rho>::from(Rho::from_bytes(&action.nullifier)).unwrap();
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed_bytes, &rho)).unwrap();
        let note = Option::<Note>::from(Note::from_parts(
            recipient,
            orchard::value::NoteValue::from_raw(value_zat),
            rho,
            rseed,
            NoteVersion::V3,
        ))
        .unwrap();
        let cmx_bytes: [u8; 32] = (&ExtractedNoteCommitment::from(note.commitment())).into();
        assert_eq!(
            cmx_bytes, action.cmx,
            "reconstructed note commits to the real on-chain cmx"
        );

        let cv_net =
            Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&action.cv)).unwrap();
        let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
            &action.cmx,
        ))
        .unwrap();

        // The encrypted note plaintext (independent of ovk) matches the real on-chain bytes,
        // confirming esk/epk — and hence the whole note reconstruction — is correct.
        let placeholder_memo = [0u8; 512];
        let enc = NoteEncryption::<IronwoodDomain>::new(None, note, placeholder_memo);
        assert_eq!(
            enc.encrypt_note_plaintext().to_vec(),
            action.enc_ciphertext.to_vec(),
            "reconstructed note encrypts to the real on-chain enc_ciphertext"
        );

        // Real `ovk`s derived from the note's own spending key do not decrypt the real on-chain
        // out_ciphertext — it was built keyless (ovk = None), so there is nothing for a real ovk to
        // recover there.
        let sk_bytes: [u8; 32] = hex::decode(spending_key_hex).unwrap().try_into().unwrap();
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let rk = VerificationKey::<SpendAuth>::try_from(action.rk).expect("valid rk");
        let nf = Option::from(Nullifier::from_bytes(&action.nullifier)).expect("valid nf");
        let on_chain_encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: action.ephemeral_key,
            enc_ciphertext: action.enc_ciphertext,
            out_ciphertext: action.out_ciphertext,
        };
        let on_chain_action = OrchardAction::from_parts(
            nf,
            rk.clone(),
            cmx,
            on_chain_encrypted_note,
            cv_net.clone(),
            (),
        )
        .expect("valid action");
        let domain = IronwoodDomain::for_action(&on_chain_action);
        for scope in [Scope::External, Scope::Internal] {
            assert!(
                try_output_recovery_with_ovk(
                    &domain,
                    &fvk.to_ovk(scope),
                    &on_chain_action,
                    &cv_net,
                    &action.out_ciphertext,
                )
                .is_none(),
                "the real on-chain out_ciphertext is not recoverable under any real ovk \
                 ({scope:?}) — it was built keyless"
            );
        }

        // Feeding this note's real cv/cmx (from the chain) and a real ovk (from the note's own key
        // material) into the same `NoteEncryption::encrypt_outgoing_plaintext` primitive
        // [`compute_out_ciphertext`] wraps produces ciphertext that *is* correctly recoverable end
        // to end — unlike the on-chain placeholder just shown above.
        let real_ovk = fvk.to_ovk(Scope::External);
        let enc_with_real_ovk =
            NoteEncryption::<IronwoodDomain>::new(Some(real_ovk.clone()), note, placeholder_memo);
        let recomputed = enc_with_real_ovk.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut OsRng);
        let recomputed_encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: action.ephemeral_key,
            enc_ciphertext: action.enc_ciphertext,
            out_ciphertext: recomputed,
        };
        let recomputed_action =
            OrchardAction::from_parts(nf, rk, cmx, recomputed_encrypted_note, cv_net.clone(), ())
                .expect("valid action");
        let (recovered_note, recovered_recipient, _memo) = try_output_recovery_with_ovk(
            &domain,
            &real_ovk,
            &recomputed_action,
            &cv_net,
            &recomputed,
        )
        .expect("our own out_ciphertext, built from real on-chain cv/cmx, is recoverable");
        assert_eq!(recovered_recipient, recipient);
        assert_eq!(
            recovered_note.value(),
            orchard::value::NoteValue::from_raw(value_zat)
        );
    }

    // ---- Client-managed `ovk` ----

    /// A fixed secp256k1 key pair standing in for "the BitGo cosigner pubkey" and "the user's
    /// private key" — the two ECDH counterparties [`derive_client_ovk`] combines.
    fn test_key_pair(seed: u8) -> (secp256k1::PublicKey, secp256k1::SecretKey) {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        (pk, sk)
    }

    #[test]
    fn derive_client_ovk_is_a_deterministic_ecdh_agreement() {
        let (bitgo_pk, _) = test_key_pair(0x11);
        let (_, user_sk) = test_key_pair(0x22);

        let ovk1 = derive_client_ovk(&bitgo_pk.serialize(), &user_sk.secret_bytes()).unwrap();
        let ovk2 = derive_client_ovk(&bitgo_pk.serialize(), &user_sk.secret_bytes()).unwrap();
        assert_eq!(ovk1, ovk2, "deterministic in its two key inputs");

        // ECDH agreement: the same shared secret is reachable from either side of the key pair —
        // BitGo's privkey + the user's pubkey agrees with BitGo's pubkey + the user's privkey.
        let secp = secp256k1::Secp256k1::new();
        let (_, bitgo_sk) = test_key_pair(0x11);
        let (user_pk, _) = test_key_pair(0x22);
        assert_eq!(
            bitgo_pk,
            secp256k1::PublicKey::from_secret_key(&secp, &bitgo_sk)
        );
        let ovk_from_other_side =
            derive_client_ovk(&user_pk.serialize(), &bitgo_sk.secret_bytes()).unwrap();
        assert_eq!(ovk1, ovk_from_other_side, "ECDH agreement is symmetric");

        // A different user key yields a different ovk.
        let (_, other_user_sk) = test_key_pair(0x33);
        let ovk3 = derive_client_ovk(&bitgo_pk.serialize(), &other_user_sk.secret_bytes()).unwrap();
        assert_ne!(ovk1, ovk3);
    }

    #[test]
    fn derive_client_ovk_rejects_malformed_keys() {
        let (bitgo_pk, _) = test_key_pair(0x11);
        let (_, user_sk) = test_key_pair(0x22);
        assert!(matches!(
            derive_client_ovk(&[0u8; 33], &user_sk.secret_bytes()),
            Err(IronwoodBuildError::BadKey(_))
        ));
        assert!(matches!(
            derive_client_ovk(&bitgo_pk.serialize(), &[0u8; 32]),
            Err(IronwoodBuildError::BadKey(_))
        ));
    }

    #[test]
    fn compute_out_ciphertext_is_recoverable_only_with_the_matching_ovk() {
        use orchard::note_encryption::IronwoodDomain;
        use zcash_note_encryption::try_output_recovery_with_ovk;

        let pczt = construct_shield_pczt(
            &test_recipient(),
            100_000_000,
            None, // keyless server build
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        let action = &pczt.actions()[0];

        let (bitgo_pk, _) = test_key_pair(0xaa);
        let (_, user_sk) = test_key_pair(0xbb);
        let ovk = derive_client_ovk(&bitgo_pk.serialize(), &user_sk.secret_bytes()).unwrap();
        let out_ct = compute_out_ciphertext(&pczt, 0, ovk, &mut OsRng.clone()).unwrap();

        let domain = IronwoodDomain::for_pczt_action(action);
        let recovered = try_output_recovery_with_ovk(
            &domain,
            &orchard::keys::OutgoingViewingKey::from(ovk),
            action,
            action.cv_net(),
            &out_ct,
        );
        let (note, recipient, _memo) = recovered.expect("recoverable with the matching ovk");
        assert_eq!(recipient, *action.output().recipient().as_ref().unwrap());
        assert_eq!(note.value(), *action.output().value().as_ref().unwrap());

        // A different (wrong) ovk does not recover the note.
        let (_, wrong_user_sk) = test_key_pair(0xcc);
        let wrong_ovk =
            derive_client_ovk(&bitgo_pk.serialize(), &wrong_user_sk.secret_bytes()).unwrap();
        assert!(try_output_recovery_with_ovk(
            &domain,
            &orchard::keys::OutgoingViewingKey::from(wrong_ovk),
            action,
            action.cv_net(),
            &out_ct,
        )
        .is_none());

        // Rejects an out-of-range action index.
        assert!(matches!(
            compute_out_ciphertext(&pczt, 1, ovk, &mut OsRng.clone()),
            Err(IronwoodBuildError::ActionIndexOutOfRange)
        ));
    }

    /// A PCZT whose output fields no longer reconstruct the note its `cmx` commits to is rejected
    /// rather than producing an `out_ciphertext` whose `esk` disagrees with the action's fixed
    /// `ephemeral_key` — ciphertext that would splice in cleanly and only reveal itself as garbage
    /// when someone later tried to recover the note.
    #[test]
    fn compute_out_ciphertext_rejects_a_note_that_does_not_match_the_committed_cmx() {
        use crate::zcash::ironwood_pczt::with_output_rseed_for_test;

        let pczt = construct_shield_pczt(
            &test_recipient(),
            100_000_000,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        let bytes = serialize_pczt(&pczt).unwrap();
        let tampered =
            deserialize_pczt(&with_output_rseed_for_test(&bytes, 0, [0x5au8; 32]).unwrap())
                .unwrap();

        let (bitgo_pk, _) = test_key_pair(0xa1);
        let (_, user_sk) = test_key_pair(0xa2);
        let ovk = derive_client_ovk(&bitgo_pk.serialize(), &user_sk.secret_bytes()).unwrap();
        assert!(matches!(
            compute_out_ciphertext(&tampered, 0, ovk, &mut OsRng.clone()),
            Err(IronwoodBuildError::NoteCommitmentMismatch)
        ));
    }

    /// Server-side validation: ECDH agreement is symmetric, so the server — holding
    /// `bitgo_privkey` — can derive the *same* `ovk` from the other side of the key pair
    /// (`ECDH(bitgo_privkey, user_pubkey)`, vs. the client's `ECDH(bitgo_pubkey, user_privkey)`)
    /// without ever learning `user_privkey` or the `ovk` itself over the wire. It then uses that
    /// independently-derived `ovk` to decrypt `out_ciphertext` and check it actually describes the
    /// action's committed note (`recipient`/`value`) before it would be willing to countersign —
    /// rather than trusting the client-supplied ciphertext blindly.
    #[test]
    fn server_can_independently_derive_ovk_and_validate_out_ciphertext_before_signing() {
        use orchard::note_encryption::IronwoodDomain;
        use zcash_note_encryption::try_output_recovery_with_ovk;

        // Keyless server build, exactly as it would happen for real.
        let pczt = construct_shield_pczt(
            &test_recipient(),
            100_000_000,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        let action = &pczt.actions()[0];

        let (bitgo_pk, bitgo_sk) = test_key_pair(0xd1);
        let (user_pk, user_sk) = test_key_pair(0xd2);

        // Client side: derive ovk from (bitgo pubkey, user privkey) and produce out_ciphertext.
        let client_ovk = derive_client_ovk(&bitgo_pk.serialize(), &user_sk.secret_bytes()).unwrap();
        let out_ct = compute_out_ciphertext(&pczt, 0, client_ovk, &mut OsRng.clone()).unwrap();

        // Server side: never sees `user_sk` or `client_ovk`. It only has its own `bitgo_sk` and the
        // user's public key (e.g. from wallet metadata), and derives the ovk from the other side of
        // the same ECDH pair.
        let server_ovk = derive_client_ovk(&user_pk.serialize(), &bitgo_sk.secret_bytes()).unwrap();
        assert_eq!(
            server_ovk, client_ovk,
            "ECDH agreement: the server derives the identical ovk from its own privkey + the \
             user's pubkey"
        );

        // The server decrypts out_ciphertext with its independently-derived ovk and checks it
        // actually matches the action's committed note — the check it would run before countersigning.
        let domain = IronwoodDomain::for_pczt_action(action);
        let (note, recipient, _memo) = try_output_recovery_with_ovk(
            &domain,
            &orchard::keys::OutgoingViewingKey::from(server_ovk),
            action,
            action.cv_net(),
            &out_ct,
        )
        .expect("server validates out_ciphertext with its own ECDH-derived ovk");
        assert_eq!(recipient, *action.output().recipient().as_ref().unwrap());
        assert_eq!(note.value(), *action.output().value().as_ref().unwrap());

        // If the client used a *different* user pubkey than the one the server has on file for that
        // user, the server's derived ovk no longer agrees, and validation correctly fails — this is
        // the check that would block signing.
        let (wrong_user_pk, _) = test_key_pair(0xd3);
        let mismatched_server_ovk =
            derive_client_ovk(&wrong_user_pk.serialize(), &bitgo_sk.secret_bytes()).unwrap();
        assert_ne!(mismatched_server_ovk, client_ovk);
        assert!(
            try_output_recovery_with_ovk(
                &domain,
                &orchard::keys::OutgoingViewingKey::from(mismatched_server_ovk),
                action,
                action.cv_net(),
                &out_ct,
            )
            .is_none(),
            "server rejects out_ciphertext when the on-file user pubkey doesn't match"
        );
    }

    /// End-to-end test: the server builds a **keyless** shielding PCZT (single
    /// transparent input, single Ironwood output — the same shape `ZcashBitGoPsbt::add_ironwood_output`
    /// produces) and hands its serialized bytes to "the client". The client deserializes, derives its
    /// `ovk` on the fly as the ECDH agreement of the BitGo cosigner pubkey and its own private key,
    /// recomputes `out_ciphertext` under that `ovk`, and splices it back in — all *before* the ZIP-244
    /// sighash (which commits to `out_ciphertext`) is computed and the transparent input is signed.
    #[test]
    fn keyless_build_then_client_sets_out_ciphertext_via_ecdh_ovk_then_signs_and_combines() {
        let amount = 100_000_000u64;
        let pczt = construct_shield_pczt(
            &test_recipient(),
            amount,
            None, // keyless: server never sees an ovk
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();

        let transparent = transparent_skeleton();
        let data_before = pczt_action_data(&pczt).unwrap();
        assert_eq!(transparent.input.len(), 1, "single transparent input");
        assert_eq!(
            data_before.actions.len(),
            1,
            "single Ironwood output/action"
        );

        // Server: serialize the keyless PCZT for handoff (this is what `ZcashBitGoPsbt::serialize_v6`
        // carries in the PSBT's proprietary map).
        let server_bytes = serialize_pczt(&pczt).unwrap();

        // Client: deserialize, derive its ovk on the fly (ECDH of the BitGo cosigner pubkey and its
        // own signing private key — the server never sees either the ovk or the user privkey).
        let client_pczt = deserialize_pczt(&server_bytes).unwrap();
        let (bitgo_pubkey, _) = test_key_pair(0x42);
        let (_, user_privkey) = test_key_pair(0x99);
        let ovk =
            derive_client_ovk(&bitgo_pubkey.serialize(), &user_privkey.secret_bytes()).unwrap();
        let new_out_ciphertext =
            compute_out_ciphertext(&client_pczt, 0, ovk, &mut OsRng.clone()).unwrap();
        assert_ne!(
            new_out_ciphertext.to_vec(),
            data_before.actions[0].out_ciphertext.to_vec(),
            "client's ovk-encrypted ciphertext differs from the keyless placeholder"
        );

        let patched_bytes = with_out_ciphertext(&server_bytes, 0, new_out_ciphertext).unwrap();
        let mut patched = deserialize_pczt(&patched_bytes).unwrap();

        let data_after = pczt_action_data(&patched).unwrap();
        assert_eq!(
            data_after.actions[0].out_ciphertext.to_vec(),
            new_out_ciphertext.to_vec()
        );
        // Every other action-data field is untouched by the splice.
        assert_eq!(data_after.actions[0].cv, data_before.actions[0].cv);
        assert_eq!(data_after.actions[0].cmx, data_before.actions[0].cmx);
        assert_eq!(
            data_after.actions[0].enc_ciphertext,
            data_before.actions[0].enc_ciphertext
        );
        assert_eq!(data_after.value_balance, data_before.value_balance);

        // Now — and only now — the ZIP-244 sighash is computed (it commits to `out_ciphertext`) and
        // the transparent input is "signed" (finalize_shield_io signs the dummy spend over it).
        let input_amounts = [200_000_000i64];
        let input_scripts = [ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac])];
        let tx_for_sighash = v6_tx(transparent.clone(), Some(data_after.clone()));
        let sighash = compute_v6_sig_digest(&tx_for_sighash, &input_amounts, &input_scripts);

        // The sighash differs from what it would have been over the keyless placeholder — pinning
        // the ordering constraint: signing before setting out_ciphertext would sign the wrong digest.
        let placeholder_tx = v6_tx(transparent.clone(), Some(data_before.clone()));
        let placeholder_sighash =
            compute_v6_sig_digest(&placeholder_tx, &input_amounts, &input_scripts);
        assert_ne!(
            sighash, placeholder_sighash,
            "out_ciphertext is sighash-committed"
        );

        finalize_shield_io(&mut patched, sighash, OsRng).unwrap();
        let signed_bytes = serialize_pczt(&patched).unwrap();
        let proof = vec![0u8; Proof::expected_proof_size(1)];
        let proven = deserialize_pczt(&with_zkproof(&signed_bytes, proof).unwrap()).unwrap();

        let bundle = combine(&proven, sighash, OsRng).unwrap();
        assert_eq!(
            bundle.actions[0].out_ciphertext.to_vec(),
            new_out_ciphertext.to_vec(),
            "the client-set out_ciphertext survives to the combined bundle"
        );

        // The resulting v6 transaction encodes/decodes round-trip cleanly.
        let tx = v6_tx(transparent, Some(bundle));
        let encoded = encode_v6_transaction(&tx).unwrap();
        let decoded = decode_v6_transaction(&encoded).unwrap();
        assert_eq!(decoded, tx);
    }

    // ---- Real-spend construction (Constructor role) ----

    /// A real-spend fixture: a wallet note (fvk/recipient/value/rho/rseed) plus a self-consistent
    /// witness path around its cmx — what a wallet that scanned the note would supply. Returns the
    /// bundle `anchor` the witness recomputes to.
    fn test_spend_spec() -> (IronwoodSpendSpec, AnchorBytes) {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let rho = Option::<Rho>::from(Rho::from_bytes(&field_bytes(100))).unwrap();
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes([42u8; 32], &rho)).unwrap();
        let address = Option::<Address>::from(Address::from_raw_address_bytes(&recipient)).unwrap();
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
        let sibling_hashes: [MerkleHashOrchard; IRONWOOD_MERKLE_DEPTH] =
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
                witness: IronwoodWitness {
                    position,
                    auth_path,
                },
            },
            anchor,
        )
    }

    #[test]
    fn construct_spend_pczt_builds_a_real_spend_bundle() {
        let (spec, anchor) = test_spend_spec();
        let (bundle, action_map) =
            construct_spend_pczt_multi(&[spec], &[], &anchor, OsRng).unwrap();
        assert_eq!(
            action_map.spend_action_indices(),
            &[0],
            "one spend ⇒ one action"
        );
        assert!(action_map.output_action_indices().is_empty());

        let spend = bundle.actions()[0].spend();
        // The in-memory Constructor uses the FVK, but the persisted PCZT carries no FVK or alpha.
        assert!(spend.fvk().is_none());
        assert!(spend.alpha().is_none());
        assert_eq!(<[u8; 32]>::from(spend.rk()), PLACEHOLDER_RK);
        // The note plaintext required by the proof flow remains available, excluding the FVK.
        assert_eq!(spend.value().as_ref().map(|v| v.inner()), Some(spec.value));
        assert_eq!(spend.rho().as_ref().map(|r| r.to_bytes()), Some(spec.rho));
        assert_eq!(
            spend.rseed().as_ref().map(|r| *r.as_bytes()),
            Some(spec.rseed)
        );
        assert_eq!(
            spend
                .recipient()
                .as_ref()
                .map(|a| a.to_raw_address_bytes().to_vec()),
            Some(spec.recipient.to_vec())
        );
        assert!(spend.witness().is_some());
        assert!(spend.spend_auth_sig().is_none());
        assert!(spend.dummy_sk().is_none());
        assert_eq!(
            spend
                .proprietary()
                .get(CMX_PROPRIETARY_KEY)
                .map(|v| v.as_slice()),
            Some(&spec.cmx.to_vec()[..])
        );
        // Spend-only action: the paired output side is a zero-valued dummy note.
        let output = bundle.actions()[0].output();
        assert!(output.recipient().is_some());
        assert_eq!(output.value().as_ref().map(|v| v.inner()), Some(0));
        assert_ne!(output.cmx().to_bytes(), spec.cmx);

        let bytes = serialize_pczt(&bundle).unwrap();
        assert!(!bytes
            .windows(spec.fvk.len())
            .any(|window| window == &spec.fvk[..]));
        let roundtrip = deserialize_pczt(&bytes).unwrap();
        assert!(roundtrip.actions()[0].spend().fvk().is_none());
        assert_eq!(serialize_pczt(&roundtrip).unwrap(), bytes);
    }

    #[test]
    fn construct_spend_pczt_defaults_output_ovk_to_the_spending_fvk() {
        let (spec, anchor) = test_spend_spec();
        let (bundle, action_map) = construct_spend_pczt_multi(
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
        let out_idx = action_map.output_action_index(0).unwrap();
        let output = bundle.actions()[out_idx].output();
        assert!(output.recipient().is_some(), "real output, not a dummy");

        // Its out_ciphertext is exactly what this crate computes under the spending FVK's
        // external ovk — the outgoing note is recoverable by the wallet at construction time,
        // with no separate key-supply or re-encryption step.
        let ovk = FullViewingKey::from_bytes(&spec.fvk)
            .unwrap()
            .to_ovk(Scope::External)
            .as_ref()
            .to_owned();
        let mut rng = OsRng;
        let recomputed = compute_out_ciphertext(&bundle, out_idx, ovk, &mut rng).unwrap();
        assert_eq!(
            output.encrypted_note().out_ciphertext,
            recomputed,
            "out_ciphertext must be final at construction under the FVK ovk"
        );
    }

    #[test]
    fn construct_spend_pczt_rejects_inconsistent_note_data() {
        let (spec, anchor) = test_spend_spec();

        // A cmx the note plaintext does not commit to.
        let mut bad = spec;
        bad.cmx = field_bytes(999);
        assert!(matches!(
            construct_spend_pczt_multi(&[bad], &[], &anchor, OsRng),
            Err(IronwoodBuildError::NoteCommitmentMismatch)
        ));

        // Non-canonical rho bytes.
        let mut bad = spec;
        bad.rho = [0xffu8; 32];
        assert!(matches!(
            construct_spend_pczt_multi(&[bad], &[], &anchor, OsRng),
            Err(IronwoodBuildError::InvalidNote)
        ));

        // A valid recipient the note does not own (different address index) — the reconstructed
        // note commits elsewhere.
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let mut bad = spec;
        bad.recipient = fvk.address_at(1u32, Scope::External).to_raw_address_bytes();
        assert!(matches!(
            construct_spend_pczt_multi(&[bad], &[], &anchor, OsRng),
            Err(IronwoodBuildError::NoteCommitmentMismatch)
        ));
    }

    #[test]
    fn construct_spend_pczt_rejects_a_witness_not_recomputing_to_the_anchor() {
        let (spec, _anchor) = test_spend_spec();
        assert!(matches!(
            construct_spend_pczt_multi(&[spec], &[], &Anchor::empty_tree().to_bytes(), OsRng),
            Err(IronwoodBuildError::WitnessAnchorMismatch)
        ));
    }

    #[test]
    fn construct_spend_pczt_rejects_a_non_canonical_witness_entry() {
        let (mut spec, anchor) = test_spend_spec();
        spec.witness.auth_path[3] = [0xffu8; 32];
        assert!(matches!(
            construct_spend_pczt_multi(&[spec], &[], &anchor, OsRng),
            Err(IronwoodBuildError::BadWitnessPath)
        ));
    }

    #[test]
    fn construct_spend_pczt_rejects_bad_and_mixed_fvks() {
        let (spec, anchor) = test_spend_spec();

        let mut bad = spec;
        bad.fvk = [0xffu8; 96];
        assert!(matches!(
            construct_spend_pczt_multi(&[bad], &[], &anchor, OsRng),
            Err(IronwoodBuildError::BadFvk)
        ));

        // Two spends from two different wallets.
        let sk2 = Option::<SpendingKey>::from(SpendingKey::from_bytes([9u8; 32])).unwrap();
        let mut other = spec;
        other.fvk = FullViewingKey::from(&sk2).to_bytes();
        assert!(matches!(
            construct_spend_pczt_multi(&[spec, other], &[], &anchor, OsRng),
            Err(IronwoodBuildError::MixedSpendingFvks)
        ));
    }

    #[test]
    fn construct_spend_pczt_rejects_an_empty_bundle() {
        let (_spec, anchor) = test_spend_spec();
        assert!(matches!(
            construct_spend_pczt_multi(&[], &[], &anchor, OsRng),
            Err(IronwoodBuildError::EmptyBundle)
        ));

        // Shielding (no spends) still builds keyless with ovk None.
        let (_, action_map) = construct_spend_pczt_multi(
            &[],
            &[IronwoodOutputSpec {
                recipient: test_recipient(),
                amount: 1,
                ovk: None,
                memo: [0u8; 512],
            }],
            &anchor,
            OsRng,
        )
        .unwrap();
        assert_eq!(action_map.output_action_indices().len(), 1);
    }

    #[test]
    fn verify_spend_pczt_accepts_constructed_bundles() {
        let (spec, anchor) = test_spend_spec();
        let (bundle, _) = construct_spend_pczt_multi(&[spec], &[], &anchor, OsRng).unwrap();
        verify_spend_pczt(&bundle).unwrap();

        // The Constructor ran nullifier, note-commitment, and cv_net checks before serializing; the
        // returned PCZT intentionally no longer carries the FVK needed to repeat spend checks.
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
        verify_spend_pczt(&bundle).unwrap();

        // Shielding bundle (dummy spend): every check is skipped, the cross-address restriction
        // is a no-op with cross-address enabled.
        let shield =
            construct_shield_pczt(&test_recipient(), 1_000, None, &anchor, &[0u8; 512], OsRng)
                .unwrap();
        verify_spend_pczt(&shield).unwrap();
    }

    #[test]
    fn verify_spend_pczt_rejects_a_tampered_output_note() {
        let (spec, anchor) = test_spend_spec();
        let (bundle, action_map) = construct_spend_pczt_multi(
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
        let tampered = with_output_rseed_for_test(
            &bytes,
            action_map.output_action_index(0).unwrap(),
            [9u8; 32],
        )
        .unwrap();
        let msg = match verify_spend_pczt(&deserialize_pczt(&tampered).unwrap()) {
            Err(IronwoodBuildError::Verify(msg)) => msg,
            other => panic!("expected a Verify error, got {other:?}"),
        };
        assert!(msg.contains("cmx"), "got {msg:?}");
    }

    /// Gap 13: a spend validated against a **real** note-commitment tree — real commitment
    /// leaves folded with `MerkleHashOrchard::combine` and real empty-leaf subtrees — not the
    /// self-consistent synthetic fixtures (arbitrary field bytes keyed off their own anchor).
    #[test]
    fn construct_witnesses_against_a_real_tree() {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let (anchor, leaves) = super::test_util::real_two_leaf_tree(
            &fvk,
            [
                (100_000_000u64, field_bytes(200), [52u8; 32]),
                (80_000_000u64, field_bytes(201), [53u8; 32]),
            ],
        );
        let spec = |leaf: &super::test_util::RealLeaf| IronwoodSpendSpec {
            fvk: fvk.to_bytes(),
            recipient: leaf.recipient,
            value: leaf.value,
            rho: leaf.rho,
            rseed: leaf.rseed,
            cmx: leaf.cmx,
            witness: leaf.witness,
        };

        // Positive: both leaves' witnesses recompute to the shared real root.
        let specs = [spec(&leaves[0]), spec(&leaves[1])];
        let (bundle, map) = construct_spend_pczt_multi(&specs, &[], &anchor, OsRng).unwrap();
        assert_eq!(bundle.actions().len(), 2);
        assert_eq!(map.spend_action_indices().len(), 2);

        // Negative: a witness recomputed for the WRONG leaf does not fold to the anchor — a
        // real tree distinguishes its leaves, so a spend cannot ride another note's witness.
        let wrong = IronwoodSpendSpec {
            witness: leaves[1].witness,
            ..spec(&leaves[0])
        };
        let err = construct_spend_pczt_multi(&[wrong], &[], &anchor, OsRng).unwrap_err();
        assert!(
            matches!(err, IronwoodBuildError::WitnessAnchorMismatch),
            "unexpected: {err:?}"
        );
    }

    // ---- Signing-time hooks + the Verifier role ----

    use crate::error::WasmErrorCode as _;
    use ff::{Field as _, PrimeField as _};
    use orchard::keys::SpendAuthorizingKey;

    /// The parsed spend-validating key behind `fvk_bytes` — the `ak` argument of
    /// [`set_spend_auth_randomizer`].
    fn test_ak(fvk_bytes: &FvkBytes) -> VerificationKey<SpendAuth> {
        VerificationKey::<SpendAuth>::try_from(<[u8; 32]>::try_from(&fvk_bytes[..32]).unwrap())
            .unwrap()
    }

    #[test]
    fn installing_the_randomizer_replaces_the_placeholder_atomically() {
        let (spec, anchor) = test_spend_spec();
        let (mut bundle, _) = construct_spend_pczt_multi(&[spec], &[], &anchor, OsRng).unwrap();
        // Placeholder state: rk == PLACEHOLDER_RK, no alpha.
        let spend = bundle.actions()[0].spend();
        assert_eq!(<[u8; 32]>::from(spend.rk()), PLACEHOLDER_RK);
        assert!(spend.alpha().is_none());
        let placeholder_actions = pczt_action_data(&bundle).unwrap().actions;

        let alpha = pasta_curves::pallas::Scalar::random(&mut OsRng);
        let alpha_bytes = alpha.to_repr();
        let rsk = SpendAuthorizingKey::from(
            &Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap(),
        )
        .randomize(&alpha);
        let rk = <[u8; 32]>::from(orchard::primitives::redpallas::VerificationKey::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(&rsk));

        set_spend_auth_randomizer(&mut bundle, 0, &alpha_bytes, &rk, Some(&test_ak(&spec.fvk)))
            .unwrap();
        // Only rk is installed: alpha never enters the PCZT.
        let spend = bundle.actions()[0].spend();
        assert_eq!(<[u8; 32]>::from(spend.rk()), rk);
        assert!(spend.alpha().is_none());

        // The ZIP-244-committed action data carries the replaced rk (alpha is witness-side and
        // deliberately absent from it).
        let installed_actions = pczt_action_data(&bundle).unwrap().actions;
        assert_ne!(placeholder_actions[0].rk, installed_actions[0].rk);
    }

    #[test]
    fn set_spend_auth_randomizer_rejects_an_unrandomized_rk_and_dummy_spends() {
        let (spec, anchor) = test_spend_spec();
        let (mut bundle, _) = construct_spend_pczt_multi(&[spec], &[], &anchor, OsRng).unwrap();
        let ak = test_ak(&spec.fvk);
        let ak_bytes = <[u8; 32]>::from(&ak);
        let alpha = pasta_curves::pallas::Scalar::random(&mut OsRng).to_repr();

        // alpha = 0 yields rk = ak: the wallet's own, linkable key.
        assert!(matches!(
            set_spend_auth_randomizer(&mut bundle, 0, &[0u8; 32], &ak_bytes, Some(&ak)),
            Err(IronwoodBuildError::UnrandomizedRk)
        ));
        // The placeholder itself is not a randomized rk, with or without the wallet's ak.
        for ak in [Some(&ak), None] {
            assert!(matches!(
                set_spend_auth_randomizer(&mut bundle, 0, &alpha, &PLACEHOLDER_RK, ak),
                Err(IronwoodBuildError::UnrandomizedRk)
            ));
        }
        // A non-zero alpha paired with the unrandomized ak is a mismatched pair.
        assert!(matches!(
            set_spend_auth_randomizer(&mut bundle, 0, &alpha, &ak_bytes, Some(&ak)),
            Err(IronwoodBuildError::RandomizerMismatch)
        ));
        // A non-canonical alpha names its action.
        assert!(matches!(
            set_spend_auth_randomizer(&mut bundle, 0, &[0xffu8; 32], &ak_bytes, None),
            Err(IronwoodBuildError::BadAlpha { action_index: 0 })
        ));
        // Nothing was installed: the signature gate still sees the placeholder.
        assert!(matches!(
            apply_spend_signature(&mut bundle, 0, [7u8; 32], &[7u8; 64]),
            Err(IronwoodBuildError::RandomizersNotInstalled)
        ));

        // A dummy spend's alpha/rk belong to its fabricating builder.
        let mut shield =
            construct_shield_pczt(&test_recipient(), 1_000, None, &anchor, &[0u8; 512], OsRng)
                .unwrap();
        let rk = <[u8; 32]>::from(shield.actions()[0].spend().rk());
        assert!(matches!(
            set_spend_auth_randomizer(&mut shield, 0, &alpha, &rk, Some(&test_ak(&spec.fvk))),
            Err(IronwoodBuildError::RandomizerOnDummySpend)
        ));
    }

    #[test]
    fn verify_ironwood_spends_passes_for_the_installed_pair() {
        let (spec, anchor) = test_spend_spec();
        let (mut bundle, _) = construct_spend_pczt_multi(&[spec], &[], &anchor, OsRng).unwrap();
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let ask = SpendAuthorizingKey::from(&sk);
        let alpha = pasta_curves::pallas::Scalar::random(&mut OsRng);
        let rk = <[u8; 32]>::from(orchard::primitives::redpallas::VerificationKey::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(&ask.randomize(&alpha)));
        set_spend_auth_randomizer(
            &mut bundle,
            0,
            &alpha.to_repr(),
            &rk,
            Some(&test_ak(&spec.fvk)),
        )
        .unwrap();

        verify_ironwood_spends(&bundle, &spec.fvk, &[(0, alpha.to_repr())]).unwrap();
        // The alpha is needed out of band: without it the rk cannot be checked.
        let err = verify_ironwood_spends(&bundle, &spec.fvk, &[]).unwrap_err();
        assert_eq!(err.code(), "IronwoodVerifyError.Rk");
    }

    #[test]
    fn verify_ironwood_spends_rejects_a_mismatched_rk() {
        let (spec, anchor) = test_spend_spec();
        let (bundle, _) = construct_spend_pczt_multi(&[spec], &[], &anchor, OsRng).unwrap();
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let ask = SpendAuthorizingKey::from(&sk);
        // rk randomized under a DIFFERENT alpha than the one the prover is given: without the
        // wallet's ak the installer cannot tell, but the keyed verifier does.
        let (mut bundle, alpha) = (bundle, pasta_curves::pallas::Scalar::random(&mut OsRng));
        let other_alpha = pasta_curves::pallas::Scalar::random(&mut OsRng);
        let rk = <[u8; 32]>::from(orchard::primitives::redpallas::VerificationKey::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(&ask.randomize(&other_alpha)));
        set_spend_auth_randomizer(&mut bundle, 0, &alpha.to_repr(), &rk, None).unwrap();

        let err = verify_ironwood_spends(&bundle, &spec.fvk, &[(0, alpha.to_repr())]).unwrap_err();
        assert!(
            matches!(
                err,
                IronwoodVerifyError::Action {
                    check: IronwoodVerifyCheck::Rk,
                    ..
                }
            ),
            "unexpected: {err:?}"
        );
        assert_eq!(err.code(), "IronwoodVerifyError.Rk");
    }

    #[test]
    fn verify_ironwood_spends_rejects_a_foreign_fvk_and_bad_bytes() {
        let (spec, anchor) = test_spend_spec();
        let (mut bundle, _) = construct_spend_pczt_multi(&[spec], &[], &anchor, OsRng).unwrap();
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let ask = SpendAuthorizingKey::from(&sk);
        let alpha = pasta_curves::pallas::Scalar::random(&mut OsRng);
        let rk = <[u8; 32]>::from(orchard::primitives::redpallas::VerificationKey::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(&ask.randomize(&alpha)));
        set_spend_auth_randomizer(
            &mut bundle,
            0,
            &alpha.to_repr(),
            &rk,
            Some(&test_ak(&spec.fvk)),
        )
        .unwrap();
        let alphas = [(0, alpha.to_repr())];

        // A different wallet's FVK does not own the note.
        let foreign_sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([9u8; 32])).unwrap();
        let foreign_fvk = FullViewingKey::from(&foreign_sk).to_bytes();
        let err = verify_ironwood_spends(&bundle, &foreign_fvk, &alphas).unwrap_err();
        assert!(
            matches!(
                err,
                IronwoodVerifyError::Action {
                    check: IronwoodVerifyCheck::Nullifier,
                    ..
                }
            ),
            "unexpected: {err:?}"
        );

        assert_eq!(err.code(), "IronwoodVerifyError.Nullifier");

        // Garbage FVK bytes are a distinct code.
        let err = verify_ironwood_spends(&bundle, &[0xffu8; 96], &alphas).unwrap_err();
        assert!(matches!(err, IronwoodVerifyError::BadFvk));
        assert_eq!(err.code(), "IronwoodVerifyError.BadFvk");
    }

    /// The ZIP-244 sighash commits every action's `rk`, so a signature on ANY action — not only
    /// the target — blocks installing a randomizer.
    #[test]
    fn set_spend_auth_randomizer_rejects_once_any_action_is_signed() {
        use crate::zcash::ironwood_pczt::with_spend_auth_sig;

        let (spec, anchor) = test_spend_spec();
        // Two outputs force a second action (its spend side is a dummy).
        let output = IronwoodOutputSpec {
            recipient: test_recipient(),
            amount: 1_000,
            ovk: None,
            memo: [0u8; 512],
        };
        let (bundle, _) =
            construct_spend_pczt_multi(&[spec], &[output, output], &anchor, OsRng).unwrap();
        assert_eq!(bundle.actions().len(), 2);
        let real = bundle
            .actions()
            .iter()
            .position(|a| a.spend().dummy_sk().is_none())
            .unwrap();
        let other = (0..bundle.actions().len()).find(|&i| i != real).unwrap();

        // A (shape-only) signature on the OTHER action.
        let bytes =
            with_spend_auth_sig(&serialize_pczt(&bundle).unwrap(), other, [7u8; 64]).unwrap();
        let mut bundle = deserialize_pczt(&bytes).unwrap();

        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let alpha = pasta_curves::pallas::Scalar::random(&mut OsRng);
        let rk = <[u8; 32]>::from(orchard::primitives::redpallas::VerificationKey::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(
            &SpendAuthorizingKey::from(&sk).randomize(&alpha)
        ));
        assert!(matches!(
            set_spend_auth_randomizer(
                &mut bundle,
                real,
                &alpha.to_repr(),
                &rk,
                Some(&test_ak(&spec.fvk))
            ),
            Err(IronwoodBuildError::SpendSignatureAlreadyPresent)
        ));
    }

    #[test]
    fn apply_spend_signature_rejects_a_pre_installation_digest_then_accepts_the_current_one() {
        let (spec, anchor) = test_spend_spec();
        let (mut bundle, _) = construct_spend_pczt_multi(&[spec], &[], &anchor, OsRng).unwrap();
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let ask = SpendAuthorizingKey::from(&sk);

        // Digest over the PLACEHOLDER action data (what a stale signing session saw).
        let input_amounts = [200_000_000i64];
        let input_scripts = [ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac])];
        let digest_of = |bundle: &PcztBundle| {
            compute_v6_sig_digest(
                &v6_tx(
                    transparent_skeleton(),
                    Some(pczt_action_data(bundle).unwrap()),
                ),
                &input_amounts,
                &input_scripts,
            )
        };
        let pre_installation = digest_of(&bundle);
        let sig = ask
            .randomize(&pasta_curves::pallas::Scalar::random(&mut OsRng))
            .sign(OsRng, &pre_installation);

        // Install the real pair; the committed action data (and hence the digest) changes.
        let alpha = pasta_curves::pallas::Scalar::random(&mut OsRng);
        let rk = <[u8; 32]>::from(orchard::primitives::redpallas::VerificationKey::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(&ask.randomize(&alpha)));
        set_spend_auth_randomizer(
            &mut bundle,
            0,
            &alpha.to_repr(),
            &rk,
            Some(&test_ak(&spec.fvk)),
        )
        .unwrap();
        let current = digest_of(&bundle);
        assert_ne!(pre_installation, current);

        // A signature over the pre-installation digest fails verification against the
        // installed rk and the CURRENT sighash.
        let err =
            apply_spend_signature(&mut bundle, 0, current, &<[u8; 64]>::from(&sig)).unwrap_err();
        assert!(
            matches!(err, IronwoodBuildError::InvalidExternalSignature),
            "unexpected: {err:?}"
        );

        // The correctly-computed signature verifies and is stored.
        let current_sig = ask.randomize(&alpha).sign(OsRng, &current);
        apply_spend_signature(&mut bundle, 0, current, &<[u8; 64]>::from(&current_sig)).unwrap();
        assert!(bundle.actions()[0].spend().spend_auth_sig().is_some());

        // Ordering guard: the randomizer cannot be reinstalled under an existing signature.
        let alpha2 = pasta_curves::pallas::Scalar::random(&mut OsRng);
        let rk2 = <[u8; 32]>::from(orchard::primitives::redpallas::VerificationKey::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(&ask.randomize(&alpha2)));
        assert!(matches!(
            set_spend_auth_randomizer(
                &mut bundle,
                0,
                &alpha2.to_repr(),
                &rk2,
                Some(&test_ak(&spec.fvk))
            ),
            Err(IronwoodBuildError::SpendSignatureAlreadyPresent)
        ));
    }

    #[test]
    fn placeholder_rk_is_the_domain_separated_hash_to_curve_point() {
        use pasta_curves::arithmetic::CurveExt;
        use pasta_curves::group::{Group, GroupEncoding};

        let point = pasta_curves::pallas::Point::hash_to_curve("BitGo-Ironwood")(b"placeholder-rk");
        assert!(!bool::from(point.is_identity()));
        assert_eq!(point.to_bytes(), PLACEHOLDER_RK);
        VerificationKey::<SpendAuth>::try_from(PLACEHOLDER_RK).unwrap();
    }

    #[test]
    fn with_spend_alphas_needs_exactly_one_alpha_per_real_spend() {
        let (spec, anchor) = test_spend_spec();
        let output = IronwoodOutputSpec {
            recipient: test_recipient(),
            amount: 1_000,
            ovk: None,
            memo: [0u8; 512],
        };
        let (bundle, map) =
            construct_spend_pczt_multi(&[spec], &[output, output], &anchor, OsRng).unwrap();
        let real = map.spend_action_index(0).unwrap();
        let dummy = (0..2).find(|&i| i != real).unwrap();
        let alpha = pasta_curves::pallas::Scalar::random(&mut OsRng).to_repr();

        let patched = with_spend_alphas(&bundle, &[(real, alpha)]).unwrap();
        assert_eq!(
            patched.actions()[real]
                .spend()
                .alpha()
                .as_ref()
                .map(|a| a.to_repr()),
            Some(alpha)
        );
        // The input bundle is untouched.
        assert!(bundle.actions()[real].spend().alpha().is_none());

        assert!(matches!(
            with_spend_alphas(&bundle, &[]),
            Err(IronwoodBuildError::RandomizerMissing { action_index }) if action_index == real
        ));
        assert!(matches!(
            with_spend_alphas(&bundle, &[(real, alpha), (real, alpha)]),
            Err(IronwoodBuildError::DuplicateRandomizer { .. })
        ));
        assert!(matches!(
            with_spend_alphas(&bundle, &[(real, alpha), (dummy, alpha)]),
            Err(IronwoodBuildError::RandomizerOnDummySpend)
        ));
        assert!(matches!(
            with_spend_alphas(&bundle, &[(7, alpha)]),
            Err(IronwoodBuildError::ActionIndexOutOfRange)
        ));
        assert!(matches!(
            with_spend_alphas(&bundle, &[(real, [0u8; 32])]),
            Err(IronwoodBuildError::UnrandomizedRk)
        ));
    }

    #[test]
    fn apply_spend_signature_rejects_uninstalled_randomizers() {
        let (spec, anchor) = test_spend_spec();
        let (mut bundle, _) = construct_spend_pczt_multi(&[spec], &[], &anchor, OsRng).unwrap();
        let err = apply_spend_signature(&mut bundle, 0, [7u8; 32], &[7u8; 64]).unwrap_err();
        assert!(
            matches!(err, IronwoodBuildError::RandomizersNotInstalled),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn set_spend_fvk_installs_the_holder_copy_and_rejects_dummies() {
        let (spec, anchor) = test_spend_spec();
        let (mut bundle, _) = construct_spend_pczt_multi(&[spec], &[], &anchor, OsRng).unwrap();
        // The Constructor scrubbed the FVK.
        assert!(bundle.actions()[0].spend().fvk().is_none());
        set_spend_fvk(&mut bundle, 0, &spec.fvk).unwrap();
        assert_eq!(
            bundle.actions()[0]
                .spend()
                .fvk()
                .as_ref()
                .map(|f| f.to_bytes()),
            Some(spec.fvk)
        );
        // With the FVK present, the construction-time verifier's spend checks also re-run.
        verify_spend_pczt(&bundle).unwrap();

        // A dummy spend keeps its fabricating FVK: the caller is refused loudly.
        let mut shield =
            construct_shield_pczt(&test_recipient(), 1_000, None, &anchor, &[0u8; 512], OsRng)
                .unwrap();
        assert!(shield.actions()[0].spend().dummy_sk().is_some());
        assert!(matches!(
            set_spend_fvk(&mut shield, 0, &spec.fvk),
            Err(IronwoodBuildError::SetFvkOnDummySpend)
        ));

        // Out-of-range action index.
        assert!(matches!(
            set_spend_fvk(&mut bundle, 9, &spec.fvk),
            Err(IronwoodBuildError::ActionIndexOutOfRange)
        ));
    }

    /// Invariant 5: two spends deriving the same nullifier are rejected at construction —
    /// orchard does not check this, and consensus rejects a transaction with a repeated
    /// nullifier.
    #[test]
    fn construct_rejects_duplicate_nullifiers() {
        // The nullifier derives from (nk, rho) alone, so the SAME note spent twice in one
        // bundle collides regardless of anything else.
        let (spec, anchor) = test_spend_spec();
        let err = construct_spend_pczt_multi(&[spec, spec], &[], &anchor, OsRng).unwrap_err();
        assert!(
            matches!(
                err,
                IronwoodBuildError::DuplicateNullifier { action_index: 1 }
            ),
            "unexpected: {err:?}"
        );
    }

    /// B5: the builder reorders actions, so the returned map — not the request index — must
    /// route per-spend/per-output data to the action that actually carries it.
    #[test]
    fn action_map_pins_the_reordered_action_positions() {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let (anchor, leaves) = super::test_util::real_two_leaf_tree(
            &fvk,
            [
                (100_000_000u64, field_bytes(200), [52u8; 32]),
                (80_000_000u64, field_bytes(201), [53u8; 32]),
            ],
        );
        let spec = |leaf: &super::test_util::RealLeaf| IronwoodSpendSpec {
            fvk: fvk.to_bytes(),
            recipient: leaf.recipient,
            value: leaf.value,
            rho: leaf.rho,
            rseed: leaf.rseed,
            cmx: leaf.cmx,
            witness: leaf.witness,
        };
        let specs = [spec(&leaves[0]), spec(&leaves[1])];
        let outputs = [
            IronwoodOutputSpec {
                recipient: fvk
                    .address_at(10u32, Scope::External)
                    .to_raw_address_bytes(),
                amount: 30_000_000,
                ovk: None,
                memo: [0u8; 512],
            },
            IronwoodOutputSpec {
                recipient: fvk
                    .address_at(11u32, Scope::External)
                    .to_raw_address_bytes(),
                amount: 20_000_000,
                ovk: None,
                memo: [0u8; 512],
            },
        ];
        let (bundle, map) = construct_spend_pczt_multi(&specs, &outputs, &anchor, OsRng).unwrap();
        assert_eq!(bundle.actions().len(), 2, "UNPADDED 2+2 => 2 actions");

        for (i, s) in specs.iter().enumerate() {
            let idx = map.spend_action_index(i).expect("map covers every spend");
            let recorded = bundle.actions()[idx]
                .spend()
                .proprietary()
                .get(CMX_PROPRIETARY_KEY)
                .expect("the Constructor recorded the spend's cmx")
                .clone();
            assert_eq!(
                recorded.as_slice(),
                s.cmx,
                "spend {i} maps to the action carrying its cmx"
            );
        }
        for (i, o) in outputs.iter().enumerate() {
            let idx = map.output_action_index(i).expect("map covers every output");
            let recipient = bundle.actions()[idx]
                .output()
                .recipient()
                .expect("real output carries its recipient")
                .to_raw_address_bytes();
            assert_eq!(recipient, o.recipient, "output {i} maps to its own action");
        }
    }
}

/// Test-only fixtures shared across modules (the `zcash_psbt` tests build multi-spend flows on
/// the same tree). Not compiled outside `cargo test`.
#[cfg(test)]
pub(crate) mod test_util {
    use super::*;

    /// One leaf of the fixture tree: everything needed to spend the note, plus the witness that
    /// proves it against the shared root.
    pub(crate) struct RealLeaf {
        pub recipient: OrchardAddressBytes,
        pub value: u64,
        pub rho: [u8; 32],
        pub rseed: [u8; 32],
        pub cmx: [u8; 32],
        pub witness: IronwoodWitness,
    }

    /// Build a real, internally consistent 2-leaf Orchard note-commitment tree over two notes
    /// owned by `fvk` — `(value, rho, rseed)` per leaf, recipients `fvk.address_at(i)`. Leaves
    /// are real commitments, the level-1 parent folds them with `MerkleHashOrchard::combine`,
    /// and every empty subtree is the real `empty_leaf` hash, so each leaf's witness recomputes
    /// to the shared root exactly as it would against a live tree.
    pub(crate) fn real_two_leaf_tree(
        fvk: &FullViewingKey,
        notes: [(u64, [u8; 32], [u8; 32]); 2],
    ) -> (AnchorBytes, [RealLeaf; 2]) {
        let note_version = BundleVersion::ironwood_v3().note_version();
        let mut cmxs = [[0u8; 32]; 2];
        let mut parts = Vec::with_capacity(2);
        for (i, (value, rho_bytes, rseed_bytes)) in notes.iter().enumerate() {
            let recipient = fvk
                .address_at(i as u32, Scope::External)
                .to_raw_address_bytes();
            let address =
                Option::<Address>::from(Address::from_raw_address_bytes(&recipient)).unwrap();
            let rho = Option::<Rho>::from(Rho::from_bytes(rho_bytes)).unwrap();
            let rseed =
                Option::<RandomSeed>::from(RandomSeed::from_bytes(*rseed_bytes, &rho)).unwrap();
            let note = Option::<Note>::from(Note::from_parts(
                address,
                NoteValue::from_raw(*value),
                rho,
                rseed,
                note_version,
            ))
            .unwrap();
            cmxs[i] = ExtractedNoteCommitment::from(note.commitment()).to_bytes();
            parts.push((recipient, *value, *rho_bytes, *rseed_bytes));
        }

        let leaf = |bytes: &[u8; 32]| {
            MerkleHashOrchard::from_cmx(
                &Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
                    bytes,
                ))
                .unwrap(),
            )
        };
        let (leaf0, leaf1) = (leaf(&cmxs[0]), leaf(&cmxs[1]));
        let empty = MerkleHashOrchard::empty_leaf();
        // Fold a leaf up to the root through `siblings[d]` (its sibling at depth `d`).
        // Orchard's `combine` takes the CHILDREN's level: leaves combine at level 0.
        let fold = |start: MerkleHashOrchard,
                    index: u64,
                    siblings: &[MerkleHashOrchard; IRONWOOD_MERKLE_DEPTH]| {
            let mut node = start;
            for (d, sibling) in siblings.iter().enumerate() {
                node = if index & (1 << d) == 0 {
                    MerkleHashOrchard::combine(Level::new(d as u8), &node, sibling)
                } else {
                    MerkleHashOrchard::combine(Level::new(d as u8), sibling, &node)
                };
            }
            node
        };
        let mut sibs0 = [empty; IRONWOOD_MERKLE_DEPTH];
        sibs0[0] = leaf1;
        let mut sibs1 = [empty; IRONWOOD_MERKLE_DEPTH];
        sibs1[0] = leaf0;
        let root0 = fold(leaf0, 0, &sibs0);
        let root1 = fold(leaf1, 1, &sibs1);
        assert_eq!(root0, root1, "both leaves fold to the same root");
        let to_path = |s: &[MerkleHashOrchard; IRONWOOD_MERKLE_DEPTH]| {
            std::array::from_fn(|i| s[i].to_bytes())
        };
        let mk_leaf = |i: usize, siblings: &[MerkleHashOrchard; IRONWOOD_MERKLE_DEPTH]| {
            let (recipient, value, rho, rseed) = parts[i];
            RealLeaf {
                recipient,
                value,
                rho,
                rseed,
                cmx: cmxs[i],
                witness: IronwoodWitness {
                    position: i as u32,
                    auth_path: to_path(siblings),
                },
            }
        };
        (root0.to_bytes(), [mk_leaf(0, &sibs0), mk_leaf(1, &sibs1)])
    }
}
