//! Typed errors for the Ironwood PSBT workflow.
//!
//! Every new Ironwood method on [`super::ZcashBitGoPsbt`] returns
//! [`IronwoodPsbtError`], whose variant name is the JS `err.code`
//! (`"IronwoodPsbtError.MixedInputKinds"`, …) via [`crate::error::WasmUtxoError`]. Wrapped
//! lower-layer errors surface their own codes instead: `Build`/`Verify`/`Pczt` re-raise the
//! constructor, key-free-verifier and wire errors with their established
//! `IronwoodBuildError.*` / `IronwoodVerifyError.*` / `IronwoodPcztError.*` codes, so callers
//! key diagnostics on the layer that failed.

/// An Ironwood PSBT workflow error.
#[derive(Debug, strum::IntoStaticStr)]
pub enum IronwoodPsbtError {
    /// One input kind: a v6 PSBT spends either transparent inputs or shielded notes,
    /// never both. [`super::ZcashBitGoPsbt::add_shielded_spends`] rejects a PSBT that
    /// already carries transparent inputs.
    MixedInputKinds,
    /// Only one Ironwood Constructor call is supported per PSBT — calling it again would
    /// silently overwrite the first batch, whose value the transparent side is funding.
    AlreadyAdded,
    /// A caller-supplied Unified Address is not a valid Unified Address, has no Orchard
    /// receiver, or its Orchard receiver is not the output's `recipient`; or a verified
    /// spend's Orchard receiver could not be encoded as a Unified Address.
    BadUnifiedAddress(String),
    /// The PSBT carries no Ironwood PCZT, or its bundle is not a spend bundle (no real
    /// spends), and the operation needs one.
    NotSpendBundle,
    /// An action index the operation named does not exist in the bundle.
    UnknownAction,
    /// The action index names a fabricated (dummy) half, not a real spend or output.
    DummyAction,
    /// Ciphertexts first: these real outputs' `out_ciphertext`s are still pending — the
    /// ciphertexts must be installed before randomizers, sighashes, or proof requests.
    OutCiphertextPending {
        /// The pending real outputs' action indices.
        action_indices: Vec<usize>,
    },
    /// The action already has an `out_ciphertext`, and the entry carries different bytes;
    /// re-delivering identical bytes is accepted.
    OutCiphertextConflict {
        /// The offending action index.
        action_index: usize,
    },
    /// Randomizers installed: these real spends still carry the placeholder `rk` — the signer's
    /// randomized `rk`s must be installed before any sighash or the proof request.
    RandomizerPending {
        /// The pending real spends' action indices.
        action_indices: Vec<usize>,
    },
    /// Signed before proven: these real spends have no `spend_auth_sig` yet — the proof is
    /// requested only after the wallet has signed.
    SpendSignaturePending {
        /// The unsigned real spends' action indices.
        action_indices: Vec<usize>,
    },
    /// The bundle is frozen: a spend-auth signature (or a transparent
    /// partial signature, as defense in depth) exists, so ciphertexts and randomizers can no
    /// longer be installed.
    AlreadySigned,
    /// The batch names the same action index more than once.
    DuplicateAction {
        /// The repeated action index.
        action_index: usize,
    },
    /// The proof request was given no `alpha` for these real spends: the PSBT never stores
    /// the randomizers, so the prover needs one per real spend out of band.
    RandomizerMissing {
        /// The real spends' action indices without an `alpha`.
        action_indices: Vec<usize>,
    },
    /// The proof is not the canonical size for the bundle's action count.
    ProofLength {
        /// `orchard::Proof::expected_proof_size` for the bundle's actions.
        expected: usize,
        /// The supplied proof's length.
        actual: usize,
    },
    /// The operation has nothing to act on: there is no pending item, or the batch is empty.
    NothingPending,
    /// A caller-supplied byte field has the wrong length.
    BadLength {
        /// The field's name as the caller spelled it (`outCiphertext`, `anchor`, …).
        field: &'static str,
        /// The field's fixed size.
        expected: usize,
        /// The supplied length.
        actual: usize,
    },
    /// The Ironwood Constructor rejected the request; the wrapped
    /// [`IronwoodBuildError`](crate::zcash::ironwood_build::IronwoodBuildError) carries the
    /// reason (and its own `IronwoodBuildError.*` code).
    Build(crate::zcash::ironwood_build::IronwoodBuildError),
    /// The Ironwood PCZT wire round-trip failed inside a PSBT operation; the wrapped
    /// [`IronwoodPcztError`](crate::zcash::ironwood_pczt::IronwoodPcztError) carries the
    /// reason.
    Pczt(crate::zcash::ironwood_pczt::IronwoodPcztError),
    /// The key-free verifier rejected the bundle; the wrapped
    /// [`IronwoodVerifyError`](crate::zcash::ironwood_build::IronwoodVerifyError) carries
    /// the failing check (and its own `IronwoodVerifyError.<check>` code).
    Verify(crate::zcash::ironwood_build::IronwoodVerifyError),
    /// Encoding the final v6 transaction failed; the wrapped
    /// [`ZcashV6Error`](crate::zcash::v6::ZcashV6Error) carries the reason.
    Encode(crate::zcash::v6::ZcashV6Error),
}

impl std::fmt::Display for IronwoodPsbtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IronwoodPsbtError::MixedInputKinds => write!(
                f,
                "a v6 PSBT spends either transparent inputs or shielded notes, never both; \
                 build the shielded spends in a PSBT without transparent inputs"
            ),
            IronwoodPsbtError::AlreadyAdded => write!(
                f,
                "an Ironwood PCZT is already present; only one call is supported"
            ),
            IronwoodPsbtError::BadUnifiedAddress(e) => write!(f, "invalid unified address: {e}"),
            IronwoodPsbtError::NotSpendBundle => {
                write!(f, "this PSBT carries no Ironwood spend bundle")
            }
            IronwoodPsbtError::UnknownAction => {
                write!(f, "the named action index does not exist in the bundle")
            }
            IronwoodPsbtError::DummyAction => write!(
                f,
                "the named action is a fabricated dummy, not a real spend or output"
            ),
            IronwoodPsbtError::OutCiphertextPending { action_indices } => write!(
                f,
                "real outputs {action_indices:?} are still pending their out_ciphertext; \
                 install the out_ciphertexts first"
            ),
            IronwoodPsbtError::OutCiphertextConflict { action_index } => write!(
                f,
                "action {action_index}'s out_ciphertext is already set to different bytes"
            ),
            IronwoodPsbtError::RandomizerPending { action_indices } => write!(
                f,
                "real spends {action_indices:?} still carry the placeholder rk; install the \
                 signer's randomizers first"
            ),
            IronwoodPsbtError::SpendSignaturePending { action_indices } => write!(
                f,
                "real spends {action_indices:?} are not signed yet; the proof is requested \
                 only after the spend-auth signatures are installed"
            ),
            IronwoodPsbtError::AlreadySigned => write!(
                f,
                "the bundle is frozen: a signature exists, so out_ciphertexts and randomizers \
                 can no longer be installed"
            ),
            IronwoodPsbtError::DuplicateAction { action_index } => {
                write!(
                    f,
                    "action {action_index} appears more than once in the batch"
                )
            }
            IronwoodPsbtError::RandomizerMissing { action_indices } => write!(
                f,
                "no alpha was supplied for real spends {action_indices:?}; the proof request \
                 needs one per real spend"
            ),
            IronwoodPsbtError::ProofLength { expected, actual } => write!(
                f,
                "the proof is {actual} bytes; a bundle of this many actions needs {expected}"
            ),
            IronwoodPsbtError::NothingPending => {
                write!(f, "there is nothing pending for this operation")
            }
            IronwoodPsbtError::BadLength {
                field,
                expected,
                actual,
            } => write!(f, "{field} must be {expected} bytes, got {actual}"),
            IronwoodPsbtError::Build(e) => write!(f, "{e}"),
            IronwoodPsbtError::Pczt(e) => write!(f, "{e}"),
            IronwoodPsbtError::Verify(e) => write!(f, "{e}"),
            IronwoodPsbtError::Encode(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IronwoodPsbtError {}

impl From<crate::zcash::ironwood_build::IronwoodBuildError> for IronwoodPsbtError {
    fn from(error: crate::zcash::ironwood_build::IronwoodBuildError) -> Self {
        IronwoodPsbtError::Build(error)
    }
}

impl From<crate::zcash::v6::ZcashV6Error> for IronwoodPsbtError {
    fn from(error: crate::zcash::v6::ZcashV6Error) -> Self {
        IronwoodPsbtError::Encode(error)
    }
}

impl From<crate::zcash::ironwood_pczt::IronwoodPcztError> for IronwoodPsbtError {
    fn from(error: crate::zcash::ironwood_pczt::IronwoodPcztError) -> Self {
        IronwoodPsbtError::Pczt(error)
    }
}

/// Wrapped lower-layer errors surface their own code (`IronwoodBuildError.OvkNotAllowed`, …),
/// not the wrapping variant's name; the PSBT-level variants use `IronwoodPsbtError.*`.
impl crate::error::WasmErrorCode for IronwoodPsbtError {
    fn code(&self) -> String {
        match self {
            IronwoodPsbtError::Build(error) => crate::error::WasmErrorCode::code(error),
            IronwoodPsbtError::Pczt(error) => crate::error::WasmErrorCode::code(error),
            IronwoodPsbtError::Verify(error) => crate::error::WasmErrorCode::code(error),
            other => format!("IronwoodPsbtError.{}", <&'static str>::from(other)),
        }
    }
}
