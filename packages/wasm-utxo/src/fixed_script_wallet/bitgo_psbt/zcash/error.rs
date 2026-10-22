//! Typed errors for the Ironwood PSBT workflow (plan §6.4).
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
    /// Rule 0 (plan §3): a v6 PSBT spends either transparent inputs or shielded notes,
    /// never both. [`super::ZcashBitGoPsbt::add_shielded_spends`] rejects a PSBT that
    /// already carries transparent inputs.
    MixedInputKinds,
    /// Only one Ironwood Constructor call is supported per PSBT — calling it again would
    /// silently overwrite the first batch, whose value the transparent side is funding.
    AlreadyAdded,
    /// A caller-supplied Unified Address is not a valid Unified Address, has no Orchard
    /// receiver, or its Orchard receiver is not the output's `recipient`.
    BadUnifiedAddress(String),
    /// The Ironwood Constructor rejected the request; the wrapped
    /// [`IronwoodBuildError`](crate::zcash::ironwood_build::IronwoodBuildError) carries the
    /// reason (and its own `IronwoodBuildError.*` code).
    Build(crate::zcash::ironwood_build::IronwoodBuildError),
    /// The Ironwood PCZT wire round-trip failed inside a PSBT operation; the wrapped
    /// [`IronwoodPcztError`](crate::zcash::ironwood_pczt::IronwoodPcztError) carries the
    /// reason.
    Pczt(crate::zcash::ironwood_pczt::IronwoodPcztError),
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
            IronwoodPsbtError::Build(e) => write!(f, "{e}"),
            IronwoodPsbtError::Pczt(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IronwoodPsbtError {}

impl From<crate::zcash::ironwood_build::IronwoodBuildError> for IronwoodPsbtError {
    fn from(error: crate::zcash::ironwood_build::IronwoodBuildError) -> Self {
        IronwoodPsbtError::Build(error)
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
            other => format!("IronwoodPsbtError.{}", <&'static str>::from(other)),
        }
    }
}
