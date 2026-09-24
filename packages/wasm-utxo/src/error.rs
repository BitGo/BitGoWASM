use core::fmt;

use crate::fixed_script_wallet::bitgo_psbt::zcash_psbt::VerifyV6SignatureError;
use crate::fixed_script_wallet::bitgo_psbt::ParseTransactionError;

pub trait WasmErrorCode {
    fn code(&self) -> String;
}

/// Derives `WasmErrorCode` for leaf error enums (no nested error variants).
/// Requires `#[derive(strum::IntoStaticStr)]` on the enum.
#[macro_export]
macro_rules! impl_wasm_error_code {
    ($t:ty) => {
        impl $crate::error::WasmErrorCode for $t {
            fn code(&self) -> String {
                format!("{}.{}", stringify!($t), <&'static str>::from(self))
            }
        }
    };
}

#[derive(Debug, strum::IntoStaticStr)]
pub enum LegacyPrevoutValidationError {
    InputCountMismatch {
        psbt_inputs: usize,
        transaction_inputs: usize,
    },
    PreviousTransactionTxidMismatch {
        input_index: usize,
    },
    PreviousOutputIndexOutOfBounds {
        input_index: usize,
        vout: u32,
    },
    WitnessUtxoMismatch {
        input_index: usize,
    },
    MissingNonWitnessUtxo {
        input_index: usize,
    },
}

impl fmt::Display for LegacyPrevoutValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputCountMismatch {
                psbt_inputs,
                transaction_inputs,
            } => write!(
                f,
                "PSBT input count {psbt_inputs} does not match unsigned transaction input count {transaction_inputs}"
            ),
            Self::PreviousTransactionTxidMismatch { input_index } => write!(
                f,
                "Input {input_index} non_witness_utxo txid does not match the referenced txid"
            ),
            Self::PreviousOutputIndexOutOfBounds { input_index, vout } => write!(
                f,
                "Input {input_index} non_witness_utxo has no output at index {vout}"
            ),
            Self::WitnessUtxoMismatch { input_index } => write!(
                f,
                "Input {input_index} witness_utxo does not match its non_witness_utxo output"
            ),
            Self::MissingNonWitnessUtxo { input_index } => write!(
                f,
                "Input {input_index} spends a legacy output and requires non_witness_utxo"
            ),
        }
    }
}

impl std::error::Error for LegacyPrevoutValidationError {}
crate::impl_wasm_error_code!(LegacyPrevoutValidationError);

#[derive(Debug, strum::IntoStaticStr)]
pub enum WasmUtxoError {
    StringError(String),
    LegacyPrevoutValidation(LegacyPrevoutValidationError),
    Parse(ParseTransactionError),
    UnifiedAddress(crate::zcash::unified_address::UnifiedAddressError),
    ZcashV6(crate::zcash::v6::ZcashV6Error),
    Ironwood(crate::zcash::ironwood_build::IronwoodBuildError),
    VerifyV6Signature(VerifyV6SignatureError),
}

impl std::error::Error for WasmUtxoError {}

impl fmt::Display for WasmUtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmUtxoError::StringError(s) => write!(f, "{}", s),
            WasmUtxoError::LegacyPrevoutValidation(e) => write!(f, "{}", e),
            WasmUtxoError::Parse(e) => write!(f, "{}", e),
            WasmUtxoError::UnifiedAddress(e) => write!(f, "{}", e),
            WasmUtxoError::ZcashV6(e) => write!(f, "{}", e),
            WasmUtxoError::Ironwood(e) => write!(f, "{}", e),
            WasmUtxoError::VerifyV6Signature(e) => write!(f, "{}", e),
        }
    }
}

impl WasmErrorCode for WasmUtxoError {
    fn code(&self) -> String {
        match self {
            WasmUtxoError::StringError(_) => "WasmUtxoError.StringError".to_string(),
            WasmUtxoError::LegacyPrevoutValidation(e) => e.code(),
            WasmUtxoError::Parse(e) => e.code(),
            WasmUtxoError::UnifiedAddress(e) => e.code(),
            WasmUtxoError::ZcashV6(e) => e.code(),
            WasmUtxoError::Ironwood(e) => e.code(),
            WasmUtxoError::VerifyV6Signature(e) => e.code(),
        }
    }
}

impl From<&str> for WasmUtxoError {
    fn from(s: &str) -> Self {
        WasmUtxoError::StringError(s.to_string())
    }
}

impl From<String> for WasmUtxoError {
    fn from(s: String) -> Self {
        WasmUtxoError::StringError(s)
    }
}

impl From<miniscript::Error> for WasmUtxoError {
    fn from(err: miniscript::Error) -> Self {
        WasmUtxoError::StringError(err.to_string())
    }
}

impl From<miniscript::descriptor::NonDefiniteKeyError> for WasmUtxoError {
    fn from(err: miniscript::descriptor::NonDefiniteKeyError) -> Self {
        WasmUtxoError::StringError(err.to_string())
    }
}

impl From<crate::address::AddressError> for WasmUtxoError {
    fn from(err: crate::address::AddressError) -> Self {
        WasmUtxoError::StringError(err.to_string())
    }
}

impl From<LegacyPrevoutValidationError> for WasmUtxoError {
    fn from(err: LegacyPrevoutValidationError) -> Self {
        WasmUtxoError::LegacyPrevoutValidation(err)
    }
}

impl From<ParseTransactionError> for WasmUtxoError {
    fn from(err: ParseTransactionError) -> Self {
        WasmUtxoError::Parse(err)
    }
}

impl From<crate::zcash::unified_address::UnifiedAddressError> for WasmUtxoError {
    fn from(err: crate::zcash::unified_address::UnifiedAddressError) -> Self {
        WasmUtxoError::UnifiedAddress(err)
    }
}

impl From<crate::zcash::v6::ZcashV6Error> for WasmUtxoError {
    fn from(err: crate::zcash::v6::ZcashV6Error) -> Self {
        WasmUtxoError::ZcashV6(err)
    }
}

impl From<crate::zcash::ironwood_build::IronwoodBuildError> for WasmUtxoError {
    fn from(err: crate::zcash::ironwood_build::IronwoodBuildError) -> Self {
        WasmUtxoError::Ironwood(err)
    }
}
impl From<VerifyV6SignatureError> for WasmUtxoError {
    fn from(err: VerifyV6SignatureError) -> Self {
        WasmUtxoError::VerifyV6Signature(err)
    }
}

impl WasmUtxoError {
    pub fn new(s: &str) -> WasmUtxoError {
        WasmUtxoError::StringError(s.to_string())
    }

    pub fn from_errors<E: fmt::Display>(errors: impl IntoIterator<Item = E>) -> WasmUtxoError {
        let messages: Vec<String> = errors.into_iter().map(|e| e.to_string()).collect();
        WasmUtxoError::StringError(format!(
            "{} errors: {}",
            messages.len(),
            messages.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_script_wallet::bitgo_psbt::{
        psbt_wallet_input::{OutputScriptError, ParseInputError},
        psbt_wallet_output::ParseOutputError,
        ParseTransactionError,
    };

    #[test]
    fn string_error_code() {
        let e = WasmUtxoError::new("oops");
        assert_eq!(e.code(), "WasmUtxoError.StringError");
    }

    #[test]
    fn legacy_prevout_validation_error_code() {
        let error = WasmUtxoError::from(LegacyPrevoutValidationError::MissingNonWitnessUtxo {
            input_index: 2,
        });
        assert_eq!(
            error.code(),
            "LegacyPrevoutValidationError.MissingNonWitnessUtxo"
        );
    }

    #[test]
    fn parse_input_wallet_validation_code() {
        let inner = ParseInputError::WalletValidation("no script type matches".to_string());
        let e = WasmUtxoError::Parse(ParseTransactionError::Input {
            index: 0,
            error: inner,
        });
        assert_eq!(
            e.code(),
            "ParseTransactionError.Input/ParseInputError.WalletValidation"
        );
    }

    #[test]
    fn parse_input_utxo_code() {
        let inner = ParseInputError::Utxo(OutputScriptError::NoUtxoFields);
        let e = WasmUtxoError::Parse(ParseTransactionError::Input {
            index: 0,
            error: inner,
        });
        assert_eq!(
            e.code(),
            "ParseTransactionError.Input/ParseInputError.Utxo/OutputScriptError.NoUtxoFields"
        );
    }

    #[test]
    fn parse_output_code() {
        let inner = ParseOutputError::WalletMatch("bad".to_string());
        let e = WasmUtxoError::Parse(ParseTransactionError::Output {
            index: 0,
            error: inner,
        });
        assert_eq!(
            e.code(),
            "ParseTransactionError.Output/ParseOutputError.WalletMatch"
        );
    }

    #[test]
    fn leaf_variants_code() {
        assert_eq!(
            ParseInputError::ValueOverflow.code(),
            "ParseInputError.ValueOverflow"
        );
        assert_eq!(
            ParseInputError::Derivation("x".into()).code(),
            "ParseInputError.Derivation"
        );
        assert_eq!(
            ParseInputError::ScriptTypeDetection("x".into()).code(),
            "ParseInputError.ScriptTypeDetection"
        );
        assert_eq!(
            OutputScriptError::OutputIndexOutOfBounds { vout: 0 }.code(),
            "OutputScriptError.OutputIndexOutOfBounds"
        );
    }
}
