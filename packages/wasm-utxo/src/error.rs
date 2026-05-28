use core::fmt;

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
pub enum WasmUtxoError {
    StringError(String),
    Parse(ParseTransactionError),
}

impl std::error::Error for WasmUtxoError {}

impl fmt::Display for WasmUtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmUtxoError::StringError(s) => write!(f, "{}", s),
            WasmUtxoError::Parse(e) => write!(f, "{}", e),
        }
    }
}

impl WasmErrorCode for WasmUtxoError {
    fn code(&self) -> String {
        match self {
            WasmUtxoError::StringError(_) => "WasmUtxoError.StringError".to_string(),
            WasmUtxoError::Parse(e) => e.code(),
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

impl From<ParseTransactionError> for WasmUtxoError {
    fn from(err: ParseTransactionError) -> Self {
        WasmUtxoError::Parse(err)
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
