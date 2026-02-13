//! Error types for wasm-dot

use core::fmt;
use wasm_bindgen::prelude::*;

/// Main error type for wasm-dot operations
#[derive(Debug, Clone)]
pub enum WasmDotError {
    /// Invalid SS58 address
    InvalidAddress(String),
    /// Invalid transaction format
    InvalidTransaction(String),
    /// Invalid signature
    InvalidSignature(String),
    /// SCALE codec decode error
    ScaleDecodeError(String),
    /// Missing required context
    MissingContext(String),
    /// Invalid input
    InvalidInput(String),
    /// Generic string error
    StringError(String),
}

impl std::error::Error for WasmDotError {}

impl fmt::Display for WasmDotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmDotError::InvalidAddress(s) => write!(f, "Invalid address: {}", s),
            WasmDotError::InvalidTransaction(s) => write!(f, "Invalid transaction: {}", s),
            WasmDotError::InvalidSignature(s) => write!(f, "Invalid signature: {}", s),
            WasmDotError::ScaleDecodeError(s) => write!(f, "SCALE decode error: {}", s),
            WasmDotError::MissingContext(s) => write!(f, "Missing context: {}", s),
            WasmDotError::InvalidInput(s) => write!(f, "Invalid input: {}", s),
            WasmDotError::StringError(s) => write!(f, "{}", s),
        }
    }
}

impl From<&str> for WasmDotError {
    fn from(s: &str) -> Self {
        WasmDotError::StringError(s.to_string())
    }
}

impl From<String> for WasmDotError {
    fn from(s: String) -> Self {
        WasmDotError::StringError(s)
    }
}

impl From<parity_scale_codec::Error> for WasmDotError {
    fn from(err: parity_scale_codec::Error) -> Self {
        WasmDotError::ScaleDecodeError(err.to_string())
    }
}

// REQUIRED: Converts to JS Error with stack trace
impl From<WasmDotError> for JsValue {
    fn from(err: WasmDotError) -> Self {
        js_sys::Error::new(&err.to_string()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = WasmDotError::InvalidAddress("bad address".to_string());
        assert_eq!(err.to_string(), "Invalid address: bad address");
    }

    #[test]
    fn test_from_str() {
        let err: WasmDotError = "test error".into();
        assert_eq!(err.to_string(), "test error");
    }
}
