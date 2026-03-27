//! Error types for wasm-ton

use core::fmt;
use wasm_bindgen::prelude::*;

/// Main error type for wasm-ton operations
#[derive(Debug, Clone)]
pub enum WasmTonError {
    /// Invalid TON address
    InvalidAddress(String),
    /// Invalid transaction format
    InvalidTransaction(String),
    /// Invalid signature
    InvalidSignature(String),
    /// Invalid input
    InvalidInput(String),
    /// Generic string error
    StringError(String),
}

impl std::error::Error for WasmTonError {}

impl fmt::Display for WasmTonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmTonError::InvalidAddress(s) => write!(f, "Invalid address: {}", s),
            WasmTonError::InvalidTransaction(s) => write!(f, "Invalid transaction: {}", s),
            WasmTonError::InvalidSignature(s) => write!(f, "Invalid signature: {}", s),
            WasmTonError::InvalidInput(s) => write!(f, "Invalid input: {}", s),
            WasmTonError::StringError(s) => write!(f, "{}", s),
        }
    }
}

impl From<&str> for WasmTonError {
    fn from(s: &str) -> Self {
        WasmTonError::StringError(s.to_string())
    }
}

impl From<String> for WasmTonError {
    fn from(s: String) -> Self {
        WasmTonError::StringError(s)
    }
}

// REQUIRED: Converts to JS Error with stack trace
impl From<WasmTonError> for JsValue {
    fn from(err: WasmTonError) -> Self {
        js_sys::Error::new(&err.to_string()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = WasmTonError::InvalidAddress("bad address".to_string());
        assert_eq!(err.to_string(), "Invalid address: bad address");
    }

    #[test]
    fn test_from_str() {
        let err: WasmTonError = "test error".into();
        assert_eq!(err.to_string(), "test error");
    }
}
