//! Error types for wasm-ton

use core::fmt;
use wasm_bindgen::prelude::*;

/// Main error type for wasm-ton operations
#[derive(Debug, Clone)]
pub enum WasmTonError {
    /// Invalid TON address
    AddressError(String),
    /// Cell/BOC encoding error
    CellError(String),
    /// Generic string error
    StringError(String),
}

impl std::error::Error for WasmTonError {}

impl fmt::Display for WasmTonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmTonError::AddressError(s) => write!(f, "Address error: {}", s),
            WasmTonError::CellError(s) => write!(f, "Cell error: {}", s),
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

impl From<tonlib_core::cell::TonCellError> for WasmTonError {
    fn from(err: tonlib_core::cell::TonCellError) -> Self {
        WasmTonError::CellError(err.to_string())
    }
}

impl From<tonlib_core::types::TonAddressParseError> for WasmTonError {
    fn from(err: tonlib_core::types::TonAddressParseError) -> Self {
        WasmTonError::AddressError(err.to_string())
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
        let err = WasmTonError::AddressError("bad address".to_string());
        assert_eq!(err.to_string(), "Address error: bad address");
    }

    #[test]
    fn test_from_str() {
        let err: WasmTonError = "test error".into();
        assert_eq!(err.to_string(), "test error");
    }
}
