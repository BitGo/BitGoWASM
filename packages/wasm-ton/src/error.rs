use core::fmt;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone)]
pub enum WasmTonError {
    StringError(String),
}

impl std::error::Error for WasmTonError {}

impl fmt::Display for WasmTonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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

impl WasmTonError {
    pub fn new(s: &str) -> WasmTonError {
        WasmTonError::StringError(s.to_string())
    }
}

// Required for wasm_bindgen to convert errors to JavaScript exceptions
// Uses js_sys::Error to create a proper JavaScript Error with stack trace
impl From<WasmTonError> for JsValue {
    fn from(err: WasmTonError) -> Self {
        js_sys::Error::new(&err.to_string()).into()
    }
}
