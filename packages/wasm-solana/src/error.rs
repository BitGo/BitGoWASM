use core::fmt;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone)]
pub enum WasmSolanaError {
    StringError(String),
}

impl std::error::Error for WasmSolanaError {}

impl fmt::Display for WasmSolanaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmSolanaError::StringError(s) => write!(f, "{}", s),
        }
    }
}

impl From<&str> for WasmSolanaError {
    fn from(s: &str) -> Self {
        WasmSolanaError::StringError(s.to_string())
    }
}

impl From<String> for WasmSolanaError {
    fn from(s: String) -> Self {
        WasmSolanaError::StringError(s)
    }
}

impl WasmSolanaError {
    pub fn new(s: &str) -> WasmSolanaError {
        WasmSolanaError::StringError(s.to_string())
    }
}

// Required for wasm_bindgen to convert errors to JavaScript exceptions
// Uses js_sys::Error to create a proper JavaScript Error with stack trace
impl From<WasmSolanaError> for JsValue {
    fn from(err: WasmSolanaError) -> Self {
        js_sys::Error::new(&err.to_string()).into()
    }
}
