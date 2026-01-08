use wasm_bindgen::prelude::*;

/// Error type for wasm-bip32 operations
#[derive(Debug, Clone)]
pub struct WasmBip32Error {
    message: String,
}

impl WasmBip32Error {
    pub fn new(message: &str) -> Self {
        WasmBip32Error {
            message: message.to_string(),
        }
    }
}

impl std::fmt::Display for WasmBip32Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for WasmBip32Error {}

impl From<WasmBip32Error> for JsValue {
    fn from(err: WasmBip32Error) -> JsValue {
        JsValue::from_str(&err.message)
    }
}

impl From<bip32::Error> for WasmBip32Error {
    fn from(err: bip32::Error) -> Self {
        WasmBip32Error::new(&format!("BIP32 error: {}", err))
    }
}

impl From<k256::ecdsa::Error> for WasmBip32Error {
    fn from(err: k256::ecdsa::Error) -> Self {
        WasmBip32Error::new(&format!("ECDSA error: {}", err))
    }
}

impl From<bs58::decode::Error> for WasmBip32Error {
    fn from(err: bs58::decode::Error) -> Self {
        WasmBip32Error::new(&format!("Base58 decode error: {}", err))
    }
}

impl From<bs58::encode::Error> for WasmBip32Error {
    fn from(err: bs58::encode::Error) -> Self {
        WasmBip32Error::new(&format!("Base58 encode error: {}", err))
    }
}
