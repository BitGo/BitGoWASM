use core::fmt;

#[derive(Debug, Clone)]
pub enum WasmUtxoError {
    StringError(String),
}

impl std::error::Error for WasmUtxoError {}
impl fmt::Display for WasmUtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmUtxoError::StringError(s) => write!(f, "{}", s),
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

impl WasmUtxoError {
    pub fn new(s: &str) -> WasmUtxoError {
        WasmUtxoError::StringError(s.to_string())
    }
}

impl From<crate::address::AddressError> for WasmUtxoError {
    fn from(err: crate::address::AddressError) -> Self {
        WasmUtxoError::StringError(err.to_string())
    }
}
