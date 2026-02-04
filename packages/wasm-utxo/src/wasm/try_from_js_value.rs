use std::ops::Deref;

use crate::address::utxolib_compat::{CashAddr, UtxolibNetwork};
use crate::error::WasmUtxoError;
use wasm_bindgen::JsValue;

// =============================================================================
// TryFromJsValue trait
// =============================================================================

/// Trait for converting JsValue to Rust types
pub(crate) trait TryFromJsValue: Sized {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmUtxoError>;
}

// =============================================================================
// Bytes<N>: Fixed-size byte array wrapper
// =============================================================================

/// Fixed-size byte array that implements TryFromJsValue
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bytes<const N: usize>(pub [u8; N]);

impl<const N: usize> Deref for Bytes<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8]> for Bytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<Bytes<N>> for [u8; N] {
    fn from(bytes: Bytes<N>) -> Self {
        bytes.0
    }
}

impl<const N: usize> TryFromJsValue for Bytes<N> {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmUtxoError> {
        let buffer = js_sys::Uint8Array::new(value);
        if buffer.length() as usize != N {
            return Err(WasmUtxoError::new(&format!(
                "Expected {} bytes, got {}",
                N,
                buffer.length()
            )));
        }
        let mut bytes = [0u8; N];
        buffer.copy_to(&mut bytes);
        Ok(Bytes(bytes))
    }
}

// =============================================================================
// TryFromJsValue implementations for primitive types
// =============================================================================

impl TryFromJsValue for String {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmUtxoError> {
        value
            .as_string()
            .ok_or_else(|| WasmUtxoError::new("Expected a string"))
    }
}

impl TryFromJsValue for u8 {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmUtxoError> {
        value
            .as_f64()
            .ok_or_else(|| WasmUtxoError::new("Expected a number"))
            .map(|n| n as u8)
    }
}

impl TryFromJsValue for u32 {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmUtxoError> {
        value
            .as_f64()
            .ok_or_else(|| WasmUtxoError::new("Expected a number"))
            .map(|n| n as u32)
    }
}

impl TryFromJsValue for Vec<u8> {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmUtxoError> {
        let buffer = js_sys::Uint8Array::new(value);
        let mut bytes = vec![0u8; buffer.length() as usize];
        buffer.copy_to(&mut bytes);
        Ok(bytes)
    }
}

impl<T: TryFromJsValue> TryFromJsValue for Option<T> {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmUtxoError> {
        if value.is_undefined() || value.is_null() {
            Ok(None)
        } else {
            T::try_from_js_value(value).map(Some)
        }
    }
}

// =============================================================================
// Field access functions
// =============================================================================

/// Get a raw JsValue field from an object without conversion
fn get_raw_field(obj: &JsValue, key: &str) -> Result<JsValue, WasmUtxoError> {
    js_sys::Reflect::get(obj, &JsValue::from_str(key))
        .map_err(|_| WasmUtxoError::new(&format!("Failed to read {} from object", key)))
}

/// Navigate to a nested object using dot notation (e.g., "network.bip32")
fn get_nested_raw(obj: &JsValue, path: &str) -> Result<JsValue, WasmUtxoError> {
    path.split('.').try_fold(obj.clone(), |current, part| {
        js_sys::Reflect::get(&current, &JsValue::from_str(part))
            .map_err(|_| WasmUtxoError::new(&format!("Failed to read {} from object", part)))
    })
}

/// Get a field and convert it using TryFromJsValue
pub(crate) fn get_field<T: TryFromJsValue>(obj: &JsValue, key: &str) -> Result<T, WasmUtxoError> {
    let field_value = get_raw_field(obj, key)?;
    T::try_from_js_value(&field_value)
        .map_err(|e| WasmUtxoError::new(&format!("{} (field: {})", e, key)))
}

/// Get a nested field using dot notation (e.g., "network.bip32.public")
pub(crate) fn get_nested_field<T: TryFromJsValue>(
    obj: &JsValue,
    path: &str,
) -> Result<T, WasmUtxoError> {
    let field_value = get_nested_raw(obj, path)?;
    T::try_from_js_value(&field_value)
        .map_err(|e| WasmUtxoError::new(&format!("{} (path: {})", e, path)))
}

// =============================================================================
// TryFromJsValue implementations for domain types
// =============================================================================

impl TryFromJsValue for UtxolibNetwork {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmUtxoError> {
        Ok(UtxolibNetwork {
            pub_key_hash: get_field(value, "pubKeyHash")?,
            script_hash: get_field(value, "scriptHash")?,
            bech32: get_field(value, "bech32")?,
            cash_addr: get_field(value, "cashAddr")?,
        })
    }
}

impl TryFromJsValue for CashAddr {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmUtxoError> {
        Ok(CashAddr {
            prefix: get_field(value, "prefix")?,
            pub_key_hash: get_field(value, "pubKeyHash")?,
            script_hash: get_field(value, "scriptHash")?,
        })
    }
}

impl TryFromJsValue for crate::inscriptions::TapLeafScript {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmUtxoError> {
        Ok(crate::inscriptions::TapLeafScript {
            leaf_version: get_field(value, "leafVersion")?,
            script: get_field(value, "script")?,
            control_block: get_field(value, "controlBlock")?,
        })
    }
}

impl TryFromJsValue for crate::networks::Network {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmUtxoError> {
        let network_str = value
            .as_string()
            .ok_or_else(|| WasmUtxoError::new("Expected a string for network parameter"))?;

        crate::networks::Network::from_utxolib_name(&network_str)
            .or_else(|| crate::networks::Network::from_coin_name(&network_str))
            .ok_or_else(|| {
                WasmUtxoError::new(&format!(
                    "Unknown network '{}'. Expected a utxolib name (e.g., 'bitcoin', 'testnet') \
                     or coin name (e.g., 'btc', 'tbtc')",
                    network_str
                ))
            })
    }
}
