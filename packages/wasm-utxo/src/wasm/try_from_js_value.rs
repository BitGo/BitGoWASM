use std::ops::Deref;

use crate::address::utxolib_compat::{CashAddr, UtxolibNetwork};
use crate::error::WasmUtxoError;
use miniscript::bitcoin::psbt::raw;
use wasm_bindgen::{JsCast, JsValue};

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

impl TryFromJsValue for bool {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmUtxoError> {
        value
            .as_bool()
            .ok_or_else(|| WasmUtxoError::new("Expected a boolean"))
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

// =============================================================================
// PsbtKvKey: composable PSBT key for set_kv / get_kv WASM methods
// =============================================================================

/// A PSBT key that can represent either an unknown or proprietary record.
/// The `bitgo` variant is a convenience alias for proprietary with prefix `b"BITGO"`.
pub(crate) enum PsbtKvKey {
    Unknown(raw::Key),
    Proprietary(raw::ProprietaryKey),
}

impl TryFromJsValue for PsbtKvKey {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmUtxoError> {
        let typ: String = get_field(value, "type")?;
        match typ.as_str() {
            "unknown" => Ok(PsbtKvKey::Unknown(raw::Key {
                type_value: get_field(value, "keyType")?,
                key: get_field::<Option<Vec<u8>>>(value, "data")?.unwrap_or_default(),
            })),
            "proprietary" => Ok(PsbtKvKey::Proprietary(raw::ProprietaryKey {
                prefix: get_field(value, "prefix")?,
                subtype: get_field(value, "subtype")?,
                key: get_field::<Option<Vec<u8>>>(value, "key")?.unwrap_or_default(),
            })),
            "bitgo" => Ok(PsbtKvKey::Proprietary(raw::ProprietaryKey {
                prefix: b"BITGO".to_vec(),
                subtype: get_field(value, "subtype")?,
                key: get_field::<Option<Vec<u8>>>(value, "key")?.unwrap_or_default(),
            })),
            _ => Err(WasmUtxoError::new(&format!("Unknown PSBT key type: {typ}"))),
        }
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

// =============================================================================
// HydrationUnspentInput: Wallet or replay protection input
// =============================================================================

impl TryFromJsValue for crate::fixed_script_wallet::bitgo_psbt::HydrationUnspentInput {
    fn try_from_js_value(item: &JsValue) -> Result<Self, WasmUtxoError> {
        use crate::fixed_script_wallet::ScriptIdWithValue;

        // Read 'value' as BigInt (required)
        let value_js = js_sys::Reflect::get(item, &"value".into())
            .map_err(|_| WasmUtxoError::new("Missing 'value' field on unspent"))?;
        let value = u64::try_from(js_sys::BigInt::unchecked_from_js(value_js))
            .map_err(|_| WasmUtxoError::new("'value' must be a bigint convertible to u64"))?;

        // Check if 'chain' is present; if missing → ReplayProtection, else → Wallet
        let chain_val = js_sys::Reflect::get(item, &"chain".into()).unwrap_or(JsValue::UNDEFINED);

        if chain_val.is_undefined() {
            // Replay protection input: requires 'pubkey' field
            let pubkey_val = js_sys::Reflect::get(item, &"pubkey".into())
                .map_err(|_| WasmUtxoError::new("Missing 'pubkey' on replay protection unspent"))?;
            let pubkey_bytes = js_sys::Uint8Array::new(&pubkey_val).to_vec();
            let pubkey = miniscript::bitcoin::CompressedPublicKey::from_slice(&pubkey_bytes)
                .map_err(|_| {
                    WasmUtxoError::new("'pubkey' is not a valid compressed public key (33 bytes)")
                })?;
            Ok(
                crate::fixed_script_wallet::bitgo_psbt::HydrationUnspentInput::ReplayProtection {
                    pubkey,
                    value,
                },
            )
        } else {
            // Wallet input: requires 'chain' and 'index' fields
            let chain = chain_val
                .as_f64()
                .ok_or_else(|| WasmUtxoError::new("'chain' must be a number"))?
                as u32;
            let index = js_sys::Reflect::get(item, &"index".into())
                .map_err(|_| WasmUtxoError::new("Missing 'index' field on wallet unspent"))?
                .as_f64()
                .ok_or_else(|| WasmUtxoError::new("'index' must be a number"))?
                as u32;
            Ok(
                crate::fixed_script_wallet::bitgo_psbt::HydrationUnspentInput::Wallet(
                    ScriptIdWithValue {
                        chain,
                        index,
                        value,
                    },
                ),
            )
        }
    }
}
