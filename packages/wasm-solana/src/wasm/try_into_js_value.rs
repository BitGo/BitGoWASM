//! Trait for converting Rust types to JavaScript values.
//!
//! This module provides a trait similar to wasm-utxo's TryIntoJsValue,
//! allowing us to convert Rust types directly to JS values with proper
//! BigInt handling for u64 amounts.

use wasm_bindgen::JsValue;

/// Error type for JS value conversion failures.
#[derive(Debug)]
pub struct JsConversionError(String);

impl JsConversionError {
    pub fn new(msg: &str) -> Self {
        JsConversionError(msg.to_string())
    }
}

impl std::fmt::Display for JsConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<JsConversionError> for JsValue {
    fn from(err: JsConversionError) -> Self {
        js_sys::Error::new(&err.to_string()).into()
    }
}

/// Trait for converting Rust types to JavaScript values.
pub trait TryIntoJsValue {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError>;
}

// =============================================================================
// Primitive implementations
// =============================================================================

impl TryIntoJsValue for String {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_str(self))
    }
}

impl TryIntoJsValue for str {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_str(self))
    }
}

impl TryIntoJsValue for &str {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_str(self))
    }
}

impl TryIntoJsValue for u8 {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_f64(*self as f64))
    }
}

impl TryIntoJsValue for u32 {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_f64(*self as f64))
    }
}

impl TryIntoJsValue for u64 {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(js_sys::BigInt::from(*self).into())
    }
}

impl TryIntoJsValue for bool {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_bool(*self))
    }
}

impl<T: TryIntoJsValue> TryIntoJsValue for Option<T> {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        match self {
            Some(v) => v.try_to_js_value(),
            None => Ok(JsValue::UNDEFINED),
        }
    }
}

impl<T: TryIntoJsValue> TryIntoJsValue for Vec<T> {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        let arr = js_sys::Array::new();
        for item in self.iter() {
            arr.push(&item.try_to_js_value()?);
        }
        Ok(arr.into())
    }
}

// =============================================================================
// Macro for building JS objects
// =============================================================================

/// Macro to create a JavaScript object from key-value pairs.
/// Each value must implement TryIntoJsValue.
#[macro_export]
macro_rules! js_obj {
    ( $( $key:expr => $value:expr ),* $(,)? ) => {{
        let obj = js_sys::Object::new();
        $(
            js_sys::Reflect::set(
                &obj,
                &wasm_bindgen::JsValue::from_str($key),
                &$crate::wasm::try_into_js_value::TryIntoJsValue::try_to_js_value(&$value)?
            ).map_err(|_| $crate::wasm::try_into_js_value::JsConversionError::new(
                concat!("Failed to set object property: ", $key)
            ))?;
        )*
        Ok::<wasm_bindgen::JsValue, $crate::wasm::try_into_js_value::JsConversionError>(obj.into())
    }};
}

pub use js_obj;
