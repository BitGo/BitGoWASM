//! Rust to JavaScript value conversion
//!
//! This module provides the TryIntoJsValue trait for converting Rust types
//! to JavaScript values with proper BigInt handling for u64/u128.

use wasm_bindgen::prelude::*;

/// Error type for JS conversion failures
#[derive(Debug, Clone)]
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
        js_sys::Error::new(&err.0).into()
    }
}

/// Trait for converting Rust types to JavaScript values
pub trait TryIntoJsValue {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError>;
}

impl TryIntoJsValue for String {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_str(self))
    }
}

impl TryIntoJsValue for &str {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_str(self))
    }
}

impl TryIntoJsValue for bool {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_bool(*self))
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
        // Convert to BigInt to avoid precision loss
        Ok(js_sys::BigInt::from(*self).into())
    }
}

impl TryIntoJsValue for u128 {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        // Convert to BigInt via string (BigInt::from only supports u64)
        let s = self.to_string();
        js_sys::BigInt::new(&JsValue::from_str(&s))
            .map(|b| b.into())
            .map_err(|_| JsConversionError::new("Failed to create BigInt"))
    }
}

impl TryIntoJsValue for i32 {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_f64(*self as f64))
    }
}

impl<T: TryIntoJsValue> TryIntoJsValue for Option<T> {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        match self {
            Some(v) => v.try_to_js_value(),
            None => Ok(JsValue::undefined()),
        }
    }
}

impl<T: TryIntoJsValue> TryIntoJsValue for Vec<T> {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        let arr = js_sys::Array::new();
        for item in self {
            arr.push(&item.try_to_js_value()?);
        }
        Ok(arr.into())
    }
}

impl TryIntoJsValue for serde_json::Value {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        serde_wasm_bindgen::to_value(self)
            .map_err(|e| JsConversionError::new(&format!("JSON conversion error: {}", e)))
    }
}

/// Macro for building JavaScript objects
#[macro_export]
macro_rules! js_obj {
    ( $( $key:expr => $value:expr ),* $(,)? ) => {{
        use $crate::wasm::try_into_js_value::{TryIntoJsValue, JsConversionError};
        let obj = js_sys::Object::new();
        $(
            js_sys::Reflect::set(
                &obj,
                &wasm_bindgen::JsValue::from_str($key),
                &TryIntoJsValue::try_to_js_value(&$value)?
            ).map_err(|_| JsConversionError::new(&format!("Failed to set property: {}", $key)))?;
        )*
        Ok::<wasm_bindgen::JsValue, JsConversionError>(obj.into())
    }};
}

// WASM tests - only run in wasm32 target
#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_string_conversion() {
        let s = "hello".to_string();
        let result = s.try_to_js_value();
        assert!(result.is_ok());
    }

    #[wasm_bindgen_test]
    fn test_option_conversion() {
        let some: Option<String> = Some("value".to_string());
        let none: Option<String> = None;

        assert!(some.try_to_js_value().is_ok());
        assert!(none.try_to_js_value().is_ok());
    }
}
