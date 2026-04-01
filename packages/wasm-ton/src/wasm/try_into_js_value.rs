//! Trait for converting Rust types to JavaScript values.
//!
//! This module provides proper BigInt handling for u64 amounts.

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

/// Macro to create a JavaScript object from key-value pairs.
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

// ============================================================================
// TryIntoJsValue implementations for parser types
// ============================================================================

use crate::parser::{JettonTransferFields, ParsedSendAction, ParsedTransaction, TransactionType};

impl TryIntoJsValue for TransactionType {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_str(self.as_str()))
    }
}

impl TryIntoJsValue for JettonTransferFields {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "queryId" => self.query_id,
            "amount" => self.amount,
            "destination" => self.destination,
            "responseDestination" => self.response_destination,
            "forwardTonAmount" => self.forward_ton_amount
        )
    }
}

impl TryIntoJsValue for ParsedSendAction {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        let obj = js_sys::Object::new();

        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("mode"),
            &TryIntoJsValue::try_to_js_value(&self.mode)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set mode"))?;

        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("destination"),
            &TryIntoJsValue::try_to_js_value(&self.destination)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set destination"))?;

        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("destinationBounceable"),
            &TryIntoJsValue::try_to_js_value(&self.destination_bounceable)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set destinationBounceable"))?;

        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("amount"),
            &TryIntoJsValue::try_to_js_value(&self.amount)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set amount"))?;

        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("bounce"),
            &TryIntoJsValue::try_to_js_value(&self.bounce)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set bounce"))?;

        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("stateInit"),
            &TryIntoJsValue::try_to_js_value(&self.state_init)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set stateInit"))?;

        if let Some(opcode) = self.body_opcode {
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("bodyOpcode"),
                &TryIntoJsValue::try_to_js_value(&opcode)?,
            )
            .map_err(|_| JsConversionError::new("Failed to set bodyOpcode"))?;
        }

        if let Some(ref memo) = self.memo {
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("memo"),
                &TryIntoJsValue::try_to_js_value(memo)?,
            )
            .map_err(|_| JsConversionError::new("Failed to set memo"))?;
        }

        if let Some(ref jetton) = self.jetton_transfer {
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("jettonTransfer"),
                &TryIntoJsValue::try_to_js_value(jetton)?,
            )
            .map_err(|_| JsConversionError::new("Failed to set jettonTransfer"))?;
        }

        if let Some(withdraw_amount) = self.withdraw_amount {
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("withdrawAmount"),
                &TryIntoJsValue::try_to_js_value(&withdraw_amount)?,
            )
            .map_err(|_| JsConversionError::new("Failed to set withdrawAmount"))?;
        }

        Ok(obj.into())
    }
}

impl TryIntoJsValue for ParsedTransaction {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "transactionType" => self.transaction_type,
            "sender" => self.sender,
            "walletId" => self.wallet_id,
            "seqno" => self.seqno,
            "expireAt" => self.expire_at,
            "signature" => self.signature,
            "sendActions" => self.send_actions
        )
    }
}
