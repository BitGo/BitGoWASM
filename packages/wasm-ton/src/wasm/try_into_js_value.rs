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

use crate::parser::{
    EffectiveAmountKind, JettonTransferFields, ParsedSendAction, ParsedTransaction,
    TransactionType,
};

impl TryIntoJsValue for EffectiveAmountKind {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_str(self.as_str()))
    }
}

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
            &JsValue::from_str("nominalAmount"),
            &TryIntoJsValue::try_to_js_value(&self.nominal_amount)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set nominalAmount"))?;

        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("effectiveAmountKind"),
            &TryIntoJsValue::try_to_js_value(&self.effective_amount_kind)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set effectiveAmountKind"))?;

        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("payFeesSeparately"),
            &TryIntoJsValue::try_to_js_value(&self.pay_fees_separately)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set payFeesSeparately"))?;

        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("ignoreActionErrors"),
            &TryIntoJsValue::try_to_js_value(&self.ignore_action_errors)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set ignoreActionErrors"))?;

        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("bounceOnActionFail"),
            &TryIntoJsValue::try_to_js_value(&self.bounce_on_action_fail)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set bounceOnActionFail"))?;

        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("carriesInboundValue"),
            &TryIntoJsValue::try_to_js_value(&self.carries_inbound_value)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set carriesInboundValue"))?;

        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("carriesAllBalance"),
            &TryIntoJsValue::try_to_js_value(&self.carries_all_balance)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set carriesAllBalance"))?;

        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("destroyAccountIfZero"),
            &TryIntoJsValue::try_to_js_value(&self.destroy_account_if_zero)?,
        )
        .map_err(|_| JsConversionError::new("Failed to set destroyAccountIfZero"))?;

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

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    fn send_action(mode: u8) -> ParsedSendAction {
        ParsedSendAction {
            mode,
            nominal_amount: 7,
            effective_amount_kind: EffectiveAmountKind::AllRemainingBalance,
            pay_fees_separately: mode & 1 != 0,
            ignore_action_errors: mode & 2 != 0,
            bounce_on_action_fail: mode & 16 != 0,
            carries_inbound_value: false,
            carries_all_balance: true,
            destroy_account_if_zero: mode & 32 != 0,
            destination: "destination".to_string(),
            destination_bounceable: "destination".to_string(),
            bounce: true,
            body_opcode: None,
            state_init: false,
            memo: None,
            jetton_transfer: None,
            withdraw_amount: None,
        }
    }

    #[wasm_bindgen_test]
    fn send_mode_semantics_survive_javascript_conversion() {
        for (mode, destroy_account_if_zero) in [(128, false), (160, true)] {
            let value = send_action(mode).try_to_js_value().unwrap();

            assert_eq!(
                js_sys::Reflect::get(&value, &JsValue::from_str("mode"))
                    .unwrap()
                    .as_f64(),
                Some(mode as f64)
            );
            let actual_amount =
                js_sys::Reflect::get(&value, &JsValue::from_str("nominalAmount")).unwrap();
            let expected_amount: JsValue = js_sys::BigInt::from(7u64).into();
            assert!(js_sys::Object::is(&actual_amount, &expected_amount));
            assert_eq!(
                js_sys::Reflect::get(&value, &JsValue::from_str("effectiveAmountKind"))
                    .unwrap()
                    .as_string()
                    .as_deref(),
                Some("AllRemainingBalance")
            );
            assert_eq!(
                js_sys::Reflect::get(&value, &JsValue::from_str("payFeesSeparately"))
                    .unwrap()
                    .as_bool(),
                Some(false)
            );
            assert_eq!(
                js_sys::Reflect::get(&value, &JsValue::from_str("ignoreActionErrors"))
                    .unwrap()
                    .as_bool(),
                Some(false)
            );
            assert_eq!(
                js_sys::Reflect::get(&value, &JsValue::from_str("bounceOnActionFail"))
                    .unwrap()
                    .as_bool(),
                Some(false)
            );
            assert_eq!(
                js_sys::Reflect::get(&value, &JsValue::from_str("carriesInboundValue"))
                    .unwrap()
                    .as_bool(),
                Some(false)
            );
            assert_eq!(
                js_sys::Reflect::get(&value, &JsValue::from_str("carriesAllBalance"))
                    .unwrap()
                    .as_bool(),
                Some(true)
            );
            assert_eq!(
                js_sys::Reflect::get(&value, &JsValue::from_str("destroyAccountIfZero"))
                    .unwrap()
                    .as_bool(),
                Some(destroy_account_if_zero)
            );
            assert_eq!(
                js_sys::Reflect::get(&value, &JsValue::from_str("bounce"))
                    .unwrap()
                    .as_bool(),
                Some(true)
            );
            assert!(!js_sys::Reflect::has(&value, &JsValue::from_str("amount")).unwrap());
        }
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
