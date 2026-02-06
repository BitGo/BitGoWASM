//! WASM bindings for transaction building
//!
//! BuilderNamespace provides static methods for building DOT transactions from intents

use crate::builder::{build_transaction, types::TransactionIntent};
use crate::types::{BuildContext, Material, Validity};
use crate::wasm::transaction::WasmTransaction;
use wasm_bindgen::prelude::*;

/// Namespace for building operations
#[wasm_bindgen]
pub struct BuilderNamespace;

#[wasm_bindgen]
impl BuilderNamespace {
    /// Build a transaction from an intent
    ///
    /// # Arguments
    /// * `intent` - JSON object describing the transaction intent
    /// * `context` - Build context with sender, nonce, material, validity
    ///
    /// # Returns
    /// WasmTransaction ready for signing
    ///
    /// # Example Intent (Transfer)
    /// ```json
    /// {
    ///   "type": "transfer",
    ///   "to": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
    ///   "amount": "1000000000000",
    ///   "keepAlive": true
    /// }
    /// ```
    #[wasm_bindgen(js_name = buildTransaction)]
    pub fn build_transaction_wasm(
        intent: JsValue,
        context: BuildContextJs,
    ) -> Result<WasmTransaction, JsValue> {
        // Deserialize intent from JS
        let intent: TransactionIntent = serde_wasm_bindgen::from_value(intent)
            .map_err(|e| JsValue::from_str(&format!("Invalid intent: {}", e)))?;

        // Build the transaction
        let tx = build_transaction(intent, context.into_inner())?;

        // Wrap in WasmTransaction
        Ok(WasmTransaction::from_inner(tx))
    }

    /// Build a transfer transaction
    ///
    /// Convenience method for simple transfers
    #[wasm_bindgen(js_name = buildTransfer)]
    pub fn build_transfer(
        to: &str,
        amount: &str,
        keep_alive: bool,
        context: BuildContextJs,
    ) -> Result<WasmTransaction, JsValue> {
        let amount: u128 = amount
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid amount: {}", e)))?;

        let intent = TransactionIntent::Transfer(crate::builder::types::TransferIntent {
            to: to.to_string(),
            amount,
            keep_alive,
        });

        let tx = build_transaction(intent, context.into_inner())?;
        Ok(WasmTransaction::from_inner(tx))
    }

    /// Build a staking (bond) transaction
    #[wasm_bindgen(js_name = buildStake)]
    pub fn build_stake(
        amount: &str,
        payee: &str,
        context: BuildContextJs,
    ) -> Result<WasmTransaction, JsValue> {
        let amount: u128 = amount
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid amount: {}", e)))?;

        let payee = match payee.to_lowercase().as_str() {
            "staked" => crate::builder::types::StakePayee::Staked,
            "stash" => crate::builder::types::StakePayee::Stash,
            "controller" => crate::builder::types::StakePayee::Controller,
            addr if addr.starts_with("5") => crate::builder::types::StakePayee::Account {
                address: addr.to_string(),
            },
            _ => crate::builder::types::StakePayee::Staked,
        };

        let intent = TransactionIntent::Stake(crate::builder::types::StakeIntent { amount, payee });

        let tx = build_transaction(intent, context.into_inner())?;
        Ok(WasmTransaction::from_inner(tx))
    }

    /// Build an unstake (unbond) transaction
    #[wasm_bindgen(js_name = buildUnstake)]
    pub fn build_unstake(
        amount: &str,
        context: BuildContextJs,
    ) -> Result<WasmTransaction, JsValue> {
        let amount: u128 = amount
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid amount: {}", e)))?;

        let intent = TransactionIntent::Unstake(crate::builder::types::UnstakeIntent { amount });

        let tx = build_transaction(intent, context.into_inner())?;
        Ok(WasmTransaction::from_inner(tx))
    }
}

/// JavaScript-friendly wrapper for BuildContext
#[wasm_bindgen]
pub struct BuildContextJs {
    inner: BuildContext,
}

#[wasm_bindgen]
impl BuildContextJs {
    #[wasm_bindgen(constructor)]
    pub fn new(
        sender: &str,
        nonce: u32,
        tip: &str,
        material: MaterialBuilderJs,
        validity: ValidityBuilderJs,
        reference_block: &str,
    ) -> Result<BuildContextJs, JsValue> {
        let tip: u128 = tip
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid tip: {}", e)))?;

        Ok(BuildContextJs {
            inner: BuildContext {
                sender: sender.to_string(),
                nonce,
                tip,
                material: material.into_inner(),
                validity: validity.into_inner(),
                reference_block: reference_block.to_string(),
            },
        })
    }

    /// Create from a JS object
    #[wasm_bindgen(js_name = fromObject)]
    pub fn from_object(obj: JsValue) -> Result<BuildContextJs, JsValue> {
        let ctx: BuildContext = serde_wasm_bindgen::from_value(obj)
            .map_err(|e| JsValue::from_str(&format!("Invalid context: {}", e)))?;
        Ok(BuildContextJs { inner: ctx })
    }
}

impl BuildContextJs {
    pub fn into_inner(self) -> BuildContext {
        self.inner
    }
}

/// JavaScript-friendly Material for builder
#[wasm_bindgen]
pub struct MaterialBuilderJs {
    inner: Material,
}

#[wasm_bindgen]
impl MaterialBuilderJs {
    #[wasm_bindgen(constructor)]
    pub fn new(
        genesis_hash: &str,
        chain_name: &str,
        spec_name: &str,
        spec_version: u32,
        tx_version: u32,
    ) -> MaterialBuilderJs {
        MaterialBuilderJs {
            inner: Material {
                genesis_hash: genesis_hash.to_string(),
                chain_name: chain_name.to_string(),
                spec_name: spec_name.to_string(),
                spec_version,
                tx_version,
            },
        }
    }
}

impl MaterialBuilderJs {
    pub fn into_inner(self) -> Material {
        self.inner
    }
}

/// JavaScript-friendly Validity for builder
#[wasm_bindgen]
pub struct ValidityBuilderJs {
    inner: Validity,
}

#[wasm_bindgen]
impl ValidityBuilderJs {
    #[wasm_bindgen(constructor)]
    pub fn new(first_valid: u32, max_duration: u32) -> ValidityBuilderJs {
        ValidityBuilderJs {
            inner: Validity {
                first_valid,
                max_duration,
            },
        }
    }
}

impl ValidityBuilderJs {
    pub fn into_inner(self) -> Validity {
        self.inner
    }
}
