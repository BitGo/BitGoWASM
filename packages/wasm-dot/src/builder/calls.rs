//! Call encoding using subxt dynamic API
//!
//! Two entry points:
//! - `encode_intent()`: public — accepts a business-level `TransactionIntent`,
//!   composes it into calls, and encodes (batching if needed)
//! - `encode_call()`: internal — encodes a single `CallIntent` to call data bytes

use crate::address::decode_ss58;
use crate::builder::types::{intent_to_calls, CallIntent, StakePayee, TransactionIntent};
use crate::error::WasmDotError;
use subxt_core::{
    ext::scale_value::{Composite, Value},
    metadata::Metadata,
    tx::payload::{dynamic, Payload},
};

/// Encode a business-level intent to call data bytes.
///
/// Handles composition: single-call intents are encoded directly,
/// multi-call intents (e.g., stake with proxy) are wrapped in batchAll.
pub fn encode_intent(
    intent: &TransactionIntent,
    sender: &str,
    metadata: &Metadata,
) -> Result<Vec<u8>, WasmDotError> {
    let calls = intent_to_calls(intent, sender)?;

    match calls.len() {
        0 => Err(WasmDotError::InvalidInput(
            "Intent produced no calls".to_string(),
        )),
        1 => encode_call(&calls[0], metadata),
        _ => encode_batch(&calls, metadata),
    }
}

/// Encode a single call-level intent to call data bytes.
fn encode_call(call: &CallIntent, metadata: &Metadata) -> Result<Vec<u8>, WasmDotError> {
    let payload = match call {
        CallIntent::Transfer {
            to,
            amount,
            keep_alive,
        } => {
            let method = if *keep_alive {
                "transfer_keep_alive"
            } else {
                "transfer_allow_death"
            };
            balances(method, to, *amount)?
        }
        CallIntent::TransferAll { to, keep_alive } => transfer_all(to, *keep_alive)?,
        CallIntent::Bond { amount, payee } => staking_bond(*amount, payee)?,
        CallIntent::BondExtra { amount } => staking_bond_extra(*amount),
        CallIntent::Unbond { amount } => staking_unbond(*amount),
        CallIntent::WithdrawUnbonded { slashing_spans } => {
            staking_withdraw_unbonded(*slashing_spans)
        }
        CallIntent::Chill => staking_chill(),
        CallIntent::AddProxy {
            delegate,
            proxy_type,
            delay,
        } => proxy_add(delegate, proxy_type, *delay)?,
        CallIntent::RemoveProxy {
            delegate,
            proxy_type,
            delay,
        } => proxy_remove(delegate, proxy_type, *delay)?,
    };

    payload
        .encode_call_data(metadata)
        .map_err(|e| WasmDotError::InvalidInput(format!("Failed to encode call: {}", e)))
}

// =============================================================================
// Balances pallet
// =============================================================================

fn balances(
    method: &str,
    to: &str,
    amount: u64,
) -> Result<subxt_core::tx::payload::DynamicPayload, WasmDotError> {
    Ok(dynamic(
        "Balances",
        method,
        named([
            ("dest", multi_address(to)?),
            ("value", Value::u128(amount as u128)),
        ]),
    ))
}

fn transfer_all(
    to: &str,
    keep_alive: bool,
) -> Result<subxt_core::tx::payload::DynamicPayload, WasmDotError> {
    Ok(dynamic(
        "Balances",
        "transfer_all",
        named([
            ("dest", multi_address(to)?),
            ("keep_alive", Value::bool(keep_alive)),
        ]),
    ))
}

// =============================================================================
// Staking pallet
// =============================================================================

fn staking_bond(
    amount: u64,
    payee: &StakePayee,
) -> Result<subxt_core::tx::payload::DynamicPayload, WasmDotError> {
    let payee_value = match payee {
        StakePayee::Staked => Value::unnamed_variant("Staked", []),
        StakePayee::Stash => Value::unnamed_variant("Stash", []),
        StakePayee::Controller => Value::unnamed_variant("Controller", []),
        StakePayee::Account { address } => {
            Value::unnamed_variant("Account", [account_id(address)?])
        }
    };

    Ok(dynamic(
        "Staking",
        "bond",
        named([
            ("value", Value::u128(amount as u128)),
            ("payee", payee_value),
        ]),
    ))
}

fn staking_bond_extra(amount: u64) -> subxt_core::tx::payload::DynamicPayload {
    dynamic(
        "Staking",
        "bond_extra",
        named([("max_additional", Value::u128(amount as u128))]),
    )
}

fn staking_unbond(amount: u64) -> subxt_core::tx::payload::DynamicPayload {
    dynamic(
        "Staking",
        "unbond",
        named([("value", Value::u128(amount as u128))]),
    )
}

fn staking_withdraw_unbonded(num_slashing_spans: u32) -> subxt_core::tx::payload::DynamicPayload {
    dynamic(
        "Staking",
        "withdraw_unbonded",
        named([(
            "num_slashing_spans",
            Value::u128(num_slashing_spans as u128),
        )]),
    )
}

fn staking_chill() -> subxt_core::tx::payload::DynamicPayload {
    dynamic("Staking", "chill", Composite::Unnamed(vec![]))
}

// =============================================================================
// Proxy pallet
// =============================================================================

fn proxy_add(
    delegate: &str,
    proxy_type: &str,
    delay: u32,
) -> Result<subxt_core::tx::payload::DynamicPayload, WasmDotError> {
    Ok(dynamic(
        "Proxy",
        "add_proxy",
        named([
            ("delegate", multi_address(delegate)?),
            ("proxy_type", Value::unnamed_variant(proxy_type, [])),
            ("delay", Value::u128(delay as u128)),
        ]),
    ))
}

fn proxy_remove(
    delegate: &str,
    proxy_type: &str,
    delay: u32,
) -> Result<subxt_core::tx::payload::DynamicPayload, WasmDotError> {
    Ok(dynamic(
        "Proxy",
        "remove_proxy",
        named([
            ("delegate", multi_address(delegate)?),
            ("proxy_type", Value::unnamed_variant(proxy_type, [])),
            ("delay", Value::u128(delay as u128)),
        ]),
    ))
}

// =============================================================================
// Utility pallet (batch)
// =============================================================================

/// Encode multiple calls as a batchAll (atomic batch).
fn encode_batch(calls: &[CallIntent], metadata: &Metadata) -> Result<Vec<u8>, WasmDotError> {
    use parity_scale_codec::{Compact, Encode};

    let encoded_calls: Result<Vec<_>, _> = calls
        .iter()
        .map(|call| encode_call(call, metadata))
        .collect();
    let encoded_calls = encoded_calls?;

    let (pallet_idx, call_idx) = get_call_index(metadata, "Utility", "batch_all")?;

    let mut result = vec![pallet_idx, call_idx];
    Compact(encoded_calls.len() as u32).encode_to(&mut result);
    for call in encoded_calls {
        result.extend(call);
    }
    Ok(result)
}

/// Get pallet and call index from metadata
fn get_call_index(
    metadata: &Metadata,
    pallet: &str,
    method: &str,
) -> Result<(u8, u8), WasmDotError> {
    let p = metadata
        .pallet_by_name(pallet)
        .ok_or_else(|| WasmDotError::InvalidInput(format!("{} pallet not found", pallet)))?;
    let c = p
        .call_variant_by_name(method)
        .ok_or_else(|| WasmDotError::InvalidInput(format!("{}.{} not found", pallet, method)))?;
    Ok((p.index(), c.index))
}

// =============================================================================
// Helpers
// =============================================================================

/// Build a named composite from key-value pairs
fn named<const N: usize>(fields: [(&str, Value<()>); N]) -> Composite<()> {
    Composite::Named(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

/// Convert SS58 address to MultiAddress::Id value
fn multi_address(address: &str) -> Result<Value<()>, WasmDotError> {
    Ok(Value::unnamed_variant("Id", [account_id(address)?]))
}

/// Convert SS58 address to AccountId32 bytes value
fn account_id(address: &str) -> Result<Value<()>, WasmDotError> {
    let (pubkey, _) = decode_ss58(address)?;
    let bytes: [u8; 32] = pubkey.try_into().map_err(|v: Vec<u8>| {
        WasmDotError::InvalidInput(format!(
            "Invalid pubkey length: expected 32, got {}",
            v.len()
        ))
    })?;
    Ok(Value::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_named_helper() {
        let composite = named([("foo", Value::u128(42)), ("bar", Value::bool(true))]);
        match composite {
            Composite::Named(fields) => {
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0].0, "foo");
                assert_eq!(fields[1].0, "bar");
            }
            _ => panic!("Expected Named composite"),
        }
    }

    #[test]
    fn test_account_id() {
        // Valid SS58 address
        let result = account_id("5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty");
        assert!(result.is_ok());
    }
}
