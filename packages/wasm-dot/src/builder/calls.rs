//! Call encoding using subxt dynamic API
//!
//! Clean, readable call building - similar to txwrapper-polkadot's methods.balances.transferKeepAlive()

use crate::address::decode_ss58;
use crate::builder::types::{StakePayee, TransactionIntent};
use crate::error::WasmDotError;
use subxt_core::{
    ext::scale_value::{Composite, Value},
    metadata::Metadata,
    tx::payload::{dynamic, Payload},
};

/// Encode a transaction intent to call data bytes
pub fn encode_call(
    intent: &TransactionIntent,
    metadata: &Metadata,
) -> Result<Vec<u8>, WasmDotError> {
    let payload = match intent {
        TransactionIntent::Transfer {
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
        TransactionIntent::TransferAll { to, keep_alive } => transfer_all(to, *keep_alive)?,
        TransactionIntent::Stake { amount, payee } => staking_bond(*amount, payee)?,
        TransactionIntent::Unstake { amount } => staking_unbond(*amount),
        TransactionIntent::WithdrawUnbonded { slashing_spans } => {
            staking_withdraw_unbonded(*slashing_spans)
        }
        TransactionIntent::Chill => staking_chill(),
        TransactionIntent::AddProxy {
            delegate,
            proxy_type,
            delay,
        } => proxy_add(delegate, proxy_type, *delay)?,
        TransactionIntent::RemoveProxy {
            delegate,
            proxy_type,
            delay,
        } => proxy_remove(delegate, proxy_type, *delay)?,
        TransactionIntent::Batch { calls, atomic } => {
            return encode_batch(calls, *atomic, metadata);
        }
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
    amount: u128,
) -> Result<subxt_core::tx::payload::DynamicPayload, WasmDotError> {
    Ok(dynamic(
        "Balances",
        method,
        named([("dest", multi_address(to)?), ("value", Value::u128(amount))]),
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
    amount: u128,
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
        named([("value", Value::u128(amount)), ("payee", payee_value)]),
    ))
}

fn staking_unbond(amount: u128) -> subxt_core::tx::payload::DynamicPayload {
    dynamic("Staking", "unbond", named([("value", Value::u128(amount))]))
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

/// Encode a batch - like txwrapper's methods.utility.batch({ calls })
fn encode_batch(
    intents: &[TransactionIntent],
    atomic: bool,
    metadata: &Metadata,
) -> Result<Vec<u8>, WasmDotError> {
    use parity_scale_codec::{Compact, Encode};

    if intents.is_empty() {
        return Err(WasmDotError::InvalidInput(
            "Batch cannot be empty".to_string(),
        ));
    }

    // Reject nested batches
    if intents
        .iter()
        .any(|i| matches!(i, TransactionIntent::Batch { .. }))
    {
        return Err(WasmDotError::InvalidInput(
            "Nested batch not supported".to_string(),
        ));
    }

    // Encode each call (same as txwrapper's unsigned.method)
    let calls: Result<Vec<_>, _> = intents
        .iter()
        .map(|intent| encode_call(intent, metadata))
        .collect();
    let calls = calls?;

    // Build batch: [pallet][method][calls...]
    let method = if atomic { "batch_all" } else { "batch" };
    let (pallet_idx, call_idx) = get_call_index(metadata, "Utility", method)?;

    let mut result = vec![pallet_idx, call_idx];
    Compact(calls.len() as u32).encode_to(&mut result);
    for call in calls {
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
    Ok(Value::from_bytes(&bytes))
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
