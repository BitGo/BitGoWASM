//! Transaction building from intents
//!
//! Build DOT transactions from high-level intent descriptions

pub mod types;

use crate::address::decode_ss58;
use crate::error::WasmDotError;
use crate::transaction::Transaction;
use crate::types::{BuildContext, Era, Validity};
use types::TransactionIntent;

/// Build a transaction from an intent
///
/// # Arguments
/// * `intent` - High-level description of the transaction
/// * `context` - Chain context (sender, nonce, material, etc.)
pub fn build_transaction(
    intent: TransactionIntent,
    context: BuildContext,
) -> Result<Transaction, WasmDotError> {
    // Build the call data based on intent type
    let call_data = build_call_data(&intent, &context)?;

    // Calculate era from validity
    let era = compute_era(&context.validity);

    // Build the unsigned transaction bytes
    let unsigned_bytes = build_unsigned_extrinsic(&call_data, &era, context.nonce, context.tip)?;

    // Create transaction from bytes and set context
    let mut tx = Transaction::from_bytes(&unsigned_bytes, None)?;

    // Set the context for signing operations
    tx.set_context(context.material, context.validity, &context.reference_block)?;

    Ok(tx)
}

/// Build call data for an intent
fn build_call_data(
    intent: &TransactionIntent,
    context: &BuildContext,
) -> Result<Vec<u8>, WasmDotError> {
    match intent {
        TransactionIntent::Transfer(transfer) => {
            build_transfer_call(&transfer.to, transfer.amount, transfer.keep_alive, context)
        }
        TransactionIntent::TransferAll(transfer) => {
            build_transfer_all_call(&transfer.to, transfer.keep_alive, context)
        }
        TransactionIntent::Stake(stake) => build_stake_call(stake, context),
        TransactionIntent::Unstake(unstake) => build_unstake_call(unstake.amount),
        TransactionIntent::WithdrawUnbonded(withdraw) => {
            build_withdraw_unbonded_call(withdraw.slashing_spans)
        }
        TransactionIntent::Chill => build_chill_call(),
        TransactionIntent::AddProxy(proxy) => build_add_proxy_call(proxy, context),
        TransactionIntent::RemoveProxy(proxy) => build_remove_proxy_call(proxy, context),
        TransactionIntent::Batch(batch) => build_batch_call(&batch.calls, batch.atomic, context),
    }
}

/// Build transfer call data
fn build_transfer_call(
    to: &str,
    amount: u128,
    keep_alive: bool,
    _context: &BuildContext,
) -> Result<Vec<u8>, WasmDotError> {
    let (dest_pubkey, _) = decode_ss58(to)?;

    let mut call = Vec::new();

    // Pallet index for balances (typically 5, but varies)
    // We'll use 5 as default (Polkadot mainnet)
    let pallet_index = 5u8;

    // Method index: 3 = transferKeepAlive, 0 = transfer
    let method_index = if keep_alive { 3u8 } else { 0u8 };

    call.push(pallet_index);
    call.push(method_index);

    // Destination (MultiAddress::Id)
    call.push(0x00); // Id variant
    call.extend_from_slice(&dest_pubkey);

    // Amount (compact encoded)
    call.extend_from_slice(&encode_compact(amount));

    Ok(call)
}

/// Build transferAll call data
fn build_transfer_all_call(
    to: &str,
    keep_alive: bool,
    _context: &BuildContext,
) -> Result<Vec<u8>, WasmDotError> {
    let (dest_pubkey, _) = decode_ss58(to)?;

    let mut call = Vec::new();

    // Balances pallet
    call.push(5u8);
    // transferAll method
    call.push(4u8);

    // Destination
    call.push(0x00);
    call.extend_from_slice(&dest_pubkey);

    // Keep alive flag
    call.push(if keep_alive { 1 } else { 0 });

    Ok(call)
}

/// Build stake (bond) call data
fn build_stake_call(
    stake: &types::StakeIntent,
    _context: &BuildContext,
) -> Result<Vec<u8>, WasmDotError> {
    let mut call = Vec::new();

    // Staking pallet (typically 7)
    call.push(7u8);
    // bond method
    call.push(0u8);

    // Value (compact)
    call.extend_from_slice(&encode_compact(stake.amount));

    // Payee
    match &stake.payee {
        types::StakePayee::Staked => call.push(0u8),
        types::StakePayee::Stash => call.push(1u8),
        types::StakePayee::Controller => call.push(2u8),
        types::StakePayee::Account { address } => {
            call.push(3u8);
            let (pubkey, _) = decode_ss58(address)?;
            call.extend_from_slice(&pubkey);
        }
    }

    Ok(call)
}

/// Build unstake (unbond) call data
fn build_unstake_call(amount: u128) -> Result<Vec<u8>, WasmDotError> {
    let mut call = Vec::new();

    // Staking pallet
    call.push(7u8);
    // unbond method
    call.push(2u8);

    // Value (compact)
    call.extend_from_slice(&encode_compact(amount));

    Ok(call)
}

/// Build withdrawUnbonded call data
fn build_withdraw_unbonded_call(slashing_spans: u32) -> Result<Vec<u8>, WasmDotError> {
    let mut call = Vec::new();

    // Staking pallet
    call.push(7u8);
    // withdrawUnbonded method
    call.push(3u8);

    // Slashing spans (u32)
    call.extend_from_slice(&slashing_spans.to_le_bytes());

    Ok(call)
}

/// Build chill call data
fn build_chill_call() -> Result<Vec<u8>, WasmDotError> {
    Ok(vec![7u8, 6u8]) // Staking pallet, chill method
}

/// Build addProxy call data
fn build_add_proxy_call(
    proxy: &types::AddProxyIntent,
    _context: &BuildContext,
) -> Result<Vec<u8>, WasmDotError> {
    let (delegate_pubkey, _) = decode_ss58(&proxy.delegate)?;

    let mut call = Vec::new();

    // Proxy pallet (typically 29)
    call.push(29u8);
    // addProxy method
    call.push(1u8);

    // Delegate
    call.push(0x00);
    call.extend_from_slice(&delegate_pubkey);

    // Proxy type (encoded as enum variant)
    let proxy_type_byte = match proxy.proxy_type.as_str() {
        "Any" => 0u8,
        "NonTransfer" => 1u8,
        "Staking" => 3u8,
        _ => 0u8,
    };
    call.push(proxy_type_byte);

    // Delay (u32)
    call.extend_from_slice(&proxy.delay.to_le_bytes());

    Ok(call)
}

/// Build removeProxy call data
fn build_remove_proxy_call(
    proxy: &types::RemoveProxyIntent,
    _context: &BuildContext,
) -> Result<Vec<u8>, WasmDotError> {
    let (delegate_pubkey, _) = decode_ss58(&proxy.delegate)?;

    let mut call = Vec::new();

    // Proxy pallet
    call.push(29u8);
    // removeProxy method
    call.push(2u8);

    // Delegate
    call.push(0x00);
    call.extend_from_slice(&delegate_pubkey);

    // Proxy type
    let proxy_type_byte = match proxy.proxy_type.as_str() {
        "Any" => 0u8,
        "NonTransfer" => 1u8,
        "Staking" => 3u8,
        _ => 0u8,
    };
    call.push(proxy_type_byte);

    // Delay (u32)
    call.extend_from_slice(&proxy.delay.to_le_bytes());

    Ok(call)
}

/// Build batch call data
fn build_batch_call(
    calls: &[TransactionIntent],
    atomic: bool,
    context: &BuildContext,
) -> Result<Vec<u8>, WasmDotError> {
    let mut call = Vec::new();

    // Utility pallet (typically 26)
    call.push(26u8);
    // batch (0) or batchAll (2)
    call.push(if atomic { 2u8 } else { 0u8 });

    // Build inner calls
    let mut inner_calls = Vec::new();
    for intent in calls {
        let inner_call = build_call_data(intent, context)?;
        inner_calls.push(inner_call);
    }

    // Encode as Vec<Call>
    // First, the length (compact)
    call.extend_from_slice(&encode_compact(inner_calls.len() as u128));

    // Then each call
    for inner_call in inner_calls {
        call.extend_from_slice(&inner_call);
    }

    Ok(call)
}

/// Compute era from validity window
fn compute_era(validity: &Validity) -> Era {
    if validity.max_duration == 0 {
        Era::Immortal
    } else {
        let period = validity.max_duration.next_power_of_two().min(65536).max(4);
        let phase = validity.first_valid % period;
        Era::Mortal { period, phase }
    }
}

/// Build unsigned extrinsic bytes
fn build_unsigned_extrinsic(
    call_data: &[u8],
    _era: &Era,
    _nonce: u32,
    _tip: u128,
) -> Result<Vec<u8>, WasmDotError> {
    let mut body = Vec::new();

    // For unsigned parsing format, we encode:
    // - call data
    // - era
    // - nonce
    // - tip
    // - spec version, tx version, genesis hash, block hash (for signing payload)

    // However, for the "unsigned extrinsic" that gets passed around,
    // we typically just include call + metadata for signing

    // Version byte: 0x04 = unsigned, version 4
    body.push(0x04);

    // Call data
    body.extend_from_slice(call_data);

    // Length prefix
    let mut result = encode_compact(body.len() as u128);
    result.extend_from_slice(&body);

    Ok(result)
}

/// Encode compact
fn encode_compact(value: u128) -> Vec<u8> {
    if value < 0x40 {
        vec![(value as u8) << 2]
    } else if value < 0x4000 {
        let v = ((value as u16) << 2) | 0b01;
        v.to_le_bytes().to_vec()
    } else if value < 0x4000_0000 {
        let v = ((value as u32) << 2) | 0b10;
        v.to_le_bytes().to_vec()
    } else {
        let bytes_needed = ((128 - value.leading_zeros() + 7) / 8) as usize;
        let mut result = vec![((bytes_needed - 4) << 2 | 0b11) as u8];
        for i in 0..bytes_needed {
            result.push((value >> (8 * i)) as u8);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Material;

    fn test_context() -> BuildContext {
        BuildContext {
            sender: "5EGoFA95omzemRssELLDjVenNZ68aXyUeqtKQScXSEBvVJkr".to_string(),
            nonce: 0,
            tip: 0,
            material: Material {
                genesis_hash: "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3"
                    .to_string(),
                chain_name: "Polkadot".to_string(),
                spec_name: "polkadot".to_string(),
                spec_version: 9150,
                tx_version: 9,
            },
            validity: Validity {
                first_valid: 1000,
                max_duration: 2400,
            },
            reference_block: "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3"
                .to_string(),
        }
    }

    #[test]
    fn test_build_transfer() {
        let context = test_context();
        let intent = TransactionIntent::Transfer(types::TransferIntent {
            to: "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty".to_string(),
            amount: 1_000_000_000_000, // 1 DOT
            keep_alive: true,
        });

        let result = build_transaction(intent, context);
        assert!(result.is_ok());
    }
}
