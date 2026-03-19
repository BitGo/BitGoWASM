//! Transaction building from intents
//!
//! Build DOT transactions from high-level business intent descriptions.
//! Accepts intents like Payment, Stake, Unstake (not low-level calls)
//! and handles composition into the correct extrinsic calls.

mod calls;
pub mod types;

use crate::error::WasmDotError;
use crate::transaction::Transaction;
use crate::types::{Era, Validity};
use calls::encode_intent;
use parity_scale_codec::{Compact, Encode};
use subxt_core::metadata::Metadata;
use types::{BuildContext, TransactionIntent};

/// Build a transaction from a business-level intent and context.
///
/// The intent describes *what* to do (payment, stake, etc.) and the context
/// provides *how* to build it (sender, nonce, material, validity).
/// Multi-call intents (e.g., stake with proxy) are batched automatically.
pub fn build_transaction(
    intent: TransactionIntent,
    context: BuildContext,
) -> Result<Transaction, WasmDotError> {
    // Decode metadata once
    let metadata = decode_metadata(&context.material.metadata)?;

    // Compose intent into calls and encode (batching if needed)
    let call_data = encode_intent(&intent, &context.sender, &metadata)?;

    // Calculate era from validity
    let era = compute_era(&context.validity);

    // Build unsigned extrinsic: compact(length) | 0x04 | call_data
    let unsigned_bytes = build_unsigned_extrinsic(
        &call_data,
        &era,
        context.nonce,
        context.tip as u128,
        &metadata,
    )?;

    // Create transaction from bytes — pass metadata so parser uses metadata-aware decoding
    let mut tx = Transaction::from_bytes(&unsigned_bytes, None, Some(&metadata))?;
    tx.set_context(context.material, context.validity, &context.reference_block)?;

    // Set era/nonce/tip from build context (not parsed from unsigned extrinsic body,
    // since standard format doesn't include signed extensions in the body)
    tx.set_era(era);
    tx.set_nonce(context.nonce);
    tx.set_tip(context.tip as u128);

    Ok(tx)
}

// Re-use the central decode_metadata from transaction.rs
use crate::transaction::decode_metadata;

/// Compute era from validity window
fn compute_era(validity: &Validity) -> Era {
    if validity.max_duration == 0 {
        Era::Immortal
    } else {
        let period = validity.max_duration.next_power_of_two().clamp(4, 65536);
        let phase = validity.first_valid % period;
        Era::Mortal { period, phase }
    }
}

/// Build unsigned extrinsic bytes in standard Substrate V4 format.
///
/// Format: `compact(length) | 0x04 | call_data`
///
/// Signed extensions (era, nonce, tip) are NOT included in the unsigned
/// extrinsic body. They belong only in the signing payload, which is
/// computed separately by `signable_payload()` via subxt-core.
///
/// This matches the format that polkadot-js, txwrapper, and all standard
/// Substrate tools expect for unsigned extrinsics.
fn build_unsigned_extrinsic(
    call_data: &[u8],
    _era: &Era,
    _nonce: u32,
    _tip: u128,
    _metadata: &Metadata,
) -> Result<Vec<u8>, WasmDotError> {
    let mut body = Vec::new();

    // Version byte: 0x04 = unsigned, version 4
    body.push(0x04);

    // Call data immediately after version byte
    body.extend_from_slice(call_data);

    // Length prefix (compact encoded)
    let mut result = Compact(body.len() as u32).encode();
    result.extend_from_slice(&body);

    Ok(result)
}

#[cfg(test)]
mod tests {
    // Tests require real metadata - will be added with test fixtures
    // For now, unit tests are in calls.rs for the encoding logic
}
