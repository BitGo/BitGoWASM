//! Transaction building from intents
//!
//! Build DOT transactions from high-level intent descriptions.
//! Follows wallet-platform pattern: buildTransaction(intent, context)

mod calls;
pub mod types;

use crate::error::WasmDotError;
use crate::transaction::Transaction;
use crate::types::{Era, Validity};
use calls::encode_call;
use parity_scale_codec::{Compact, Encode};
use types::{BuildContext, TransactionIntent};

/// Build a transaction from an intent and context
///
/// This is the main entry point, matching wallet-platform's pattern.
pub fn build_transaction(
    intent: TransactionIntent,
    context: BuildContext,
) -> Result<Transaction, WasmDotError> {
    // Decode metadata once
    let metadata = decode_metadata(&context.material.metadata_hex)?;

    // Build call data using metadata
    let call_data = encode_call(&intent, &metadata)?;

    // Calculate era from validity
    let era = compute_era(&context.validity);

    // Build unsigned extrinsic
    let unsigned_bytes = build_unsigned_extrinsic(&call_data)?;

    // Create transaction and set context
    let mut tx = Transaction::from_bytes(&unsigned_bytes, None)?;
    tx.set_nonce(context.nonce);
    tx.set_tip(context.tip);
    tx.set_era(era);
    tx.set_context(context.material, context.validity, &context.reference_block)?;

    Ok(tx)
}

/// Decode metadata from hex string
fn decode_metadata(metadata_hex: &str) -> Result<subxt_core::metadata::Metadata, WasmDotError> {
    let bytes = hex::decode(metadata_hex.trim_start_matches("0x"))
        .map_err(|e| WasmDotError::InvalidInput(format!("Invalid metadata hex: {}", e)))?;

    subxt_core::metadata::decode_from(&bytes[..])
        .map_err(|e| WasmDotError::InvalidInput(format!("Failed to decode metadata: {}", e)))
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
fn build_unsigned_extrinsic(call_data: &[u8]) -> Result<Vec<u8>, WasmDotError> {
    let mut body = Vec::new();

    // Version byte: 0x04 = unsigned, version 4
    body.push(0x04);

    // Call data
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
