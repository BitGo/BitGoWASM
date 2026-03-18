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

    // Create transaction directly from components (no extrinsic encoding needed).
    // to_bytes() on unsigned transactions returns signable_payload(), which is the
    // signing payload format: call_data | era | nonce | tip | extensions | additional_signed.
    let mut tx = Transaction::new(call_data, era, context.nonce, context.tip as u128);
    tx.set_context(context.material, context.validity, &context.reference_block)?;

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

#[cfg(test)]
mod tests {
    // Tests require real metadata - will be added with test fixtures
    // For now, unit tests are in calls.rs for the encoding logic
}
