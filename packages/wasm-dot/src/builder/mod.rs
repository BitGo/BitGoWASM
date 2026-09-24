//! Transaction building from intents
//!
//! Build DOT transactions from high-level business intent descriptions.
//! Accepts intents like Payment, Stake, Unstake (not low-level calls)
//! and handles composition into the correct extrinsic calls.

mod calls;
pub mod types;

use crate::error::WasmDotError;
use crate::transaction::{compute_era, Transaction};
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
    // Validate and normalize validity before any transaction construction.
    let era = compute_era(&context.validity)?;

    // Decode metadata once
    let metadata = decode_metadata(&context.material.metadata)?;

    // Compose intent into calls and encode (batching if needed)
    let call_data = encode_intent(&intent, &context.sender, &metadata)?;

    // Create transaction directly from components (no extrinsic encoding needed).
    // to_bytes() on unsigned transactions returns signable_payload(), which is the
    // signing payload format: call_data | era | nonce | tip | extensions | additional_signed.
    let mut tx = Transaction::new(call_data, era, context.nonce, context.tip as u128);
    tx.set_context(context.material, context.validity, &context.reference_block)?;

    Ok(tx)
}

// Re-use the central decode_metadata from transaction.rs
use crate::transaction::decode_metadata;

