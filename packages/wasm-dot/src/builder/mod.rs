//! Transaction building from intents
//!
//! Build DOT transactions from high-level intent descriptions.
//! Follows wallet-platform pattern: buildTransaction(intent, context)

mod calls;
pub mod types;

use crate::error::WasmDotError;
use crate::transaction::{encode_era, Transaction};
use crate::types::{Era, Validity};
use calls::encode_call;
use parity_scale_codec::{Compact, Encode};
use subxt_core::metadata::Metadata;
use types::{BuildContext, TransactionIntent};

/// Build a transaction from an intent and context
///
/// This is the main entry point, matching wallet-platform's pattern.
pub fn build_transaction(
    intent: TransactionIntent,
    context: BuildContext,
) -> Result<Transaction, WasmDotError> {
    // Decode metadata once
    let metadata = decode_metadata(&context.material.metadata)?;

    // Build call data using metadata
    let call_data = encode_call(&intent, &metadata)?;

    // Calculate era from validity
    let era = compute_era(&context.validity);

    // Build unsigned extrinsic with signed extensions encoded per the chain's metadata
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

/// Build unsigned extrinsic bytes with metadata-driven signed extension encoding.
///
/// Iterates the chain's signed extension list from metadata and encodes each:
/// - Empty types (0-size composites/tuples): skip
/// - CheckMortality: era bytes
/// - CheckNonce: Compact<u32>
/// - ChargeTransactionPayment: Compact<u128> tip
/// - ChargeAssetTxPayment: Compact<u128> tip + 0x00 (None asset_id)
/// - CheckMetadataHash: 0x00 (Disabled mode)
/// - Other non-empty types: encode default bytes using scale_decode to determine size
fn build_unsigned_extrinsic(
    call_data: &[u8],
    era: &Era,
    nonce: u32,
    tip: u128,
    metadata: &Metadata,
) -> Result<Vec<u8>, WasmDotError> {
    let mut body = Vec::new();

    // Version byte: 0x04 = unsigned, version 4
    body.push(0x04);

    // Encode signed extensions per metadata
    for ext in metadata.extrinsic().signed_extensions() {
        let id = ext.identifier();
        let ty_id = ext.extra_ty();

        if is_empty_type(metadata, ty_id) {
            continue;
        }

        match id {
            "CheckMortality" | "CheckEra" => {
                body.extend_from_slice(&encode_era(era));
            }
            "CheckNonce" => {
                Compact(nonce).encode_to(&mut body);
            }
            "ChargeTransactionPayment" => {
                Compact(tip).encode_to(&mut body);
            }
            "ChargeAssetTxPayment" => {
                // Struct: { tip: Compact<u128>, asset_id: Option<T> }
                Compact(tip).encode_to(&mut body);
                body.push(0x00); // None — no asset_id
            }
            "CheckMetadataHash" => {
                // Mode enum: 0x00 = Disabled
                body.push(0x00);
            }
            _ => {
                // Unknown non-empty extension — encode zero bytes.
                // This shouldn't happen for known chains but is a safety fallback.
                encode_zero_value(&mut body, ty_id, metadata)?;
            }
        }
    }

    // Call data
    body.extend_from_slice(call_data);

    // Length prefix (compact encoded)
    let mut result = Compact(body.len() as u32).encode();
    result.extend_from_slice(&body);

    Ok(result)
}

/// Check if a type ID resolves to an empty (zero-size) type.
fn is_empty_type(metadata: &Metadata, ty_id: u32) -> bool {
    let Some(ty) = metadata.types().resolve(ty_id) else {
        return false;
    };
    match &ty.type_def {
        scale_info::TypeDef::Tuple(t) => t.fields.is_empty(),
        scale_info::TypeDef::Composite(c) => c.fields.is_empty(),
        _ => false,
    }
}

/// Encode the zero/default value for a type. Used for unknown signed extensions
/// where we don't know the semantic meaning but need to produce valid SCALE bytes.
fn encode_zero_value(
    buf: &mut Vec<u8>,
    ty_id: u32,
    metadata: &Metadata,
) -> Result<(), WasmDotError> {
    let Some(ty) = metadata.types().resolve(ty_id) else {
        return Ok(()); // Unknown type — skip
    };
    match &ty.type_def {
        scale_info::TypeDef::Primitive(p) => {
            use scale_info::TypeDefPrimitive;
            let zeros: usize = match p {
                TypeDefPrimitive::Bool | TypeDefPrimitive::U8 | TypeDefPrimitive::I8 => 1,
                TypeDefPrimitive::U16 | TypeDefPrimitive::I16 => 2,
                TypeDefPrimitive::U32 | TypeDefPrimitive::I32 => 4,
                TypeDefPrimitive::U64 | TypeDefPrimitive::I64 => 8,
                TypeDefPrimitive::U128 | TypeDefPrimitive::I128 => 16,
                TypeDefPrimitive::U256 | TypeDefPrimitive::I256 => 32,
                TypeDefPrimitive::Str | TypeDefPrimitive::Char => {
                    buf.push(0x00); // empty compact-encoded string/char
                    return Ok(());
                }
            };
            buf.extend_from_slice(&vec![0u8; zeros]);
        }
        scale_info::TypeDef::Compact(_) => {
            buf.push(0x00); // Compact(0)
        }
        scale_info::TypeDef::Variant(v) => {
            // Use first variant (index 0 or lowest)
            if let Some(variant) = v.variants.first() {
                buf.push(variant.index);
                for field in &variant.fields {
                    encode_zero_value(buf, field.ty.id, metadata)?;
                }
            }
        }
        scale_info::TypeDef::Composite(c) => {
            for field in &c.fields {
                encode_zero_value(buf, field.ty.id, metadata)?;
            }
        }
        scale_info::TypeDef::Sequence(_) | scale_info::TypeDef::Array(_) => {
            buf.push(0x00); // empty sequence
        }
        _ => {} // BitSequence, etc. — skip
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests require real metadata - will be added with test fixtures
    // For now, unit tests are in calls.rs for the encoding logic
}
