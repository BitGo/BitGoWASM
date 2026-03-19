//! Transaction parsing for DOT
//!
//! Parses raw extrinsic bytes into structured data.
//!
//! Supports two modes of call_data decoding:
//! - **Metadata-driven (generic)**: Uses `scale_value::scale::decode_as_type()` with the
//!   runtime metadata type registry to decode any call generically. No per-method parsers needed.
//! - **Hardcoded fallback**: When no metadata is provided, resolves pallet/method names from
//!   a static mapping and returns raw hex args (cannot decode without type info).

use crate::address::encode_ss58;
use crate::error::WasmDotError;
use crate::transaction::Transaction;
use crate::types::{AddressFormat, Era, ParseContext};
use serde::{Deserialize, Serialize};
use subxt_core::ext::scale_value::{Composite, Primitive, Value, ValueDef, Variant};

/// Maximum nesting depth for batch/proxy recursive parsing.
/// Substrate limits nesting on-chain, so 10 is generous.
const MAX_NESTING_DEPTH: usize = 10;

/// Maximum number of calls allowed in a batch.
/// Prevents absurd memory allocation from untrusted compact count.
const MAX_BATCH_SIZE: usize = 256;

/// Parsed transaction data
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedTransaction {
    /// Transaction ID (hash, if signed)
    pub id: Option<String>,
    /// Sender address (SS58 encoded)
    pub sender: Option<String>,
    /// Account nonce
    pub nonce: u32,
    /// Tip amount (in planck)
    pub tip: String, // String for BigInt compatibility
    /// Transaction era
    pub era: Era,
    /// Decoded method/call
    pub method: ParsedMethod,
    /// Whether transaction is signed
    pub is_signed: bool,
}

/// Parsed method/call data
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedMethod {
    /// Pallet name (e.g., "balances")
    pub pallet: String,
    /// Method name (e.g., "transferKeepAlive")
    pub name: String,
    /// Pallet index
    pub pallet_index: u8,
    /// Method index
    pub method_index: u8,
    /// Method arguments (decoded if known)
    pub args: serde_json::Value,
}

/// Parse a raw transaction
///
/// # Arguments
/// * `bytes` - Raw extrinsic bytes
/// * `context` - Optional parsing context with chain material
#[must_use = "parsed transaction result should not be discarded"]
pub fn parse_transaction(
    bytes: &[u8],
    context: Option<ParseContext>,
) -> Result<ParsedTransaction, WasmDotError> {
    // Extract prefix and decode metadata BEFORE moving context into from_bytes.
    // This avoids cloning the entire context (which contains megabytes of metadata hex).
    let prefix = context
        .as_ref()
        .map(|ctx| AddressFormat::from_chain_name(&ctx.material.chain_name).prefix())
        .unwrap_or(42); // Default to Substrate generic

    let metadata = context
        .as_ref()
        .and_then(|ctx| decode_metadata(&ctx.material.metadata).ok());

    let tx = Transaction::from_bytes(bytes, context, metadata.as_ref())?;

    build_parsed_transaction(&tx, prefix, metadata.as_ref())
}

/// Parse a pre-deserialized Transaction into structured data.
///
/// Same logic as `parse_transaction(bytes, context)` but skips deserialization.
/// Used when the caller already has a `Transaction` from `fromBytes()`.
pub fn parse_from_transaction(
    tx: &Transaction,
    context: Option<&ParseContext>,
) -> Result<ParsedTransaction, WasmDotError> {
    let prefix = context
        .map(|ctx| AddressFormat::from_chain_name(&ctx.material.chain_name).prefix())
        .unwrap_or(42);

    let metadata = context.and_then(|ctx| decode_metadata(&ctx.material.metadata).ok());

    build_parsed_transaction(tx, prefix, metadata.as_ref())
}

/// Shared logic for building ParsedTransaction from an already-deserialized Transaction.
fn build_parsed_transaction(
    tx: &Transaction,
    prefix: u16,
    metadata: Option<&subxt_core::metadata::Metadata>,
) -> Result<ParsedTransaction, WasmDotError> {
    let sender = tx.sender(prefix);
    let id = tx.id();

    // Parse the call data (with optional metadata for dynamic resolution)
    let method = parse_call_data(tx.call_data(), prefix, metadata)?;

    Ok(ParsedTransaction {
        id,
        sender,
        nonce: tx.nonce(),
        tip: tx.tip().to_string(),
        era: tx.era().clone(),
        method,
        is_signed: tx.is_signed(),
    })
}

// Re-use the central decode_metadata from transaction.rs
use crate::transaction::decode_metadata;

/// Parse call data into method info.
///
/// When metadata is provided, uses generic metadata-driven decoding via
/// `scale_value::scale::decode_as_type()`. Falls back to hardcoded name
/// resolution with raw hex args when no metadata is available.
fn parse_call_data(
    call_data: &[u8],
    address_prefix: u16,
    metadata: Option<&subxt_core::metadata::Metadata>,
) -> Result<ParsedMethod, WasmDotError> {
    if call_data.len() < 2 {
        return Err(WasmDotError::InvalidTransaction(
            "call data too short".to_string(),
        ));
    }

    if let Some(md) = metadata {
        // Full generic decoding via type registry
        decode_call_data_from_metadata(call_data, address_prefix, md)
    } else {
        // Fallback: names from hardcoded mapping, args as raw hex
        let (pallet, name) = resolve_call_hardcoded(call_data[0], call_data[1]);
        Ok(ParsedMethod {
            pallet: pallet.to_string(),
            name: name.to_string(),
            pallet_index: call_data[0],
            method_index: call_data[1],
            args: serde_json::json!({ "raw": format!("0x{}", hex::encode(&call_data[2..])) }),
        })
    }
}

// =============================================================================
// Metadata-driven generic decoding
// =============================================================================

/// Decode call_data bytes using metadata type registry.
/// Returns ParsedMethod with fully decoded args as JSON.
fn decode_call_data_from_metadata(
    call_data: &[u8],
    address_prefix: u16,
    metadata: &subxt_core::metadata::Metadata,
) -> Result<ParsedMethod, WasmDotError> {
    let call_ty_id = metadata.outer_enums().call_enum_ty();
    let mut cursor = call_data;
    let decoded = subxt_core::ext::scale_value::scale::decode_as_type(
        &mut cursor,
        call_ty_id,
        metadata.types(),
    )
    .map_err(|e| WasmDotError::ScaleDecodeError(format!("failed to decode call_data: {}", e)))?;

    value_to_parsed_method(
        &decoded,
        call_data[0],
        call_data[1],
        address_prefix,
        metadata,
        0,
    )
}

/// Convert a decoded RuntimeCall Value into a ParsedMethod.
///
/// The Value tree structure is:
/// ```text
/// Variant("PalletName") {
///     values: Named([
///         ("method_name", Variant("method_name") {
///             values: Named([("arg1", ...), ("arg2", ...)])
///         })
///     ])
/// }
/// ```
fn value_to_parsed_method(
    value: &Value<u32>,
    pallet_index: u8,
    method_index: u8,
    address_prefix: u16,
    metadata: &subxt_core::metadata::Metadata,
    depth: usize,
) -> Result<ParsedMethod, WasmDotError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(WasmDotError::InvalidTransaction(
            "exceeded maximum nesting depth for batch/proxy calls".to_string(),
        ));
    }

    // Outer variant = pallet name
    let outer = match &value.value {
        ValueDef::Variant(v) => v,
        _ => {
            return Err(WasmDotError::ScaleDecodeError(
                "expected RuntimeCall to be a Variant".to_string(),
            ))
        }
    };

    let pallet_name = outer.name.to_lowercase();

    // The pallet variant has one named field: the method call variant
    let method_variant = match &outer.values {
        Composite::Named(fields) if fields.len() == 1 => match &fields[0].1.value {
            ValueDef::Variant(v) => v,
            _ => {
                return Err(WasmDotError::ScaleDecodeError(
                    "expected pallet call to be a Variant".to_string(),
                ))
            }
        },
        _ => {
            return Err(WasmDotError::ScaleDecodeError(
                "expected pallet variant to have one named field".to_string(),
            ))
        }
    };

    let method_name = snake_to_camel(&method_variant.name);

    // Extract args from the method variant's fields
    let args = method_fields_to_json(&method_variant.values, address_prefix, metadata, depth)?;

    Ok(ParsedMethod {
        pallet: pallet_name,
        name: method_name,
        pallet_index,
        method_index,
        args,
    })
}

/// Convert method variant fields into a JSON object.
fn method_fields_to_json(
    fields: &Composite<u32>,
    address_prefix: u16,
    metadata: &subxt_core::metadata::Metadata,
    depth: usize,
) -> Result<serde_json::Value, WasmDotError> {
    match fields {
        Composite::Named(named_fields) => {
            let mut map = serde_json::Map::new();
            for (name, val) in named_fields {
                let json_key = field_name_to_json_key(name);
                let json_val = value_to_json(val, address_prefix, metadata, depth)?;
                map.insert(json_key, json_val);
            }
            Ok(serde_json::Value::Object(map))
        }
        Composite::Unnamed(vals) if vals.is_empty() => Ok(serde_json::json!({})),
        Composite::Unnamed(_) => {
            // Unnamed fields: build an array
            let mut arr = Vec::new();
            for val in fields.values() {
                arr.push(value_to_json(val, address_prefix, metadata, depth)?);
            }
            Ok(serde_json::Value::Array(arr))
        }
    }
}

/// Convert field names to match existing JSON output format.
/// Most field names stay as-is (snake_case), but some need special handling.
fn field_name_to_json_key(name: &str) -> String {
    match name {
        // withdrawUnbonded uses camelCase "numSlashingSpans" in JSON
        "num_slashing_spans" => "numSlashingSpans".to_string(),
        // payoutStakers uses camelCase "validatorStash" in JSON
        "validator_stash" => "validatorStash".to_string(),
        // transferAll uses camelCase "keepAlive" in JSON
        "keep_alive" => "keepAlive".to_string(),
        // proxy.proxy uses camelCase "forceProxyType" in JSON
        "force_proxy_type" => "forceProxyType".to_string(),
        // bondExtra uses camelCase "maxAdditional" but we rename to "value" for consistency
        // Actually, let's keep metadata field names as-is and handle via snake_to_camel
        _ => name.to_string(),
    }
}

/// Convert a decoded Value tree into serde_json::Value with post-processing.
fn value_to_json(
    value: &Value<u32>,
    address_prefix: u16,
    metadata: &subxt_core::metadata::Metadata,
    depth: usize,
) -> Result<serde_json::Value, WasmDotError> {
    let type_id = value.context;

    // Check if this is an AccountId32 type
    if is_account_id_type(type_id, metadata) {
        return extract_account_id(value, address_prefix);
    }

    // Check if this is a RuntimeCall type (for nested calls in batch/proxy)
    if is_runtime_call_type(type_id, metadata) {
        return runtime_call_to_json(value, address_prefix, metadata, depth);
    }

    // Check if this is a Vec<RuntimeCall> (for batch calls field)
    if is_vec_of_runtime_call(type_id, metadata) {
        return vec_runtime_call_to_json(value, address_prefix, metadata, depth);
    }

    match &value.value {
        ValueDef::Primitive(p) => primitive_to_json(p, type_id, metadata),
        ValueDef::Variant(v) => variant_to_json(v, type_id, address_prefix, metadata, depth),
        ValueDef::Composite(c) => composite_to_json(c, address_prefix, metadata, depth),
        ValueDef::BitSequence(_) => Ok(serde_json::Value::String("BitSequence".to_string())),
    }
}

/// Convert a primitive value to JSON.
/// U128 values are always serialized as strings for BigInt compatibility.
fn primitive_to_json(
    p: &Primitive,
    type_id: u32,
    metadata: &subxt_core::metadata::Metadata,
) -> Result<serde_json::Value, WasmDotError> {
    match p {
        Primitive::Bool(b) => Ok(serde_json::Value::Bool(*b)),
        Primitive::U128(n) => {
            // Check if the underlying type is a small integer (u8, u16, u32)
            // If so, emit as number. Otherwise emit as string for BigInt compatibility.
            if is_small_uint_type(type_id, metadata) {
                Ok(serde_json::Value::Number(serde_json::Number::from(
                    *n as u64,
                )))
            } else {
                Ok(serde_json::Value::String(n.to_string()))
            }
        }
        Primitive::I128(n) => Ok(serde_json::Value::String(n.to_string())),
        Primitive::String(s) => Ok(serde_json::Value::String(s.clone())),
        Primitive::Char(c) => Ok(serde_json::Value::String(c.to_string())),
        Primitive::U256(bytes) | Primitive::I256(bytes) => Ok(serde_json::Value::String(format!(
            "0x{}",
            hex::encode(bytes)
        ))),
    }
}

/// Check if a type_id refers to a small unsigned integer (u8, u16, u32) that should
/// be serialized as a JSON number rather than a string.
fn is_small_uint_type(type_id: u32, metadata: &subxt_core::metadata::Metadata) -> bool {
    let Some(ty) = metadata.types().resolve(type_id) else {
        return false;
    };
    // Check for Compact<T> wrapper: the inner type determines the size
    if let scale_info::TypeDef::Compact(compact) = &ty.type_def {
        return is_small_uint_type(compact.type_param.id, metadata);
    }
    matches!(
        ty.type_def,
        scale_info::TypeDef::Primitive(
            scale_info::TypeDefPrimitive::U8
                | scale_info::TypeDefPrimitive::U16
                | scale_info::TypeDefPrimitive::U32
        )
    )
}

/// Convert a variant to JSON.
/// Fieldless variants (like enum values) become just the variant name as a string.
fn variant_to_json(
    v: &Variant<u32>,
    _type_id: u32,
    address_prefix: u16,
    metadata: &subxt_core::metadata::Metadata,
    depth: usize,
) -> Result<serde_json::Value, WasmDotError> {
    if v.values.is_empty() {
        // Fieldless variant: just the name (e.g., "Staked", "Staking", "Any")
        return Ok(serde_json::Value::String(v.name.clone()));
    }

    // MultiAddress variant: flatten to just the inner value
    // MultiAddress::Id(AccountId32) -> just the SS58 string
    if v.name == "Id" {
        // Check if it wraps an AccountId32
        if let Some(inner) = single_inner_value(&v.values) {
            if is_account_id_type(inner.context, metadata) {
                return extract_account_id(inner, address_prefix);
            }
        }
    }

    // Option::Some: unwrap to inner value
    if v.name == "Some" {
        if let Some(inner) = single_inner_value(&v.values) {
            return value_to_json(inner, address_prefix, metadata, depth);
        }
    }

    // Option::None
    if v.name == "None" && v.values.is_empty() {
        return Ok(serde_json::Value::Null);
    }

    // Generic variant with fields: convert fields to JSON
    let fields = method_fields_to_json(&v.values, address_prefix, metadata, depth)?;
    Ok(fields)
}

/// Convert a composite to JSON.
fn composite_to_json(
    c: &Composite<u32>,
    address_prefix: u16,
    metadata: &subxt_core::metadata::Metadata,
    depth: usize,
) -> Result<serde_json::Value, WasmDotError> {
    match c {
        Composite::Named(fields) => {
            let mut map = serde_json::Map::new();
            for (name, val) in fields {
                let json_key = field_name_to_json_key(name);
                let json_val = value_to_json(val, address_prefix, metadata, depth)?;
                map.insert(json_key, json_val);
            }
            Ok(serde_json::Value::Object(map))
        }
        Composite::Unnamed(vals) => {
            // Single-field unnamed composite: unwrap (handles Box<T>, newtype wrappers)
            if vals.len() == 1 {
                return value_to_json(&vals[0], address_prefix, metadata, depth);
            }
            let mut arr = Vec::new();
            for val in vals {
                arr.push(value_to_json(val, address_prefix, metadata, depth)?);
            }
            Ok(serde_json::Value::Array(arr))
        }
    }
}

/// Extract the single inner value from a composite (if it has exactly one field).
fn single_inner_value(c: &Composite<u32>) -> Option<&Value<u32>> {
    match c {
        Composite::Named(fields) if fields.len() == 1 => Some(&fields[0].1),
        Composite::Unnamed(vals) if vals.len() == 1 => Some(&vals[0]),
        _ => None,
    }
}

/// Check if a type_id refers to AccountId32 by inspecting its path in the registry.
fn is_account_id_type(type_id: u32, metadata: &subxt_core::metadata::Metadata) -> bool {
    metadata
        .types()
        .resolve(type_id)
        .map(|ty| {
            ty.path
                .segments
                .last()
                .map(|s| s == "AccountId32")
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Check if a type_id refers to the RuntimeCall enum type.
fn is_runtime_call_type(type_id: u32, metadata: &subxt_core::metadata::Metadata) -> bool {
    type_id == metadata.outer_enums().call_enum_ty()
}

/// Check if a type_id refers to Vec<RuntimeCall>.
fn is_vec_of_runtime_call(type_id: u32, metadata: &subxt_core::metadata::Metadata) -> bool {
    let Some(ty) = metadata.types().resolve(type_id) else {
        return false;
    };
    if let scale_info::TypeDef::Sequence(seq) = &ty.type_def {
        return is_runtime_call_type(seq.type_param.id, metadata);
    }
    false
}

/// Extract 32 bytes from an AccountId32 Value and SS58-encode.
fn extract_account_id(
    value: &Value<u32>,
    address_prefix: u16,
) -> Result<serde_json::Value, WasmDotError> {
    // AccountId32 is decoded as an unnamed composite of 32 byte values
    let bytes = extract_bytes_from_composite(value)?;
    if bytes.len() != 32 {
        return Err(WasmDotError::ScaleDecodeError(format!(
            "AccountId32 expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let address = encode_ss58(&bytes, address_prefix)?;
    Ok(serde_json::Value::String(address))
}

/// Extract raw bytes from a Value that represents a byte array/composite.
fn extract_bytes_from_composite(value: &Value<u32>) -> Result<Vec<u8>, WasmDotError> {
    match &value.value {
        ValueDef::Composite(Composite::Unnamed(vals)) => {
            let mut bytes = Vec::with_capacity(vals.len());
            for v in vals {
                match &v.value {
                    ValueDef::Primitive(Primitive::U128(n)) => bytes.push(*n as u8),
                    _ => {
                        return Err(WasmDotError::ScaleDecodeError(
                            "expected byte values in AccountId32 composite".to_string(),
                        ))
                    }
                }
            }
            Ok(bytes)
        }
        _ => Err(WasmDotError::ScaleDecodeError(
            "expected unnamed composite for AccountId32".to_string(),
        )),
    }
}

/// Convert a nested RuntimeCall Value into a serialized ParsedMethod JSON.
fn runtime_call_to_json(
    value: &Value<u32>,
    address_prefix: u16,
    metadata: &subxt_core::metadata::Metadata,
    depth: usize,
) -> Result<serde_json::Value, WasmDotError> {
    // Extract pallet_index and method_index from the variant
    let (pallet_index, method_index) = extract_call_indices(value, metadata)?;
    let parsed = value_to_parsed_method(
        value,
        pallet_index,
        method_index,
        address_prefix,
        metadata,
        depth + 1,
    )?;
    serde_json::to_value(&parsed).map_err(|e| {
        WasmDotError::InvalidTransaction(format!("failed to serialize nested call: {}", e))
    })
}

/// Convert a Vec<RuntimeCall> Value into a JSON array of serialized ParsedMethods.
fn vec_runtime_call_to_json(
    value: &Value<u32>,
    address_prefix: u16,
    metadata: &subxt_core::metadata::Metadata,
    depth: usize,
) -> Result<serde_json::Value, WasmDotError> {
    let calls = match &value.value {
        ValueDef::Composite(Composite::Unnamed(vals)) => vals,
        _ => {
            return Err(WasmDotError::ScaleDecodeError(
                "expected sequence for Vec<RuntimeCall>".to_string(),
            ))
        }
    };

    if calls.len() > MAX_BATCH_SIZE {
        return Err(WasmDotError::InvalidTransaction(format!(
            "batch call count {} exceeds maximum {}",
            calls.len(),
            MAX_BATCH_SIZE,
        )));
    }

    let mut arr = Vec::with_capacity(calls.len());
    for call_value in calls {
        let (pallet_index, method_index) = extract_call_indices(call_value, metadata)?;
        let parsed = value_to_parsed_method(
            call_value,
            pallet_index,
            method_index,
            address_prefix,
            metadata,
            depth + 1,
        )?;
        let json = serde_json::to_value(&parsed).map_err(|e| {
            WasmDotError::InvalidTransaction(format!("failed to serialize batch call: {}", e))
        })?;
        arr.push(json);
    }
    Ok(serde_json::Value::Array(arr))
}

/// Extract pallet and method indices from a RuntimeCall variant by looking up metadata.
fn extract_call_indices(
    value: &Value<u32>,
    metadata: &subxt_core::metadata::Metadata,
) -> Result<(u8, u8), WasmDotError> {
    let outer = match &value.value {
        ValueDef::Variant(v) => v,
        _ => {
            return Err(WasmDotError::ScaleDecodeError(
                "expected RuntimeCall variant".to_string(),
            ))
        }
    };

    // Look up pallet by name to get its index
    let pallet = metadata.pallet_by_name(&outer.name).ok_or_else(|| {
        WasmDotError::ScaleDecodeError(format!("pallet '{}' not found in metadata", outer.name))
    })?;
    let pallet_index = pallet.index();

    // Get inner method variant name
    let method_name = match &outer.values {
        Composite::Named(fields) if fields.len() == 1 => match &fields[0].1.value {
            ValueDef::Variant(v) => &v.name,
            _ => {
                return Err(WasmDotError::ScaleDecodeError(
                    "expected method variant".to_string(),
                ))
            }
        },
        _ => {
            return Err(WasmDotError::ScaleDecodeError(
                "expected pallet variant with one field".to_string(),
            ))
        }
    };

    // Look up method index from pallet call variants
    let method_variant = pallet.call_variant_by_name(method_name).ok_or_else(|| {
        WasmDotError::ScaleDecodeError(format!(
            "method '{}' not found in pallet '{}'",
            method_name, outer.name
        ))
    })?;

    Ok((pallet_index, method_variant.index))
}

// =============================================================================
// Hardcoded fallback (no metadata)
// =============================================================================

/// Resolve pallet and call names using the hardcoded static mapping.
///
/// This is the fallback when no metadata is available. It covers known
/// pallet indices for Polkadot, Kusama, and Westend.
fn resolve_call_hardcoded(pallet_index: u8, method_index: u8) -> (&'static str, &'static str) {
    match (pallet_index, method_index) {
        // Balances pallet
        // Polkadot: 5, Kusama: 4, Westend: 10
        (4, 0) | (5, 0) | (10, 0) => ("balances", "transfer"),
        (4, 3) | (5, 3) | (10, 3) => ("balances", "transferKeepAlive"),
        (4, 4) | (5, 4) | (10, 4) => ("balances", "transferAll"),

        // Staking pallet
        // Polkadot: 7, Kusama: 6, Westend: 8
        (6, 0) | (7, 0) | (8, 0) => ("staking", "bond"),
        (6, 1) | (7, 1) | (8, 1) => ("staking", "bondExtra"),
        (6, 2) | (7, 2) | (8, 2) => ("staking", "unbond"),
        (6, 3) | (7, 3) | (8, 3) => ("staking", "withdrawUnbonded"),
        (6, 6) | (7, 6) | (8, 6) => ("staking", "chill"),
        (6, 18) | (7, 18) | (8, 18) => ("staking", "payoutStakers"),

        // Proxy pallet
        // Polkadot: 29, Kusama: 29, Westend: 30
        (29, 0) | (30, 0) => ("proxy", "proxy"),
        (29, 1) | (30, 1) => ("proxy", "addProxy"),
        (29, 2) | (30, 2) => ("proxy", "removeProxy"),
        (29, 4) | (30, 4) => ("proxy", "createPure"),

        // Utility pallet
        // Polkadot: 26, Kusama: 24, Westend: 16
        (16, 0) | (24, 0) | (26, 0) => ("utility", "batch"),
        (16, 2) | (24, 2) | (26, 2) => ("utility", "batchAll"),

        // Unknown
        _ => ("unknown", "unknown"),
    }
}

/// Convert snake_case to camelCase.
///
/// Examples:
///   "transfer_keep_alive" -> "transferKeepAlive"
///   "bond" -> "bond"
///   "batch_all" -> "batchAll"
///   "payout_stakers" -> "payoutStakers"
fn snake_to_camel(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut capitalize_next = false;

    for ch in s.chars() {
        if ch == '_' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(ch.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test with a known transfer transaction hex from BitGoJS fixtures
    const TRANSFER_UNSIGNED: &str = "a80a03009f7b0675db59d19b4bd9c8c72eaabba75a9863d02b30115b8b3c3ca5c20f02540bfadb9bbae251d50121030000009d880f001000000067f9723393ef76214df0118c34bbbd3dbebc8ed46a10973a8c969d48fe7598c9149799bc9602cb5cf201f3425fb8d253b2d4e61fc119dcab3249f307f594754d00";

    #[test]
    fn test_parse_fixture_hex_does_not_panic() {
        let bytes = hex::decode(TRANSFER_UNSIGNED).unwrap();
        // This fixture includes signing payload bytes that don't parse as a standalone
        // extrinsic without context. The test verifies no panic occurs.
        let _result = parse_transaction(&bytes, None);
    }

    #[test]
    fn test_snake_to_camel_single_word() {
        assert_eq!(snake_to_camel("bond"), "bond");
    }

    #[test]
    fn test_snake_to_camel_two_words() {
        assert_eq!(snake_to_camel("batch_all"), "batchAll");
    }

    #[test]
    fn test_snake_to_camel_three_words() {
        assert_eq!(snake_to_camel("transfer_keep_alive"), "transferKeepAlive");
    }

    #[test]
    fn test_snake_to_camel_payout() {
        assert_eq!(snake_to_camel("payout_stakers"), "payoutStakers");
    }

    #[test]
    fn test_snake_to_camel_withdraw() {
        assert_eq!(snake_to_camel("withdraw_unbonded"), "withdrawUnbonded");
    }

    #[test]
    fn test_snake_to_camel_allow_death() {
        assert_eq!(snake_to_camel("transfer_allow_death"), "transferAllowDeath");
    }

    #[test]
    fn test_resolve_hardcoded_polkadot_balances() {
        assert_eq!(
            resolve_call_hardcoded(5, 3),
            ("balances", "transferKeepAlive")
        );
    }

    #[test]
    fn test_resolve_hardcoded_kusama_balances() {
        assert_eq!(
            resolve_call_hardcoded(4, 3),
            ("balances", "transferKeepAlive")
        );
    }

    #[test]
    fn test_resolve_hardcoded_westend_balances() {
        assert_eq!(
            resolve_call_hardcoded(10, 3),
            ("balances", "transferKeepAlive")
        );
    }

    #[test]
    fn test_resolve_hardcoded_unknown() {
        assert_eq!(resolve_call_hardcoded(255, 255), ("unknown", "unknown"));
    }

    #[test]
    fn test_parse_call_data_without_metadata() {
        // Polkadot balances::transferKeepAlive (pallet=5, method=3) with a dummy address + amount
        let mut call_data = vec![5u8, 3u8]; // pallet=5, method=3
        call_data.push(0x00); // MultiAddress::Id variant
        call_data.extend_from_slice(&[0u8; 32]); // dummy pubkey
        call_data.push(0x04); // compact amount = 1

        let result = parse_call_data(&call_data, 42, None).unwrap();
        assert_eq!(result.pallet, "balances");
        assert_eq!(result.name, "transferKeepAlive");
        assert_eq!(result.pallet_index, 5);
        assert_eq!(result.method_index, 3);
        // Without metadata, args should be raw hex
        assert!(result.args.get("raw").is_some());
    }

    #[test]
    fn test_parse_call_data_too_short() {
        let call_data = vec![5u8]; // only 1 byte
        let result = parse_call_data(&call_data, 42, None);
        assert!(result.is_err());
    }
}
