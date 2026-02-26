//! Transaction parsing for DOT
//!
//! Parses raw extrinsic bytes into structured data.
//!
//! Supports two modes of pallet/method resolution:
//! - **Dynamic (metadata-based)**: Uses runtime metadata to resolve pallet and call names
//!   from their indices. This is the preferred approach as it handles runtime upgrades
//!   and chain-specific index differences automatically.
//! - **Hardcoded fallback**: Uses a static mapping of known pallet/method indices.
//!   Used when no metadata is provided in the parsing context.

use crate::address::encode_ss58;
use crate::error::WasmDotError;
use crate::transaction::Transaction;
use crate::types::{AddressFormat, Era, ParseContext};
use serde::{Deserialize, Serialize};

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

    let sender = tx.sender(prefix);
    let id = tx.id();

    // Parse the call data (with optional metadata for dynamic resolution)
    let method = parse_call_data(tx.call_data(), prefix, metadata.as_ref())?;

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

/// Decode metadata from raw bytes
fn decode_metadata(metadata_bytes: &[u8]) -> Result<subxt_core::metadata::Metadata, WasmDotError> {
    subxt_core::metadata::decode_from(metadata_bytes)
        .map_err(|e| WasmDotError::InvalidInput(format!("Failed to decode metadata: {}", e)))
}

/// Resolve pallet and call names from metadata using indices.
///
/// Returns `(pallet_name, call_name)` in JS-friendly format:
/// - Pallet names are lowercased (e.g., "Balances" -> "balances")
/// - Call names are converted from snake_case to camelCase
///   (e.g., "transfer_keep_alive" -> "transferKeepAlive")
fn resolve_call_from_metadata(
    metadata: &subxt_core::metadata::Metadata,
    pallet_index: u8,
    method_index: u8,
) -> Option<(String, String)> {
    let pallet = metadata.pallet_by_index(pallet_index)?;
    let variant = pallet.call_variant_by_index(method_index)?;

    let pallet_name = pallet.name().to_lowercase();
    let call_name = snake_to_camel(&variant.name);

    Some((pallet_name, call_name))
}

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

/// Parse call data into method info.
///
/// When metadata is provided, uses dynamic resolution via `pallet_by_index()` and
/// `call_variant_by_index()`. Falls back to hardcoded mapping otherwise.
fn parse_call_data(
    call_data: &[u8],
    address_prefix: u16,
    metadata: Option<&subxt_core::metadata::Metadata>,
) -> Result<ParsedMethod, WasmDotError> {
    let (method, _) = parse_call_data_with_size(call_data, address_prefix, metadata, 0)?;
    Ok(method)
}

/// Parse call data, returning the parsed method and total bytes consumed.
/// Required for batch parsing where calls are concatenated without length prefixes.
fn parse_call_data_with_size(
    call_data: &[u8],
    address_prefix: u16,
    metadata: Option<&subxt_core::metadata::Metadata>,
    depth: usize,
) -> Result<(ParsedMethod, usize), WasmDotError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(WasmDotError::InvalidTransaction(
            "exceeded maximum nesting depth for batch/proxy calls".to_string(),
        ));
    }
    if call_data.len() < 2 {
        return Err(WasmDotError::InvalidTransaction(
            "call data too short".to_string(),
        ));
    }

    let pallet_index = call_data[0];
    let method_index = call_data[1];
    let args_data = &call_data[2..];

    // Resolve pallet and method names: prefer metadata, fall back to hardcoded
    let (pallet, name) = if let Some(md) = metadata {
        resolve_call_from_metadata(md, pallet_index, method_index).unwrap_or_else(|| {
            let (p, n) = resolve_call_hardcoded(pallet_index, method_index);
            (p.to_string(), n.to_string())
        })
    } else {
        let (p, n) = resolve_call_hardcoded(pallet_index, method_index);
        (p.to_string(), n.to_string())
    };

    // Parse args based on method, getting bytes consumed
    let (args, args_consumed) =
        parse_method_args_with_size(&pallet, &name, args_data, address_prefix, metadata, depth)?;

    Ok((
        ParsedMethod {
            pallet,
            name,
            pallet_index,
            method_index,
            args,
        },
        2 + args_consumed, // 2 bytes for pallet + method indices
    ))
}

/// Parse method-specific arguments, returning (value, bytes_consumed).
/// The size tracking is needed for batch parsing.
fn parse_method_args_with_size(
    pallet: &str,
    method: &str,
    args_data: &[u8],
    address_prefix: u16,
    metadata: Option<&subxt_core::metadata::Metadata>,
    depth: usize,
) -> Result<(serde_json::Value, usize), WasmDotError> {
    match (pallet, method) {
        // Handle both legacy name ("transfer") and metadata-resolved name ("transferAllowDeath")
        ("balances", "transfer")
        | ("balances", "transferAllowDeath")
        | ("balances", "transferKeepAlive") => parse_transfer_args(args_data, address_prefix),
        ("balances", "transferAll") => parse_transfer_all_args(args_data, address_prefix),
        ("staking", "bond") => parse_bond_args(args_data, address_prefix),
        ("staking", "bondExtra") | ("staking", "unbond") => parse_compact_value_args(args_data),
        ("staking", "withdrawUnbonded") => parse_withdraw_unbonded_args(args_data),
        ("staking", "chill") => Ok((serde_json::json!({}), 0)),
        ("staking", "payoutStakers") => parse_payout_stakers_args(args_data, address_prefix),
        ("proxy", "addProxy") | ("proxy", "removeProxy") => {
            parse_proxy_args(args_data, address_prefix, metadata)
        }
        ("proxy", "createPure") => parse_create_pure_args(args_data, metadata),
        ("proxy", "proxy") => parse_proxy_proxy_args(args_data, address_prefix, metadata, depth),
        ("utility", "batch") | ("utility", "batchAll") => {
            parse_batch_args(args_data, address_prefix, metadata, depth)
        }
        _ => {
            // Unknown methods: consume all remaining bytes
            Ok((
                serde_json::json!({
                    "raw": format!("0x{}", hex::encode(args_data))
                }),
                args_data.len(),
            ))
        }
    }
}

/// Parse transfer arguments (dest, value) → (json, bytes_consumed)
fn parse_transfer_args(
    args: &[u8],
    address_prefix: u16,
) -> Result<(serde_json::Value, usize), WasmDotError> {
    let (dest, mut cursor) = parse_multi_address(args, address_prefix)?;
    let (value, value_size) = decode_compact(&args[cursor..])?;
    cursor += value_size;

    Ok((
        serde_json::json!({
            "dest": dest,
            "value": value.to_string()
        }),
        cursor,
    ))
}

/// Parse transferAll arguments (dest, keepAlive) → (json, bytes_consumed)
fn parse_transfer_all_args(
    args: &[u8],
    address_prefix: u16,
) -> Result<(serde_json::Value, usize), WasmDotError> {
    let (dest, mut cursor) = parse_multi_address(args, address_prefix)?;
    if cursor >= args.len() {
        return Err(WasmDotError::InvalidTransaction(
            "truncated transferAll args: missing keepAlive byte".to_string(),
        ));
    }
    let keep_alive = args[cursor] != 0;
    cursor += 1;

    Ok((
        serde_json::json!({
            "dest": dest,
            "keepAlive": keep_alive
        }),
        cursor,
    ))
}

/// Parse bond arguments: value (compact u128) + payee → (json, bytes_consumed)
///
/// Note: older runtimes had a controller field before value, but modern
/// Polkadot runtimes (spec >= 9420) removed it. We parse the modern format.
fn parse_bond_args(
    args: &[u8],
    address_prefix: u16,
) -> Result<(serde_json::Value, usize), WasmDotError> {
    let mut cursor = 0;

    // Value (compact u128)
    let (value, value_size) = decode_compact(args)?;
    cursor += value_size;

    // Payee
    let payee = if cursor < args.len() {
        let payee_type = args[cursor];
        cursor += 1;
        match payee_type {
            0 => "Staked".to_string(),
            1 => "Stash".to_string(),
            2 => "Controller".to_string(),
            3 => {
                // Account variant
                if cursor + 32 <= args.len() {
                    let pubkey = &args[cursor..cursor + 32];
                    cursor += 32;
                    encode_ss58(pubkey, address_prefix)?
                } else {
                    "Unknown".to_string()
                }
            }
            _ => "Unknown".to_string(),
        }
    } else {
        "Staked".to_string()
    };

    Ok((
        serde_json::json!({
            "value": value.to_string(),
            "payee": payee
        }),
        cursor,
    ))
}

/// Parse args with a single compact u128 value (used by unbond, bondExtra)
fn parse_compact_value_args(args: &[u8]) -> Result<(serde_json::Value, usize), WasmDotError> {
    let (value, consumed) = decode_compact(args)?;
    Ok((
        serde_json::json!({
            "value": value.to_string()
        }),
        consumed,
    ))
}

/// Parse withdrawUnbonded arguments: u32 numSlashingSpans (LE, not compact)
fn parse_withdraw_unbonded_args(args: &[u8]) -> Result<(serde_json::Value, usize), WasmDotError> {
    if args.len() < 4 {
        return Err(WasmDotError::InvalidTransaction(
            "truncated withdrawUnbonded args".to_string(),
        ));
    }
    let num_slashing_spans = u32::from_le_bytes([args[0], args[1], args[2], args[3]]);
    Ok((
        serde_json::json!({
            "numSlashingSpans": num_slashing_spans
        }),
        4,
    ))
}

/// Parse payoutStakers arguments: AccountId32 (32 bytes raw, NOT MultiAddress) + u32 era (LE)
fn parse_payout_stakers_args(
    args: &[u8],
    address_prefix: u16,
) -> Result<(serde_json::Value, usize), WasmDotError> {
    if args.len() < 36 {
        return Err(WasmDotError::InvalidTransaction(
            "truncated payoutStakers args".to_string(),
        ));
    }
    let validator = encode_ss58(&args[0..32], address_prefix)?;
    let era = u32::from_le_bytes([args[32], args[33], args[34], args[35]]);
    Ok((
        serde_json::json!({
            "validatorStash": validator,
            "era": era
        }),
        36,
    ))
}

/// Parse addProxy/removeProxy arguments: MultiAddress delegate + u8 proxyType + u32 delay (LE)
fn parse_proxy_args(
    args: &[u8],
    address_prefix: u16,
    metadata: Option<&subxt_core::metadata::Metadata>,
) -> Result<(serde_json::Value, usize), WasmDotError> {
    let (delegate, mut cursor) = parse_multi_address(args, address_prefix)?;

    if cursor + 5 > args.len() {
        return Err(WasmDotError::InvalidTransaction(
            "truncated proxy args".to_string(),
        ));
    }

    let proxy_type = resolve_proxy_type(args[cursor], metadata);
    cursor += 1;

    let delay = u32::from_le_bytes([
        args[cursor],
        args[cursor + 1],
        args[cursor + 2],
        args[cursor + 3],
    ]);
    cursor += 4;

    Ok((
        serde_json::json!({
            "delegate": delegate,
            "proxy_type": proxy_type,
            "delay": delay
        }),
        cursor,
    ))
}

/// Parse createPure arguments: u8 proxyType + u32 delay (LE) + u16 index (LE)
fn parse_create_pure_args(
    args: &[u8],
    metadata: Option<&subxt_core::metadata::Metadata>,
) -> Result<(serde_json::Value, usize), WasmDotError> {
    if args.len() < 7 {
        return Err(WasmDotError::InvalidTransaction(
            "truncated createPure args".to_string(),
        ));
    }
    let proxy_type = resolve_proxy_type(args[0], metadata);
    let delay = u32::from_le_bytes([args[1], args[2], args[3], args[4]]);
    let index = u16::from_le_bytes([args[5], args[6]]);

    Ok((
        serde_json::json!({
            "proxy_type": proxy_type,
            "delay": delay,
            "index": index
        }),
        7,
    ))
}

/// Parse batch/batchAll arguments: compact(count) + concatenated call bytes
fn parse_batch_args(
    args: &[u8],
    address_prefix: u16,
    metadata: Option<&subxt_core::metadata::Metadata>,
    depth: usize,
) -> Result<(serde_json::Value, usize), WasmDotError> {
    let (count, count_size) = decode_compact(args)?;
    if count > MAX_BATCH_SIZE as u128 {
        return Err(WasmDotError::InvalidTransaction(format!(
            "batch call count {} exceeds maximum {}",
            count, MAX_BATCH_SIZE,
        )));
    }
    let count = count as usize;
    let mut cursor = count_size;

    let mut calls = Vec::with_capacity(count);
    for _ in 0..count {
        let (method, consumed) =
            parse_call_data_with_size(&args[cursor..], address_prefix, metadata, depth + 1)?;
        cursor += consumed;
        calls.push(serde_json::to_value(&method).map_err(|e| {
            WasmDotError::InvalidTransaction(format!("failed to serialize batch call: {}", e))
        })?);
    }

    Ok((serde_json::json!({ "calls": calls }), cursor))
}

/// Parse proxy.proxy arguments: MultiAddress real + Option<u8> forceProxyType + nested call
fn parse_proxy_proxy_args(
    args: &[u8],
    address_prefix: u16,
    metadata: Option<&subxt_core::metadata::Metadata>,
    depth: usize,
) -> Result<(serde_json::Value, usize), WasmDotError> {
    let (real, mut cursor) = parse_multi_address(args, address_prefix)?;

    // Option<ProxyType>: 0x00 = None, 0x01 = Some(type)
    if cursor >= args.len() {
        return Err(WasmDotError::InvalidTransaction(
            "truncated proxy.proxy args".to_string(),
        ));
    }

    let force_proxy_type = if args[cursor] == 0x01 {
        cursor += 1;
        if cursor >= args.len() {
            return Err(WasmDotError::InvalidTransaction(
                "truncated proxy type".to_string(),
            ));
        }
        let pt = resolve_proxy_type(args[cursor], metadata);
        cursor += 1;
        Some(pt)
    } else {
        cursor += 1; // skip the 0x00 None marker
        None
    };

    // Remaining bytes are the nested call
    let (call, consumed) =
        parse_call_data_with_size(&args[cursor..], address_prefix, metadata, depth + 1)?;
    cursor += consumed;

    let call_value = serde_json::to_value(&call).map_err(|e| {
        WasmDotError::InvalidTransaction(format!("failed to serialize proxy call: {}", e))
    })?;

    let mut result = serde_json::json!({
        "real": real,
        "call": call_value
    });
    if let Some(pt) = force_proxy_type {
        result["forceProxyType"] = serde_json::json!(pt);
    }

    Ok((result, cursor))
}

/// Parse a MultiAddress from bytes, returns (address_string, bytes_consumed)
fn parse_multi_address(args: &[u8], address_prefix: u16) -> Result<(String, usize), WasmDotError> {
    if args.is_empty() {
        return Err(WasmDotError::InvalidTransaction(
            "empty MultiAddress".to_string(),
        ));
    }
    let variant = args[0];
    if variant == 0x00 {
        // Id variant: 1 byte variant + 32 bytes pubkey
        if args.len() < 33 {
            return Err(WasmDotError::InvalidTransaction(
                "truncated MultiAddress".to_string(),
            ));
        }
        let address = encode_ss58(&args[1..33], address_prefix)?;
        Ok((address, 33))
    } else {
        Err(WasmDotError::InvalidTransaction(format!(
            "Unsupported MultiAddress variant: {}",
            variant
        )))
    }
}

/// Resolve proxy type name from metadata, falling back to hardcoded Polkadot mainnet mapping.
fn resolve_proxy_type(
    proxy_type_byte: u8,
    metadata: Option<&subxt_core::metadata::Metadata>,
) -> String {
    if let Some(md) = metadata {
        if let Some(name) = resolve_proxy_type_from_metadata(md, proxy_type_byte) {
            return name;
        }
    }
    // Fallback: Polkadot mainnet proxy type indices
    match proxy_type_byte {
        0 => "Any".to_string(),
        1 => "NonTransfer".to_string(),
        2 => "Governance".to_string(),
        3 => "Staking".to_string(),
        4 => "IdentityJudgement".to_string(),
        5 => "CancelProxy".to_string(),
        6 => "Auction".to_string(),
        7 => "NominationPools".to_string(),
        _ => format!("Unknown({})", proxy_type_byte),
    }
}

/// Look up the ProxyType enum variant name from chain metadata.
fn resolve_proxy_type_from_metadata(
    metadata: &subxt_core::metadata::Metadata,
    proxy_type_byte: u8,
) -> Option<String> {
    let proxy_pallet = metadata.pallet_by_name("Proxy")?;
    let call_ty_id = proxy_pallet.call_ty_id()?;
    let call_ty = metadata.types().resolve(call_ty_id)?;
    if let scale_info::TypeDef::Variant(ref variants) = call_ty.type_def {
        // Find addProxy or add_proxy variant
        let add_proxy = variants
            .variants
            .iter()
            .find(|v| v.name == "add_proxy" || v.name == "addProxy")?;
        // Find the proxy_type field
        let pt_field = add_proxy
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("proxy_type"))?;
        // Resolve the ProxyType enum type
        let pt_ty = metadata.types().resolve(pt_field.ty.id)?;
        if let scale_info::TypeDef::Variant(ref pt_variants) = pt_ty.type_def {
            let variant = pt_variants
                .variants
                .iter()
                .find(|v| v.index == proxy_type_byte)?;
            return Some(variant.name.clone());
        }
    }
    None
}

/// Decode SCALE compact encoding, returning (value, bytes_consumed)
fn decode_compact(bytes: &[u8]) -> Result<(u128, usize), WasmDotError> {
    if bytes.is_empty() {
        return Err(WasmDotError::ScaleDecodeError(
            "empty compact encoding".to_string(),
        ));
    }

    let mode = bytes[0] & 0b11;
    match mode {
        0b00 => Ok(((bytes[0] >> 2) as u128, 1)),
        0b01 => {
            if bytes.len() < 2 {
                return Err(WasmDotError::ScaleDecodeError(
                    "truncated compact".to_string(),
                ));
            }
            let value = u16::from_le_bytes([bytes[0], bytes[1]]) >> 2;
            Ok((value as u128, 2))
        }
        0b10 => {
            if bytes.len() < 4 {
                return Err(WasmDotError::ScaleDecodeError(
                    "truncated compact".to_string(),
                ));
            }
            let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) >> 2;
            Ok((value as u128, 4))
        }
        0b11 => {
            let len = (bytes[0] >> 2) + 4;
            if bytes.len() < 1 + len as usize {
                return Err(WasmDotError::ScaleDecodeError(
                    "truncated compact".to_string(),
                ));
            }
            let mut value = 0u128;
            for i in 0..len as usize {
                value |= (bytes[1 + i] as u128) << (8 * i);
            }
            Ok((value, 1 + len as usize))
        }
        _ => unreachable!(),
    }
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
    }

    #[test]
    fn test_parse_call_data_too_short() {
        let call_data = vec![5u8]; // only 1 byte
        let result = parse_call_data(&call_data, 42, None);
        assert!(result.is_err());
    }
}
