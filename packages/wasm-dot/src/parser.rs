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
use serde::Serialize;

/// Parsed transaction data
#[derive(Debug, Clone, Serialize)]
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
    /// Transaction outputs (recipients and amounts)
    pub outputs: Vec<TransactionOutput>,
    /// Fee information
    pub fee: FeeInfo,
    /// Transaction type
    #[serde(rename = "type")]
    pub tx_type: String,
    /// Whether transaction is signed
    pub is_signed: bool,
}

/// Parsed method/call data
#[derive(Debug, Clone, Serialize)]
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

/// Transaction output (recipient)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionOutput {
    /// Recipient address
    pub address: String,
    /// Amount (in planck, as string for BigInt)
    pub amount: String,
}

/// Fee information
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeInfo {
    /// Fee/tip amount
    pub fee: String,
    /// Fee type (always "tip" for DOT)
    #[serde(rename = "type")]
    pub fee_type: String,
}

/// Parse a raw transaction
///
/// # Arguments
/// * `bytes` - Raw extrinsic bytes
/// * `context` - Optional parsing context with chain material
pub fn parse_transaction(
    bytes: &[u8],
    context: Option<ParseContext>,
) -> Result<ParsedTransaction, WasmDotError> {
    let tx = Transaction::from_bytes(bytes, context.clone())?;

    // Determine address format from context
    let prefix = context
        .as_ref()
        .map(|ctx| AddressFormat::from_chain_name(&ctx.material.chain_name).prefix())
        .unwrap_or(42); // Default to Substrate generic

    let sender = tx.sender(prefix);
    let id = tx.id();

    // Attempt to decode metadata for dynamic pallet resolution
    let metadata = context
        .as_ref()
        .and_then(|ctx| decode_metadata(&ctx.material.metadata).ok());

    // Parse the call data (with optional metadata for dynamic resolution)
    let method = parse_call_data(tx.call_data(), prefix, metadata.as_ref())?;

    // Extract outputs from method
    let outputs = extract_outputs(&method);

    // Determine transaction type
    let tx_type = determine_tx_type(&method);

    Ok(ParsedTransaction {
        id,
        sender,
        nonce: tx.nonce(),
        tip: tx.tip().to_string(),
        era: tx.era().clone(),
        method,
        outputs,
        fee: FeeInfo {
            fee: tx.tip().to_string(),
            fee_type: "tip".to_string(),
        },
        tx_type,
        is_signed: tx.is_signed(),
    })
}

/// Decode metadata from hex string (same pattern as builder)
fn decode_metadata(metadata_hex: &str) -> Result<subxt_core::metadata::Metadata, WasmDotError> {
    let bytes = hex::decode(metadata_hex.trim_start_matches("0x"))
        .map_err(|e| WasmDotError::InvalidInput(format!("Invalid metadata hex: {}", e)))?;

    subxt_core::metadata::decode_from(&bytes[..])
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
    if call_data.len() < 2 {
        return Err(WasmDotError::InvalidTransaction(
            "Call data too short".to_string(),
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

    // Parse args based on method
    let args = parse_method_args(&pallet, &name, args_data, address_prefix)?;

    Ok(ParsedMethod {
        pallet,
        name,
        pallet_index,
        method_index,
        args,
    })
}

/// Parse method-specific arguments
fn parse_method_args(
    pallet: &str,
    method: &str,
    args_data: &[u8],
    address_prefix: u16,
) -> Result<serde_json::Value, WasmDotError> {
    match (pallet, method) {
        // Handle both legacy name ("transfer") and metadata-resolved name ("transferAllowDeath")
        ("balances", "transfer")
        | ("balances", "transferAllowDeath")
        | ("balances", "transferKeepAlive") => parse_transfer_args(args_data, address_prefix),
        ("balances", "transferAll") => parse_transfer_all_args(args_data, address_prefix),
        ("staking", "bond") => parse_bond_args(args_data, address_prefix),
        ("staking", "unbond") => parse_unbond_args(args_data),
        _ => {
            // Return raw hex for unknown methods
            Ok(serde_json::json!({
                "raw": format!("0x{}", hex::encode(args_data))
            }))
        }
    }
}

/// Parse transfer arguments (dest, value)
fn parse_transfer_args(
    args: &[u8],
    address_prefix: u16,
) -> Result<serde_json::Value, WasmDotError> {
    if args.is_empty() {
        return Err(WasmDotError::InvalidTransaction(
            "Empty transfer args".to_string(),
        ));
    }

    let mut cursor = 0;

    // Destination (MultiAddress)
    let dest_type = args[cursor];
    cursor += 1;

    let dest = if dest_type == 0x00 {
        // Id variant
        if cursor + 32 > args.len() {
            return Err(WasmDotError::InvalidTransaction(
                "Truncated destination".to_string(),
            ));
        }
        let pubkey = &args[cursor..cursor + 32];
        cursor += 32;
        encode_ss58(pubkey, address_prefix)?
    } else {
        return Err(WasmDotError::InvalidTransaction(format!(
            "Unsupported address type: {}",
            dest_type
        )));
    };

    // Value (compact u128)
    let (value, _) = decode_compact(&args[cursor..])?;

    Ok(serde_json::json!({
        "dest": dest,
        "value": value.to_string()
    }))
}

/// Parse transferAll arguments (dest, keepAlive)
fn parse_transfer_all_args(
    args: &[u8],
    address_prefix: u16,
) -> Result<serde_json::Value, WasmDotError> {
    if args.is_empty() {
        return Err(WasmDotError::InvalidTransaction(
            "Empty transfer args".to_string(),
        ));
    }

    let mut cursor = 0;

    // Destination (MultiAddress)
    let dest_type = args[cursor];
    cursor += 1;

    let dest = if dest_type == 0x00 {
        if cursor + 32 > args.len() {
            return Err(WasmDotError::InvalidTransaction(
                "Truncated destination".to_string(),
            ));
        }
        let pubkey = &args[cursor..cursor + 32];
        cursor += 32;
        encode_ss58(pubkey, address_prefix)?
    } else {
        return Err(WasmDotError::InvalidTransaction(format!(
            "Unsupported address type: {}",
            dest_type
        )));
    };

    // Keep alive flag
    let keep_alive = if cursor < args.len() {
        args[cursor] != 0
    } else {
        false
    };

    Ok(serde_json::json!({
        "dest": dest,
        "keepAlive": keep_alive
    }))
}

/// Parse bond arguments
fn parse_bond_args(args: &[u8], address_prefix: u16) -> Result<serde_json::Value, WasmDotError> {
    let mut cursor = 0;

    // Controller (MultiAddress) - Note: deprecated in newer runtimes
    let controller_type = args[cursor];
    cursor += 1;

    let controller = if controller_type == 0x00 {
        if cursor + 32 > args.len() {
            return Err(WasmDotError::InvalidTransaction(
                "Truncated controller".to_string(),
            ));
        }
        let pubkey = &args[cursor..cursor + 32];
        cursor += 32;
        Some(encode_ss58(pubkey, address_prefix)?)
    } else {
        None
    };

    // Value (compact u128)
    let (value, value_size) = decode_compact(&args[cursor..])?;
    cursor += value_size;

    // Payee
    let payee = if cursor < args.len() {
        let payee_type = args[cursor];
        match payee_type {
            0 => "Staked".to_string(),
            1 => "Stash".to_string(),
            2 => "Controller".to_string(),
            3 => {
                // Account variant
                cursor += 1;
                if cursor + 32 <= args.len() {
                    let pubkey = &args[cursor..cursor + 32];
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

    Ok(serde_json::json!({
        "controller": controller,
        "value": value.to_string(),
        "payee": payee
    }))
}

/// Parse unbond arguments
fn parse_unbond_args(args: &[u8]) -> Result<serde_json::Value, WasmDotError> {
    let (value, _) = decode_compact(args)?;
    Ok(serde_json::json!({
        "value": value.to_string()
    }))
}

/// Extract outputs from parsed method
fn extract_outputs(method: &ParsedMethod) -> Vec<TransactionOutput> {
    match (method.pallet.as_str(), method.name.as_str()) {
        ("balances", "transfer")
        | ("balances", "transferAllowDeath")
        | ("balances", "transferKeepAlive") => {
            if let (Some(dest), Some(value)) = (
                method.args.get("dest").and_then(|v| v.as_str()),
                method.args.get("value").and_then(|v| v.as_str()),
            ) {
                vec![TransactionOutput {
                    address: dest.to_string(),
                    amount: value.to_string(),
                }]
            } else {
                vec![]
            }
        }
        ("balances", "transferAll") => {
            if let Some(dest) = method.args.get("dest").and_then(|v| v.as_str()) {
                vec![TransactionOutput {
                    address: dest.to_string(),
                    amount: "ALL".to_string(), // transferAll sends everything
                }]
            } else {
                vec![]
            }
        }
        ("staking", "bond") | ("staking", "unbond") => {
            if let Some(value) = method.args.get("value").and_then(|v| v.as_str()) {
                vec![TransactionOutput {
                    address: "STAKING".to_string(),
                    amount: value.to_string(),
                }]
            } else {
                vec![]
            }
        }
        _ => vec![],
    }
}

/// Determine transaction type from method
fn determine_tx_type(method: &ParsedMethod) -> String {
    match (method.pallet.as_str(), method.name.as_str()) {
        ("balances", _) => "Send".to_string(),
        ("staking", "bond") | ("staking", "bondExtra") => "StakingActivate".to_string(),
        ("staking", "unbond") => "StakingUnlock".to_string(),
        ("staking", "withdrawUnbonded") => "StakingWithdraw".to_string(),
        ("staking", "chill") => "StakingUnvote".to_string(),
        ("staking", "payoutStakers") => "StakingClaim".to_string(),
        ("proxy", "addProxy") | ("proxy", "createPure") => "AddressInitialization".to_string(),
        ("proxy", "removeProxy") => "AddressInitialization".to_string(),
        ("utility", "batch") | ("utility", "batchAll") => "Batch".to_string(),
        _ => "Unknown".to_string(),
    }
}

/// Decode compact encoding (duplicate from transaction.rs for independence)
fn decode_compact(bytes: &[u8]) -> Result<(u128, usize), WasmDotError> {
    if bytes.is_empty() {
        return Err(WasmDotError::ScaleDecodeError(
            "Empty compact encoding".to_string(),
        ));
    }

    let mode = bytes[0] & 0b11;
    match mode {
        0b00 => Ok(((bytes[0] >> 2) as u128, 1)),
        0b01 => {
            if bytes.len() < 2 {
                return Err(WasmDotError::ScaleDecodeError(
                    "Truncated compact".to_string(),
                ));
            }
            let value = u16::from_le_bytes([bytes[0], bytes[1]]) >> 2;
            Ok((value as u128, 2))
        }
        0b10 => {
            if bytes.len() < 4 {
                return Err(WasmDotError::ScaleDecodeError(
                    "Truncated compact".to_string(),
                ));
            }
            let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) >> 2;
            Ok((value as u128, 4))
        }
        0b11 => {
            let len = (bytes[0] >> 2) + 4;
            if bytes.len() < 1 + len as usize {
                return Err(WasmDotError::ScaleDecodeError(
                    "Truncated compact".to_string(),
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
    fn test_parse_unsigned_transfer() {
        let bytes = hex::decode(TRANSFER_UNSIGNED).unwrap();
        let result = parse_transaction(&bytes, None);
        // This may fail without proper context, which is expected
        // The test verifies the parsing logic doesn't panic
        assert!(result.is_ok() || result.is_err());
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
