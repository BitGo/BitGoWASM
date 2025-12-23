/// Low-level PSBT parser using raw key-value pairs
///
/// This module provides parsing of PSBT (Partially Signed Bitcoin Transaction) files
/// at the raw byte level, exposing the key-value pair structure as defined in BIP-174.
///
/// # Purpose
///
/// Unlike the high-level parser, this shows:
/// - Raw key type IDs and their human-readable names
/// - Proprietary keys with their structured format (prefix, subtype, key_data)
/// - Unknown/unrecognized keys that standard parsers might skip
/// - Field presence indicators for debugging
///
/// # Example
///
/// ```ignore
/// use wasm_utxo::Network;
/// use wasm_utxo::parse_node::parse_psbt_bytes_raw_with_network;
///
/// let psbt_bytes = /* your PSBT data */;
/// let node = parse_psbt_bytes_raw_with_network(&psbt_bytes, Network::Bitcoin)?;
/// // Returns a tree structure showing raw PSBT key-value pairs
/// ```
///
/// # References
///
/// - [BIP-174: PSBT Format](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
/// - [bitcoin::psbt::raw](https://docs.rs/bitcoin/latest/bitcoin/psbt/raw/index.html)
use crate::bitcoin::consensus::Decodable;
use crate::bitcoin::psbt::raw::{Key, Pair};
use crate::bitcoin::{Transaction, VarInt};
use crate::zcash::transaction::decode_zcash_transaction_parts;

pub use super::node::{Node, Primitive};

/// Context for interpreting PSBT key types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PsbtMapContext {
    Global,
    Input,
    Output,
}

/// Check if bytes are printable ASCII
fn is_printable_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| (0x20..=0x7E).contains(&b))
}

/// Parse proprietary key structure (0xFC type keys)
fn parse_proprietary_key(key_data: &[u8]) -> Result<(Vec<u8>, u8, Vec<u8>), String> {
    if key_data.is_empty() {
        return Err("Empty proprietary key data".to_string());
    }

    let mut pos = 0;

    // Decode prefix length (varint)
    let (prefix_len, varint_size) = decode_varint(key_data, pos)?;
    pos += varint_size;

    let prefix_len = prefix_len as usize;
    if pos + prefix_len > key_data.len() {
        return Err("Not enough bytes for proprietary prefix".to_string());
    }

    // Extract prefix
    let prefix = key_data[pos..pos + prefix_len].to_vec();
    pos += prefix_len;

    // Extract subtype (1 byte)
    if pos >= key_data.len() {
        return Err("Not enough bytes for proprietary subtype".to_string());
    }
    let subtype = key_data[pos];
    pos += 1;

    // Remaining bytes are additional key data
    let remaining_key = key_data[pos..].to_vec();

    Ok((prefix, subtype, remaining_key))
}

/// Parse a raw PSBT key into a node
fn key_to_node(key: &Key, context: PsbtMapContext) -> Node {
    let mut key_node = Node::new("key", Primitive::None);

    // First byte is the key type
    if !key.key.is_empty() {
        key_node.add_child(Node::new("type_id", Primitive::U8(key.type_value)));
        key_node.add_child(Node::new(
            "type_name",
            Primitive::String(key_type_name(key.type_value, context)),
        ));
    }

    // Rest is the key data
    if key.key.len() > 1 {
        let key_data = &key.key[1..];

        // Special handling for proprietary keys (0xFC)
        if key.type_value == 0xFC {
            match parse_proprietary_key(key_data) {
                Ok((prefix, subtype, remaining_key)) => {
                    // Add prefix - show as ASCII string if printable
                    if is_printable_ascii(&prefix) {
                        key_node.add_child(Node::new(
                            "prefix",
                            Primitive::String(String::from_utf8_lossy(&prefix).to_string()),
                        ));
                    } else {
                        key_node.add_child(Node::new("prefix", Primitive::Buffer(prefix)));
                    }

                    // Add subtype
                    key_node.add_child(Node::new("subtype", Primitive::U8(subtype)));

                    // Add remaining key data if any
                    if !remaining_key.is_empty() {
                        key_node.add_child(Node::new("key_data", Primitive::Buffer(remaining_key)));
                    }
                }
                Err(_) => {
                    // Fallback: show raw key_data if parsing fails
                    key_node.add_child(Node::new("key_data", Primitive::Buffer(key_data.to_vec())));
                }
            }
        } else {
            // Non-proprietary keys: just show key_data as buffer
            key_node.add_child(Node::new("key_data", Primitive::Buffer(key_data.to_vec())));
        }
    }

    key_node
}

/// Parse a raw PSBT key-value pair into a node
fn pair_to_node(pair: &Pair, index: usize, context: PsbtMapContext) -> Node {
    let mut pair_node = Node::new(format!("pair_{}", index), Primitive::None);
    pair_node.add_child(key_to_node(&pair.key, context));
    pair_node.add_child(Node::new("value", Primitive::Buffer(pair.value.clone())));
    pair_node
}

/// Get human-readable name for PSBT key type based on context
fn key_type_name(type_id: u8, context: PsbtMapContext) -> String {
    match context {
        PsbtMapContext::Global => match type_id {
            0x00 => "PSBT_GLOBAL_UNSIGNED_TX".to_string(),
            0x01 => "PSBT_GLOBAL_XPUB".to_string(),
            0x02 => "PSBT_GLOBAL_TX_VERSION".to_string(),
            0x03 => "PSBT_GLOBAL_FALLBACK_LOCKTIME".to_string(),
            0x04 => "PSBT_GLOBAL_INPUT_COUNT".to_string(),
            0x05 => "PSBT_GLOBAL_OUTPUT_COUNT".to_string(),
            0x06 => "PSBT_GLOBAL_TX_MODIFIABLE".to_string(),
            0x07 => "PSBT_GLOBAL_VERSION".to_string(),
            0xFC => "PSBT_GLOBAL_PROPRIETARY".to_string(),
            _ => format!("UNKNOWN_TYPE_0x{:02X}", type_id),
        },
        PsbtMapContext::Input => match type_id {
            0x00 => "PSBT_IN_NON_WITNESS_UTXO".to_string(),
            0x01 => "PSBT_IN_WITNESS_UTXO".to_string(),
            0x02 => "PSBT_IN_PARTIAL_SIG".to_string(),
            0x03 => "PSBT_IN_SIGHASH_TYPE".to_string(),
            0x04 => "PSBT_IN_REDEEM_SCRIPT".to_string(),
            0x05 => "PSBT_IN_WITNESS_SCRIPT".to_string(),
            0x06 => "PSBT_IN_BIP32_DERIVATION".to_string(),
            0x07 => "PSBT_IN_FINAL_SCRIPTSIG".to_string(),
            0x08 => "PSBT_IN_FINAL_SCRIPTWITNESS".to_string(),
            0x09 => "PSBT_IN_POR_COMMITMENT".to_string(),
            0x0a => "PSBT_IN_RIPEMD160".to_string(),
            0x0b => "PSBT_IN_SHA256".to_string(),
            0x0c => "PSBT_IN_HASH160".to_string(),
            0x0d => "PSBT_IN_HASH256".to_string(),
            0x0e => "PSBT_IN_PREVIOUS_TXID".to_string(),
            0x0f => "PSBT_IN_OUTPUT_INDEX".to_string(),
            0x10 => "PSBT_IN_SEQUENCE".to_string(),
            0x11 => "PSBT_IN_REQUIRED_TIME_LOCKTIME".to_string(),
            0x12 => "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME".to_string(),
            0x13 => "PSBT_IN_TAP_KEY_SIG".to_string(),
            0x14 => "PSBT_IN_TAP_SCRIPT_SIG".to_string(),
            0x15 => "PSBT_IN_TAP_LEAF_SCRIPT".to_string(),
            0x16 => "PSBT_IN_TAP_BIP32_DERIVATION".to_string(),
            0x17 => "PSBT_IN_TAP_INTERNAL_KEY".to_string(),
            0x18 => "PSBT_IN_TAP_MERKLE_ROOT".to_string(),
            0x19 => "PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS".to_string(),
            0x1a => "PSBT_IN_MUSIG2_PUB_NONCE".to_string(),
            0x1b => "PSBT_IN_MUSIG2_PARTIAL_SIG".to_string(),
            0xFC => "PSBT_IN_PROPRIETARY".to_string(),
            _ => format!("UNKNOWN_TYPE_0x{:02X}", type_id),
        },
        PsbtMapContext::Output => match type_id {
            0x00 => "PSBT_OUT_REDEEM_SCRIPT".to_string(),
            0x01 => "PSBT_OUT_WITNESS_SCRIPT".to_string(),
            0x02 => "PSBT_OUT_BIP32_DERIVATION".to_string(),
            0x03 => "PSBT_OUT_AMOUNT".to_string(),
            0x04 => "PSBT_OUT_SCRIPT".to_string(),
            0x05 => "PSBT_OUT_TAP_INTERNAL_KEY".to_string(),
            0x06 => "PSBT_OUT_TAP_TREE".to_string(),
            0x07 => "PSBT_OUT_TAP_BIP32_DERIVATION".to_string(),
            0xFC => "PSBT_OUT_PROPRIETARY".to_string(),
            _ => format!("UNKNOWN_TYPE_0x{:02X}", type_id),
        },
    }
}

/// Decode a varint from bytes using bitcoin crate, returns (value, bytes_consumed)
fn decode_varint(bytes: &[u8], pos: usize) -> Result<(u64, usize), String> {
    if pos >= bytes.len() {
        return Err("Not enough bytes for varint".to_string());
    }

    let mut cursor = &bytes[pos..];
    let varint = VarInt::consensus_decode(&mut cursor)
        .map_err(|e| format!("Failed to decode varint: {}", e))?;

    // Calculate bytes consumed by comparing slice positions
    let bytes_consumed = bytes.len() - pos - cursor.len();

    Ok((varint.0, bytes_consumed))
}

/// Manually decode a key-value pair from bytes
///
/// Note: The bitcoin crate has `Pair::decode()` and `Key::decode()` methods, but they are
/// marked as `pub(crate)` and not exposed in the public API. We must implement our own
/// decoder to parse raw PSBT bytes at this low level. We do reuse the bitcoin crate's
/// `VarInt` decoder where possible.
fn decode_pair(bytes: &[u8], pos: usize) -> Result<(Pair, usize), String> {
    let mut current_pos = pos;

    // Decode key length (varint)
    let (key_len, varint_size) = decode_varint(bytes, current_pos)?;
    current_pos += varint_size;

    if key_len == 0 {
        return Err("Zero-length key (map separator)".to_string());
    }

    // Key is: type_value (1 byte) + key_data
    if current_pos >= bytes.len() {
        return Err("Not enough bytes for key type".to_string());
    }

    let type_value = bytes[current_pos];
    current_pos += 1;

    let key_data_len = (key_len - 1) as usize;
    if current_pos + key_data_len > bytes.len() {
        return Err(format!(
            "Not enough bytes for key data: need {}, have {}",
            key_data_len,
            bytes.len() - current_pos
        ));
    }

    let mut key_bytes = vec![type_value];
    key_bytes.extend_from_slice(&bytes[current_pos..current_pos + key_data_len]);
    current_pos += key_data_len;

    let key = Key {
        type_value,
        key: key_bytes,
    };

    // Decode value length (varint)
    let (value_len, varint_size) = decode_varint(bytes, current_pos)?;
    current_pos += varint_size;

    let value_len = value_len as usize;
    if current_pos + value_len > bytes.len() {
        return Err(format!(
            "Not enough bytes for value: need {}, have {}",
            value_len,
            bytes.len() - current_pos
        ));
    }

    let value = bytes[current_pos..current_pos + value_len].to_vec();
    current_pos += value_len;

    let pair = Pair { key, value };
    Ok((pair, current_pos - pos))
}

/// Extract transaction input/output counts from global map
/// Supports both Bitcoin and Zcash transaction formats
fn extract_tx_counts(global_pairs: &[Pair], is_zcash: bool) -> Result<(usize, usize), String> {
    // Find the unsigned transaction (type 0x00)
    for pair in global_pairs {
        if pair.key.type_value == 0x00 {
            // Try Zcash parser first if requested
            if is_zcash {
                if let Ok(parts) = decode_zcash_transaction_parts(&pair.value) {
                    return Ok((
                        parts.transaction.input.len(),
                        parts.transaction.output.len(),
                    ));
                }
            }

            // Fall back to standard Bitcoin transaction parser
            let tx = Transaction::consensus_decode(&mut &pair.value[..])
                .map_err(|e| format!("Failed to decode unsigned transaction: {}", e))?;
            return Ok((tx.input.len(), tx.output.len()));
        }
    }
    Err("No unsigned transaction found in global map".to_string())
}

/// Decode a single map (set of key-value pairs terminated by 0x00)
fn decode_map(
    bytes: &[u8],
    start_pos: usize,
    map_name: &str,
    context: PsbtMapContext,
) -> Result<(Node, Vec<Pair>, usize), String> {
    let mut map_node = Node::new(map_name, Primitive::None);
    let mut pairs = Vec::new();
    let mut pos = start_pos;

    loop {
        // Check if we hit the separator (0x00)
        if pos >= bytes.len() {
            break;
        }

        if bytes[pos] == 0x00 {
            pos += 1; // Skip the separator
            break;
        }

        // Try to decode a pair
        match decode_pair(bytes, pos) {
            Ok((pair, consumed)) => {
                pairs.push(pair);
                pos += consumed;
            }
            Err(e) => {
                // Check if this is a zero-length key (separator)
                if e.contains("Zero-length") {
                    pos += 1; // Skip the 0x00
                    break;
                }
                return Err(format!("Failed to decode pair at position {}: {}", pos, e));
            }
        }
    }

    // Add pair count first
    let pair_count = pairs.len();
    map_node.add_child(Node::new("pair_count", Primitive::U64(pair_count as u64)));

    // Process all pairs
    for (idx, pair) in pairs.iter().enumerate() {
        map_node.add_child(pair_to_node(pair, idx, context));
    }

    Ok((map_node, pairs, pos))
}

/// Parse PSBT showing raw key-value structure from bytes
/// Supports both Bitcoin and Zcash PSBT formats
fn psbt_to_raw_node_internal(bytes: &[u8], is_zcash: bool) -> Result<Node, String> {
    let mut psbt_node = Node::new("psbt_raw", Primitive::None);

    // 1. Check magic bytes: "psbt" + 0xff
    if bytes.len() < 5 {
        return Err("PSBT too short to contain magic bytes".to_string());
    }

    let magic = &bytes[0..5];
    if magic != b"psbt\xff" {
        return Err(format!("Invalid PSBT magic bytes: {:02x?}", magic));
    }

    psbt_node.add_child(Node::new(
        "magic",
        Primitive::String(format!("{:02x?}", magic)),
    ));

    let mut pos = 5; // Start after magic bytes

    // 2. Decode global map
    let (global_map, global_pairs, new_pos) =
        decode_map(bytes, pos, "global_map", PsbtMapContext::Global)?;
    psbt_node.add_child(global_map);
    pos = new_pos;

    // 3. Extract transaction input/output counts from unsigned tx
    let (expected_input_count, expected_output_count) = extract_tx_counts(&global_pairs, is_zcash)?;

    // 4. Decode input maps
    let mut input_maps_node = Node::new("input_maps", Primitive::None);

    for input_idx in 0..expected_input_count {
        let (input_map, _, new_pos) = decode_map(
            bytes,
            pos,
            &format!("input_{}", input_idx),
            PsbtMapContext::Input,
        )?;
        input_maps_node.add_child(input_map);
        pos = new_pos;
    }

    input_maps_node.value = Primitive::U64(expected_input_count as u64);
    psbt_node.add_child(input_maps_node);

    // 5. Decode output maps
    let mut output_maps_node = Node::new("output_maps", Primitive::None);

    for output_idx in 0..expected_output_count {
        let (output_map, _, new_pos) = decode_map(
            bytes,
            pos,
            &format!("output_{}", output_idx),
            PsbtMapContext::Output,
        )?;
        output_maps_node.add_child(output_map);
        pos = new_pos;
    }

    output_maps_node.value = Primitive::U64(expected_output_count as u64);
    psbt_node.add_child(output_maps_node);

    // Check if we consumed all bytes
    let remaining = bytes.len() - pos;
    if remaining > 0 {
        psbt_node.add_child(Node::new(
            "remaining_bytes",
            Primitive::U64(remaining as u64),
        ));
    }

    Ok(psbt_node)
}

/// Parse raw PSBT bytes with network support
pub fn parse_psbt_bytes_raw_with_network(
    bytes: &[u8],
    network: crate::networks::Network,
) -> Result<Node, String> {
    use crate::networks::Network as NetEnum;
    let is_zcash = matches!(network, NetEnum::Zcash | NetEnum::ZcashTestnet);
    psbt_to_raw_node_internal(bytes, is_zcash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_type_names() {
        assert_eq!(
            key_type_name(0x00, PsbtMapContext::Global),
            "PSBT_GLOBAL_UNSIGNED_TX"
        );
        assert_eq!(
            key_type_name(0xFC, PsbtMapContext::Global),
            "PSBT_GLOBAL_PROPRIETARY"
        );
        assert!(key_type_name(0xFF, PsbtMapContext::Global).starts_with("UNKNOWN_TYPE"));

        // Test input context
        assert_eq!(
            key_type_name(0x00, PsbtMapContext::Input),
            "PSBT_IN_NON_WITNESS_UTXO"
        );
        assert_eq!(
            key_type_name(0x01, PsbtMapContext::Input),
            "PSBT_IN_WITNESS_UTXO"
        );

        // Test output context
        assert_eq!(
            key_type_name(0x00, PsbtMapContext::Output),
            "PSBT_OUT_REDEEM_SCRIPT"
        );
        assert_eq!(
            key_type_name(0x03, PsbtMapContext::Output),
            "PSBT_OUT_AMOUNT"
        );
    }

    #[test]
    fn test_key_to_node() {
        let key = Key {
            type_value: 0x01,
            key: vec![0x01, 0x02, 0x03],
        };
        let node = key_to_node(&key, PsbtMapContext::Global);
        assert_eq!(node.label, "key");
        assert!(!node.children.is_empty());
    }

    #[test]
    fn test_magic_bytes() {
        let magic = b"psbt\xff";
        assert_eq!(magic.len(), 5);
        assert_eq!(magic[4], 0xff);
    }
}
