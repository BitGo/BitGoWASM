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
use crate::bitcoin::Transaction;
use crate::psbt_ops::{
    decode_compact_size, decode_compact_size_u64, decode_psbt_key_value_map,
    known_psbt_input_key_type, PsbtKeyValue,
};
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

fn key_type_primitive(value: u64) -> Primitive {
    u8::try_from(value)
        .map(Primitive::U8)
        .unwrap_or(Primitive::U64(value))
}

/// Parse proprietary key structure (0xFC type keys)
fn parse_proprietary_key(key_data: &[u8]) -> Result<(Vec<u8>, u64, Vec<u8>), String> {
    if key_data.is_empty() {
        return Err("Empty proprietary key data".to_string());
    }

    let mut pos = 0;

    // Decode prefix length (varint)
    let (prefix_len, varint_size) = decode_compact_size(&key_data[pos..])?;
    pos += varint_size;

    if pos + prefix_len > key_data.len() {
        return Err("Not enough bytes for proprietary prefix".to_string());
    }

    // Extract prefix
    let prefix = key_data[pos..pos + prefix_len].to_vec();
    pos += prefix_len;

    // Extract CompactSize subtype.
    let (subtype, subtype_size) = decode_compact_size_u64(&key_data[pos..])?;
    pos += subtype_size;

    // Remaining bytes are additional key data
    let remaining_key = key_data[pos..].to_vec();

    Ok((prefix, subtype, remaining_key))
}

/// Parse a raw PSBT key into a node.
fn key_to_node(key_value: &PsbtKeyValue, context: PsbtMapContext) -> Node {
    let mut key_node = Node::new("key", Primitive::None);

    key_node.add_child(Node::new("type_id", key_type_primitive(key_value.key_type)));
    key_node.add_child(Node::new(
        "type_name",
        Primitive::String(key_type_name(key_value.key_type, context)),
    ));

    if !key_value.key_data.is_empty() {
        let key_data = &key_value.key_data;

        // Special handling for proprietary keys (0xFC)
        if key_value.key_type == 0xFC {
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
                    key_node.add_child(Node::new("subtype", key_type_primitive(subtype)));

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

/// Parse a raw PSBT key-value pair into a node.
fn pair_to_node(pair: &PsbtKeyValue, index: usize, context: PsbtMapContext) -> Node {
    let mut pair_node = Node::new(format!("pair_{}", index), Primitive::None);
    pair_node.add_child(key_to_node(pair, context));
    pair_node.add_child(Node::new("value", Primitive::Buffer(pair.value.clone())));
    pair_node
}

/// Get human-readable name for PSBT key type based on context
fn key_type_name(type_id: u64, context: PsbtMapContext) -> String {
    match context {
        PsbtMapContext::Global => match type_id {
            0x00 => "PSBT_GLOBAL_UNSIGNED_TX".to_string(),
            0x01 => "PSBT_GLOBAL_XPUB".to_string(),
            0x02 => "PSBT_GLOBAL_TX_VERSION".to_string(),
            0x03 => "PSBT_GLOBAL_FALLBACK_LOCKTIME".to_string(),
            0x04 => "PSBT_GLOBAL_INPUT_COUNT".to_string(),
            0x05 => "PSBT_GLOBAL_OUTPUT_COUNT".to_string(),
            0x06 => "PSBT_GLOBAL_TX_MODIFIABLE".to_string(),
            0x07 => "PSBT_GLOBAL_SP_ECDH_SHARE".to_string(),
            0x08 => "PSBT_GLOBAL_SP_DLEQ".to_string(),
            0x09 => "PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE".to_string(),
            0xfb => "PSBT_GLOBAL_VERSION".to_string(),
            0xFC => "PSBT_GLOBAL_PROPRIETARY".to_string(),
            _ => format!("UNKNOWN_TYPE_0x{type_id:X}"),
        },
        PsbtMapContext::Input => known_psbt_input_key_type(type_id)
            .map(str::to_string)
            .unwrap_or_else(|| format!("UNKNOWN_TYPE_0x{type_id:X}")),
        PsbtMapContext::Output => match type_id {
            0x00 => "PSBT_OUT_REDEEM_SCRIPT".to_string(),
            0x01 => "PSBT_OUT_WITNESS_SCRIPT".to_string(),
            0x02 => "PSBT_OUT_BIP32_DERIVATION".to_string(),
            0x03 => "PSBT_OUT_AMOUNT".to_string(),
            0x04 => "PSBT_OUT_SCRIPT".to_string(),
            0x05 => "PSBT_OUT_TAP_INTERNAL_KEY".to_string(),
            0x06 => "PSBT_OUT_TAP_TREE".to_string(),
            0x07 => "PSBT_OUT_TAP_BIP32_DERIVATION".to_string(),
            0x08 => "PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS".to_string(),
            0x09 => "PSBT_OUT_SP_V0_INFO".to_string(),
            0x0a => "PSBT_OUT_SP_V0_LABEL".to_string(),
            0x35 => "PSBT_OUT_DNSSEC_PROOF".to_string(),
            0xFC => "PSBT_OUT_PROPRIETARY".to_string(),
            _ => format!("UNKNOWN_TYPE_0x{type_id:X}"),
        },
    }
}

/// Extract transaction input/output counts from global map
/// Supports both Bitcoin and Zcash transaction formats
fn extract_tx_counts(
    global_pairs: &[PsbtKeyValue],
    is_zcash: bool,
) -> Result<(usize, usize), String> {
    // Find the unsigned transaction (type 0x00)
    for pair in global_pairs {
        if pair.key_type == 0x00 {
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
) -> Result<(Node, Vec<PsbtKeyValue>, usize), String> {
    let mut map_node = Node::new(map_name, Primitive::None);
    let map_bytes = bytes
        .get(start_pos..)
        .ok_or_else(|| format!("PSBT map starts out of bounds at position {start_pos}"))?;
    let (pairs, consumed) = decode_psbt_key_value_map(map_bytes)
        .map_err(|e| format!("Failed to decode map at position {start_pos}: {e}"))?;

    // Add pair count first
    let pair_count = pairs.len();
    map_node.add_child(Node::new("pair_count", Primitive::U64(pair_count as u64)));

    // Process all pairs
    for (idx, pair) in pairs.iter().enumerate() {
        map_node.add_child(pair_to_node(pair, idx, context));
    }

    Ok((map_node, pairs, start_pos + consumed))
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
        assert_eq!(
            key_type_name(0xfb, PsbtMapContext::Global),
            "PSBT_GLOBAL_VERSION"
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
        assert_eq!(
            key_type_name(0x1c, PsbtMapContext::Input),
            "PSBT_IN_MUSIG2_PARTIAL_SIG"
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
        assert_eq!(
            key_type_name(0x09, PsbtMapContext::Output),
            "PSBT_OUT_SP_V0_INFO"
        );
    }

    #[test]
    fn test_key_to_node() {
        let key_value = PsbtKeyValue {
            key_type: 0x01,
            key_data: vec![0x02, 0x03],
            value: vec![],
        };
        let node = key_to_node(&key_value, PsbtMapContext::Global);
        assert_eq!(node.label, "key");
        assert!(!node.children.is_empty());
    }

    #[test]
    fn test_decode_map_with_compact_size_key_type() {
        let bytes = [0x04, 0xfd, 0x34, 0x12, 0xaa, 0x02, 0xbb, 0xcc, 0x00];

        let (node, pairs, consumed) =
            decode_map(&bytes, 0, "input", PsbtMapContext::Input).unwrap();

        assert_eq!(consumed, bytes.len());
        assert_eq!(pairs[0].key_type, 0x1234);
        assert_eq!(pairs[0].key_data, vec![0xaa]);
        assert!(matches!(
            node.children[1].children[0].children[0].value,
            Primitive::U64(0x1234)
        ));
    }

    #[test]
    fn test_parse_proprietary_key_with_compact_size_subtype() {
        let (prefix, subtype, key_data) =
            parse_proprietary_key(&[0x01, b'x', 0xfd, 0x34, 0x12, 0xaa]).unwrap();

        assert_eq!(prefix, vec![b'x']);
        assert_eq!(subtype, 0x1234);
        assert_eq!(key_data, vec![0xaa]);
    }

    #[test]
    fn test_magic_bytes() {
        let magic = b"psbt\xff";
        assert_eq!(magic.len(), 5);
        assert_eq!(magic[4], 0xff);
    }
}
