//! PSBT comparison utilities for testing
//!
//! This module provides low-level PSBT parsing and comparison utilities that work
//! at the key-value pair level, providing detailed error messages showing exactly
//! which fields differ between two PSBTs.
//!
//! # Example
//!
//! ```ignore
//! use crate::fixed_script_wallet::test_utils::psbt_compare::assert_equal_psbt;
//!
//! let original_bytes = original_psbt.serialize().unwrap();
//! let reconstructed_bytes = reconstructed_psbt.serialize().unwrap();
//!
//! assert_equal_psbt(&original_bytes, &reconstructed_bytes);
//! ```

use miniscript::bitcoin::consensus::Decodable;
use miniscript::bitcoin::{Transaction, VarInt};
use std::collections::HashMap;

/// Context for interpreting PSBT key types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PsbtMapContext {
    Global,
    Input,
    Output,
}

/// A raw PSBT key-value pair
#[derive(Debug, Clone)]
pub struct RawPair {
    pub type_value: u8,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// A parsed PSBT map (global, input, or output)
#[derive(Debug)]
pub struct ParsedMap {
    pub pairs: Vec<RawPair>,
}

impl ParsedMap {
    /// Check if a key type is present
    pub fn has_type(&self, type_value: u8) -> bool {
        self.pairs.iter().any(|p| p.type_value == type_value)
    }
}

/// A fully parsed PSBT structure
#[derive(Debug)]
pub struct ParsedPsbt {
    pub global: ParsedMap,
    pub inputs: Vec<ParsedMap>,
    pub outputs: Vec<ParsedMap>,
}

/// Decode a varint from bytes, returns (value, bytes_consumed)
fn decode_varint(bytes: &[u8], pos: usize) -> Result<(u64, usize), String> {
    if pos >= bytes.len() {
        return Err("Not enough bytes for varint".to_string());
    }

    let mut cursor = &bytes[pos..];
    let varint = VarInt::consensus_decode(&mut cursor)
        .map_err(|e| format!("Failed to decode varint: {}", e))?;

    let bytes_consumed = bytes.len() - pos - cursor.len();
    Ok((varint.0, bytes_consumed))
}

/// Decode a single key-value pair from bytes
fn decode_pair(bytes: &[u8], pos: usize) -> Result<(RawPair, usize), String> {
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

    let mut key = vec![type_value];
    key.extend_from_slice(&bytes[current_pos..current_pos + key_data_len]);
    current_pos += key_data_len;

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

    Ok((
        RawPair {
            type_value,
            key,
            value,
        },
        current_pos - pos,
    ))
}

/// Extract transaction input/output counts from global map
fn extract_tx_counts(global_pairs: &[RawPair]) -> Result<(usize, usize), String> {
    for pair in global_pairs {
        if pair.type_value == 0x00 {
            let tx = Transaction::consensus_decode(&mut &pair.value[..])
                .map_err(|e| format!("Failed to decode unsigned transaction: {}", e))?;
            return Ok((tx.input.len(), tx.output.len()));
        }
    }
    Err("No unsigned transaction found in global map".to_string())
}

/// Decode a single map (set of key-value pairs terminated by 0x00)
fn decode_map_pairs(bytes: &[u8], start_pos: usize) -> Result<(Vec<RawPair>, usize), String> {
    let mut pairs = Vec::new();
    let mut pos = start_pos;

    loop {
        if pos >= bytes.len() {
            break;
        }

        if bytes[pos] == 0x00 {
            pos += 1;
            break;
        }

        match decode_pair(bytes, pos) {
            Ok((pair, consumed)) => {
                pairs.push(pair);
                pos += consumed;
            }
            Err(e) => {
                if e.contains("Zero-length") {
                    pos += 1;
                    break;
                }
                return Err(format!("Failed to decode pair at position {}: {}", pos, e));
            }
        }
    }

    Ok((pairs, pos))
}

/// Parse PSBT bytes into a structured ParsedPsbt
pub fn parse_psbt_to_maps(bytes: &[u8]) -> Result<ParsedPsbt, String> {
    // Check magic bytes
    if bytes.len() < 5 {
        return Err("PSBT too short to contain magic bytes".to_string());
    }

    let magic = &bytes[0..5];
    if magic != b"psbt\xff" {
        return Err(format!("Invalid PSBT magic bytes: {:02x?}", magic));
    }

    let mut pos = 5;

    // Decode global map
    let (global_pairs, new_pos) = decode_map_pairs(bytes, pos)?;
    pos = new_pos;

    // Extract input/output counts
    let (input_count, output_count) = extract_tx_counts(&global_pairs)?;

    let global = ParsedMap {
        pairs: global_pairs,
    };

    // Decode input maps
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let (pairs, new_pos) = decode_map_pairs(bytes, pos)?;
        pos = new_pos;
        inputs.push(ParsedMap { pairs });
    }

    // Decode output maps
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let (pairs, new_pos) = decode_map_pairs(bytes, pos)?;
        pos = new_pos;
        outputs.push(ParsedMap { pairs });
    }

    Ok(ParsedPsbt {
        global,
        inputs,
        outputs,
    })
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

/// Format a key for display
fn format_key(pair: &RawPair, context: PsbtMapContext) -> String {
    let type_name = key_type_name(pair.type_value, context);
    if pair.key.len() > 1 {
        format!("{}[key_data={}]", type_name, hex::encode(&pair.key[1..]))
    } else {
        type_name
    }
}

/// Compare two maps and return differences
fn compare_maps(
    left: &ParsedMap,
    right: &ParsedMap,
    context: PsbtMapContext,
    prefix: &str,
) -> Vec<String> {
    let mut diffs = Vec::new();

    // Build lookup by full key bytes for both maps
    let left_by_key: HashMap<&[u8], &RawPair> =
        left.pairs.iter().map(|p| (p.key.as_slice(), p)).collect();
    let right_by_key: HashMap<&[u8], &RawPair> =
        right.pairs.iter().map(|p| (p.key.as_slice(), p)).collect();

    // Check for keys in left but not in right, or with different values
    for pair in &left.pairs {
        let key_display = format_key(pair, context);
        match right_by_key.get(pair.key.as_slice()) {
            Some(right_pair) => {
                if pair.value != right_pair.value {
                    diffs.push(format!(
                        "{} {} value differs:\n  left:  {}\n  right: {}",
                        prefix,
                        key_display,
                        hex::encode(&pair.value),
                        hex::encode(&right_pair.value)
                    ));
                }
            }
            None => {
                diffs.push(format!(
                    "{} {} present in left but missing in right (value={})",
                    prefix,
                    key_display,
                    hex::encode(&pair.value)
                ));
            }
        }
    }

    // Check for keys in right but not in left
    for pair in &right.pairs {
        if !left_by_key.contains_key(pair.key.as_slice()) {
            let key_display = format_key(pair, context);
            diffs.push(format!(
                "{} {} present in right but missing in left (value={})",
                prefix,
                key_display,
                hex::encode(&pair.value)
            ));
        }
    }

    diffs
}

/// Compare two parsed PSBTs and return all differences
pub fn compare_psbts(left: &ParsedPsbt, right: &ParsedPsbt) -> Vec<String> {
    let mut diffs = Vec::new();

    // Compare global maps
    diffs.extend(compare_maps(
        &left.global,
        &right.global,
        PsbtMapContext::Global,
        "global:",
    ));

    // Compare input counts
    if left.inputs.len() != right.inputs.len() {
        diffs.push(format!(
            "Input count mismatch: left={}, right={}",
            left.inputs.len(),
            right.inputs.len()
        ));
    }

    // Compare each input
    let input_count = std::cmp::min(left.inputs.len(), right.inputs.len());
    for i in 0..input_count {
        diffs.extend(compare_maps(
            &left.inputs[i],
            &right.inputs[i],
            PsbtMapContext::Input,
            &format!("input[{}]:", i),
        ));
    }

    // Compare output counts
    if left.outputs.len() != right.outputs.len() {
        diffs.push(format!(
            "Output count mismatch: left={}, right={}",
            left.outputs.len(),
            right.outputs.len()
        ));
    }

    // Compare each output
    let output_count = std::cmp::min(left.outputs.len(), right.outputs.len());
    for i in 0..output_count {
        diffs.extend(compare_maps(
            &left.outputs[i],
            &right.outputs[i],
            PsbtMapContext::Output,
            &format!("output[{}]:", i),
        ));
    }

    diffs
}

/// Compare two PSBTs and return Ok(()) if equal, or Err with detailed differences
pub fn compare_psbt_bytes(left_bytes: &[u8], right_bytes: &[u8]) -> Result<(), String> {
    let left = parse_psbt_to_maps(left_bytes)?;
    let right = parse_psbt_to_maps(right_bytes)?;

    let diffs = compare_psbts(&left, &right);

    if diffs.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "PSBTs differ in {} place(s):\n{}",
            diffs.len(),
            diffs.join("\n")
        ))
    }
}

/// Assert that two PSBT byte arrays are equal at the key-value pair level
///
/// This provides much more detailed error messages than simple byte comparison,
/// showing exactly which fields differ between the two PSBTs.
///
/// # Panics
///
/// Panics if the PSBTs differ, with a detailed message showing which fields
/// are different.
pub fn assert_equal_psbt(left_bytes: &[u8], right_bytes: &[u8]) {
    if let Err(e) = compare_psbt_bytes(left_bytes, right_bytes) {
        panic!("{}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_psbt_to_maps() {
        use crate::fixed_script_wallet::test_utils::fixtures;

        let fixture = fixtures::load_psbt_fixture_with_format(
            "bitcoin",
            fixtures::SignatureState::Unsigned,
            fixtures::TxFormat::Psbt,
        )
        .expect("Failed to load fixture");

        let psbt_bytes = fixture.to_psbt_bytes().expect("Failed to serialize PSBT");
        let parsed = parse_psbt_to_maps(&psbt_bytes).expect("Failed to parse PSBT");

        // Should have global map with at least unsigned tx
        assert!(parsed.global.has_type(0x00), "Should have unsigned tx");

        // Should have inputs and outputs
        assert!(!parsed.inputs.is_empty(), "Should have inputs");
        assert!(!parsed.outputs.is_empty(), "Should have outputs");
    }

    #[test]
    fn test_compare_identical_psbts() {
        use crate::fixed_script_wallet::test_utils::fixtures;

        let fixture = fixtures::load_psbt_fixture_with_format(
            "bitcoin",
            fixtures::SignatureState::Unsigned,
            fixtures::TxFormat::Psbt,
        )
        .expect("Failed to load fixture");

        let psbt_bytes = fixture.to_psbt_bytes().expect("Failed to serialize PSBT");

        // Comparing identical PSBTs should succeed
        assert_equal_psbt(&psbt_bytes, &psbt_bytes);
    }

    #[test]
    fn test_compare_different_psbts() {
        use crate::fixed_script_wallet::test_utils::fixtures;

        let unsigned = fixtures::load_psbt_fixture_with_format(
            "bitcoin",
            fixtures::SignatureState::Unsigned,
            fixtures::TxFormat::Psbt,
        )
        .expect("Failed to load unsigned fixture");

        let fullsigned = fixtures::load_psbt_fixture_with_format(
            "bitcoin",
            fixtures::SignatureState::Fullsigned,
            fixtures::TxFormat::Psbt,
        )
        .expect("Failed to load fullsigned fixture");

        let unsigned_bytes = unsigned.to_psbt_bytes().expect("Failed to serialize");
        let fullsigned_bytes = fullsigned.to_psbt_bytes().expect("Failed to serialize");

        // Different PSBTs should produce an error
        let result = compare_psbt_bytes(&unsigned_bytes, &fullsigned_bytes);
        assert!(result.is_err(), "Different PSBTs should produce error");

        let err = result.unwrap_err();
        assert!(
            err.contains("differ"),
            "Error should describe differences: {}",
            err
        );
    }
}
