//! Dash transaction encoding/decoding helpers
//!
//! Dash "special transactions" encode an extra `type` in the transaction version and append an
//! extra payload after the lock_time:
//! - version: u32 where low 16 bits are the base version and high 16 bits are the special tx type
//! - if type != 0: varint payload_size + payload bytes

use miniscript::bitcoin::consensus::{Decodable, Encodable};
use miniscript::bitcoin::{Transaction, TxIn, TxOut, VarInt};

/// Parsed Dash transaction fields needed for round-tripping.
#[derive(Debug, Clone)]
pub struct DashTransactionParts {
    /// Bitcoin-compatible transaction (version without the Dash type bits)
    pub transaction: Transaction,
    /// Dash-specific special transaction type (0 = standard transaction)
    pub tx_type: u16,
    /// Extra payload for special transactions (empty when tx_type == 0)
    pub extra_payload: Vec<u8>,
}

fn u16_to_u32(v: u16) -> u32 {
    u32::from(v)
}

fn version_i32_to_u16(version: i32) -> Result<u16, String> {
    let v = u32::try_from(version)
        .map_err(|_| format!("Invalid tx version (negative): {}", version))?;
    u16::try_from(v & 0xFFFF).map_err(|_| "Invalid base version".to_string())
}

/// Decode a Dash transaction, extracting the special tx type and extra payload (if present).
pub fn decode_dash_transaction_parts(bytes: &[u8]) -> Result<DashTransactionParts, String> {
    let mut slice = bytes;

    // Dash encodes tx_type in the high 16 bits of the version.
    let version_u32 = u32::consensus_decode(&mut slice)
        .map_err(|e| format!("Failed to decode version: {}", e))?;
    let base_version = (version_u32 & 0xFFFF) as i32;
    let tx_type = ((version_u32 >> 16) & 0xFFFF) as u16;

    let inputs: Vec<TxIn> =
        Vec::consensus_decode(&mut slice).map_err(|e| format!("Failed to decode inputs: {}", e))?;
    let outputs: Vec<TxOut> = Vec::consensus_decode(&mut slice)
        .map_err(|e| format!("Failed to decode outputs: {}", e))?;
    let lock_time = miniscript::bitcoin::locktime::absolute::LockTime::consensus_decode(&mut slice)
        .map_err(|e| format!("Failed to decode lock_time: {}", e))?;

    let (extra_payload, remaining) = if tx_type != 0 {
        let payload_len: VarInt = Decodable::consensus_decode(&mut slice)
            .map_err(|e| format!("Failed to decode extra_payload size: {}", e))?;
        let payload_len = payload_len.0 as usize;
        if slice.len() < payload_len {
            return Err("extra_payload size exceeds remaining bytes".to_string());
        }
        let payload = slice[..payload_len].to_vec();
        (payload, &slice[payload_len..])
    } else {
        (Vec::new(), slice)
    };

    if !remaining.is_empty() {
        return Err("Unexpected trailing bytes after Dash transaction".to_string());
    }

    Ok(DashTransactionParts {
        transaction: Transaction {
            version: miniscript::bitcoin::transaction::Version::non_standard(base_version),
            input: inputs,
            output: outputs,
            lock_time,
        },
        tx_type,
        extra_payload,
    })
}

/// Encode a Dash transaction back to bytes, including tx_type and extra payload.
pub fn encode_dash_transaction_parts(parts: &DashTransactionParts) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();

    let base_version_u16 = version_i32_to_u16(parts.transaction.version.0)?;
    let version_u32 = u16_to_u32(base_version_u16) | (u16_to_u32(parts.tx_type) << 16);
    version_u32
        .consensus_encode(&mut bytes)
        .map_err(|e| format!("Failed to encode version: {}", e))?;

    parts
        .transaction
        .input
        .consensus_encode(&mut bytes)
        .map_err(|e| format!("Failed to encode inputs: {}", e))?;
    parts
        .transaction
        .output
        .consensus_encode(&mut bytes)
        .map_err(|e| format!("Failed to encode outputs: {}", e))?;
    parts
        .transaction
        .lock_time
        .consensus_encode(&mut bytes)
        .map_err(|e| format!("Failed to encode lock_time: {}", e))?;

    if parts.tx_type != 0 {
        VarInt(parts.extra_payload.len() as u64)
            .consensus_encode(&mut bytes)
            .map_err(|e| format!("Failed to encode extra_payload size: {}", e))?;
        bytes.extend_from_slice(&parts.extra_payload);
    } else if !parts.extra_payload.is_empty() {
        return Err("tx_type=0 must not have extra_payload".to_string());
    }

    Ok(bytes)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Clone, Deserialize)]
    struct DashRpcTransaction {
        hex: String,
    }

    fn dash_evo_fixture_dir() -> String {
        format!(
            "{}/test/fixtures_thirdparty/dashTestExtra",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    #[test]
    fn test_dash_evo_fixtures_round_trip() {
        let fixtures_dir = dash_evo_fixture_dir();

        let entries = std::fs::read_dir(&fixtures_dir)
            .unwrap_or_else(|_| panic!("Failed to read fixtures directory: {}", fixtures_dir));

        let mut fixture_files: Vec<_> = entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension()? == "json" {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();

        fixture_files.sort();

        assert!(
            !fixture_files.is_empty(),
            "No fixture files found in {}",
            fixtures_dir
        );
        assert_eq!(
            fixture_files.len(),
            29,
            "Expected 29 Dash EVO fixtures in {}",
            fixtures_dir
        );

        for (idx, fixture_path) in fixture_files.iter().enumerate() {
            let content = std::fs::read_to_string(fixture_path)
                .unwrap_or_else(|_| panic!("Failed to read fixture: {:?}", fixture_path));
            let tx: DashRpcTransaction = serde_json::from_str(&content)
                .unwrap_or_else(|_| panic!("Failed to parse fixture: {:?}", fixture_path));

            let bytes = hex::decode(&tx.hex).unwrap_or_else(|_| {
                panic!(
                    "Failed to decode tx hex in {:?} (idx={}): {}",
                    fixture_path, idx, tx.hex
                )
            });

            let parts = decode_dash_transaction_parts(&bytes).unwrap_or_else(|e| {
                panic!(
                    "Failed to decode Dash tx in {:?} (idx={}): {}",
                    fixture_path, idx, e
                )
            });

            if parts.tx_type == 0 {
                assert!(
                    parts.extra_payload.is_empty(),
                    "tx_type=0 must not have extra_payload in {:?} (idx={})",
                    fixture_path,
                    idx
                );
            } else {
                assert!(
                    !parts.extra_payload.is_empty(),
                    "tx_type!=0 should have extra_payload in {:?} (idx={})",
                    fixture_path,
                    idx
                );
            }

            let encoded = encode_dash_transaction_parts(&parts).unwrap_or_else(|e| {
                panic!(
                    "Failed to encode Dash tx in {:?} (idx={}): {}",
                    fixture_path, idx, e
                )
            });

            assert_eq!(
                encoded, bytes,
                "Dash EVO tx failed round-trip in {:?} (idx={})",
                fixture_path, idx
            );
        }
    }
}
