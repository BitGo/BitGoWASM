//! Dash PSBT deserialization
//!
//! Dash uses a special transaction format for "special transactions" where:
//! - the transaction version encodes an additional `type` in the high 16 bits
//! - if type != 0, an extra payload is appended after lock_time
//!
//! This is not compatible with standard Bitcoin transaction deserialization.

use miniscript::bitcoin::consensus::{Decodable, Encodable};
use miniscript::bitcoin::psbt::Psbt;
use miniscript::bitcoin::{ScriptBuf, Transaction, TxOut, VarInt};
use std::io::Read;

/// A Dash-compatible PSBT that can handle Dash special transactions by preserving original bytes.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DashBitGoPsbt {
    /// The underlying Bitcoin-compatible PSBT
    pub psbt: Psbt,
    /// The network this PSBT is for (Dash or DashTestnet)
    pub(crate) network: crate::Network,
    /// Original unsigned transaction bytes from the PSBT global map (Dash format)
    pub unsigned_tx_bytes: Vec<u8>,
    /// Original non_witness_utxo bytes per input index (Dash format)
    pub non_witness_utxo_bytes_by_input: Vec<Option<Vec<u8>>>,
}

impl DashBitGoPsbt {
    pub fn network(&self) -> crate::Network {
        self.network
    }

    fn decode_with_dash_tx(
        bytes: &[u8],
        network: crate::Network,
    ) -> Result<Self, super::DeserializeError> {
        let mut r = bytes;

        // Read magic bytes
        let magic: [u8; 4] = Decodable::consensus_decode(&mut r)?;
        if &magic != b"psbt" {
            return Err(super::DeserializeError::Network(
                "Invalid PSBT magic".to_string(),
            ));
        }

        // Read separator
        let separator: u8 = Decodable::consensus_decode(&mut r)?;
        if separator != 0xff {
            return Err(super::DeserializeError::Network(
                "Invalid PSBT separator".to_string(),
            ));
        }

        // Rebuild PSBT while transforming Dash transactions into Bitcoin-compatible transactions
        let mut modified_psbt = Vec::new();
        modified_psbt.extend_from_slice(b"psbt\xff");

        let mut unsigned_tx_bytes: Vec<u8> = Vec::new();
        let mut unsigned_tx: Option<Transaction> = None;
        let mut found_tx = false;

        // Decode global map
        loop {
            let key_len: VarInt = Decodable::consensus_decode(&mut r)?;
            if key_len.0 == 0 {
                // End of global map
                0u8.consensus_encode(&mut modified_psbt).map_err(|e| {
                    super::DeserializeError::Network(format!("Failed to encode separator: {}", e))
                })?;
                break;
            }

            let mut key_data = vec![0u8; key_len.0 as usize];
            r.read_exact(&mut key_data)
                .map_err(|_| super::DeserializeError::Network("Failed to read key".to_string()))?;

            let val_len: VarInt = Decodable::consensus_decode(&mut r)?;
            let mut val_data = vec![0u8; val_len.0 as usize];
            r.read_exact(&mut val_data).map_err(|_| {
                super::DeserializeError::Network("Failed to read value".to_string())
            })?;

            // Global unsigned tx key: type 0x00, key length 1
            if !key_data.is_empty() && key_data[0] == 0x00 && key_data.len() == 1 {
                found_tx = true;
                unsigned_tx_bytes = val_data.clone();

                let parts = crate::dash::transaction::decode_dash_transaction_parts(&val_data)
                    .map_err(super::DeserializeError::Network)?;
                let tx = parts.transaction;

                // Serialize the bitcoin-compatible transaction (no Dash extra payload)
                let mut tx_bytes = Vec::new();
                tx.consensus_encode(&mut tx_bytes).map_err(|e| {
                    super::DeserializeError::Network(format!("Failed to encode transaction: {}", e))
                })?;
                unsigned_tx = Some(tx);

                VarInt(key_data.len() as u64)
                    .consensus_encode(&mut modified_psbt)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode key length: {}",
                            e
                        ))
                    })?;
                modified_psbt.extend_from_slice(&key_data);

                VarInt(tx_bytes.len() as u64)
                    .consensus_encode(&mut modified_psbt)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode value length: {}",
                            e
                        ))
                    })?;
                modified_psbt.extend_from_slice(&tx_bytes);
            } else {
                // Copy key-value pair as-is
                VarInt(key_data.len() as u64)
                    .consensus_encode(&mut modified_psbt)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode key length: {}",
                            e
                        ))
                    })?;
                modified_psbt.extend_from_slice(&key_data);

                VarInt(val_data.len() as u64)
                    .consensus_encode(&mut modified_psbt)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode value length: {}",
                            e
                        ))
                    })?;
                modified_psbt.extend_from_slice(&val_data);
            }
        }

        if !found_tx {
            return Err(super::DeserializeError::Network(
                "Missing unsigned transaction".to_string(),
            ));
        }

        let unsigned_tx = unsigned_tx
            .ok_or_else(|| super::DeserializeError::Network("Missing tx".to_string()))?;
        let num_inputs = unsigned_tx.input.len();
        let num_outputs = unsigned_tx.output.len();

        let mut non_witness_utxo_bytes_by_input: Vec<Option<Vec<u8>>> = vec![None; num_inputs];

        // Decode input maps and transform non_witness_utxo values.
        //
        // Subtlety: we support both PSBT and PSBT-lite for Dash, but we only support legacy p2sh
        // input types. We do NOT support p2wsh or p2tr.
        for non_witness_slot in non_witness_utxo_bytes_by_input.iter_mut() {
            let mut witness_utxo_script: Option<ScriptBuf> = None;
            loop {
                let key_len: VarInt = Decodable::consensus_decode(&mut r)?;
                if key_len.0 == 0 {
                    // End of input map
                    0u8.consensus_encode(&mut modified_psbt).map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode input separator: {}",
                            e
                        ))
                    })?;
                    break;
                }

                let mut key_data = vec![0u8; key_len.0 as usize];
                r.read_exact(&mut key_data).map_err(|_| {
                    super::DeserializeError::Network("Failed to read input key".to_string())
                })?;

                let val_len: VarInt = Decodable::consensus_decode(&mut r)?;
                let mut val_data = vec![0u8; val_len.0 as usize];
                r.read_exact(&mut val_data).map_err(|_| {
                    super::DeserializeError::Network("Failed to read input value".to_string())
                })?;

                // PSBT input key type 0x00 is non_witness_utxo
                if !key_data.is_empty() && key_data[0] == 0x00 && key_data.len() == 1 {
                    *non_witness_slot = Some(val_data.clone());

                    let parts = crate::dash::transaction::decode_dash_transaction_parts(&val_data)
                        .map_err(super::DeserializeError::Network)?;
                    let mut tx_bytes = Vec::new();
                    parts
                        .transaction
                        .consensus_encode(&mut tx_bytes)
                        .map_err(|e| {
                            super::DeserializeError::Network(format!(
                                "Failed to encode non_witness_utxo transaction: {}",
                                e
                            ))
                        })?;

                    VarInt(key_data.len() as u64)
                        .consensus_encode(&mut modified_psbt)
                        .map_err(|e| {
                            super::DeserializeError::Network(format!(
                                "Failed to encode input key length: {}",
                                e
                            ))
                        })?;
                    modified_psbt.extend_from_slice(&key_data);

                    VarInt(tx_bytes.len() as u64)
                        .consensus_encode(&mut modified_psbt)
                        .map_err(|e| {
                            super::DeserializeError::Network(format!(
                                "Failed to encode input value length: {}",
                                e
                            ))
                        })?;
                    modified_psbt.extend_from_slice(&tx_bytes);
                } else if !key_data.is_empty() && key_data[0] == 0x01 && key_data.len() == 1 {
                    // witness_utxo (PSBT-lite). Allowed only for legacy p2sh.
                    let txout = TxOut::consensus_decode(&mut &val_data[..]).map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to decode witness_utxo: {}",
                            e
                        ))
                    })?;
                    witness_utxo_script = Some(txout.script_pubkey.clone());

                    // Copy key-value pair as-is (already bitcoin consensus)
                    VarInt(key_data.len() as u64)
                        .consensus_encode(&mut modified_psbt)
                        .map_err(|e| {
                            super::DeserializeError::Network(format!(
                                "Failed to encode input key length: {}",
                                e
                            ))
                        })?;
                    modified_psbt.extend_from_slice(&key_data);
                    VarInt(val_data.len() as u64)
                        .consensus_encode(&mut modified_psbt)
                        .map_err(|e| {
                            super::DeserializeError::Network(format!(
                                "Failed to encode input value length: {}",
                                e
                            ))
                        })?;
                    modified_psbt.extend_from_slice(&val_data);
                } else {
                    // Copy key-value pair as-is
                    VarInt(key_data.len() as u64)
                        .consensus_encode(&mut modified_psbt)
                        .map_err(|e| {
                            super::DeserializeError::Network(format!(
                                "Failed to encode input key length: {}",
                                e
                            ))
                        })?;
                    modified_psbt.extend_from_slice(&key_data);

                    VarInt(val_data.len() as u64)
                        .consensus_encode(&mut modified_psbt)
                        .map_err(|e| {
                            super::DeserializeError::Network(format!(
                                "Failed to encode input value length: {}",
                                e
                            ))
                        })?;
                    modified_psbt.extend_from_slice(&val_data);
                }
            }

            // If witness_utxo is present, ensure it is p2sh. (Reject p2wsh/p2tr/etc.)
            if let Some(script) = witness_utxo_script {
                if !script.is_p2sh() {
                    return Err(super::DeserializeError::Network(
                        "Dash PSBT-lite only supported for p2sh (no p2wsh/p2tr)".to_string(),
                    ));
                }
            }
        }

        // Copy output maps and any remaining data as-is. Count is determined by unsigned tx.
        // We don't need to transform outputs for Dash.
        // (If there are additional bytes, `Psbt::deserialize` will validate structure.)
        modified_psbt.extend_from_slice(r);

        // Deserialize as standard PSBT
        let psbt = Psbt::deserialize(&modified_psbt)?;

        // Sanity check: match global counts
        if psbt.inputs.len() != num_inputs || psbt.outputs.len() != num_outputs {
            return Err(super::DeserializeError::Network(
                "PSBT input/output map count mismatch".to_string(),
            ));
        }

        Ok(DashBitGoPsbt {
            psbt,
            network,
            unsigned_tx_bytes,
            non_witness_utxo_bytes_by_input,
        })
    }

    pub fn deserialize(
        bytes: &[u8],
        network: crate::Network,
    ) -> Result<Self, super::DeserializeError> {
        Self::decode_with_dash_tx(bytes, network)
    }

    /// Serialize the Dash PSBT back to bytes, preserving original Dash transaction bytes.
    pub fn serialize(&self) -> Result<Vec<u8>, super::DeserializeError> {
        let bitcoin_psbt_bytes = self.psbt.serialize();
        let mut r = bitcoin_psbt_bytes.as_slice();

        // Copy magic + separator
        if r.len() < 5 || &r[0..5] != b"psbt\xff" {
            return Err(super::DeserializeError::Network(
                "Invalid PSBT bytes during serialize".to_string(),
            ));
        }

        let mut result = Vec::new();
        result.extend_from_slice(&bitcoin_psbt_bytes[0..5]);
        r = &r[5..];

        // Read global map to find tx and determine counts
        let mut unsigned_tx: Option<Transaction> = None;
        let mut found_tx = false;

        // First pass: copy global map, but replace tx value with the original Dash bytes
        loop {
            let key_len: VarInt = Decodable::consensus_decode(&mut r)?;
            if key_len.0 == 0 {
                0u8.consensus_encode(&mut result).map_err(|e| {
                    super::DeserializeError::Network(format!("Failed to encode separator: {}", e))
                })?;
                break;
            }

            let mut key_data = vec![0u8; key_len.0 as usize];
            r.read_exact(&mut key_data)
                .map_err(|_| super::DeserializeError::Network("Failed to read key".to_string()))?;

            let val_len: VarInt = Decodable::consensus_decode(&mut r)?;
            let mut val_data = vec![0u8; val_len.0 as usize];
            r.read_exact(&mut val_data).map_err(|_| {
                super::DeserializeError::Network("Failed to read value".to_string())
            })?;

            if !key_data.is_empty() && key_data[0] == 0x00 && key_data.len() == 1 {
                found_tx = true;
                // Decode the bitcoin-compatible unsigned tx (present in the serialized psbt)
                let tx = Transaction::consensus_decode(&mut &val_data[..]).map_err(|e| {
                    super::DeserializeError::Network(format!(
                        "Failed to decode unsigned transaction during serialize: {}",
                        e
                    ))
                })?;
                unsigned_tx = Some(tx);

                // Write key
                VarInt(key_data.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode key length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&key_data);

                // Write original Dash bytes
                VarInt(self.unsigned_tx_bytes.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode value length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&self.unsigned_tx_bytes);
            } else {
                // Copy as-is
                VarInt(key_data.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode key length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&key_data);
                VarInt(val_data.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode value length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&val_data);
            }
        }

        if !found_tx {
            return Err(super::DeserializeError::Network(
                "Missing unsigned transaction in PSBT".to_string(),
            ));
        }

        let unsigned_tx = unsigned_tx
            .ok_or_else(|| super::DeserializeError::Network("Missing tx".to_string()))?;
        let num_inputs = unsigned_tx.input.len();
        let _num_outputs = unsigned_tx.output.len();

        // Rewrite input maps, replacing non_witness_utxo values with preserved original bytes.
        //
        // Simplification: Dash support is legacy p2sh-only, so we assume `non_witness_utxo`
        // exists for relevant inputs and we don't attempt to synthesize it or rewrite segwit fields.
        for original_non_witness_opt in self.non_witness_utxo_bytes_by_input.iter().take(num_inputs)
        {
            let original_non_witness = original_non_witness_opt.as_ref();

            loop {
                let key_len: VarInt = Decodable::consensus_decode(&mut r)?;
                if key_len.0 == 0 {
                    0u8.consensus_encode(&mut result).map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode input separator: {}",
                            e
                        ))
                    })?;
                    break;
                }

                let mut key_data = vec![0u8; key_len.0 as usize];
                r.read_exact(&mut key_data).map_err(|_| {
                    super::DeserializeError::Network("Failed to read input key".to_string())
                })?;

                let val_len: VarInt = Decodable::consensus_decode(&mut r)?;
                let mut val_data = vec![0u8; val_len.0 as usize];
                r.read_exact(&mut val_data).map_err(|_| {
                    super::DeserializeError::Network("Failed to read input value".to_string())
                })?;

                if !key_data.is_empty() && key_data[0] == 0x00 && key_data.len() == 1 {
                    if let Some(original) = original_non_witness {
                        VarInt(key_data.len() as u64)
                            .consensus_encode(&mut result)
                            .map_err(|e| {
                                super::DeserializeError::Network(format!(
                                    "Failed to encode input key length: {}",
                                    e
                                ))
                            })?;
                        result.extend_from_slice(&key_data);
                        VarInt(original.len() as u64)
                            .consensus_encode(&mut result)
                            .map_err(|e| {
                                super::DeserializeError::Network(format!(
                                    "Failed to encode input value length: {}",
                                    e
                                ))
                            })?;
                        result.extend_from_slice(original);
                        continue;
                    }
                }

                // Default: copy as-is
                VarInt(key_data.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode input key length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&key_data);
                VarInt(val_data.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode input value length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&val_data);
            }
        }

        // Copy remaining bytes (outputs maps) as-is
        result.extend_from_slice(r);
        Ok(result)
    }

    pub fn into_bitcoin_psbt(self) -> Psbt {
        self.psbt
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use miniscript::bitcoin::consensus::Encodable;
    use miniscript::bitcoin::{
        absolute::LockTime, transaction::Version, OutPoint, ScriptBuf, TxIn, TxOut,
    };
    use serde::Deserialize;

    #[derive(Debug, Clone, Deserialize)]
    struct DashRpcTransaction {
        hex: String,
    }

    fn read_dash_evo_fixture_hex(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/test/fixtures_thirdparty/dashTestExtra/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        );
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("Failed to read dash evo fixture: {}", path));
        let tx: DashRpcTransaction =
            serde_json::from_str(&content).expect("Failed to parse dash evo fixture JSON");
        hex::decode(&tx.hex).expect("Failed to decode tx hex")
    }

    fn replace_first_input_non_witness_utxo(psbt_bytes: &[u8], new_tx_bytes: &[u8]) -> Vec<u8> {
        let mut r = psbt_bytes;

        // magic + separator
        let magic: [u8; 4] = Decodable::consensus_decode(&mut r).expect("magic");
        assert_eq!(&magic, b"psbt");
        let sep: u8 = Decodable::consensus_decode(&mut r).expect("sep");
        assert_eq!(sep, 0xff);

        let mut out = Vec::new();
        out.extend_from_slice(b"psbt\xff");

        // Copy global map unchanged
        loop {
            let key_len: VarInt = Decodable::consensus_decode(&mut r).expect("key_len");
            if key_len.0 == 0 {
                0u8.consensus_encode(&mut out).unwrap();
                break;
            }
            let mut key = vec![0u8; key_len.0 as usize];
            r.read_exact(&mut key).unwrap();
            let val_len: VarInt = Decodable::consensus_decode(&mut r).expect("val_len");
            let mut val = vec![0u8; val_len.0 as usize];
            r.read_exact(&mut val).unwrap();

            VarInt(key.len() as u64).consensus_encode(&mut out).unwrap();
            out.extend_from_slice(&key);
            VarInt(val.len() as u64).consensus_encode(&mut out).unwrap();
            out.extend_from_slice(&val);
        }

        // Input map #0: replace key 0x00 value
        let mut replaced = false;
        loop {
            let key_len: VarInt = Decodable::consensus_decode(&mut r).expect("in_key_len");
            if key_len.0 == 0 {
                0u8.consensus_encode(&mut out).unwrap();
                break;
            }
            let mut key = vec![0u8; key_len.0 as usize];
            r.read_exact(&mut key).unwrap();
            let val_len: VarInt = Decodable::consensus_decode(&mut r).expect("in_val_len");
            let mut val = vec![0u8; val_len.0 as usize];
            r.read_exact(&mut val).unwrap();

            if key == [0x00] {
                replaced = true;
                VarInt(1).consensus_encode(&mut out).unwrap();
                out.push(0x00);
                VarInt(new_tx_bytes.len() as u64)
                    .consensus_encode(&mut out)
                    .unwrap();
                out.extend_from_slice(new_tx_bytes);
                continue;
            }

            VarInt(key.len() as u64).consensus_encode(&mut out).unwrap();
            out.extend_from_slice(&key);
            VarInt(val.len() as u64).consensus_encode(&mut out).unwrap();
            out.extend_from_slice(&val);
        }
        assert!(replaced, "Expected input[0] non_witness_utxo key 0x00");

        // Copy the rest (remaining input maps + outputs)
        out.extend_from_slice(r);
        out
    }

    fn extract_first_input_non_witness_utxo(psbt_bytes: &[u8]) -> Vec<u8> {
        let mut r = psbt_bytes;

        let magic: [u8; 4] = Decodable::consensus_decode(&mut r).expect("magic");
        assert_eq!(&magic, b"psbt");
        let sep: u8 = Decodable::consensus_decode(&mut r).expect("sep");
        assert_eq!(sep, 0xff);

        // Skip global map
        loop {
            let key_len: VarInt = Decodable::consensus_decode(&mut r).expect("key_len");
            if key_len.0 == 0 {
                break;
            }
            let mut key = vec![0u8; key_len.0 as usize];
            r.read_exact(&mut key).unwrap();
            let val_len: VarInt = Decodable::consensus_decode(&mut r).expect("val_len");
            let mut val = vec![0u8; val_len.0 as usize];
            r.read_exact(&mut val).unwrap();
        }

        // Read input map #0 and find key 0x00
        loop {
            let key_len: VarInt = Decodable::consensus_decode(&mut r).expect("in_key_len");
            if key_len.0 == 0 {
                break;
            }
            let mut key = vec![0u8; key_len.0 as usize];
            r.read_exact(&mut key).unwrap();
            let val_len: VarInt = Decodable::consensus_decode(&mut r).expect("in_val_len");
            let mut val = vec![0u8; val_len.0 as usize];
            r.read_exact(&mut val).unwrap();
            if key == [0x00] {
                return val;
            }
        }
        panic!("Missing non_witness_utxo key 0x00 in input[0]");
    }

    #[test]
    fn test_dash_psbt_preserves_non_witness_utxo_bytes() {
        // Load a Dash EVO tx (may be special or normal); treat it as a prev_tx in non_witness_utxo.
        let dash_prev_tx_bytes = read_dash_evo_fixture_hex("evo_transaction_000.json");

        // Also create a bitcoin-compatible transaction for miniscript's PSBT to serialize initially.
        let parts = crate::dash::transaction::decode_dash_transaction_parts(&dash_prev_tx_bytes)
            .expect("decode dash tx");
        let bitcoin_prev_tx = parts.transaction;

        // Minimal unsigned transaction for the PSBT itself (must be PSBT-valid: empty scripts).
        let unsigned_tx = Transaction {
            version: Version(2),
            lock_time: LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: miniscript::bitcoin::transaction::Sequence(0xFFFF_FFFE),
                witness: miniscript::bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: miniscript::bitcoin::Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("psbt from unsigned tx");
        psbt.inputs[0].non_witness_utxo = Some(bitcoin_prev_tx);

        let bitcoin_psbt_bytes = psbt.serialize();
        let patched_psbt_bytes =
            replace_first_input_non_witness_utxo(&bitcoin_psbt_bytes, &dash_prev_tx_bytes);

        // Deserialize through DashBitGoPsbt: should succeed and preserve original bytes.
        let dash_psbt = DashBitGoPsbt::deserialize(&patched_psbt_bytes, crate::Network::Dash)
            .expect("deserialize");

        // Serialize should re-insert the original Dash bytes into non_witness_utxo.
        let serialized = dash_psbt.serialize().expect("serialize");
        let extracted = extract_first_input_non_witness_utxo(&serialized);
        assert_eq!(extracted, dash_prev_tx_bytes);
    }
}
