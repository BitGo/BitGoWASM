use miniscript::bitcoin::consensus::encode::VarInt;
use miniscript::bitcoin::consensus::Decodable;
use miniscript::bitcoin::{psbt, psbt::raw, Psbt, TxIn, TxOut};

/// A raw PSBT key-value record.
///
/// `key_type` identifies the standard or proprietary record type and `key_data`
/// carries the remainder of the key. Keeping this representation raw ensures
/// callers can inspect every known and future PSBT key without duplicating the
/// typed field layout maintained by rust-bitcoin.
#[derive(Debug, Clone)]
pub(crate) struct PsbtKeyValue {
    pub key_type: u64,
    pub key_data: Vec<u8>,
    pub value: Vec<u8>,
}

/// Return the standard name for a known PSBT input key type.
pub(crate) fn known_psbt_input_key_type(key_type: u64) -> Option<&'static str> {
    match key_type {
        0x00 => Some("PSBT_IN_NON_WITNESS_UTXO"),
        0x01 => Some("PSBT_IN_WITNESS_UTXO"),
        0x02 => Some("PSBT_IN_PARTIAL_SIG"),
        0x03 => Some("PSBT_IN_SIGHASH_TYPE"),
        0x04 => Some("PSBT_IN_REDEEM_SCRIPT"),
        0x05 => Some("PSBT_IN_WITNESS_SCRIPT"),
        0x06 => Some("PSBT_IN_BIP32_DERIVATION"),
        0x07 => Some("PSBT_IN_FINAL_SCRIPTSIG"),
        0x08 => Some("PSBT_IN_FINAL_SCRIPTWITNESS"),
        0x09 => Some("PSBT_IN_POR_COMMITMENT"),
        0x0a => Some("PSBT_IN_RIPEMD160"),
        0x0b => Some("PSBT_IN_SHA256"),
        0x0c => Some("PSBT_IN_HASH160"),
        0x0d => Some("PSBT_IN_HASH256"),
        0x0e => Some("PSBT_IN_PREVIOUS_TXID"),
        0x0f => Some("PSBT_IN_OUTPUT_INDEX"),
        0x10 => Some("PSBT_IN_SEQUENCE"),
        0x11 => Some("PSBT_IN_REQUIRED_TIME_LOCKTIME"),
        0x12 => Some("PSBT_IN_REQUIRED_HEIGHT_LOCKTIME"),
        0x13 => Some("PSBT_IN_TAP_KEY_SIG"),
        0x14 => Some("PSBT_IN_TAP_SCRIPT_SIG"),
        0x15 => Some("PSBT_IN_TAP_LEAF_SCRIPT"),
        0x16 => Some("PSBT_IN_TAP_BIP32_DERIVATION"),
        0x17 => Some("PSBT_IN_TAP_INTERNAL_KEY"),
        0x18 => Some("PSBT_IN_TAP_MERKLE_ROOT"),
        0x1a => Some("PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS"),
        0x1b => Some("PSBT_IN_MUSIG2_PUB_NONCE"),
        0x1c => Some("PSBT_IN_MUSIG2_PARTIAL_SIG"),
        0x1d => Some("PSBT_IN_SP_ECDH_SHARE"),
        0x1e => Some("PSBT_IN_SP_DLEQ"),
        0x1f => Some("PSBT_IN_SP_SPEND_BIP32_DERIVATION"),
        0x20 => Some("PSBT_IN_SP_TWEAK"),
        0xfc => Some("PSBT_IN_PROPRIETARY"),
        _ => None,
    }
}

/// Decode one canonical Bitcoin CompactSize integer and report its byte length.
pub(crate) fn decode_compact_size_u64(bytes: &[u8]) -> Result<(u64, usize), String> {
    let mut reader = bytes;
    let value = VarInt::consensus_decode(&mut reader)
        .map_err(|e| format!("failed to read compact size: {e}"))?
        .0;
    Ok((value, bytes.len() - reader.len()))
}

/// Decode one canonical Bitcoin CompactSize length and report its byte length.
pub(crate) fn decode_compact_size(bytes: &[u8]) -> Result<(usize, usize), String> {
    let (value, size) = decode_compact_size_u64(bytes)?;
    let value = usize::try_from(value)
        .map_err(|_| format!("compact size {value} exceeds platform limits"))?;
    Ok((value, size))
}

/// Decode one BIP-174 key-value map, including its terminating empty key.
///
/// rust-bitcoin keeps raw `Pair` decoding crate-private, so this is the
/// feature-independent equivalent used by both the inspection and WASM APIs.
pub(crate) fn decode_psbt_key_value_map(
    bytes: &[u8],
) -> Result<(Vec<PsbtKeyValue>, usize), String> {
    let mut key_values = Vec::new();
    let mut offset = 0;

    loop {
        let (key_length, key_length_size) = decode_compact_size(&bytes[offset..])?;
        offset += key_length_size;
        if key_length == 0 {
            return Ok((key_values, offset));
        }

        let key_end = offset
            .checked_add(key_length)
            .ok_or_else(|| "PSBT key length overflows platform limits".to_string())?;
        let key = bytes
            .get(offset..key_end)
            .ok_or_else(|| format!("PSBT key exceeds map length at offset {offset}"))?;
        offset = key_end;

        let (key_type, key_type_size) = decode_compact_size_u64(key)?;

        let (value_length, value_length_size) = decode_compact_size(&bytes[offset..])?;
        offset += value_length_size;
        let value_end = offset
            .checked_add(value_length)
            .ok_or_else(|| "PSBT value length overflows platform limits".to_string())?;
        let value = bytes
            .get(offset..value_end)
            .ok_or_else(|| format!("PSBT value exceeds map length at offset {offset}"))?;
        offset = value_end;

        key_values.push(PsbtKeyValue {
            key_type,
            key_data: key[key_type_size..].to_vec(),
            value: value.to_vec(),
        });
    }
}

/// Returns every serialized key-value record for a PSBT input.
///
/// rust-bitcoin stores standard PSBT keys in typed struct fields and only
/// preserves unrecognized keys in `unknown`. Inspecting the serialized input
/// map exposes both sets uniformly, including metadata such as PSBT_IN_SHA256.
pub(crate) fn get_input_key_values(psbt: &Psbt, index: usize) -> Result<Vec<PsbtKeyValue>, String> {
    let input_count = psbt.inputs.len();
    if index >= input_count {
        return Err(format!(
            "input index {index} out of bounds (have {input_count} inputs)"
        ));
    }

    let serialized = psbt.serialize();
    if !serialized.starts_with(b"psbt\xff") {
        return Err("serialized PSBT has an invalid magic prefix".to_string());
    }

    let mut offset = 5;
    let (_, consumed) = decode_psbt_key_value_map(&serialized[offset..])?;
    offset += consumed;
    for current_index in 0..=index {
        let (key_values, consumed) = decode_psbt_key_value_map(&serialized[offset..])?;
        offset += consumed;
        if current_index == index {
            return Ok(key_values);
        }
    }

    unreachable!("input index bounds were checked before parsing")
}

/// Shared accessor trait for types that wrap a `Psbt`.
///
/// Provides default implementations for common introspection methods so that
/// both `WrapPsbt` and `BitGoPsbt` can reuse the same logic.
pub trait PsbtAccess {
    fn psbt(&self) -> &Psbt;
    fn psbt_mut(&mut self) -> &mut Psbt;

    fn input_count(&self) -> usize {
        self.psbt().inputs.len()
    }

    fn output_count(&self) -> usize {
        self.psbt().outputs.len()
    }

    fn version(&self) -> i32 {
        self.psbt().unsigned_tx.version.0
    }

    fn lock_time(&self) -> u32 {
        self.psbt().unsigned_tx.lock_time.to_consensus_u32()
    }

    fn unsigned_tx_id(&self) -> String {
        self.psbt().unsigned_tx.compute_txid().to_string()
    }

    // -------------------------------------------------------------------------
    // Global KV accessors
    // -------------------------------------------------------------------------

    fn set_global_unknown_kv(&mut self, key: raw::Key, value: Vec<u8>) {
        self.psbt_mut().unknown.insert(key, value);
    }

    fn get_global_unknown_kv(&self, key: &raw::Key) -> Option<Vec<u8>> {
        self.psbt().unknown.get(key).cloned()
    }

    fn set_global_proprietary_kv(&mut self, key: raw::ProprietaryKey, value: Vec<u8>) {
        self.psbt_mut().proprietary.insert(key, value);
    }

    fn get_global_proprietary_kv(&self, key: &raw::ProprietaryKey) -> Option<Vec<u8>> {
        self.psbt().proprietary.get(key).cloned()
    }

    fn delete_global_unknown_kv(&mut self, key: raw::Key) {
        self.psbt_mut().unknown.remove(&key);
    }

    fn delete_global_proprietary_kv(&mut self, key: raw::ProprietaryKey) {
        self.psbt_mut().proprietary.remove(&key);
    }

    // -------------------------------------------------------------------------
    // Per-input KV accessors
    // -------------------------------------------------------------------------

    fn set_input_unknown_kv(
        &mut self,
        index: usize,
        key: raw::Key,
        value: Vec<u8>,
    ) -> Result<(), String> {
        let len = self.psbt().inputs.len();
        if index >= len {
            return Err(format!(
                "input index {index} out of bounds (have {len} inputs)"
            ));
        }
        self.psbt_mut().inputs[index].unknown.insert(key, value);
        Ok(())
    }

    fn get_input_unknown_kv(
        &self,
        index: usize,
        key: &raw::Key,
    ) -> Result<Option<Vec<u8>>, String> {
        let len = self.psbt().inputs.len();
        if index >= len {
            return Err(format!(
                "input index {index} out of bounds (have {len} inputs)"
            ));
        }
        Ok(self.psbt().inputs[index].unknown.get(key).cloned())
    }

    fn set_input_proprietary_kv(
        &mut self,
        index: usize,
        key: raw::ProprietaryKey,
        value: Vec<u8>,
    ) -> Result<(), String> {
        let len = self.psbt().inputs.len();
        if index >= len {
            return Err(format!(
                "input index {index} out of bounds (have {len} inputs)"
            ));
        }
        self.psbt_mut().inputs[index].proprietary.insert(key, value);
        Ok(())
    }

    fn get_input_proprietary_kv(
        &self,
        index: usize,
        key: &raw::ProprietaryKey,
    ) -> Result<Option<Vec<u8>>, String> {
        let len = self.psbt().inputs.len();
        if index >= len {
            return Err(format!(
                "input index {index} out of bounds (have {len} inputs)"
            ));
        }
        Ok(self.psbt().inputs[index].proprietary.get(key).cloned())
    }

    fn delete_input_unknown_kv(&mut self, index: usize, key: raw::Key) -> Result<(), String> {
        let len = self.psbt().inputs.len();
        if index >= len {
            return Err(format!(
                "input index {index} out of bounds (have {len} inputs)"
            ));
        }
        self.psbt_mut().inputs[index].unknown.remove(&key);
        Ok(())
    }

    fn delete_input_proprietary_kv(
        &mut self,
        index: usize,
        key: raw::ProprietaryKey,
    ) -> Result<(), String> {
        let len = self.psbt().inputs.len();
        if index >= len {
            return Err(format!(
                "input index {index} out of bounds (have {len} inputs)"
            ));
        }
        self.psbt_mut().inputs[index].proprietary.remove(&key);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Per-output KV accessors
    // -------------------------------------------------------------------------

    fn set_output_unknown_kv(
        &mut self,
        index: usize,
        key: raw::Key,
        value: Vec<u8>,
    ) -> Result<(), String> {
        let len = self.psbt().outputs.len();
        if index >= len {
            return Err(format!(
                "output index {index} out of bounds (have {len} outputs)"
            ));
        }
        self.psbt_mut().outputs[index].unknown.insert(key, value);
        Ok(())
    }

    fn get_output_unknown_kv(
        &self,
        index: usize,
        key: &raw::Key,
    ) -> Result<Option<Vec<u8>>, String> {
        let len = self.psbt().outputs.len();
        if index >= len {
            return Err(format!(
                "output index {index} out of bounds (have {len} outputs)"
            ));
        }
        Ok(self.psbt().outputs[index].unknown.get(key).cloned())
    }

    fn set_output_proprietary_kv(
        &mut self,
        index: usize,
        key: raw::ProprietaryKey,
        value: Vec<u8>,
    ) -> Result<(), String> {
        let len = self.psbt().outputs.len();
        if index >= len {
            return Err(format!(
                "output index {index} out of bounds (have {len} outputs)"
            ));
        }
        self.psbt_mut().outputs[index]
            .proprietary
            .insert(key, value);
        Ok(())
    }

    fn get_output_proprietary_kv(
        &self,
        index: usize,
        key: &raw::ProprietaryKey,
    ) -> Result<Option<Vec<u8>>, String> {
        let len = self.psbt().outputs.len();
        if index >= len {
            return Err(format!(
                "output index {index} out of bounds (have {len} outputs)"
            ));
        }
        Ok(self.psbt().outputs[index].proprietary.get(key).cloned())
    }

    fn delete_output_unknown_kv(&mut self, index: usize, key: raw::Key) -> Result<(), String> {
        let len = self.psbt().outputs.len();
        if index >= len {
            return Err(format!(
                "output index {index} out of bounds (have {len} outputs)"
            ));
        }
        self.psbt_mut().outputs[index].unknown.remove(&key);
        Ok(())
    }

    fn delete_output_proprietary_kv(
        &mut self,
        index: usize,
        key: raw::ProprietaryKey,
    ) -> Result<(), String> {
        let len = self.psbt().outputs.len();
        if index >= len {
            return Err(format!(
                "output index {index} out of bounds (have {len} outputs)"
            ));
        }
        self.psbt_mut().outputs[index].proprietary.remove(&key);
        Ok(())
    }

    fn remove_input(&mut self, index: usize) -> Result<(), String> {
        let psbt = self.psbt_mut();
        if index >= psbt.inputs.len() {
            return Err(format!(
                "input index {index} out of bounds (have {} inputs)",
                psbt.inputs.len()
            ));
        }
        psbt.unsigned_tx.input.remove(index);
        psbt.inputs.remove(index);
        Ok(())
    }

    fn remove_output(&mut self, index: usize) -> Result<(), String> {
        let psbt = self.psbt_mut();
        if index >= psbt.outputs.len() {
            return Err(format!(
                "output index {index} out of bounds (have {} outputs)",
                psbt.outputs.len()
            ));
        }
        psbt.unsigned_tx.output.remove(index);
        psbt.outputs.remove(index);
        Ok(())
    }
}

fn check_bounds(index: usize, len: usize, name: &str) -> Result<(), String> {
    if index > len {
        return Err(format!(
            "{name} index {index} out of bounds (have {len} {name}s)"
        ));
    }
    Ok(())
}

pub fn insert_input(
    psbt: &mut Psbt,
    index: usize,
    tx_in: TxIn,
    psbt_input: psbt::Input,
) -> Result<usize, String> {
    check_bounds(index, psbt.inputs.len(), "input")?;
    psbt.unsigned_tx.input.insert(index, tx_in);
    psbt.inputs.insert(index, psbt_input);
    Ok(index)
}

pub fn insert_output(
    psbt: &mut Psbt,
    index: usize,
    tx_out: TxOut,
    psbt_output: psbt::Output,
) -> Result<usize, String> {
    check_bounds(index, psbt.outputs.len(), "output")?;
    psbt.unsigned_tx.output.insert(index, tx_out);
    psbt.outputs.insert(index, psbt_output);
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::{decode_compact_size, decode_psbt_key_value_map, known_psbt_input_key_type};

    #[test]
    fn decodes_compact_size_key_types() {
        let bytes = [0x04, 0xfd, 0x34, 0x12, 0xaa, 0x02, 0xbb, 0xcc, 0x00];

        let (key_values, consumed) = decode_psbt_key_value_map(&bytes).unwrap();

        assert_eq!(consumed, bytes.len());
        assert_eq!(key_values.len(), 1);
        assert_eq!(key_values[0].key_type, 0x1234);
        assert_eq!(key_values[0].key_data, vec![0xaa]);
        assert_eq!(key_values[0].value, vec![0xbb, 0xcc]);
    }

    #[test]
    fn rejects_truncated_compact_sizes() {
        assert!(decode_compact_size(&[0xfd, 0x34]).is_err());
    }

    #[test]
    fn recognizes_registered_psbt_input_key_types() {
        let known_key_types = [
            (0x00, "PSBT_IN_NON_WITNESS_UTXO"),
            (0x01, "PSBT_IN_WITNESS_UTXO"),
            (0x02, "PSBT_IN_PARTIAL_SIG"),
            (0x03, "PSBT_IN_SIGHASH_TYPE"),
            (0x04, "PSBT_IN_REDEEM_SCRIPT"),
            (0x05, "PSBT_IN_WITNESS_SCRIPT"),
            (0x06, "PSBT_IN_BIP32_DERIVATION"),
            (0x07, "PSBT_IN_FINAL_SCRIPTSIG"),
            (0x08, "PSBT_IN_FINAL_SCRIPTWITNESS"),
            (0x09, "PSBT_IN_POR_COMMITMENT"),
            (0x0a, "PSBT_IN_RIPEMD160"),
            (0x0b, "PSBT_IN_SHA256"),
            (0x0c, "PSBT_IN_HASH160"),
            (0x0d, "PSBT_IN_HASH256"),
            (0x0e, "PSBT_IN_PREVIOUS_TXID"),
            (0x0f, "PSBT_IN_OUTPUT_INDEX"),
            (0x10, "PSBT_IN_SEQUENCE"),
            (0x11, "PSBT_IN_REQUIRED_TIME_LOCKTIME"),
            (0x12, "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME"),
            (0x13, "PSBT_IN_TAP_KEY_SIG"),
            (0x14, "PSBT_IN_TAP_SCRIPT_SIG"),
            (0x15, "PSBT_IN_TAP_LEAF_SCRIPT"),
            (0x16, "PSBT_IN_TAP_BIP32_DERIVATION"),
            (0x17, "PSBT_IN_TAP_INTERNAL_KEY"),
            (0x18, "PSBT_IN_TAP_MERKLE_ROOT"),
            (0x1a, "PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS"),
            (0x1b, "PSBT_IN_MUSIG2_PUB_NONCE"),
            (0x1c, "PSBT_IN_MUSIG2_PARTIAL_SIG"),
            (0x1d, "PSBT_IN_SP_ECDH_SHARE"),
            (0x1e, "PSBT_IN_SP_DLEQ"),
            (0x1f, "PSBT_IN_SP_SPEND_BIP32_DERIVATION"),
            (0x20, "PSBT_IN_SP_TWEAK"),
            (0xfc, "PSBT_IN_PROPRIETARY"),
        ];

        for (key_type, expected_name) in known_key_types {
            assert_eq!(known_psbt_input_key_type(key_type), Some(expected_name));
        }
        for key_type in [0x19, 0x21, 0xfd, 0x1234] {
            assert_eq!(known_psbt_input_key_type(key_type), None);
        }
    }
}
