use miniscript::bitcoin::{psbt, psbt::raw, Psbt, TxIn, TxOut};

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

pub fn remove_input(psbt: &mut Psbt, index: usize) -> Result<(), String> {
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

pub fn remove_output(psbt: &mut Psbt, index: usize) -> Result<(), String> {
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
