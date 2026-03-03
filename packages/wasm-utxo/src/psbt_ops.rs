use miniscript::bitcoin::{psbt, Psbt, TxIn, TxOut};

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
