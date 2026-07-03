use anyhow::{Context, Result};
use std::path::PathBuf;
use wasm_utxo::bitcoin::psbt::Psbt;

use crate::input::{decode_input, read_input_bytes};

/// Read and deserialize a PSBT from a file path or stdin (`-`), auto-detecting
/// hex/base64/raw encoding.
pub fn read_psbt(path: &PathBuf) -> Result<Psbt> {
    let raw_bytes = read_input_bytes(path, "PSBT")?;
    let bytes = decode_input(&raw_bytes)?;
    Psbt::deserialize(&bytes).context("Failed to parse PSBT")
}

/// Serialize a PSBT and print it as hex to stdout.
pub fn print_psbt(psbt: &Psbt) {
    println!("{}", hex::encode(psbt.serialize()));
}
