use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use wasm_utxo::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt;
use wasm_utxo::Network;

use crate::input::{decode_input, read_input_bytes};

/// Finalize transparent inputs and extract the broadcast-ready v6 transaction for a PSBT that
/// has no shielded output (no PCZT). This is the transparent-only v6 counterpart of
/// `combine-ironwood-proof`: it calls `extract_transparent_only_v6_tx()` instead of
/// `combine_ironwood_proof()`. Prints the raw transaction as hex to stdout.
pub fn handle_extract_transparent_only_command(path: PathBuf, network: Network) -> Result<()> {
    let raw_bytes = read_input_bytes(&path, "PSBT")?;
    let bytes = decode_input(&raw_bytes)?;
    let psbt = ZcashBitGoPsbt::deserialize(&bytes, network)
        .map_err(|e| anyhow!("Failed to parse v6 PSBT: {e}"))?;

    let tx_bytes = psbt
        .extract_transparent_only_v6_tx()
        .map_err(|e| anyhow!(e))
        .context("failed to extract transparent-only v6 transaction")?;

    println!("{}", hex::encode(tx_bytes));
    Ok(())
}
