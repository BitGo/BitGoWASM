use anyhow::{anyhow, bail, Context, Result};
use rand::rngs::OsRng;
use std::path::PathBuf;
use wasm_utxo::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt;
use wasm_utxo::Network;

use crate::input::{decode_input, read_input_bytes};

/// Transaction Extractor role: finalize the transparent inputs, splice in the proof (external, via
/// `--proof`, or produced locally via `--local-proof`), and produce the broadcast-ready v6
/// transaction bytes. Prints the raw transaction as hex.
pub fn handle_combine_ironwood_proof_command(
    path: PathBuf,
    network: Network,
    proof: Option<String>,
    local_proof: bool,
) -> Result<()> {
    let raw_bytes = read_input_bytes(&path, "PSBT")?;
    let bytes = decode_input(&raw_bytes)?;
    let psbt = ZcashBitGoPsbt::deserialize(&bytes, network)
        .map_err(|e| anyhow!("Failed to parse v6 PSBT: {e}"))?;

    let tx_bytes = match (proof, local_proof) {
        (Some(_), true) => bail!("expected exactly one of --proof or --local-proof"),
        (Some(proof), false) => {
            let proof = hex::decode(&proof).context("invalid --proof hex")?;
            psbt.combine_ironwood_proof(proof, OsRng)
        }
        (None, true) => psbt.combine_ironwood_proof_locally(OsRng),
        (None, false) => bail!("expected exactly one of --proof or --local-proof"),
    }
    .map_err(|e| anyhow!(e))
    .context("failed to combine Ironwood proof")?;

    println!("{}", hex::encode(tx_bytes));
    Ok(())
}
