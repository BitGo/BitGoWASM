use anyhow::{anyhow, Context, Result};
use rand::rngs::OsRng;
use std::path::PathBuf;
use wasm_utxo::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt;
use wasm_utxo::Network;

use crate::input::{decode_input, read_input_bytes};

#[allow(clippy::too_many_arguments)]
pub fn handle_add_shielded_output_command(
    path: PathBuf,
    network: Network,
    recipient: String,
    value: u64,
    anchor: String,
    ovk: Option<String>,
    memo: Option<String>,
    unified_address: Option<String>,
) -> Result<()> {
    let raw_bytes = read_input_bytes(&path, "PSBT")?;
    let bytes = decode_input(&raw_bytes)?;
    let mut psbt = ZcashBitGoPsbt::deserialize_v6_pre_shield(&bytes, network)
        .map_err(|e| anyhow!("Failed to parse v6 PSBT: {e}"))?;

    let recipient: [u8; 43] = hex::decode(&recipient)
        .context("invalid --recipient hex")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("--recipient must be 43 bytes, got {}", v.len()))?;
    let anchor: [u8; 32] = hex::decode(&anchor)
        .context("invalid --anchor hex")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("--anchor must be 32 bytes, got {}", v.len()))?;
    let ovk = ovk
        .map(|s| {
            hex::decode(&s)
                .context("invalid --ovk hex")?
                .try_into()
                .map_err(|v: Vec<u8>| anyhow!("--ovk must be 32 bytes, got {}", v.len()))
        })
        .transpose()?;
    let memo: [u8; 512] = match memo {
        Some(s) => hex::decode(&s)
            .context("invalid --memo hex")?
            .try_into()
            .map_err(|v: Vec<u8>| anyhow!("--memo must be 512 bytes, got {}", v.len()))?,
        None => [0u8; 512],
    };

    psbt.add_ironwood_output(
        &recipient,
        value,
        ovk,
        &anchor,
        &memo,
        unified_address.as_deref(),
        OsRng,
    )
    .map_err(|e| anyhow!(e))
    .context("failed to add shielded output")?;

    println!("{}", hex::encode(psbt.serialize().map_err(|e| anyhow!(e))?));
    Ok(())
}
