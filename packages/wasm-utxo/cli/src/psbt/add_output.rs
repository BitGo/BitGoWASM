use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use wasm_utxo::bitcoin::psbt::Output as PsbtOutput;
use wasm_utxo::bitcoin::{Amount, ScriptBuf, TxOut};
use wasm_utxo::psbt_ops::insert_output;
use wasm_utxo::to_output_script_with_network;

use super::common::{print_psbt, read_psbt};
use crate::network::NetworkArg;

pub fn handle_add_output_command(
    path: PathBuf,
    network: Option<NetworkArg>,
    address: Option<String>,
    script: Option<String>,
    value: u64,
) -> Result<()> {
    let mut psbt = read_psbt(&path)?;

    let script_pubkey = match (address, script) {
        (Some(address), None) => {
            let network = network
                .ok_or_else(|| anyhow!("--network is required when using --address"))?
                .into();
            to_output_script_with_network(&address, network).context("invalid --address")?
        }
        (None, Some(script)) => {
            ScriptBuf::from(hex::decode(&script).context("invalid --script hex")?)
        }
        _ => bail!("expected exactly one of --address or --script"),
    };

    let index = psbt.outputs.len();
    insert_output(
        &mut psbt,
        index,
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        },
        PsbtOutput::default(),
    )
    .map_err(|e| anyhow!(e))
    .with_context(|| format!("failed to add output {index}"))?;

    print_psbt(&psbt);
    Ok(())
}
