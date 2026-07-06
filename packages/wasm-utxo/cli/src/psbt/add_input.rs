use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use std::str::FromStr;
use wasm_utxo::add_input_with_descriptor;
use wasm_utxo::bitcoin::consensus::Decodable;
use wasm_utxo::bitcoin::{ScriptBuf, Transaction, Txid};

use super::common::{print_psbt, read_psbt};
use crate::network::NetworkArg;

#[allow(clippy::too_many_arguments)]
pub fn handle_add_input_command(
    path: PathBuf,
    network: NetworkArg,
    txid: String,
    vout: u32,
    value: u64,
    script: String,
    descriptor: String,
    sequence: u32,
    prev_tx: Option<String>,
) -> Result<()> {
    let network: wasm_utxo::Network = network.into();
    let mut psbt = read_psbt(&path)?;

    let txid = Txid::from_str(&txid).context("invalid --txid")?;
    let script_pubkey = ScriptBuf::from(hex::decode(&script).context("invalid --script hex")?);

    let non_witness_utxo = match prev_tx {
        Some(hex_str) => {
            let bytes = hex::decode(&hex_str).context("invalid --prev-tx hex")?;
            let tx = Transaction::consensus_decode(&mut bytes.as_slice())
                .context("invalid --prev-tx transaction")?;
            if tx.compute_txid() != txid {
                bail!(
                    "--prev-tx txid {} does not match --txid {}",
                    tx.compute_txid(),
                    txid
                );
            }
            Some(tx)
        }
        None if network.requires_prev_tx_for_legacy_input() => {
            bail!(
                "--prev-tx is required for network {network} (only value-committing networks \
                 like Zcash/BCH-family can omit it)"
            );
        }
        None => None,
    };

    let index = psbt.inputs.len();
    add_input_with_descriptor(
        &mut psbt,
        index,
        txid,
        vout,
        value,
        script_pubkey,
        &descriptor,
        sequence,
        non_witness_utxo,
    )
    .map_err(|e| anyhow!(e))
    .with_context(|| format!("failed to add input {index}"))?;

    print_psbt(&psbt);
    Ok(())
}
