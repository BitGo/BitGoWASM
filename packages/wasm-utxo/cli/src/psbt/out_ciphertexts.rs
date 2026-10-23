//! The viewing-key holder's ciphertext round (the stand-in for the out-ciphertext step):
//! request the pending real outputs, re-encrypt each under the FVK's external `ovk`, and
//! apply the response in one atomic batch. A bundle with nothing pending (a deshield with no
//! shielded outputs, or a repeated round) passes through unchanged. Prints the PSBT as hex to
//! stdout, with the action indices served on stderr.

use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use std::path::PathBuf;
use wasm_utxo::fixed_script_wallet::bitgo_psbt::zcash::IronwoodPsbtError;
use wasm_utxo::zcash::ironwood_build::compute_out_ciphertext;
use wasm_utxo::zcash::ironwood_pczt::deserialize_pczt;
use wasm_utxo::Network;

use crate::psbt::common::{parse_fvk_file, print_zcash_psbt, read_zcash_psbt};

pub fn handle_out_ciphertexts_command(
    path: PathBuf,
    network: Network,
    fvk_file: PathBuf,
) -> Result<()> {
    let mut psbt = read_zcash_psbt(&path, network)?;
    let fvk = parse_fvk_file(&fvk_file)?;

    let (pczt_bytes, pending) = match psbt.out_ciphertext_request() {
        Ok(request) => request,
        Err(IronwoodPsbtError::NothingPending) => {
            eprintln!("{}", serde_json::json!({ "actionIndices": [] }));
            return print_zcash_psbt(&psbt);
        }
        Err(e) => return Err(anyhow!("failed to build the out-ciphertext request: {e}")),
    };
    let pczt = deserialize_pczt(&pczt_bytes)
        .map_err(|e| anyhow!("the stored PCZT does not deserialize: {e}"))?;
    let ovk = *fvk.to_ovk(orchard::keys::Scope::External).as_ref();
    let entries = pending
        .iter()
        .map(|&action_index| {
            let out_ciphertext = compute_out_ciphertext(&pczt, action_index, ovk, &mut OsRng)
                .map_err(|e| {
                    anyhow!("action {action_index}: computing the out-ciphertext failed: {e}")
                })?;
            Ok((action_index, out_ciphertext))
        })
        .collect::<Result<Vec<_>>>()?;

    psbt.add_out_ciphertexts(&entries)
        .map_err(|e| anyhow!("failed to apply the out-ciphertexts: {e}"))?;
    eprintln!("{}", serde_json::json!({ "actionIndices": pending }));
    print_zcash_psbt(&psbt)
}
