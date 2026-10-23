//! The prover role for the spend flow: hand the prover what it needs. The PSBT never stores
//! the randomizers, so the alphas come in via `--alpha <action_index>:<hex32>`, exactly one
//! per real spend.
//!
//! Both modes first build the gated proof request, so a PSBT that is not ready for its proof
//! (pending ciphertexts, randomizers or signatures, or missing alphas) fails with a typed error
//! before any proving work. With `--request`, prints that request — the alpha-patched PCZT
//! bytes an external prover (the KMS stand-in) consumes. Without it, produces the Halo2 proof
//! locally (the `orchard-proving` feature) and prints the proof hex to feed straight into
//! `combine-ironwood-proof --proof`. Either way nothing is stored: the proof and the alphas
//! never sit in the PSBT.

use anyhow::{anyhow, Context, Result};
use rand::rngs::OsRng;
use std::path::PathBuf;
use wasm_utxo::Network;

use crate::psbt::common::{parse_fvk_file, parse_hex, read_zcash_psbt};

pub fn handle_prove_command(
    path: PathBuf,
    network: Network,
    alphas: Vec<String>,
    fvk_file: Option<PathBuf>,
    request: bool,
) -> Result<()> {
    let psbt = read_zcash_psbt(&path, network)?;

    let alphas = alphas
        .iter()
        .map(|alpha| parse_alpha_arg(alpha))
        .collect::<Result<Vec<_>>>()?;

    let request_bytes = psbt
        .proof_request(&alphas)
        .map_err(|e| anyhow!("failed to build the proof request: {e}"))?;
    if request {
        println!("{}", hex::encode(request_bytes));
        return Ok(());
    }

    // Local proof: the stand-in prover patches the FVK and the alphas into a working copy,
    // proves, and the proof is sliced out of the produced transaction. The PSBT itself is
    // untouched — combine is a separate, explicit step.
    let fvk_file = fvk_file.context("local proving needs --fvk-file (the stand-in key holder)")?;
    let fvk = parse_fvk_file(&fvk_file)?;
    let raw = psbt
        .combine_ironwood_proof_locally_with_alphas(&alphas, Some(&fvk.to_bytes()), OsRng)
        .map_err(|e| anyhow!("local proving failed: {e}"))?;
    let tx = wasm_utxo::zcash::v6::decode_v6_transaction(&raw)
        .map_err(|e| anyhow!("the locally produced transaction does not decode: {e}"))?;
    let proof = tx
        .ironwood_bundle
        .context("the produced transaction carries no Ironwood bundle")?
        .proof;
    println!("{}", hex::encode(proof));
    Ok(())
}

/// Parse one `--alpha` argument: `<action_index>:<hex32>`.
fn parse_alpha_arg(alpha: &str) -> Result<(usize, [u8; 32])> {
    let (index, hex_part) = alpha
        .split_once(':')
        .ok_or_else(|| anyhow!("--alpha expects <action_index>:<hex32>, got \"{alpha}\""))?;
    let index: usize = index
        .trim()
        .parse()
        .with_context(|| format!("--alpha has an invalid action index: \"{index}\""))?;
    Ok((index, parse_hex(hex_part, &format!("--alpha {index}"))?))
}
