//! The FROST stand-in's randomizer round, one spend at a time: install
//! `rk = ak.randomize(alpha)` for one real spend. Only `rk` is stored — the PSBT never
//! carries `alpha` or the wallet's `ak`, so the alpha must be kept for the later
//! `add-spend-signature` and `prove` steps. When `--alpha` is omitted a fresh random scalar
//! is generated. Prints the updated PSBT as hex to stdout, with the alpha on stderr.

use anyhow::{anyhow, Result};
use ff::{Field, PrimeField};
use orchard::primitives::redpallas::{SpendAuth, VerificationKey};
use rand::rngs::OsRng;
use std::path::PathBuf;
use wasm_utxo::Network;

use crate::psbt::common::{parse_alpha, parse_fvk_file, print_zcash_psbt, read_zcash_psbt};

pub fn handle_set_spend_randomizer_command(
    path: PathBuf,
    network: Network,
    action_index: usize,
    fvk_file: PathBuf,
    alpha: Option<String>,
) -> Result<()> {
    let mut psbt = read_zcash_psbt(&path, network)?;
    let fvk = parse_fvk_file(&fvk_file)?;

    // The FVK's first 32 bytes are the spend-validating key `ak`.
    let ak_bytes: [u8; 32] = fvk.to_bytes()[..32].try_into().expect("FVK is 96 bytes");
    let ak = VerificationKey::<SpendAuth>::try_from(ak_bytes)
        .map_err(|e| anyhow!("the FVK's ak is not a canonical verification key: {e}"))?;

    let (alpha, alpha_scalar) = match alpha {
        Some(alpha) => parse_alpha(&alpha, "--alpha")?,
        None => {
            let scalar = pasta_curves::pallas::Scalar::random(&mut OsRng);
            (scalar.to_repr(), scalar)
        }
    };
    let rk: [u8; 32] = ak.randomize(&alpha_scalar).into();

    // The library rejects a zero or non-canonical alpha and checks `rk` against `ak`.
    psbt.add_spend_randomizers(&[(action_index, alpha, rk)], Some(&ak_bytes))
        .map_err(|e| anyhow!("failed to install the randomizer: {e}"))?;

    eprintln!(
        "{}",
        serde_json::json!({ "actionIndex": action_index, "alpha": hex::encode(alpha) })
    );
    print_zcash_psbt(&psbt)
}
