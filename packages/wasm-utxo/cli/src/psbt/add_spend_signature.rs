//! The FROST stand-in's signing round, one spend at a time: sign the PSBT's ZIP-244 spend
//! sighash with the spend's randomized authorizing key (`ask.randomize(alpha)`, from
//! `--sk-file` and `--alpha`) — or ingest an externally produced signature (`--signature`, the
//! FROST case). The alpha is the one `set-spend-randomizer` installed for this action; the
//! PSBT never stores it. Prints the updated PSBT as hex to stdout.

use anyhow::{anyhow, bail, Result};
use rand::rngs::OsRng;
use std::path::PathBuf;
use wasm_utxo::Network;

use crate::psbt::common::{
    parse_alpha, parse_hex, parse_spending_key_file, print_zcash_psbt, read_zcash_psbt,
};

pub fn handle_add_spend_signature_command(
    path: PathBuf,
    network: Network,
    action_index: usize,
    alpha: Option<String>,
    sk_file: Option<PathBuf>,
    signature: Option<String>,
) -> Result<()> {
    let mut psbt = read_zcash_psbt(&path, network)?;

    let signature: [u8; 64] = match (sk_file, alpha, signature) {
        (Some(sk_file), Some(alpha), None) => {
            let (_, alpha) = parse_alpha(&alpha, "--alpha")?;
            let sk = parse_spending_key_file(&sk_file)?;
            let ask = orchard::keys::SpendAuthorizingKey::from(&sk);
            let sighash = psbt
                .spend_sighash()
                .map_err(|e| anyhow!("failed to compute the spend sighash: {e}"))?;
            <[u8; 64]>::from(&ask.randomize(&alpha).sign(OsRng, &sighash))
        }
        (None, None, Some(signature)) => parse_hex(&signature, "--signature")?,
        _ => bail!("expected either --sk-file with --alpha, or --signature"),
    };

    psbt.add_spend_signatures(&[(action_index, signature)])
        .map_err(|e| anyhow!("failed to add the spend signature: {e}"))?;
    print_zcash_psbt(&psbt)
}
