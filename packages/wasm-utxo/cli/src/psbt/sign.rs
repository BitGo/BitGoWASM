use anyhow::{anyhow, bail, Result};
use std::path::PathBuf;
use wasm_utxo::bitcoin::secp256k1::Secp256k1;
use wasm_utxo::zcash::transaction::ZCASH_SAPLING_VERSION_GROUP_ID;
use wasm_utxo::{
    finalize_and_encode_transaction, finalize_and_encode_zcash_transaction, sign_with_privkey,
    sign_zcash_with_privkey, Network,
};

use super::common::read_psbt;
use crate::input::{parse_private_key, parse_u32_flexible};
use crate::network::NetworkArg;

#[allow(clippy::too_many_arguments)]
pub fn handle_sign_command(
    path: PathBuf,
    network: NetworkArg,
    privkey: String,
    consensus_branch_id: Option<String>,
    version_group_id: Option<String>,
    expiry_height: u32,
) -> Result<()> {
    let network: Network = network.into();
    let mut psbt = read_psbt(&path)?;
    let privkey = parse_private_key(&privkey)?;
    let secp = Secp256k1::new();

    let tx_bytes = if network.mainnet() == Network::Zcash {
        let consensus_branch_id = consensus_branch_id
            .ok_or_else(|| anyhow!("--consensus-branch-id is required for network {network}"))
            .and_then(|s| parse_u32_flexible(&s))?;
        let version_group_id = version_group_id
            .as_deref()
            .map(parse_u32_flexible)
            .transpose()?
            .unwrap_or(ZCASH_SAPLING_VERSION_GROUP_ID);

        sign_zcash_with_privkey(
            &mut psbt,
            privkey,
            &secp,
            consensus_branch_id,
            version_group_id,
            expiry_height,
        )
        .map_err(|errors| anyhow!("signing failed: {:?}", errors))?;

        finalize_and_encode_zcash_transaction(
            psbt,
            consensus_branch_id,
            version_group_id,
            expiry_height,
        )
        .map_err(|e| anyhow!(e))?
    } else {
        if consensus_branch_id.is_some() || version_group_id.is_some() || expiry_height != 0 {
            bail!("--consensus-branch-id/--version-group-id/--expiry-height only apply to Zcash");
        }

        let fork_id = network.sighash_fork_id();
        sign_with_privkey(&mut psbt, privkey, &secp, fork_id)
            .map_err(|errors| anyhow!("signing failed: {:?}", errors))?;

        finalize_and_encode_transaction(psbt, fork_id).map_err(|e| anyhow!(e))?
    };

    println!("{}", hex::encode(tx_bytes));
    Ok(())
}
