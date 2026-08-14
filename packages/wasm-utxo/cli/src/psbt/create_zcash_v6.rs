use anyhow::{anyhow, bail, Context, Result};
use wasm_utxo::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt;
use wasm_utxo::zcash::NetworkUpgrade;
use wasm_utxo::Network;

use crate::input::parse_u32_flexible;

pub fn handle_create_zcash_v6_command(
    network: Network,
    consensus_branch_id: String,
    lock_time: u32,
    expiry_height: u32,
) -> Result<()> {
    let consensus_branch_id =
        parse_u32_flexible(&consensus_branch_id).context("invalid --consensus-branch-id")?;

    // v6 (Ironwood) is only valid at or after NU6.3 activation, and NU6.3 is currently the
    // latest defined upgrade — so the only branch id that satisfies "at or after" today is
    // NU6.3's own. Reject anything else rather than building an unshieldable PSBT the CLI's
    // later steps would fail on with a less obvious error.
    let nu6_3_branch_id = NetworkUpgrade::Nu6_3.branch_id();
    if consensus_branch_id != nu6_3_branch_id {
        bail!(
            "--consensus-branch-id 0x{consensus_branch_id:08x} is not at or after NU6.3 \
             (Ironwood) activation (expected 0x{nu6_3_branch_id:08x})"
        );
    }

    let psbt = ZcashBitGoPsbt::new_v6_bare(
        network,
        consensus_branch_id,
        Some(lock_time),
        Some(expiry_height),
    );

    println!("{}", hex::encode(psbt.serialize().map_err(|e| anyhow!(e))?));
    Ok(())
}
