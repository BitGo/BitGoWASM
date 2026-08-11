use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use wasm_utxo::bitcoin::secp256k1::{Message, PublicKey as SecpPublicKey, Secp256k1};
use wasm_utxo::bitcoin::{CompressedPublicKey, PublicKey};
use wasm_utxo::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt;
use wasm_utxo::Network;

use crate::input::{decode_input, parse_private_key, read_input_bytes};

pub fn handle_sign_v6_input_command(
    path: PathBuf,
    network: Network,
    index: usize,
    privkey: String,
) -> Result<()> {
    let raw_bytes = read_input_bytes(&path, "PSBT")?;
    let bytes = decode_input(&raw_bytes)?;
    let mut psbt = ZcashBitGoPsbt::deserialize(&bytes, network)
        .map_err(|e| anyhow!("Failed to parse v6 PSBT: {e}"))?;

    let privkey = parse_private_key(&privkey)?;
    let secp = Secp256k1::new();
    let secp_pubkey = SecpPublicKey::from_secret_key(&secp, &privkey.inner);
    let pubkey = PublicKey::from(CompressedPublicKey(secp_pubkey));

    let sighash = psbt
        .v6_transparent_sighash(index)
        .map_err(|e| anyhow!(e))
        .context("failed to compute v6 transparent sighash")?;
    let msg = Message::from_digest(sighash);
    let mut der = secp
        .sign_ecdsa(&msg, &privkey.inner)
        .serialize_der()
        .to_vec();
    der.push(0x01); // SIGHASH_ALL

    psbt.add_v6_transparent_signature(index, pubkey, &der)
        .map_err(|e| anyhow!(e))
        .context("failed to add v6 transparent signature")?;

    println!("{}", hex::encode(psbt.serialize().map_err(|e| anyhow!(e))?));
    Ok(())
}
