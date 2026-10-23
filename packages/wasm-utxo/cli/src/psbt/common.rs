use anyhow::{anyhow, bail, Context, Result};
use ff::PrimeField;
use std::path::PathBuf;
use wasm_utxo::bitcoin::psbt::Psbt;
use wasm_utxo::fixed_script_wallet::bitgo_psbt::ZcashBitGoPsbt;
use wasm_utxo::zcash::ironwood_build::{MemoBytes, WitnessAuthPath, IRONWOOD_MERKLE_DEPTH};
use wasm_utxo::Network;

use crate::input::{decode_input, read_input_bytes};

/// Read and deserialize a PSBT from a file path or stdin (`-`), auto-detecting
/// hex/base64/raw encoding.
pub fn read_psbt(path: &PathBuf) -> Result<Psbt> {
    let raw_bytes = read_input_bytes(path, "PSBT")?;
    let bytes = decode_input(&raw_bytes)?;
    Psbt::deserialize(&bytes).context("Failed to parse PSBT")
}

/// Serialize a PSBT and print it as hex to stdout.
pub fn print_psbt(psbt: &Psbt) {
    println!("{}", hex::encode(psbt.serialize()));
}

/// Read and deserialize a Zcash PSBT from a file path or stdin (`-`), auto-detecting
/// hex/base64/raw encoding.
pub fn read_zcash_psbt(path: &PathBuf, network: Network) -> Result<ZcashBitGoPsbt> {
    let raw_bytes = read_input_bytes(path, "PSBT")?;
    let bytes = decode_input(&raw_bytes)?;
    ZcashBitGoPsbt::deserialize(&bytes, network).map_err(|e| anyhow!("Failed to parse PSBT: {e}"))
}

/// Serialize a Zcash PSBT and print it as hex to stdout.
pub fn print_zcash_psbt(psbt: &ZcashBitGoPsbt) -> Result<()> {
    println!("{}", hex::encode(psbt.serialize().map_err(|e| anyhow!(e))?));
    Ok(())
}

/// Parse a fixed-length hex string, tolerating a `0x` prefix and surrounding whitespace, and
/// naming the field in the error.
pub fn parse_hex<const N: usize>(input: &str, what: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(input.trim().trim_start_matches("0x"))
        .with_context(|| format!("{what} is not hex"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("{what} must be {N} bytes, got {}", v.len()))
}

/// Read a fixed-length hex string from a file (or `-` for stdin).
fn read_hex_file<const N: usize>(path: &PathBuf, what: &str) -> Result<[u8; N]> {
    let text = read_input_bytes(path, what)?;
    let text = String::from_utf8(text).with_context(|| format!("{what} file is not UTF-8 text"))?;
    parse_hex(&text, what)
}

/// Parse a 96-byte full viewing key (`ak ‖ nk ‖ rivk`, orchard's `FullViewingKey::to_bytes`
/// layout) from a hex file — the stand-in key holder for the prover/ciphertext rounds.
pub fn parse_fvk_file(path: &PathBuf) -> Result<orchard::keys::FullViewingKey> {
    let bytes = read_hex_file::<96>(path, "full viewing key")?;
    orchard::keys::FullViewingKey::from_bytes(&bytes)
        .context("full viewing key bytes are not a valid FVK")
}

/// Parse a 32-byte spending key from a hex file — the stand-in key holder for the
/// spend-auth signing round.
pub fn parse_spending_key_file(path: &PathBuf) -> Result<orchard::keys::SpendingKey> {
    let bytes = read_hex_file::<32>(path, "spending key")?;
    Option::<orchard::keys::SpendingKey>::from(orchard::keys::SpendingKey::from_bytes(bytes))
        .context("spending key bytes are not a valid key")
}

/// Parse a spend randomizer `alpha`: 32 hex bytes encoding a canonical Pallas scalar. Returns
/// both the bytes and the scalar.
pub fn parse_alpha(input: &str, what: &str) -> Result<([u8; 32], pasta_curves::pallas::Scalar)> {
    let bytes = parse_hex::<32>(input, what)?;
    let scalar = pasta_curves::pallas::Scalar::from_repr(bytes)
        .into_option()
        .with_context(|| format!("{what} is not a canonical scalar"))?;
    Ok((bytes, scalar))
}

/// A witness auth path from its 32 sibling hashes (leaf-to-root), each hex-encoded.
pub fn auth_path_from_hashes<S: AsRef<str>>(hashes: &[S], what: &str) -> Result<WitnessAuthPath> {
    if hashes.len() != IRONWOOD_MERKLE_DEPTH {
        bail!(
            "{what} must have exactly {IRONWOOD_MERKLE_DEPTH} entries, got {}",
            hashes.len()
        );
    }
    let mut auth_path: WitnessAuthPath = [[0u8; 32]; IRONWOOD_MERKLE_DEPTH];
    for (level, (node, hash)) in auth_path.iter_mut().zip(hashes).enumerate() {
        *node = parse_hex(hash.as_ref(), &format!("{what}[{level}]"))?;
    }
    Ok(auth_path)
}

/// A witness auth path from the flattened hex encoding of its 32 sibling hashes.
pub fn auth_path_from_flat_hex(input: &str, what: &str) -> Result<WitnessAuthPath> {
    let flattened = parse_hex::<{ IRONWOOD_MERKLE_DEPTH * 32 }>(input, what)?;
    let mut auth_path: WitnessAuthPath = [[0u8; 32]; IRONWOOD_MERKLE_DEPTH];
    for (node, chunk) in auth_path.iter_mut().zip(flattened.chunks_exact(32)) {
        node.copy_from_slice(chunk);
    }
    Ok(auth_path)
}

/// The ZIP-302 "no memo" encoding: the `0xf6` marker byte followed by zeros — not the
/// all-zeros memo, which decodes as a text memo holding the empty string.
pub fn zip302_no_memo() -> MemoBytes {
    let mut memo = [0u8; 512];
    memo[0] = 0xf6;
    memo
}
