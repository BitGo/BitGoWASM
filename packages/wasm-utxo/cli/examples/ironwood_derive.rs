//! Derive Orchard/Ironwood receiving addresses from a spending key file.
//!
//! Prints the raw 43-byte Ironwood receiver and the single-receiver Unified Address for
//! diversifiers 0..count (External scope), plus the 96-byte FVK — the material a spend flow's
//! `--fvk-file` / shielded-output `--recipient` consumes.
//!
//! Usage: `cargo run --example ironwood_derive -- <sk-hex|sk-file> [count]` (count defaults to
//! 2, at most 100).

use anyhow::{bail, Context};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use wasm_utxo::zcash::unified_address::encode_orchard_receiver;

const MAX_COUNT: u32 = 100;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        bail!("usage: ironwood_derive <sk-hex|sk-file> [count]");
    }
    // A readable file holds the key; anything else is the key itself.
    let raw = std::fs::read_to_string(&args[1]).unwrap_or_else(|_| args[1].clone());
    let sk_bytes: [u8; 32] = hex::decode(raw.trim())
        .context("invalid spending key hex")?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("sk must be 32 bytes"))?;
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes))
        .context("not a valid spending key")?;
    let fvk = FullViewingKey::from(&sk);
    let count: u32 = args
        .get(2)
        .map(|s| s.parse().context("count must be a number"))
        .transpose()?
        .unwrap_or(2);
    if count > MAX_COUNT {
        bail!("count must be at most {MAX_COUNT}");
    }

    let mut receivers = Vec::new();
    for diversifier in 0..count {
        let receiver: [u8; 43] = fvk
            .address_at(diversifier, Scope::External)
            .to_raw_address_bytes();
        let ua = encode_orchard_receiver(&receiver, "tzec")
            .map_err(|e| anyhow::anyhow!("encoding receiver as UA: {e}"))?;
        receivers.push(serde_json::json!({
            "diversifier": diversifier,
            "receiverHex": hex::encode(receiver),
            "unifiedAddress": ua,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "fvkHex": hex::encode(fvk.to_bytes()),
            "skHex": hex::encode(sk_bytes),
            "receivers": receivers,
        }))?
    );
    Ok(())
}
