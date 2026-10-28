//! Generate a Zcash testnet wallet for exercising the Ironwood shield/spend flows.
//!
//! Prints the wallet and writes the key files the wasm-utxo-cli shield/spend commands consume
//! (`--sk-file`, `--fvk-file`, `--privkey`, `--descriptor`):
//!
//! - an Orchard spending key + full viewing key, the raw 43-byte Ironwood receiver at
//!   diversifier 0 (External), and its single-receiver Unified Address (`utest1…`);
//! - a 2-of-3 P2SH transparent funding address with three WIF keys — the shape
//!   `psbt sign-v6-input` requires for transparent inputs;
//! - a plain P2PKH t-address to receive a deshield payout.
//!
//! Usage: `cargo run --example ironwood_keygen -- [<output-dir>] [--from-sk <32-byte-hex>]`.
//! The output directory defaults to `ironwood-e2e-wallet` (relative to the cwd); `--from-sk`
//! re-derives the Orchard keys of a known spending key instead of generating one. The
//! transparent keys are always fresh. TESTNET-ONLY key material; never reuse on mainnet.

use anyhow::{bail, Context};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::json;
use wasm_utxo::bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_2, OP_PUSHNUM_3};
use wasm_utxo::bitcoin::script::Builder;
use wasm_utxo::bitcoin::secp256k1::{Secp256k1, SecretKey};
use wasm_utxo::bitcoin::{Network as BtcNetwork, PrivateKey, ScriptBuf};
use wasm_utxo::zcash::unified_address::{encode_orchard_receiver, UnifiedAddress};
use wasm_utxo::{from_output_script_with_network, Network};

/// Network every address/key below is bound to: Zcash testnet (`tzec` / `utest` HRP).
const NETWORK: Network = Network::ZcashTestnet;
const UA_NETWORK: &str = "tzec";
const DEFAULT_OUT_DIR: &str = "ironwood-e2e-wallet";
const USAGE: &str = "usage: ironwood_keygen [<output-dir>] [--from-sk <32-byte-hex>]";

fn main() -> anyhow::Result<()> {
    let (out_dir, from_sk) = parse_args()?;
    std::fs::create_dir_all(&out_dir).context("creating output dir")?;

    // ---- Orchard / Ironwood keys -------------------------------------------
    // SpendingKey::from_bytes rejects ~2^-252 of byte strings (non-canonical Pallas scalars);
    // loop for the (never taken in practice) rejection.
    let spending_key = match from_sk {
        Some(hex_sk) => {
            let bytes: [u8; 32] = hex::decode(hex_sk.trim())
                .context("invalid --from-sk hex")?
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("--from-sk must be 32 bytes"))?;
            Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes))
                .context("--from-sk is not a valid spending key")?
        }
        None => loop {
            if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(random_bytes())) {
                break sk;
            }
        },
    };

    let fvk = FullViewingKey::from(&spending_key);
    let sk_hex = hex::encode(spending_key.to_bytes());
    let fvk_hex = hex::encode(fvk.to_bytes());

    let receiver: [u8; 43] = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
    let receiver_hex = hex::encode(receiver);
    let unified_address = encode_orchard_receiver(&receiver, UA_NETWORK)
        .map_err(|e| anyhow::anyhow!("encoding orchard receiver as UA: {e}"))?;

    // Round-trip: the UA must parse back to the same Orchard receiver (and only it).
    let parsed = UnifiedAddress::parse(&unified_address, UA_NETWORK)
        .map_err(|e| anyhow::anyhow!("generated UA failed to parse: {e}"))?;
    let parsed_receiver = parsed
        .orchard_receiver()
        .map_err(|e| anyhow::anyhow!("generated UA has no orchard receiver: {e}"))?;
    if parsed_receiver.as_deref() != Some(receiver.as_slice()) {
        bail!("UA round-trip lost the orchard receiver");
    }

    // ---- Transparent 2-of-3 funding address (sign-v6-input's required shape) ----
    let secp = Secp256k1::new();
    let funding_keys = (0..3)
        .map(|_| random_private_key())
        .collect::<anyhow::Result<Vec<_>>>()?;
    let pubkeys: Vec<_> = funding_keys.iter().map(|k| k.public_key(&secp)).collect();
    let redeem_script = Builder::new()
        .push_opcode(OP_PUSHNUM_2)
        .push_key(&pubkeys[0])
        .push_key(&pubkeys[1])
        .push_key(&pubkeys[2])
        .push_opcode(OP_PUSHNUM_3)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();
    let p2sh_script = ScriptBuf::new_p2sh(&redeem_script.script_hash());
    let funding_address = from_output_script_with_network(&p2sh_script, NETWORK)
        .context("encoding 2-of-3 P2SH t-address")?;
    let descriptor = format!("sh(multi(2,{},{},{}))", pubkeys[0], pubkeys[1], pubkeys[2]);

    // ---- Plain P2PKH t-address (deshield payout destination) ----
    let payout_key = random_private_key()?;
    let p2pkh_script = ScriptBuf::new_p2pkh(&payout_key.public_key(&secp).pubkey_hash());
    let payout_address = from_output_script_with_network(&p2pkh_script, NETWORK)
        .context("encoding P2PKH t-address")?;

    let summary = json!({
        "network": "tzec (Zcash testnet)",
        "orchard": {
            "spendingKeyHex": sk_hex,
            "fvkHex": fvk_hex,
            "ironwoodReceiverHex": receiver_hex,
            "unifiedAddress": unified_address,
        },
        "funding": {
            "address": funding_address,
            "descriptor": descriptor,
            "redeemScriptHex": hex::encode(redeem_script.as_bytes()),
            "p2shScriptHex": hex::encode(p2sh_script.as_bytes()),
            "wifs": funding_keys.iter().map(|k| k.to_wif()).collect::<Vec<_>>(),
            "pubkeys": pubkeys.iter().map(|k| k.to_string()).collect::<Vec<_>>(),
        },
        "payout": {
            "address": payout_address,
            "wif": payout_key.to_wif(),
            "p2pkhScriptHex": hex::encode(p2pkh_script.as_bytes()),
        },
    });
    let summary = serde_json::to_string_pretty(&summary)?;

    for (name, contents) in [
        ("orchard_sk.hex", sk_hex.as_str()),
        ("orchard_fvk.hex", fvk_hex.as_str()),
        ("orchard_receiver.hex", receiver_hex.as_str()),
        ("wallet.json", summary.as_str()),
    ] {
        std::fs::write(format!("{out_dir}/{name}"), contents)
            .with_context(|| format!("writing {name}"))?;
    }

    println!("{summary}");
    println!("\nfiles written to {out_dir}/");
    Ok(())
}

/// `[<output-dir>] [--from-sk <hex>]`, in that order.
fn parse_args() -> anyhow::Result<(String, Option<String>)> {
    let mut args = std::env::args().skip(1).peekable();
    let out_dir = match args.peek() {
        Some(arg) if arg != "--from-sk" => args.next().unwrap(),
        _ => DEFAULT_OUT_DIR.to_string(),
    };
    let from_sk = match args.next().as_deref() {
        None => None,
        Some("--from-sk") => Some(args.next().context("--from-sk requires a value")?),
        Some(other) => bail!("unexpected argument {other}\n{USAGE}"),
    };
    if let Some(extra) = args.next() {
        bail!("unexpected argument {extra}\n{USAGE}");
    }
    Ok((out_dir, from_sk))
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn random_private_key() -> anyhow::Result<PrivateKey> {
    let secret = SecretKey::from_slice(&random_bytes()).context("secp256k1 secret key")?;
    Ok(PrivateKey::new(secret, BtcNetwork::Testnet))
}
