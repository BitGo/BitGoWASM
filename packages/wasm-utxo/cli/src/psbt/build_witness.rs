//! Build (and validate) an Ironwood Merkle witness for a note commitment — either from the
//! full 32-entry sibling path, or from a pruned shard + cap as a real note-commitment tree
//! store would supply it. Prints the witness as JSON to stdout:
//! `{"position": <u32>, "authPath": ["<hex32>" × 32]}` — the shape `add-shielded-input`'s
//! notes file takes.

use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use wasm_utxo::zcash::ironwood_build::{
    build_ironwood_witness, build_ironwood_witness_from_shard, ShardTreeNode, ShardWitnessInput,
    WitnessAuthPath,
};

use crate::input::read_input_bytes;
use crate::psbt::common::{auth_path_from_flat_hex, auth_path_from_hashes, parse_hex};

pub struct BuildWitnessArgs {
    pub cmx: String,
    pub position: u32,
    pub anchor: String,
    pub auth_path: Option<String>,
    pub shard_file: Option<PathBuf>,
    pub cap_file: Option<PathBuf>,
    pub shard_height: Option<u8>,
    pub leaf_count: Option<u64>,
}

pub fn handle_build_witness_command(args: BuildWitnessArgs) -> Result<()> {
    let cmx: [u8; 32] = parse_hex(&args.cmx, "--cmx")?;
    let anchor: [u8; 32] = parse_hex(&args.anchor, "--anchor")?;

    let witness = match args {
        BuildWitnessArgs {
            auth_path: Some(auth_path),
            shard_file: None,
            ..
        } => {
            let auth_path = parse_auth_path(&auth_path)?;
            build_ironwood_witness(&cmx, args.position, &auth_path, &anchor)
                .map_err(|e| anyhow!("building the witness failed: {e}"))?
        }
        BuildWitnessArgs {
            auth_path: None,
            shard_file: Some(shard_file),
            cap_file: Some(cap_file),
            shard_height: Some(shard_height),
            leaf_count: Some(leaf_count),
            ..
        } => {
            let shard = read_shard_tree_node(&shard_file).context("--shard-file")?;
            let cap = read_shard_tree_node(&cap_file).context("--cap-file")?;
            let input = ShardWitnessInput {
                position: args.position,
                shard_height,
                leaf_count,
                cmx: &cmx,
                shard: &shard,
                cap: &cap,
            };
            build_ironwood_witness_from_shard(&input, &anchor)
                .map_err(|e| anyhow!("building the witness from the shard failed: {e}"))?
        }
        _ => bail!(
            "expected exactly one witness source: --auth-path, or --shard-file + --cap-file \
             (with --shard-height and --leaf-count)"
        ),
    };

    println!(
        "{}",
        serde_json::json!({
            "position": witness.position,
            "authPath": witness.auth_path.iter().map(hex::encode).collect::<Vec<_>>(),
        })
    );
    Ok(())
}

/// The auth path: a JSON array of 32 hex hashes, 32 comma-separated hex hashes, or the
/// flattened 1024-byte hex encoding.
fn parse_auth_path(auth_path: &str) -> Result<WitnessAuthPath> {
    if auth_path.trim_start().starts_with('[') {
        let hashes: Vec<String> = serde_json::from_str(auth_path)
            .context("--auth-path is not a JSON array of hex hashes")?;
        auth_path_from_hashes(&hashes, "--auth-path")
    } else if auth_path.contains(',') {
        let hashes: Vec<&str> = auth_path.split(',').collect();
        auth_path_from_hashes(&hashes, "--auth-path")
    } else {
        auth_path_from_flat_hex(auth_path, "--auth-path")
    }
}

fn read_shard_tree_node(path: &PathBuf) -> Result<ShardTreeNode> {
    let text = read_input_bytes(path, "shard node")?;
    serde_json::from_slice(&text).context("the shard node is not valid ShardTreeNode JSON")
}
