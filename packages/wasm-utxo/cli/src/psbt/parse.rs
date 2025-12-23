use anyhow::Result;
use std::path::PathBuf;

use crate::format::{render_tree_with_scheme, ColorScheme};
use crate::input::{decode_input, read_input_bytes};
use wasm_utxo::parse_node::{parse_psbt_bytes_raw_with_network, parse_psbt_bytes_with_network};
use wasm_utxo::Network;

pub fn handle_parse_command(
    path: PathBuf,
    no_color: bool,
    raw: bool,
    network: Network,
) -> Result<()> {
    // Read from file or stdin
    let raw_bytes = read_input_bytes(&path, "PSBT")?;

    // Decode input (auto-detect hex, base64, or raw bytes)
    let bytes = decode_input(&raw_bytes)?;

    let node = if raw {
        parse_psbt_bytes_raw_with_network(&bytes, network)
            .map_err(|e| anyhow::anyhow!("Failed to parse PSBT (raw): {}", e))?
    } else {
        parse_psbt_bytes_with_network(&bytes, network)
            .map_err(|e| anyhow::anyhow!("Failed to parse PSBT: {}", e))?
    };

    let color_scheme = if no_color {
        ColorScheme::no_color()
    } else {
        ColorScheme::default()
    };

    render_tree_with_scheme(&node, &color_scheme)?;

    Ok(())
}
