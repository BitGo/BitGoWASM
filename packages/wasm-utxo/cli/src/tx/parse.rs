use anyhow::Result;
use std::path::PathBuf;

use crate::format::{render_tree_with_scheme, ColorScheme};
use crate::input::{decode_input, read_input_bytes};
use wasm_utxo::parse_node::parse_tx_bytes_internal;

pub fn handle_parse_command(path: PathBuf, no_color: bool) -> Result<()> {
    // Read from file or stdin
    let raw_bytes = read_input_bytes(&path, "transaction")?;

    // Decode input (auto-detect hex, base64, or raw bytes)
    let bytes = decode_input(&raw_bytes)?;

    let node = parse_tx_bytes_internal(&bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse transaction: {}", e))?;

    let color_scheme = if no_color {
        ColorScheme::no_color()
    } else {
        ColorScheme::default()
    };

    render_tree_with_scheme(&node, &color_scheme)?;

    Ok(())
}
