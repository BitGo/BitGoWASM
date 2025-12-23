//! WASM bindings for parse_node functionality
//!
//! These bindings are always available but will throw runtime errors
//! if the `parse_node` feature is not enabled.

use wasm_bindgen::prelude::*;

#[cfg(not(feature = "parse_node"))]
const FEATURE_NOT_ENABLED_ERROR: &str =
    "parse_node feature is not enabled. Rebuild with --features parse_node";

#[cfg(feature = "parse_node")]
fn parse_network(coin_name: &str) -> Result<crate::networks::Network, JsError> {
    crate::networks::Network::from_coin_name(coin_name)
        .ok_or_else(|| JsError::new(&format!("Unknown network: {}", coin_name)))
}

/// Parse a PSBT and return a JSON representation of its structure.
///
/// This function parses the PSBT using the standard bitcoin crate parser
/// and returns a hierarchical node structure suitable for display.
///
/// # Arguments
/// * `psbt_bytes` - The raw PSBT bytes
/// * `coin_name` - The network coin name (e.g., "btc", "ltc", "bch")
///
/// # Returns
/// A JSON string representing the parsed PSBT structure
///
/// # Errors
/// Returns an error if:
/// - The `parse_node` feature is not enabled
/// - The PSBT bytes are invalid
/// - The network name is unknown
#[wasm_bindgen(js_name = parsePsbtToJson)]
pub fn parse_psbt_to_json(psbt_bytes: &[u8], coin_name: &str) -> Result<String, JsError> {
    #[cfg(feature = "parse_node")]
    {
        let network = parse_network(coin_name)?;
        let node = crate::parse_node::parse_psbt_bytes_with_network(psbt_bytes, network)
            .map_err(|e| JsError::new(&e))?;
        serde_json::to_string(&node).map_err(|e| JsError::new(&e.to_string()))
    }

    #[cfg(not(feature = "parse_node"))]
    {
        let _ = (psbt_bytes, coin_name);
        Err(JsError::new(FEATURE_NOT_ENABLED_ERROR))
    }
}

/// Parse a transaction and return a JSON representation of its structure.
///
/// # Arguments
/// * `tx_bytes` - The raw transaction bytes
/// * `coin_name` - The network coin name (e.g., "btc", "ltc", "bch")
///
/// # Returns
/// A JSON string representing the parsed transaction structure
///
/// # Errors
/// Returns an error if:
/// - The `parse_node` feature is not enabled
/// - The transaction bytes are invalid
/// - The network name is unknown
#[wasm_bindgen(js_name = parseTxToJson)]
pub fn parse_tx_to_json(tx_bytes: &[u8], coin_name: &str) -> Result<String, JsError> {
    #[cfg(feature = "parse_node")]
    {
        let network = parse_network(coin_name)?;
        let node = crate::parse_node::parse_tx_bytes_with_network(tx_bytes, network)
            .map_err(|e| JsError::new(&e))?;
        serde_json::to_string(&node).map_err(|e| JsError::new(&e.to_string()))
    }

    #[cfg(not(feature = "parse_node"))]
    {
        let _ = (tx_bytes, coin_name);
        Err(JsError::new(FEATURE_NOT_ENABLED_ERROR))
    }
}

/// Parse a PSBT at the raw byte level and return a JSON representation.
///
/// Unlike `parsePsbtToJson`, this function exposes the raw key-value pair
/// structure as defined in BIP-174, showing:
/// - Raw key type IDs and their human-readable names
/// - Proprietary keys with their structured format
/// - Unknown/unrecognized keys that standard parsers might skip
///
/// # Arguments
/// * `psbt_bytes` - The raw PSBT bytes
/// * `coin_name` - The network coin name (e.g., "btc", "ltc", "zec")
///
/// # Returns
/// A JSON string representing the raw PSBT key-value structure
///
/// # Errors
/// Returns an error if:
/// - The `parse_node` feature is not enabled
/// - The PSBT bytes are invalid
/// - The network name is unknown
#[wasm_bindgen(js_name = parsePsbtRawToJson)]
pub fn parse_psbt_raw_to_json(psbt_bytes: &[u8], coin_name: &str) -> Result<String, JsError> {
    #[cfg(feature = "parse_node")]
    {
        let network = parse_network(coin_name)?;
        let node = crate::parse_node::parse_psbt_bytes_raw_with_network(psbt_bytes, network)
            .map_err(|e| JsError::new(&e))?;
        serde_json::to_string(&node).map_err(|e| JsError::new(&e.to_string()))
    }

    #[cfg(not(feature = "parse_node"))]
    {
        let _ = (psbt_bytes, coin_name);
        Err(JsError::new(FEATURE_NOT_ENABLED_ERROR))
    }
}

/// Check if the parse_node feature is enabled.
///
/// # Returns
/// `true` if the feature is enabled, `false` otherwise
#[wasm_bindgen(js_name = isParseNodeEnabled)]
pub fn is_parse_node_enabled() -> bool {
    cfg!(feature = "parse_node")
}

