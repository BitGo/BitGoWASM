use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

use crate::address::networks::AddressFormat;
use crate::error::WasmUtxoError;
use crate::fixed_script_wallet::{Chain, WalletScripts};
use crate::utxolib_compat::UtxolibNetwork;
use crate::wasm::try_from_js_value::TryFromJsValue;
use crate::wasm::try_from_js_value::{get_buffer_array_field, get_string_array_field};
use crate::wasm::try_into_js_value::TryIntoJsValue;
use crate::wasm::wallet_keys_helpers::root_wallet_keys_from_jsvalue;

/// Parse a network from a string that can be either a utxolib name or a coin name
fn parse_network(network_str: &str) -> Result<crate::networks::Network, WasmUtxoError> {
    crate::networks::Network::from_utxolib_name(network_str)
        .or_else(|| crate::networks::Network::from_coin_name(network_str))
        .ok_or_else(|| {
            WasmUtxoError::new(&format!(
                "Unknown network '{}'. Expected a utxolib name (e.g., 'bitcoin', 'testnet') or coin name (e.g., 'btc', 'tbtc')",
                network_str
            ))
        })
}

/// Helper function to create ReplayProtection from JsValue
/// Supports two formats:
/// 1. { outputScripts: Buffer[] } - direct scripts
/// 2. { addresses: string[] } - addresses to decode (uses provided network)
fn replay_protection_from_js_value(
    replay_protection: &JsValue,
    network: crate::networks::Network,
) -> Result<
    crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::ReplayProtection,
    WasmUtxoError,
> {
    // Try to get outputScripts first
    if let Ok(script_bytes) = get_buffer_array_field(replay_protection, "outputScripts") {
        let permitted_scripts = script_bytes
            .into_iter()
            .map(miniscript::bitcoin::ScriptBuf::from_bytes)
            .collect();

        return Ok(
            crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::ReplayProtection::new(
                permitted_scripts,
            ),
        );
    }

    // Try to get addresses array
    let addresses = get_string_array_field(replay_protection, "addresses").map_err(|_| {
        WasmUtxoError::new("replay_protection must have either outputScripts or addresses property")
    })?;

    // Convert addresses to scripts using provided network
    let mut permitted_scripts = Vec::new();
    for address_str in addresses {
        let script = crate::address::networks::to_output_script_with_network(&address_str, network)
            .map_err(|e| {
                WasmUtxoError::new(&format!(
                    "Failed to decode address '{}': {}",
                    address_str, e
                ))
            })?;

        permitted_scripts.push(script);
    }

    Ok(
        crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::ReplayProtection::new(
            permitted_scripts,
        ),
    )
}

#[wasm_bindgen]
pub struct FixedScriptWalletNamespace;

#[wasm_bindgen]
impl FixedScriptWalletNamespace {
    #[wasm_bindgen]
    pub fn output_script(
        keys: JsValue,
        chain: u32,
        index: u32,
        network: JsValue,
    ) -> Result<Vec<u8>, WasmUtxoError> {
        let network = UtxolibNetwork::try_from_js_value(&network)?;
        let chain = Chain::try_from(chain)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid chain: {}", e)))?;

        let wallet_keys = root_wallet_keys_from_jsvalue(&keys)?;
        let scripts = WalletScripts::from_wallet_keys(
            &wallet_keys,
            chain,
            index,
            &network.output_script_support(),
        )?;
        Ok(scripts.output_script().to_bytes())
    }

    #[wasm_bindgen]
    pub fn address(
        keys: JsValue,
        chain: u32,
        index: u32,
        network: JsValue,
        address_format: Option<String>,
    ) -> Result<String, WasmUtxoError> {
        let network = UtxolibNetwork::try_from_js_value(&network)?;
        let wallet_keys = root_wallet_keys_from_jsvalue(&keys)?;
        let chain = Chain::try_from(chain)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid chain: {}", e)))?;
        let scripts = WalletScripts::from_wallet_keys(
            &wallet_keys,
            chain,
            index,
            &network.output_script_support(),
        )?;
        let script = scripts.output_script();
        let address_format = AddressFormat::from_optional_str(address_format.as_deref())
            .map_err(|e| WasmUtxoError::new(&format!("Invalid address format: {}", e)))?;
        let address = crate::address::utxolib_compat::from_output_script_with_network(
            &script,
            &network,
            address_format,
        )
        .map_err(|e| WasmUtxoError::new(&format!("Failed to generate address: {}", e)))?;
        Ok(address)
    }
}
#[wasm_bindgen]
pub struct BitGoPsbt {
    psbt: crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt,
}

#[wasm_bindgen]
impl BitGoPsbt {
    /// Deserialize a PSBT from bytes with network-specific logic
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8], network: &str) -> Result<BitGoPsbt, WasmUtxoError> {
        let network = parse_network(network)?;

        let psbt =
            crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt::deserialize(bytes, network)
                .map_err(|e| WasmUtxoError::new(&format!("Failed to deserialize PSBT: {}", e)))?;

        Ok(BitGoPsbt { psbt })
    }

    /// Parse transaction with wallet keys to identify wallet inputs/outputs
    #[wasm_bindgen(js_name = parseTransactionWithWalletKeys)]
    pub fn parse_transaction_with_wallet_keys(
        &self,
        wallet_keys: JsValue,
        replay_protection: JsValue,
    ) -> Result<JsValue, WasmUtxoError> {
        // Convert wallet keys from JsValue
        let wallet_keys = root_wallet_keys_from_jsvalue(&wallet_keys)?;

        // Convert replay protection from JsValue, using the PSBT's network
        let network = self.psbt.network();
        let replay_protection = replay_protection_from_js_value(&replay_protection, network)?;

        // Call the Rust implementation
        let parsed_tx = self
            .psbt
            .parse_transaction_with_wallet_keys(&wallet_keys, &replay_protection)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to parse transaction: {}", e)))?;

        // Convert to JsValue directly using TryIntoJsValue
        parsed_tx.try_to_js_value()
    }

    /// Parse outputs with wallet keys to identify which outputs belong to a wallet
    ///
    /// Note: This method does NOT validate wallet inputs. It only parses outputs.
    #[wasm_bindgen(js_name = parseOutputsWithWalletKeys)]
    pub fn parse_outputs_with_wallet_keys(
        &self,
        wallet_keys: JsValue,
    ) -> Result<JsValue, WasmUtxoError> {
        // Convert wallet keys from JsValue
        let wallet_keys = root_wallet_keys_from_jsvalue(&wallet_keys)?;

        // Call the Rust implementation
        let parsed_outputs = self
            .psbt
            .parse_outputs_with_wallet_keys(&wallet_keys)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to parse outputs: {}", e)))?;

        // Convert Vec<ParsedOutput> to JsValue
        parsed_outputs.try_to_js_value()
    }
}
