use miniscript::bitcoin::psbt::Output;
use miniscript::bitcoin::ScriptBuf;

use crate::fixed_script_wallet::{Chain, RootWalletKeys, WalletScripts};
use crate::Network;

// Re-export ScriptId from psbt_wallet_input
pub use super::psbt_wallet_input::ScriptId;

/// Parsed output from a PSBT transaction
#[derive(Debug, Clone)]
pub struct ParsedOutput {
    pub address: Option<String>,
    pub script: Vec<u8>,
    pub value: u64,
    pub script_id: Option<ScriptId>,
}

impl ParsedOutput {
    /// Parse a PSBT output with wallet keys to identify if it belongs to the wallet
    ///
    /// # Arguments
    /// - `psbt_output`: The PSBT output metadata
    /// - `tx_output`: The transaction output
    /// - `wallet_keys`: The wallet's root keys for deriving scripts
    /// - `network`: The network for address generation
    ///
    /// # Returns
    /// - `Ok(ParsedOutput)` with optional address, script bytes, value, and optional script_id
    /// - `Err(ParseOutputError)` if validation fails
    pub fn parse(
        psbt_output: &Output,
        tx_output: &miniscript::bitcoin::TxOut,
        wallet_keys: &RootWalletKeys,
        network: Network,
    ) -> Result<Self, ParseOutputError> {
        let script = &tx_output.script_pubkey;

        // Try to match output to wallet
        let script_id = match_output_to_wallet(wallet_keys, psbt_output, script, network)
            .map_err(ParseOutputError::WalletMatch)?;

        // Try to convert script to address (may fail for non-standard scripts)
        let address =
            crate::address::networks::from_output_script_with_network(script.as_script(), network)
                .ok();

        Ok(Self {
            address,
            script: script.to_bytes(),
            value: tx_output.value.to_sat(),
            script_id,
        })
    }

    /// Returns true if this is an external output (not belonging to the wallet)
    pub fn is_external(&self) -> bool {
        self.script_id.is_none()
    }
}

/// Error type for parsing a single PSBT output
#[derive(Debug)]
pub enum ParseOutputError {
    /// Failed to match output to wallet (corruption or validation error)
    WalletMatch(String),
}

impl std::fmt::Display for ParseOutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseOutputError::WalletMatch(error) => write!(f, "{}", error),
        }
    }
}

impl std::error::Error for ParseOutputError {}

/// Try to match an output script to wallet keys using PSBT output metadata
/// Returns Some(ScriptId) if the script belongs to the wallet, None otherwise
///
/// Logic:
/// - If no derivation info → external output (None)
/// - If derivation info fingerprints don't match wallet → external output (None)
/// - If derivation info matches wallet but script doesn't → error (corruption)
fn match_output_to_wallet(
    wallet_keys: &RootWalletKeys,
    psbt_output: &Output,
    script: &ScriptBuf,
    network: Network,
) -> Result<Option<ScriptId>, String> {
    use super::psbt_wallet_input;

    // Check if output has BIP32 derivation or tap key origins
    if psbt_output.bip32_derivation.is_empty() && psbt_output.tap_key_origins.is_empty() {
        // No derivation info, treat as external output
        return Ok(None);
    }

    // Check if the derivation info belongs to our wallet keys
    let belongs_to_wallet = if !psbt_output.bip32_derivation.is_empty() {
        psbt_wallet_input::is_bip32_derivation_for_wallet(
            wallet_keys,
            &psbt_output.bip32_derivation,
        )
    } else {
        psbt_wallet_input::is_tap_key_origins_for_wallet(wallet_keys, &psbt_output.tap_key_origins)
    };

    if !belongs_to_wallet {
        // Derivation info references different wallet keys, treat as external output
        return Ok(None);
    }

    // Derivation info belongs to our wallet, parse and validate
    let derivation_paths = psbt_wallet_input::get_output_derivation_paths(psbt_output);

    // Parse the shared chain and index from derivation paths
    let (chain, index) = psbt_wallet_input::parse_shared_derivation_path(&derivation_paths)
        .map_err(|e| format!("Failed to parse output derivation path: {}", e))?;

    // Derive the expected script for this wallet
    let chain_enum =
        Chain::try_from(chain).map_err(|e| format!("Invalid chain value {}: {}", chain, e))?;

    let derived_scripts = WalletScripts::from_wallet_keys(
        wallet_keys,
        chain_enum,
        index,
        &network.output_script_support(),
    )
    .map_err(|e| format!("Failed to derive wallet scripts: {}", e))?;

    if derived_scripts.output_script().as_script() == script.as_script() {
        Ok(Some(ScriptId { chain, index }))
    } else {
        // Script doesn't match even though keys are ours - this is an error
        Err(format!(
            "Output script mismatch: expected wallet output at chain={}, index={} but script doesn't match. Expected: {}, Got: {}",
            chain, index,
            derived_scripts.output_script(),
            script
        ))
    }
}
