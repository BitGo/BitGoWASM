//! WASM bindings for BIP-0322 message signing

use wasm_bindgen::prelude::*;

use crate::bip322::bitgo_psbt;
use crate::error::WasmUtxoError;
use crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::SignerKey;
use crate::fixed_script_wallet::PubTriple;
use crate::wasm::wallet_keys::WasmRootWalletKeys;
use miniscript::bitcoin::hex::FromHex;
use miniscript::bitcoin::CompressedPublicKey;

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

/// Namespace for BIP-0322 functions
#[wasm_bindgen]
pub struct Bip322Namespace;

#[wasm_bindgen]
impl Bip322Namespace {
    /// Add a BIP-0322 message input to an existing BitGoPsbt
    ///
    /// If this is the first input, also adds the OP_RETURN output.
    /// The PSBT must have version 0 per BIP-0322 specification.
    ///
    /// # Arguments
    /// * `psbt` - The BitGoPsbt to add the input to
    /// * `message` - The message to sign
    /// * `chain` - The wallet chain (e.g., 10 for external, 20 for internal)
    /// * `index` - The address index
    /// * `wallet_keys` - The wallet's root keys
    /// * `signer` - Optional signer key name for taproot (e.g., "user", "backup", "bitgo")
    /// * `cosigner` - Optional cosigner key name for taproot
    /// * `tag` - Optional custom tag for message hashing
    ///
    /// # Returns
    /// The index of the added input
    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn add_bip322_input(
        psbt: &mut super::fixed_script_wallet::BitGoPsbt,
        message: &str,
        chain: u32,
        index: u32,
        wallet_keys: &WasmRootWalletKeys,
        signer: Option<String>,
        cosigner: Option<String>,
        tag: Option<String>,
    ) -> Result<u32, WasmUtxoError> {
        // Parse sign path for taproot if provided
        let sign_path = match (&signer, &cosigner) {
            (Some(s), Some(c)) => {
                let signer_key: SignerKey =
                    s.parse().map_err(|e: String| WasmUtxoError::new(&e))?;
                let cosigner_key: SignerKey =
                    c.parse().map_err(|e: String| WasmUtxoError::new(&e))?;
                Some((signer_key.index(), cosigner_key.index()))
            }
            _ => None,
        };

        let input_index = bitgo_psbt::add_bip322_input(
            &mut psbt.psbt,
            message,
            chain,
            index,
            wallet_keys.inner(),
            sign_path,
            tag.as_deref(),
        )
        .map_err(|e| WasmUtxoError::new(&e))?;

        Ok(input_index as u32)
    }

    /// Verify a single input of a BIP-0322 transaction proof
    ///
    /// # Arguments
    /// * `tx` - The signed transaction
    /// * `input_index` - The index of the input to verify
    /// * `message` - The message that was signed
    /// * `chain` - The wallet chain
    /// * `index` - The address index
    /// * `wallet_keys` - The wallet's root keys
    /// * `network` - Network name
    /// * `tag` - Optional custom tag for message hashing
    ///
    /// # Throws
    /// Throws an error if verification fails
    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_bip322_tx_input(
        tx: &super::transaction::WasmTransaction,
        input_index: u32,
        message: &str,
        chain: u32,
        index: u32,
        wallet_keys: &WasmRootWalletKeys,
        network: &str,
        tag: Option<String>,
    ) -> Result<(), WasmUtxoError> {
        let network = parse_network(network)?;

        bitgo_psbt::verify_bip322_tx_input(
            &tx.tx,
            input_index as usize,
            message,
            chain,
            index,
            wallet_keys.inner(),
            &network,
            tag.as_deref(),
        )
        .map_err(|e| WasmUtxoError::new(&e))
    }

    /// Verify a single input of a BIP-0322 PSBT proof
    ///
    /// # Arguments
    /// * `psbt` - The signed BitGoPsbt
    /// * `input_index` - The index of the input to verify
    /// * `message` - The message that was signed
    /// * `chain` - The wallet chain
    /// * `index` - The address index
    /// * `wallet_keys` - The wallet's root keys
    /// * `tag` - Optional custom tag for message hashing
    ///
    /// # Returns
    /// An array of signer names ("user", "backup", "bitgo") that have valid signatures
    ///
    /// # Throws
    /// Throws an error if verification fails or no valid signatures found
    #[wasm_bindgen]
    pub fn verify_bip322_psbt_input(
        psbt: &super::fixed_script_wallet::BitGoPsbt,
        input_index: u32,
        message: &str,
        chain: u32,
        index: u32,
        wallet_keys: &WasmRootWalletKeys,
        tag: Option<String>,
    ) -> Result<Vec<String>, WasmUtxoError> {
        bitgo_psbt::verify_bip322_psbt_input(
            &psbt.psbt,
            input_index as usize,
            message,
            chain,
            index,
            wallet_keys.inner(),
            tag.as_deref(),
        )
        .map_err(|e| WasmUtxoError::new(&e))
    }

    /// Verify a single input of a BIP-0322 PSBT proof using pubkeys directly
    ///
    /// # Arguments
    /// * `psbt` - The signed BitGoPsbt
    /// * `input_index` - The index of the input to verify
    /// * `message` - The message that was signed
    /// * `pubkeys` - Array of 3 hex-encoded pubkeys [user, backup, bitgo]
    /// * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2"
    /// * `is_script_path` - For taproot types, whether script path was used
    /// * `tag` - Optional custom tag for message hashing
    ///
    /// # Returns
    /// An array of pubkey indices (0, 1, 2) that have valid signatures
    ///
    /// # Throws
    /// Throws an error if verification fails or no valid signatures found
    #[wasm_bindgen]
    pub fn verify_bip322_psbt_input_with_pubkeys(
        psbt: &super::fixed_script_wallet::BitGoPsbt,
        input_index: u32,
        message: &str,
        pubkeys: Vec<String>,
        script_type: &str,
        is_script_path: Option<bool>,
        tag: Option<String>,
    ) -> Result<Vec<u32>, WasmUtxoError> {
        let pub_triple = parse_pubkeys(&pubkeys)?;

        let indices = bitgo_psbt::verify_bip322_psbt_input_with_pubkeys(
            &psbt.psbt,
            input_index as usize,
            message,
            &pub_triple,
            script_type,
            is_script_path,
            tag.as_deref(),
        )
        .map_err(|e| WasmUtxoError::new(&e))?;

        Ok(indices.into_iter().map(|i| i as u32).collect())
    }

    /// Verify a single input of a BIP-0322 transaction proof using pubkeys directly
    ///
    /// # Arguments
    /// * `tx` - The signed transaction
    /// * `input_index` - The index of the input to verify
    /// * `message` - The message that was signed
    /// * `pubkeys` - Array of 3 hex-encoded pubkeys [user, backup, bitgo]
    /// * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2"
    /// * `is_script_path` - For taproot types, whether script path was used
    /// * `tag` - Optional custom tag for message hashing
    ///
    /// # Returns
    /// An array of pubkey indices (0, 1, 2) that have valid signatures
    ///
    /// # Throws
    /// Throws an error if verification fails
    #[wasm_bindgen]
    pub fn verify_bip322_tx_input_with_pubkeys(
        tx: &super::transaction::WasmTransaction,
        input_index: u32,
        message: &str,
        pubkeys: Vec<String>,
        script_type: &str,
        is_script_path: Option<bool>,
        tag: Option<String>,
    ) -> Result<Vec<u32>, WasmUtxoError> {
        let pub_triple = parse_pubkeys(&pubkeys)?;

        let indices = bitgo_psbt::verify_bip322_tx_input_with_pubkeys(
            &tx.tx,
            input_index as usize,
            message,
            &pub_triple,
            script_type,
            is_script_path,
            tag.as_deref(),
        )
        .map_err(|e| WasmUtxoError::new(&e))?;

        Ok(indices.into_iter().map(|i| i as u32).collect())
    }
}

/// Parse hex-encoded pubkeys into a PubTriple
fn parse_pubkeys(pubkeys: &[String]) -> Result<PubTriple, WasmUtxoError> {
    if pubkeys.len() != 3 {
        return Err(WasmUtxoError::new(&format!(
            "Expected 3 pubkeys, got {}",
            pubkeys.len()
        )));
    }

    let mut result: Vec<CompressedPublicKey> = Vec::with_capacity(3);
    for (i, hex_str) in pubkeys.iter().enumerate() {
        let bytes = Vec::<u8>::from_hex(hex_str)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid hex for pubkey {}: {}", i, e)))?;
        let pubkey = CompressedPublicKey::from_slice(&bytes)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid pubkey {}: {}", i, e)))?;
        result.push(pubkey);
    }

    Ok([result[0], result[1], result[2]])
}
