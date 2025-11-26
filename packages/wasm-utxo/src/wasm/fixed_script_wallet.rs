use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

use crate::address::networks::AddressFormat;
use crate::error::WasmUtxoError;
use crate::fixed_script_wallet::{Chain, WalletScripts};
use crate::utxolib_compat::UtxolibNetwork;
use crate::wasm::bip32::WasmBIP32;
use crate::wasm::ecpair::WasmECPair;
use crate::wasm::replay_protection::WasmReplayProtection;
use crate::wasm::try_from_js_value::TryFromJsValue;
use crate::wasm::try_into_js_value::TryIntoJsValue;
use crate::wasm::wallet_keys::WasmRootWalletKeys;

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

#[wasm_bindgen]
pub struct FixedScriptWalletNamespace;

#[wasm_bindgen]
impl FixedScriptWalletNamespace {
    #[wasm_bindgen]
    pub fn output_script(
        keys: &WasmRootWalletKeys,
        chain: u32,
        index: u32,
        network: JsValue,
    ) -> Result<Vec<u8>, WasmUtxoError> {
        let network = UtxolibNetwork::try_from_js_value(&network)?;
        let chain = Chain::try_from(chain)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid chain: {}", e)))?;

        let wallet_keys = keys.inner();
        let scripts = WalletScripts::from_wallet_keys(
            wallet_keys,
            chain,
            index,
            &network.output_script_support(),
        )?;
        Ok(scripts.output_script().to_bytes())
    }

    #[wasm_bindgen]
    pub fn address(
        keys: &WasmRootWalletKeys,
        chain: u32,
        index: u32,
        network: JsValue,
        address_format: Option<String>,
    ) -> Result<String, WasmUtxoError> {
        let network = UtxolibNetwork::try_from_js_value(&network)?;
        let wallet_keys = keys.inner();
        let chain = Chain::try_from(chain)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid chain: {}", e)))?;
        let scripts = WalletScripts::from_wallet_keys(
            wallet_keys,
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
    pub fn from_bytes(bytes: &[u8], network: &str) -> Result<BitGoPsbt, WasmUtxoError> {
        let network = parse_network(network)?;

        let psbt =
            crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt::deserialize(bytes, network)
                .map_err(|e| WasmUtxoError::new(&format!("Failed to deserialize PSBT: {}", e)))?;

        Ok(BitGoPsbt { psbt })
    }

    /// Get the unsigned transaction ID
    pub fn unsigned_txid(&self) -> String {
        self.psbt.unsigned_txid().to_string()
    }

    /// Get the network of the PSBT
    pub fn network(&self) -> String {
        self.psbt.network().to_string()
    }

    /// Parse transaction with wallet keys to identify wallet inputs/outputs
    pub fn parse_transaction_with_wallet_keys(
        &self,
        wallet_keys: &WasmRootWalletKeys,
        replay_protection: &WasmReplayProtection,
    ) -> Result<JsValue, WasmUtxoError> {
        // Get the inner RootWalletKeys and ReplayProtection
        let wallet_keys = wallet_keys.inner();
        let replay_protection = replay_protection.inner();

        // Call the Rust implementation
        let parsed_tx = self
            .psbt
            .parse_transaction_with_wallet_keys(wallet_keys, replay_protection)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to parse transaction: {}", e)))?;

        // Convert to JsValue directly using TryIntoJsValue
        parsed_tx.try_to_js_value()
    }

    /// Parse outputs with wallet keys to identify which outputs belong to a wallet
    ///
    /// Note: This method does NOT validate wallet inputs. It only parses outputs.
    pub fn parse_outputs_with_wallet_keys(
        &self,
        wallet_keys: &WasmRootWalletKeys,
    ) -> Result<JsValue, WasmUtxoError> {
        // Get the inner RootWalletKeys
        let wallet_keys = wallet_keys.inner();

        // Call the Rust implementation
        let parsed_outputs = self
            .psbt
            .parse_outputs_with_wallet_keys(wallet_keys)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to parse outputs: {}", e)))?;

        // Convert Vec<ParsedOutput> to JsValue
        parsed_outputs.try_to_js_value()
    }

    /// Verify if a valid signature exists for a given xpub at the specified input index
    ///
    /// This method derives the public key from the xpub using the derivation path found in the
    /// PSBT input, then verifies the signature. It supports:
    /// - ECDSA signatures (for legacy/SegWit inputs)
    /// - Schnorr signatures (for Taproot script path inputs)
    /// - MuSig2 partial signatures (for Taproot keypath MuSig2 inputs)
    ///
    /// # Arguments
    /// - `input_index`: The index of the input to check
    /// - `xpub`: The extended public key as a WasmBIP32 instance
    ///
    /// # Returns
    /// - `Ok(true)` if a valid signature exists for the derived public key
    /// - `Ok(false)` if no signature exists for the derived public key
    /// - `Err(WasmUtxoError)` if the input index is out of bounds, derivation fails, or verification fails
    pub fn verify_signature_with_xpub(
        &self,
        input_index: usize,
        xpub: &WasmBIP32,
    ) -> Result<bool, WasmUtxoError> {
        // Extract Xpub from WasmBIP32
        let xpub_inner = xpub.to_xpub()?;

        // Create secp context
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::verification_only();

        // Call the Rust implementation
        self.psbt
            .verify_signature_with_xpub(&secp, input_index, &xpub_inner)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to verify signature: {}", e)))
    }

    /// Verify if a valid signature exists for a given ECPair key at the specified input index
    ///
    /// This method verifies the signature directly with the provided ECPair's public key. It supports:
    /// - ECDSA signatures (for legacy/SegWit inputs)
    /// - Schnorr signatures (for Taproot script path inputs)
    ///
    /// Note: This method does NOT support MuSig2 inputs, as MuSig2 requires derivation from xpubs.
    /// Use `verify_signature_with_xpub` for MuSig2 inputs.
    ///
    /// # Arguments
    /// - `input_index`: The index of the input to check
    /// - `ecpair`: The ECPair key (uses the public key for verification)
    ///
    /// # Returns
    /// - `Ok(true)` if a valid signature exists for the public key
    /// - `Ok(false)` if no signature exists for the public key
    /// - `Err(WasmUtxoError)` if the input index is out of bounds or verification fails
    pub fn verify_signature_with_pub(
        &self,
        input_index: usize,
        ecpair: &WasmECPair,
    ) -> Result<bool, WasmUtxoError> {
        // Extract the public key from the ECPair
        let public_key = ecpair.get_public_key();

        // Create secp context
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::verification_only();

        // Call the Rust implementation
        self.psbt
            .verify_signature_with_pub(&secp, input_index, &public_key)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to verify signature: {}", e)))
    }

    /// Verify if a replay protection input has a valid signature
    ///
    /// This method checks if a given input is a replay protection input and cryptographically verifies
    /// the signature. Replay protection inputs (like P2shP2pk) don't use standard derivation paths,
    /// so this method verifies signatures without deriving from xpub.
    ///
    /// # Arguments
    /// - `input_index`: The index of the input to check
    /// - `replay_protection`: Replay protection configuration (same format as parseTransactionWithWalletKeys)
    ///   Can be either `{ outputScripts: Buffer[] }` or `{ addresses: string[] }`
    ///
    /// # Returns
    /// - `Ok(true)` if the input is a replay protection input and has a valid signature
    /// - `Ok(false)` if the input is a replay protection input but has no valid signature
    /// - `Err(WasmUtxoError)` if the input is not a replay protection input, index is out of bounds, or configuration is invalid
    pub fn verify_replay_protection_signature(
        &self,
        input_index: usize,
        replay_protection: &WasmReplayProtection,
    ) -> Result<bool, WasmUtxoError> {
        // Get the inner ReplayProtection
        let replay_protection = replay_protection.inner();

        // Create secp context
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::verification_only();

        // Call the Rust implementation
        self.psbt
            .verify_replay_protection_signature(&secp, input_index, replay_protection)
            .map_err(|e| {
                WasmUtxoError::new(&format!(
                    "Failed to verify replay protection signature: {}",
                    e
                ))
            })
    }

    /// Serialize the PSBT to bytes
    ///
    /// # Returns
    /// The serialized PSBT as a byte array
    pub fn serialize(&self) -> Result<Vec<u8>, WasmUtxoError> {
        self.psbt
            .serialize()
            .map_err(|e| WasmUtxoError::new(&format!("Failed to serialize PSBT: {}", e)))
    }

    /// Finalize all inputs in the PSBT
    ///
    /// This method attempts to finalize all inputs in the PSBT, computing the final
    /// scriptSig and witness data for each input.
    ///
    /// # Returns
    /// - `Ok(())` if all inputs were successfully finalized
    /// - `Err(WasmUtxoError)` if any input failed to finalize
    pub fn finalize_all_inputs(&mut self) -> Result<(), WasmUtxoError> {
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::verification_only();
        self.psbt.finalize_mut(&secp).map_err(|errors| {
            WasmUtxoError::new(&format!(
                "Failed to finalize {} input(s): {}",
                errors.len(),
                errors.join("; ")
            ))
        })
    }

    /// Extract the final transaction from a finalized PSBT
    ///
    /// This method should be called after all inputs have been finalized.
    /// It extracts the fully signed transaction.
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)` containing the serialized transaction bytes
    /// - `Err(WasmUtxoError)` if the PSBT is not fully finalized or extraction fails
    pub fn extract_transaction(&self) -> Result<Vec<u8>, WasmUtxoError> {
        let psbt = self.psbt.psbt().clone();
        let tx = psbt
            .extract_tx()
            .map_err(|e| WasmUtxoError::new(&format!("Failed to extract transaction: {}", e)))?;

        // Serialize the transaction
        use miniscript::bitcoin::consensus::encode::serialize;
        Ok(serialize(&tx))
    }
}
