mod dimensions;

pub use dimensions::WasmDimensions;

use std::collections::HashMap;
use std::str::FromStr;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

use crate::address::networks::AddressFormat;
use crate::error::WasmUtxoError;
use crate::fixed_script_wallet::wallet_scripts::{OutputScriptType, Scope};
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

    #[wasm_bindgen]
    pub fn output_script_with_network_str(
        keys: &WasmRootWalletKeys,
        chain: u32,
        index: u32,
        network: &str,
    ) -> Result<Vec<u8>, WasmUtxoError> {
        let network = parse_network(network)?;
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
    pub fn address_with_network_str(
        keys: &WasmRootWalletKeys,
        chain: u32,
        index: u32,
        network: &str,
        address_format: Option<String>,
    ) -> Result<String, WasmUtxoError> {
        let network = parse_network(network)?;
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
        let address = crate::address::networks::from_output_script_with_network_and_format(
            &script,
            network,
            address_format,
        )
        .map_err(|e| WasmUtxoError::new(&format!("Failed to generate address: {}", e)))?;
        Ok(address)
    }

    /// Check if a network supports a given fixed-script wallet script type
    ///
    /// # Arguments
    /// * `coin` - Coin name (e.g., "btc", "ltc", "doge")
    /// * `script_type` - Script type name: "p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2"
    ///
    /// # Returns
    /// `true` if the network supports the script type, `false` otherwise
    ///
    /// # Examples
    /// - Bitcoin supports all script types (p2sh, p2shP2wsh, p2wsh, p2tr, p2trMusig2)
    /// - Litecoin supports segwit but not taproot (p2sh, p2shP2wsh, p2wsh)
    /// - Dogecoin only supports legacy scripts (p2sh)
    #[wasm_bindgen]
    pub fn supports_script_type(coin: &str, script_type: &str) -> Result<bool, WasmUtxoError> {
        let network = crate::networks::Network::from_coin_name(coin)
            .ok_or_else(|| WasmUtxoError::new(&format!("Unknown coin: {}", coin)))?;
        let st = OutputScriptType::from_str(script_type).map_err(|e| WasmUtxoError::new(&e))?;
        Ok(network.output_script_support().supports_script_type(st))
    }

    /// Create an OP_RETURN output script with optional data
    ///
    /// # Arguments
    /// * `data` - Optional data bytes to include in the OP_RETURN script
    ///
    /// # Returns
    /// The OP_RETURN script as bytes
    #[wasm_bindgen]
    pub fn create_op_return_script(data: Option<Vec<u8>>) -> Result<Vec<u8>, WasmUtxoError> {
        use miniscript::bitcoin::opcodes::all::OP_RETURN;
        use miniscript::bitcoin::script::{Builder, PushBytesBuf};

        let mut builder = Builder::new().push_opcode(OP_RETURN);
        if let Some(data) = data {
            let push_bytes = PushBytesBuf::try_from(data)
                .map_err(|e| WasmUtxoError::new(&format!("Data too large for OP_RETURN: {}", e)))?;
            builder = builder.push_slice(push_bytes);
        }
        Ok(builder.into_script().to_bytes())
    }

    /// Get all chain code metadata for building TypeScript lookup tables
    ///
    /// Returns an array of [chainCode, scriptType, scope] tuples where:
    /// - chainCode: u32 (0, 1, 10, 11, 20, 21, 30, 31, 40, 41)
    /// - scriptType: string ("p2sh", "p2shP2wsh", "p2wsh", "p2trLegacy", "p2trMusig2")
    /// - scope: string ("external" or "internal")
    #[wasm_bindgen]
    pub fn chain_code_table() -> JsValue {
        use js_sys::Array;

        let result = Array::new();

        for script_type in OutputScriptType::all() {
            for scope in [Scope::External, Scope::Internal] {
                let chain = Chain::new(*script_type, scope);
                let tuple = Array::new();
                tuple.push(&JsValue::from(chain.value()));
                tuple.push(&JsValue::from_str(script_type.as_str()));
                tuple.push(&JsValue::from_str(match scope {
                    Scope::External => "external",
                    Scope::Internal => "internal",
                }));
                result.push(&tuple);
            }
        }

        result.into()
    }
}
#[wasm_bindgen]
pub struct BitGoPsbt {
    pub(crate) psbt: crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt,
    // Store FirstRound states per (input_index, xpub_string)
    #[wasm_bindgen(skip)]
    pub(crate) first_rounds: HashMap<(usize, String), musig2::FirstRound>,
}

#[wasm_bindgen]
impl BitGoPsbt {
    /// Deserialize a PSBT from bytes with network-specific logic
    pub fn from_bytes(bytes: &[u8], network: &str) -> Result<BitGoPsbt, WasmUtxoError> {
        let network = parse_network(network)?;

        let psbt =
            crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt::deserialize(bytes, network)
                .map_err(|e| WasmUtxoError::new(&format!("Failed to deserialize PSBT: {}", e)))?;

        Ok(BitGoPsbt {
            psbt,
            first_rounds: HashMap::new(),
        })
    }

    /// Create an empty PSBT for the given network with wallet keys
    ///
    /// # Arguments
    /// * `network` - Network name (utxolib or coin name)
    /// * `wallet_keys` - The wallet's root keys (used to set global xpubs)
    /// * `version` - Optional transaction version (default: 2)
    /// * `lock_time` - Optional lock time (default: 0)
    pub fn create_empty(
        network: &str,
        wallet_keys: &WasmRootWalletKeys,
        version: Option<i32>,
        lock_time: Option<u32>,
    ) -> Result<BitGoPsbt, WasmUtxoError> {
        let network = parse_network(network)?;
        let wallet_keys = wallet_keys.inner();

        let psbt = crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt::new(
            network,
            wallet_keys,
            version,
            lock_time,
        );

        Ok(BitGoPsbt {
            psbt,
            first_rounds: HashMap::new(),
        })
    }

    /// Create an empty Zcash PSBT with the required consensus branch ID
    ///
    /// This method is specifically for Zcash networks which require additional
    /// parameters for sighash computation.
    ///
    /// # Arguments
    /// * `network` - Network name (must be "zcash" or "zcashTest")
    /// * `wallet_keys` - The wallet's root keys (used to set global xpubs)
    /// * `consensus_branch_id` - Zcash consensus branch ID (e.g., 0xC2D6D0B4 for NU5)
    /// * `version` - Optional transaction version (default: 4 for Zcash Sapling+)
    /// * `lock_time` - Optional lock time (default: 0)
    /// * `version_group_id` - Optional version group ID (defaults to Sapling: 0x892F2085)
    /// * `expiry_height` - Optional expiry height
    pub fn create_empty_zcash(
        network: &str,
        wallet_keys: &WasmRootWalletKeys,
        consensus_branch_id: u32,
        version: Option<i32>,
        lock_time: Option<u32>,
        version_group_id: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Result<BitGoPsbt, WasmUtxoError> {
        let network = parse_network(network)?;
        let wallet_keys = wallet_keys.inner();

        let psbt = crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt::new_zcash(
            network,
            wallet_keys,
            consensus_branch_id,
            version,
            lock_time,
            version_group_id,
            expiry_height,
        );

        Ok(BitGoPsbt {
            psbt,
            first_rounds: HashMap::new(),
        })
    }

    /// Create an empty Zcash PSBT with consensus branch ID determined from block height
    ///
    /// This method automatically determines the correct consensus branch ID based on
    /// the network and block height using the network upgrade activation heights.
    ///
    /// # Arguments
    /// * `network` - Network name (must be "zcash" or "zcashTest")
    /// * `wallet_keys` - The wallet's root keys (used to set global xpubs)
    /// * `block_height` - Block height to determine consensus rules
    /// * `version` - Optional transaction version (default: 4 for Zcash Sapling+)
    /// * `lock_time` - Optional lock time (default: 0)
    /// * `version_group_id` - Optional version group ID (defaults to Sapling: 0x892F2085)
    /// * `expiry_height` - Optional expiry height
    ///
    /// # Errors
    /// Returns error if block height is before Overwinter activation
    #[allow(clippy::too_many_arguments)]
    pub fn create_empty_zcash_at_height(
        network: &str,
        wallet_keys: &WasmRootWalletKeys,
        block_height: u32,
        version: Option<i32>,
        lock_time: Option<u32>,
        version_group_id: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Result<BitGoPsbt, WasmUtxoError> {
        let network = parse_network(network)?;
        let wallet_keys = wallet_keys.inner();

        let psbt = crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt::new_zcash_at_height(
            network,
            wallet_keys,
            block_height,
            version,
            lock_time,
            version_group_id,
            expiry_height,
        )
        .map_err(|e| WasmUtxoError::new(&e))?;

        Ok(BitGoPsbt {
            psbt,
            first_rounds: HashMap::new(),
        })
    }

    /// Add an input to the PSBT
    ///
    /// # Arguments
    /// * `txid` - The transaction ID (hex string) of the output being spent
    /// * `vout` - The output index being spent
    /// * `value` - The value in satoshis of the output being spent
    /// * `script` - The output script (scriptPubKey) of the output being spent
    /// * `sequence` - Optional sequence number (default: 0xFFFFFFFE for RBF)
    ///
    /// # Returns
    /// The index of the newly added input
    pub fn add_input(
        &mut self,
        txid: &str,
        vout: u32,
        value: u64,
        script: &[u8],
        sequence: Option<u32>,
        prev_tx: Option<Vec<u8>>,
    ) -> Result<usize, WasmUtxoError> {
        use miniscript::bitcoin::consensus::Decodable;
        use miniscript::bitcoin::{ScriptBuf, Transaction, Txid};
        use std::str::FromStr;

        let txid = Txid::from_str(txid)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid txid: {}", e)))?;
        let script = ScriptBuf::from_bytes(script.to_vec());

        let prev_tx = prev_tx
            .map(|bytes| {
                Transaction::consensus_decode(&mut bytes.as_slice())
                    .map_err(|e| WasmUtxoError::new(&format!("Invalid prev_tx: {}", e)))
            })
            .transpose()?;

        Ok(self
            .psbt
            .add_input(txid, vout, value, script, sequence, prev_tx))
    }

    /// Add an output to the PSBT
    ///
    /// # Arguments
    /// * `script` - The output script (scriptPubKey)
    /// * `value` - The value in satoshis
    ///
    /// # Returns
    /// The index of the newly added output
    pub fn add_output(&mut self, script: &[u8], value: u64) -> Result<usize, WasmUtxoError> {
        use miniscript::bitcoin::ScriptBuf;

        let script = ScriptBuf::from_bytes(script.to_vec());

        Ok(self.psbt.add_output(script, value))
    }

    /// Add an output to the PSBT by address
    ///
    /// # Arguments
    /// * `address` - The destination address
    /// * `value` - The value in satoshis
    ///
    /// # Returns
    /// The index of the newly added output
    pub fn add_output_with_address(
        &mut self,
        address: &str,
        value: u64,
    ) -> Result<usize, WasmUtxoError> {
        Ok(self.psbt.add_output_with_address(address, value)?)
    }

    /// Add a wallet input with full PSBT metadata
    ///
    /// This is a higher-level method that adds an input and populates all required
    /// PSBT fields (scripts, derivation info, etc.) based on the wallet's chain type.
    ///
    /// # Arguments
    /// * `txid` - The transaction ID (hex string)
    /// * `vout` - The output index being spent
    /// * `value` - The value in satoshis
    /// * `chain` - The chain code (0/1=p2sh, 10/11=p2shP2wsh, 20/21=p2wsh, 30/31=p2tr, 40/41=p2trMusig2)
    /// * `index` - The derivation index
    /// * `wallet_keys` - The root wallet keys
    /// * `signer` - The key that will sign ("user", "backup", or "bitgo") - required for p2tr/p2trMusig2
    /// * `cosigner` - The key that will co-sign - required for p2tr/p2trMusig2
    /// * `sequence` - Optional sequence number (default: 0xFFFFFFFE for RBF)
    /// * `prev_tx` - Optional full previous transaction bytes (for non-segwit)
    ///
    /// # Returns
    /// The index of the newly added input
    #[allow(clippy::too_many_arguments)]
    pub fn add_wallet_input(
        &mut self,
        txid: &str,
        vout: u32,
        value: u64,
        wallet_keys: &WasmRootWalletKeys,
        chain: u32,
        index: u32,
        signer: Option<String>,
        cosigner: Option<String>,
        sequence: Option<u32>,
        prev_tx: Option<Vec<u8>>,
    ) -> Result<usize, WasmUtxoError> {
        use crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::{
            ScriptId, SignPath, SignerKey,
        };
        use miniscript::bitcoin::Txid;
        use std::str::FromStr;

        let txid = Txid::from_str(txid)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid txid: {}", e)))?;

        let wallet_keys = wallet_keys.inner();

        let script_id = ScriptId { chain, index };
        let sign_path = match (signer.as_deref(), cosigner.as_deref()) {
            (Some(signer_str), Some(cosigner_str)) => {
                let signer: SignerKey = signer_str
                    .parse()
                    .map_err(|e: String| WasmUtxoError::new(&e))?;
                let cosigner: SignerKey = cosigner_str
                    .parse()
                    .map_err(|e: String| WasmUtxoError::new(&e))?;
                Some(SignPath { signer, cosigner })
            }
            (None, None) => None,
            _ => {
                return Err(WasmUtxoError::new(
                    "Both signer and cosigner must be provided together or both omitted",
                ))
            }
        };

        use crate::fixed_script_wallet::bitgo_psbt::WalletInputOptions;

        self.psbt
            .add_wallet_input(
                txid,
                vout,
                value,
                wallet_keys,
                script_id,
                WalletInputOptions {
                    sign_path,
                    sequence,
                    prev_tx: prev_tx.as_deref(),
                },
            )
            .map_err(|e| WasmUtxoError::new(&e))
    }

    /// Add a wallet output with full PSBT metadata
    ///
    /// This creates a verifiable wallet output (typically for change) with all required
    /// PSBT fields (scripts, derivation info) based on the wallet's chain type.
    ///
    /// # Arguments
    /// * `chain` - The chain code (0/1=p2sh, 10/11=p2shP2wsh, 20/21=p2wsh, 30/31=p2tr, 40/41=p2trMusig2)
    /// * `index` - The derivation index
    /// * `value` - The value in satoshis
    /// * `wallet_keys` - The root wallet keys
    ///
    /// # Returns
    /// The index of the newly added output
    pub fn add_wallet_output(
        &mut self,
        chain: u32,
        index: u32,
        value: u64,
        wallet_keys: &WasmRootWalletKeys,
    ) -> Result<usize, WasmUtxoError> {
        let wallet_keys = wallet_keys.inner();

        self.psbt
            .add_wallet_output(chain, index, value, wallet_keys)
            .map_err(|e| WasmUtxoError::new(&e))
    }

    /// Add a replay protection input to the PSBT
    ///
    /// Replay protection inputs are P2SH-P2PK inputs used on forked networks to prevent
    /// transaction replay attacks. They use a simple pubkey script without wallet derivation.
    ///
    /// # Arguments
    /// * `ecpair` - The ECPair containing the public key for the replay protection input
    /// * `txid` - The transaction ID (hex string) of the output being spent
    /// * `vout` - The output index being spent
    /// * `value` - The value in satoshis
    /// * `sequence` - Optional sequence number (default: 0xFFFFFFFE for RBF)
    ///
    /// # Returns
    /// The index of the newly added input
    pub fn add_replay_protection_input(
        &mut self,
        ecpair: &WasmECPair,
        txid: &str,
        vout: u32,
        value: u64,
        sequence: Option<u32>,
    ) -> Result<usize, WasmUtxoError> {
        use crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::ReplayProtectionOptions;
        use miniscript::bitcoin::{CompressedPublicKey, Txid};
        use std::str::FromStr;

        // Parse txid
        let txid = Txid::from_str(txid)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid txid: {}", e)))?;

        // Get public key from ECPair and convert to CompressedPublicKey
        let pubkey = ecpair.get_public_key();
        let compressed_pubkey = CompressedPublicKey::from_slice(&pubkey.serialize())
            .map_err(|e| WasmUtxoError::new(&format!("Failed to convert public key: {}", e)))?;

        let options = ReplayProtectionOptions {
            sequence,
            sighash_type: None,
            prev_tx: None,
        };

        Ok(self
            .psbt
            .add_replay_protection_input(compressed_pubkey, txid, vout, value, options))
    }

    /// Get the unsigned transaction ID
    pub fn unsigned_txid(&self) -> String {
        self.psbt.unsigned_txid().to_string()
    }

    /// Get the network of the PSBT
    pub fn network(&self) -> String {
        self.psbt.network().to_string()
    }

    /// Get the network type for transaction extraction
    ///
    /// Returns "bitcoin", "dash", or "zcash" to indicate which transaction
    /// wrapper class should be used in TypeScript.
    pub fn get_network_type(&self) -> String {
        use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt as InnerBitGoPsbt;
        match &self.psbt {
            InnerBitGoPsbt::BitcoinLike(_, _) => "bitcoin".to_string(),
            InnerBitGoPsbt::Dash(_, _) => "dash".to_string(),
            InnerBitGoPsbt::Zcash(_, _) => "zcash".to_string(),
        }
    }

    /// Get the transaction version
    pub fn version(&self) -> i32 {
        self.psbt.psbt().unsigned_tx.version.0
    }

    /// Get the transaction lock time
    pub fn lock_time(&self) -> u32 {
        self.psbt.psbt().unsigned_tx.lock_time.to_consensus_u32()
    }

    /// Get the Zcash version group ID (returns None for non-Zcash PSBTs)
    pub fn version_group_id(&self) -> Option<u32> {
        use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt as InnerBitGoPsbt;
        match &self.psbt {
            InnerBitGoPsbt::Zcash(zcash_psbt, _) => zcash_psbt.version_group_id,
            InnerBitGoPsbt::BitcoinLike(_, _) => None,
            InnerBitGoPsbt::Dash(_, _) => None,
        }
    }

    /// Get the Zcash expiry height (returns None for non-Zcash PSBTs)
    pub fn expiry_height(&self) -> Option<u32> {
        use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt as InnerBitGoPsbt;
        match &self.psbt {
            InnerBitGoPsbt::Zcash(zcash_psbt, _) => zcash_psbt.expiry_height,
            InnerBitGoPsbt::BitcoinLike(_, _) => None,
            InnerBitGoPsbt::Dash(_, _) => None,
        }
    }

    /// Parse transaction with wallet keys to identify wallet inputs/outputs
    pub fn parse_transaction_with_wallet_keys(
        &self,
        wallet_keys: &WasmRootWalletKeys,
        replay_protection: &WasmReplayProtection,
        paygo_pubkeys: Option<Vec<WasmECPair>>,
    ) -> Result<JsValue, WasmUtxoError> {
        // Get the inner RootWalletKeys and ReplayProtection
        let wallet_keys = wallet_keys.inner();
        let replay_protection = replay_protection.inner();

        // Convert WasmECPair to secp256k1::PublicKey
        let pubkeys: Vec<_> = paygo_pubkeys
            .unwrap_or_default()
            .iter()
            .map(|ecpair| ecpair.get_public_key())
            .collect();

        // Call the Rust implementation
        let parsed_tx = self
            .psbt
            .parse_transaction_with_wallet_keys(wallet_keys, replay_protection, &pubkeys)
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
        paygo_pubkeys: Option<Vec<WasmECPair>>,
    ) -> Result<JsValue, WasmUtxoError> {
        // Get the inner RootWalletKeys
        let wallet_keys = wallet_keys.inner();

        // Convert WasmECPair to secp256k1::PublicKey
        let pubkeys: Vec<_> = paygo_pubkeys
            .unwrap_or_default()
            .iter()
            .map(|ecpair| ecpair.get_public_key())
            .collect();

        // Call the Rust implementation
        let parsed_outputs = self
            .psbt
            .parse_outputs_with_wallet_keys(wallet_keys, &pubkeys)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to parse outputs: {}", e)))?;

        // Convert Vec<ParsedOutput> to JsValue
        parsed_outputs.try_to_js_value()
    }

    /// Add a PayGo attestation to a PSBT output
    ///
    /// # Arguments
    /// - `output_index`: The index of the output to add the attestation to
    /// - `entropy`: 64 bytes of entropy
    /// - `signature`: ECDSA signature bytes
    ///
    /// # Returns
    /// - `Ok(())` if the attestation was successfully added
    /// - `Err(WasmUtxoError)` if the output index is out of bounds or entropy is invalid
    pub fn add_paygo_attestation(
        &mut self,
        output_index: usize,
        entropy: &[u8],
        signature: &[u8],
    ) -> Result<(), WasmUtxoError> {
        self.psbt
            .add_paygo_attestation(output_index, entropy.to_vec(), signature.to_vec())
            .map_err(|e| WasmUtxoError::new(&e))
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

    /// Generate and store MuSig2 nonces for all MuSig2 inputs
    ///
    /// This method generates nonces using the State-Machine API and stores them in the PSBT.
    /// The nonces are stored as proprietary fields in the PSBT and will be included when serialized.
    /// After ALL participants have generated their nonces, they can sign MuSig2 inputs using
    /// sign_with_xpriv().
    ///
    /// # Arguments
    /// * `xpriv` - The extended private key (xpriv) for signing
    /// * `session_id_bytes` - Optional 32-byte session ID for nonce generation. **Only allowed on testnets**.
    ///                        On mainnets, a secure random session ID is always generated automatically.
    ///                        Must be unique per signing session.
    ///
    /// # Returns
    /// Ok(()) if nonces were successfully generated and stored
    ///
    /// # Errors
    /// Returns error if:
    /// - Nonce generation fails
    /// - session_id length is invalid
    /// - Custom session_id is provided on a mainnet (security restriction)
    ///
    /// # Security
    /// The session_id MUST be cryptographically random and unique for each signing session.
    /// Never reuse a session_id with the same key! On mainnets, session_id is always randomly
    /// generated for security. Custom session_id is only allowed on testnets for testing purposes.
    pub fn generate_musig2_nonces(
        &mut self,
        xpriv: &WasmBIP32,
        session_id_bytes: Option<Vec<u8>>,
    ) -> Result<(), WasmUtxoError> {
        // Extract Xpriv from WasmBIP32
        let xpriv = xpriv.to_xpriv()?;

        // Get the network from the PSBT to check if custom session_id is allowed
        let network = self.psbt.network();

        // Get or generate session ID
        let session_id = match session_id_bytes {
            Some(bytes) => {
                // Only allow custom session_id on testnets for security
                if !network.is_testnet() {
                    return Err(WasmUtxoError::new(
                        "Custom session_id is only allowed on testnets. On mainnets, session_id is always randomly generated for security."
                    ));
                }
                if bytes.len() != 32 {
                    return Err(WasmUtxoError::new(&format!(
                        "Session ID must be 32 bytes, got {}",
                        bytes.len()
                    )));
                }
                let mut session_id = [0u8; 32];
                session_id.copy_from_slice(&bytes);
                session_id
            }
            None => {
                // Generate secure random session ID
                use getrandom::getrandom;
                let mut session_id = [0u8; 32];
                getrandom(&mut session_id).map_err(|e| {
                    WasmUtxoError::new(&format!("Failed to generate random session ID: {}", e))
                })?;
                session_id
            }
        };

        // Derive xpub from xpriv to use as key
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();
        let xpub = miniscript::bitcoin::bip32::Xpub::from_priv(&secp, &xpriv);
        let xpub_str = xpub.to_string();

        // Iterate over all inputs and generate nonces for MuSig2 inputs
        let input_count = self.psbt.psbt().unsigned_tx.input.len();
        for input_index in 0..input_count {
            // Check if this input is a MuSig2 input
            let psbt = self.psbt.psbt();
            if !crate::fixed_script_wallet::bitgo_psbt::p2tr_musig2_input::Musig2Input::is_musig2_input(&psbt.inputs[input_index]) {
                continue;
            }

            // Generate nonce and get the FirstRound
            // The nonce is automatically stored in the PSBT
            let (first_round, _pub_nonce) = self
                .psbt
                .generate_nonce_first_round(input_index, &xpriv, session_id)
                .map_err(|e| {
                    WasmUtxoError::new(&format!(
                        "Failed to generate nonce for input {}: {}",
                        input_index, e
                    ))
                })?;

            // Store the FirstRound for later use in signing
            // Use (input_index, xpub) as key so multiple parties can store their FirstRounds
            self.first_rounds
                .insert((input_index, xpub_str.clone()), first_round);
        }

        Ok(())
    }

    /// Sign a single input with an extended private key (xpriv)
    ///
    /// This method signs a specific input using the provided xpriv. It accepts:
    /// - An xpriv (WasmBIP32) for wallet inputs - derives the key and signs
    ///
    /// This method automatically detects and handles different input types:
    /// - For regular inputs: uses standard PSBT signing
    /// - For MuSig2 inputs: uses the FirstRound state stored by generate_musig2_nonces()
    /// - For replay protection inputs: returns error (use sign_with_privkey instead)
    ///
    /// # Arguments
    /// - `input_index`: The index of the input to sign (0-based)
    /// - `xpriv`: The extended private key as a WasmBIP32 instance
    ///
    /// # Returns
    /// - `Ok(())` if signing was successful
    /// - `Err(WasmUtxoError)` if signing fails
    pub fn sign_with_xpriv(
        &mut self,
        input_index: usize,
        xpriv: &WasmBIP32,
    ) -> Result<(), WasmUtxoError> {
        // Extract Xpriv from WasmBIP32
        let xpriv = xpriv.to_xpriv()?;

        let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();

        // Check if this is a MuSig2 input
        let psbt = self.psbt.psbt();
        if input_index >= psbt.inputs.len() {
            return Err(WasmUtxoError::new(&format!(
                "Input index {} out of bounds (total inputs: {})",
                input_index,
                psbt.inputs.len()
            )));
        }

        if crate::fixed_script_wallet::bitgo_psbt::p2tr_musig2_input::Musig2Input::is_musig2_input(
            &psbt.inputs[input_index],
        ) {
            // This is a MuSig2 input - use FirstRound signing
            let xpub = miniscript::bitcoin::bip32::Xpub::from_priv(&secp, &xpriv);
            let xpub_str = xpub.to_string();

            // Remove the stored FirstRound for this (input, xpub) pair (it can only be used once)
            let first_round = self.first_rounds.remove(&(input_index, xpub_str.clone()))
                .ok_or_else(|| WasmUtxoError::new(&format!(
                    "No FirstRound found for input {} and xpub {}. You must call generate_musig2_nonces() first.",
                    input_index, xpub_str
                )))?;

            // Sign with the FirstRound
            self.psbt
                .sign_with_first_round(input_index, first_round, &xpriv)
                .map_err(|e| {
                    WasmUtxoError::new(&format!(
                        "Failed to sign MuSig2 input {}: {}",
                        input_index, e
                    ))
                })?;

            Ok(())
        } else {
            // This is a regular input - use standard signing
            // Sign the PSBT - this will attempt to sign all inputs but we only care about the result
            // The miniscript sign method returns (SigningKeysMap, SigningErrors) on error
            let result = self.psbt.sign(&xpriv, &secp);

            // Check if this specific input was signed successfully
            match result {
                Ok(signing_keys) => {
                    // Check if our input_index was in the successfully signed keys
                    if signing_keys.contains_key(&input_index) {
                        Ok(())
                    } else {
                        Err(WasmUtxoError::new(&format!(
                            "Input {} was not signed (no key found or already signed)",
                            input_index
                        )))
                    }
                }
                Err((partial_success, errors)) => {
                    // Check if there's an error for our specific input
                    if let Some(error) = errors.get(&input_index) {
                        Err(WasmUtxoError::new(&format!(
                            "Failed to sign input {}: {:?}",
                            input_index, error
                        )))
                    } else if partial_success.contains_key(&input_index) {
                        // Input was signed successfully despite other errors
                        Ok(())
                    } else {
                        Err(WasmUtxoError::new(&format!(
                            "Input {} was not signed",
                            input_index
                        )))
                    }
                }
            }
        }
    }

    /// Sign a single input with a raw private key
    ///
    /// This method signs a specific input using the provided ECPair. It accepts:
    /// - A raw privkey (WasmECPair) for replay protection inputs - signs directly
    ///
    /// This method automatically detects and handles different input types:
    /// - For replay protection inputs: signs with legacy P2SH sighash
    /// - For regular inputs: uses standard PSBT signing
    /// - For MuSig2 inputs: returns error (requires FirstRound, use sign_with_xpriv instead)
    ///
    /// # Arguments
    /// - `input_index`: The index of the input to sign (0-based)
    /// - `ecpair`: The ECPair containing the private key
    ///
    /// # Returns
    /// - `Ok(())` if signing was successful
    /// - `Err(WasmUtxoError)` if signing fails
    pub fn sign_with_privkey(
        &mut self,
        input_index: usize,
        ecpair: &WasmECPair,
    ) -> Result<(), WasmUtxoError> {
        // Extract private key from WasmECPair
        let privkey = ecpair.get_private_key()?;

        // Call the Rust implementation
        self.psbt
            .sign_with_privkey(input_index, &privkey)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to sign input: {}", e)))
    }

    /// Sign all non-MuSig2 inputs with an extended private key (xpriv) in a single pass.
    ///
    /// This is more efficient than calling `sign_with_xpriv` for each input individually.
    /// The underlying miniscript library's `sign` method signs all matching inputs at once.
    ///
    /// **Note:** MuSig2 inputs are skipped by this method because they require FirstRound
    /// state from nonce generation. After calling this method, sign MuSig2 inputs
    /// individually using `sign_with_xpriv`.
    ///
    /// # Arguments
    /// - `xpriv`: The extended private key as a WasmBIP32 instance
    ///
    /// # Returns
    /// - `Ok(JsValue)` with an array of input indices that were signed
    /// - `Err(WasmUtxoError)` if signing fails
    pub fn sign_all_with_xpriv(&mut self, xpriv: &WasmBIP32) -> Result<JsValue, WasmUtxoError> {
        // Extract Xpriv from WasmBIP32
        let xpriv = xpriv.to_xpriv()?;

        // Call the Rust implementation
        let signing_keys = self
            .psbt
            .sign_all_with_xpriv(&xpriv)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to sign: {}", e)))?;

        // Convert to JsValue - array of input indices that were signed
        let result = js_sys::Array::new();
        for input_index in signing_keys.keys() {
            result.push(&JsValue::from(*input_index as u32));
        }

        Ok(JsValue::from(result))
    }

    /// Sign all replay protection inputs with a raw private key.
    ///
    /// This iterates through all inputs looking for P2SH-P2PK (replay protection) inputs
    /// that match the provided public key and signs them.
    ///
    /// # Arguments
    /// - `ecpair`: The ECPair containing the private key
    ///
    /// # Returns
    /// - `Ok(JsValue)` with an array of input indices that were signed
    /// - `Err(WasmUtxoError)` if signing fails
    pub fn sign_all_replay_protection_inputs(
        &mut self,
        ecpair: &WasmECPair,
    ) -> Result<JsValue, WasmUtxoError> {
        // Extract private key from WasmECPair
        let privkey = ecpair.get_private_key()?;

        // Call the Rust implementation
        let signed_indices = self
            .psbt
            .sign_all_replay_protection_inputs(&privkey)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to sign: {}", e)))?;

        // Convert to JsValue array
        let result = js_sys::Array::new();
        for index in signed_indices {
            result.push(&JsValue::from(index as u32));
        }

        Ok(JsValue::from(result))
    }

    /// Sign a single input with an extended private key, using save/restore for ECDSA inputs.
    ///
    /// For MuSig2 inputs, this returns an error (use sign_with_xpriv which handles FirstRound).
    /// For ECDSA inputs, this clones the PSBT, signs all, then copies only the target
    /// input's signatures back.
    ///
    /// **Important:** This is NOT faster than `sign_all_with_xpriv` for ECDSA inputs.
    /// The underlying miniscript library signs all inputs regardless. This method
    /// just prevents signatures from being added to other inputs.
    ///
    /// # Arguments
    /// - `input_index`: The index of the input to sign (0-based)
    /// - `xpriv`: The extended private key as a WasmBIP32 instance
    ///
    /// # Returns
    /// - `Ok(())` if the input was signed
    /// - `Err(WasmUtxoError)` if signing fails
    pub fn sign_single_input_with_xpriv(
        &mut self,
        input_index: usize,
        xpriv: &WasmBIP32,
    ) -> Result<(), WasmUtxoError> {
        // Extract Xpriv from WasmBIP32
        let xpriv = xpriv.to_xpriv()?;

        // Call the Rust implementation
        self.psbt
            .sign_single_input_with_xpriv(input_index, &xpriv)
            .map_err(|e| {
                WasmUtxoError::new(&format!("Failed to sign input {}: {}", input_index, e))
            })
    }

    /// Sign a single input with a raw private key, using save/restore for regular inputs.
    ///
    /// For replay protection inputs (P2SH-P2PK), this uses direct signing which is
    /// already single-input. For regular inputs, this clones the PSBT, signs all,
    /// then copies only the target input's signatures back.
    ///
    /// **Important:** This is NOT faster than signing all inputs for regular (non-RP) inputs.
    /// The underlying miniscript library signs all inputs regardless.
    ///
    /// # Arguments
    /// - `input_index`: The index of the input to sign (0-based)
    /// - `ecpair`: The ECPair containing the private key
    ///
    /// # Returns
    /// - `Ok(())` if the input was signed
    /// - `Err(WasmUtxoError)` if signing fails
    pub fn sign_single_input_with_privkey(
        &mut self,
        input_index: usize,
        ecpair: &WasmECPair,
    ) -> Result<(), WasmUtxoError> {
        // Extract private key from WasmECPair
        let privkey = ecpair.get_private_key()?;

        // Call the Rust implementation
        self.psbt
            .sign_single_input_with_privkey(input_index, &privkey)
            .map_err(|e| {
                WasmUtxoError::new(&format!("Failed to sign input {}: {}", input_index, e))
            })
    }

    // ==================== NEW CLEAN SIGNING API ====================

    /// Check if an input is a MuSig2 keypath input.
    ///
    /// MuSig2 inputs require special handling: nonces must be generated first with
    /// `generate_musig2_nonces()`, then signed with `sign_musig2_input()`.
    ///
    /// # Arguments
    /// - `input_index`: The index of the input to check (0-based)
    ///
    /// # Returns
    /// - `true` if the input is a MuSig2 keypath input
    /// - `false` otherwise (or if input_index is out of bounds)
    pub fn is_musig2_input(&self, input_index: usize) -> bool {
        let psbt = self.psbt.psbt();
        if input_index >= psbt.inputs.len() {
            return false;
        }
        crate::fixed_script_wallet::bitgo_psbt::p2tr_musig2_input::Musig2Input::is_musig2_input(
            &psbt.inputs[input_index],
        )
    }

    /// Sign all non-MuSig2 wallet inputs in a single efficient pass.
    ///
    /// This signs all ECDSA (P2SH, P2SH-P2WSH, P2WSH) and Taproot script path (P2TR)
    /// inputs that match the provided xpriv. MuSig2 keypath inputs are skipped.
    ///
    /// This is the most efficient way to sign wallet inputs. After calling this,
    /// sign any MuSig2 inputs using `sign_all_musig2_inputs()` or `sign_musig2_input()`.
    ///
    /// # Arguments
    /// - `xpriv`: The extended private key as a WasmBIP32 instance
    ///
    /// # Returns
    /// - `Ok(JsValue)` with an array of input indices that were signed
    /// - `Err(WasmUtxoError)` if signing fails
    pub fn sign_all_wallet_inputs(&mut self, xpriv: &WasmBIP32) -> Result<JsValue, WasmUtxoError> {
        let xpriv = xpriv.to_xpriv()?;

        let signing_keys = self
            .psbt
            .sign_all_with_xpriv(&xpriv)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to sign: {}", e)))?;

        let result = js_sys::Array::new();
        for input_index in signing_keys.keys() {
            result.push(&JsValue::from(*input_index as u32));
        }

        Ok(JsValue::from(result))
    }

    /// Sign a single non-MuSig2 wallet input using save/restore pattern.
    ///
    /// For MuSig2 inputs, returns an error (use `sign_musig2_input` instead).
    /// For ECDSA inputs, this uses a save/restore pattern: clones the PSBT,
    /// signs all inputs on the clone, then copies only the target input's
    /// signatures back.
    ///
    /// **Important:** This is NOT faster than `sign_all_wallet_inputs()` for ECDSA inputs.
    /// The underlying library signs all inputs regardless. This method just ensures
    /// that only the specified input gets signatures added to the PSBT.
    /// Use `sign_all_wallet_inputs()` when signing multiple inputs with the same key.
    ///
    /// # Arguments
    /// - `input_index`: The index of the input to sign (0-based)
    /// - `xpriv`: The extended private key as a WasmBIP32 instance
    ///
    /// # Returns
    /// - `Ok(())` if the input was signed
    /// - `Err(WasmUtxoError)` if signing fails or input is MuSig2
    pub fn sign_wallet_input(
        &mut self,
        input_index: usize,
        xpriv: &WasmBIP32,
    ) -> Result<(), WasmUtxoError> {
        let xpriv = xpriv.to_xpriv()?;

        self.psbt
            .sign_single_input_with_xpriv(input_index, &xpriv)
            .map_err(|e| {
                WasmUtxoError::new(&format!("Failed to sign input {}: {}", input_index, e))
            })
    }

    /// Sign a single MuSig2 keypath input.
    ///
    /// This uses the FirstRound state generated by `generate_musig2_nonces()`.
    /// Each FirstRound can only be used once (nonce reuse is a security risk).
    ///
    /// For non-MuSig2 inputs, returns an error (use `sign_wallet_input` instead).
    ///
    /// # Arguments
    /// - `input_index`: The index of the input to sign (0-based)
    /// - `xpriv`: The extended private key as a WasmBIP32 instance
    ///
    /// # Returns
    /// - `Ok(())` if signing was successful
    /// - `Err(WasmUtxoError)` if signing fails, no FirstRound exists, or not a MuSig2 input
    pub fn sign_musig2_input(
        &mut self,
        input_index: usize,
        xpriv: &WasmBIP32,
    ) -> Result<(), WasmUtxoError> {
        let xpriv = xpriv.to_xpriv()?;
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();

        let psbt = self.psbt.psbt();
        if input_index >= psbt.inputs.len() {
            return Err(WasmUtxoError::new(&format!(
                "Input index {} out of bounds (total inputs: {})",
                input_index,
                psbt.inputs.len()
            )));
        }

        if !crate::fixed_script_wallet::bitgo_psbt::p2tr_musig2_input::Musig2Input::is_musig2_input(
            &psbt.inputs[input_index],
        ) {
            return Err(WasmUtxoError::new(&format!(
                "Input {} is not a MuSig2 input. Use sign_wallet_input instead.",
                input_index
            )));
        }

        let xpub = miniscript::bitcoin::bip32::Xpub::from_priv(&secp, &xpriv);
        let xpub_str = xpub.to_string();

        let first_round = self.first_rounds.remove(&(input_index, xpub_str.clone()))
            .ok_or_else(|| WasmUtxoError::new(&format!(
                "No FirstRound found for input {} and xpub {}. You must call generate_musig2_nonces() first.",
                input_index, xpub_str
            )))?;

        self.psbt
            .sign_with_first_round(input_index, first_round, &xpriv)
            .map_err(|e| {
                WasmUtxoError::new(&format!(
                    "Failed to sign MuSig2 input {}: {}",
                    input_index, e
                ))
            })?;

        Ok(())
    }

    /// Sign all MuSig2 keypath inputs in a single pass with optimized sighash computation.
    ///
    /// This is more efficient than calling `sign_musig2_input()` for each input because
    /// it reuses the SighashCache across all inputs, avoiding redundant computation of
    /// sha_prevouts, sha_amounts, sha_scriptpubkeys, sha_sequences, and sha_outputs.
    ///
    /// Each MuSig2 input requires a FirstRound from `generate_musig2_nonces()`.
    /// FirstRounds that have already been consumed (signed) are skipped.
    ///
    /// # Arguments
    /// - `xpriv`: The extended private key as a WasmBIP32 instance
    ///
    /// # Returns
    /// - `Ok(JsValue)` with an array of input indices that were signed
    /// - `Err(WasmUtxoError)` if signing fails
    pub fn sign_all_musig2_inputs(&mut self, xpriv: &WasmBIP32) -> Result<JsValue, WasmUtxoError> {
        let xpriv = xpriv.to_xpriv()?;
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();
        let xpub = miniscript::bitcoin::bip32::Xpub::from_priv(&secp, &xpriv);
        let xpub_str = xpub.to_string();

        // Find all MuSig2 inputs that have a FirstRound for this xpub
        let psbt = self.psbt.psbt();
        let musig2_indices: Vec<usize> = (0..psbt.inputs.len())
            .filter(|&i| {
                crate::fixed_script_wallet::bitgo_psbt::p2tr_musig2_input::Musig2Input::is_musig2_input(
                    &psbt.inputs[i],
                ) && self.first_rounds.contains_key(&(i, xpub_str.clone()))
            })
            .collect();

        if musig2_indices.is_empty() {
            return Ok(JsValue::from(js_sys::Array::new()));
        }

        // Collect prevouts once (shared across all inputs)
        let prevouts = crate::fixed_script_wallet::bitgo_psbt::p2tr_musig2_input::collect_prevouts(
            self.psbt.psbt(),
        )
        .map_err(|e| WasmUtxoError::new(&format!("Failed to collect prevouts: {}", e)))?;

        // Clone the unsigned transaction for the SighashCache
        // (needed to avoid borrow conflicts with psbt mutation)
        let unsigned_tx = self.psbt.psbt().unsigned_tx.clone();

        // Create SighashCache once (caches sha_prevouts, sha_amounts, etc.)
        let mut sighash_cache = miniscript::bitcoin::sighash::SighashCache::new(&unsigned_tx);

        let mut signed_indices = Vec::new();

        for input_index in musig2_indices {
            // Remove the FirstRound (it can only be used once)
            let first_round = match self.first_rounds.remove(&(input_index, xpub_str.clone())) {
                Some(fr) => fr,
                None => continue, // Already consumed
            };

            // Sign with the shared sighash cache
            match self.psbt.sign_with_first_round_and_cache(
                input_index,
                first_round,
                &xpriv,
                &mut sighash_cache,
                &prevouts,
            ) {
                Ok(()) => signed_indices.push(input_index),
                Err(e) => {
                    return Err(WasmUtxoError::new(&format!(
                        "Failed to sign MuSig2 input {}: {}",
                        input_index, e
                    )));
                }
            }
        }

        let result = js_sys::Array::new();
        for index in signed_indices {
            result.push(&JsValue::from(index as u32));
        }

        Ok(JsValue::from(result))
    }

    /// Sign all replay protection inputs with a raw private key.
    ///
    /// This iterates through all inputs looking for P2SH-P2PK (replay protection) inputs
    /// that match the provided public key and signs them.
    ///
    /// # Arguments
    /// - `ecpair`: The ECPair containing the private key
    ///
    /// # Returns
    /// - `Ok(JsValue)` with an array of input indices that were signed
    /// - `Err(WasmUtxoError)` if signing fails
    pub fn sign_replay_protection_inputs(
        &mut self,
        ecpair: &WasmECPair,
    ) -> Result<JsValue, WasmUtxoError> {
        let privkey = ecpair.get_private_key()?;

        let signed_indices = self
            .psbt
            .sign_all_replay_protection_inputs(&privkey)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to sign: {}", e)))?;

        let result = js_sys::Array::new();
        for index in signed_indices {
            result.push(&JsValue::from(index as u32));
        }

        Ok(JsValue::from(result))
    }

    // ==================== END NEW API ====================

    /// Combine/merge data from another PSBT into this one
    ///
    /// This method copies MuSig2 nonces and signatures (proprietary key-value pairs) from the
    /// source PSBT to this PSBT. This is useful for merging PSBTs during the nonce exchange
    /// and signature collection phases.
    ///
    /// # Arguments
    /// * `source_psbt` - The source PSBT containing data to merge
    ///
    /// # Returns
    /// Ok(()) if data was successfully merged
    ///
    /// # Errors
    /// Returns error if networks don't match
    pub fn combine_musig2_nonces(&mut self, source_psbt: &BitGoPsbt) -> Result<(), WasmUtxoError> {
        self.psbt
            .combine_musig2_nonces(&source_psbt.psbt)
            .map_err(|e| WasmUtxoError::new(&format!("Failed to combine PSBTs: {}", e)))
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
    /// It extracts the fully signed transaction as a WASM transaction instance
    /// appropriate for the network (WasmTransaction, WasmDashTransaction, or WasmZcashTransaction).
    ///
    /// # Returns
    /// - `Ok(JsValue)` containing the WASM transaction instance
    /// - `Err(WasmUtxoError)` if the PSBT is not fully finalized or extraction fails
    pub fn extract_transaction(&self) -> Result<JsValue, WasmUtxoError> {
        use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt as InnerBitGoPsbt;
        match &self.psbt {
            InnerBitGoPsbt::BitcoinLike(..) => {
                let tx = self
                    .psbt
                    .clone()
                    .extract_bitcoin_tx()
                    .map_err(|e| WasmUtxoError::new(&e))?;
                Ok(crate::wasm::transaction::WasmTransaction::from_tx(tx).into())
            }
            InnerBitGoPsbt::Dash(..) => {
                let parts = self
                    .psbt
                    .clone()
                    .extract_dash_tx()
                    .map_err(|e| WasmUtxoError::new(&e))?;
                Ok(crate::wasm::dash_transaction::WasmDashTransaction::from_parts(parts).into())
            }
            InnerBitGoPsbt::Zcash(..) => {
                let parts = self
                    .psbt
                    .clone()
                    .extract_zcash_tx()
                    .map_err(|e| WasmUtxoError::new(&e))?;
                Ok(crate::wasm::transaction::WasmZcashTransaction::from_parts(parts).into())
            }
        }
    }

    /// Extract the final transaction as a WasmTransaction (for BitcoinLike networks)
    ///
    /// This avoids re-parsing bytes by returning the transaction directly.
    /// Only valid for Bitcoin-like networks (not Dash or Zcash).
    pub fn extract_bitcoin_transaction(
        &self,
    ) -> Result<crate::wasm::transaction::WasmTransaction, WasmUtxoError> {
        let tx = self
            .psbt
            .clone()
            .extract_bitcoin_tx()
            .map_err(|e| WasmUtxoError::new(&e))?;
        Ok(crate::wasm::transaction::WasmTransaction::from_tx(tx))
    }

    /// Extract the final transaction as a WasmDashTransaction (for Dash networks)
    ///
    /// This avoids re-parsing bytes by returning the transaction directly.
    /// Only valid for Dash networks.
    pub fn extract_dash_transaction(
        &self,
    ) -> Result<crate::wasm::dash_transaction::WasmDashTransaction, WasmUtxoError> {
        let parts = self
            .psbt
            .clone()
            .extract_dash_tx()
            .map_err(|e| WasmUtxoError::new(&e))?;
        Ok(crate::wasm::dash_transaction::WasmDashTransaction::from_parts(parts))
    }

    /// Extract the final transaction as a WasmZcashTransaction (for Zcash networks)
    ///
    /// This avoids re-parsing bytes by returning the transaction directly.
    /// Only valid for Zcash networks.
    pub fn extract_zcash_transaction(
        &self,
    ) -> Result<crate::wasm::transaction::WasmZcashTransaction, WasmUtxoError> {
        let parts = self
            .psbt
            .clone()
            .extract_zcash_tx()
            .map_err(|e| WasmUtxoError::new(&e))?;
        Ok(crate::wasm::transaction::WasmZcashTransaction::from_parts(
            parts,
        ))
    }

    /// Extract a half-signed transaction in legacy format for p2ms-based script types.
    ///
    /// This method extracts a transaction where each input has exactly one signature,
    /// formatted in the legacy style used by utxo-lib and bitcoinjs-lib. The legacy
    /// format places signatures in the correct position (0, 1, or 2) based on which
    /// key signed, with empty placeholders for unsigned positions.
    ///
    /// # Requirements
    /// - All inputs must be p2ms-based (p2sh, p2shP2wsh, or p2wsh)
    /// - Each input must have exactly 1 partial signature
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)` containing the serialized half-signed transaction bytes
    /// - `Err(WasmUtxoError)` if validation fails or extraction fails
    ///
    /// # Errors
    /// - Returns error if any input is not a p2ms type (Taproot, replay protection, etc.)
    /// - Returns error if any input has 0 or more than 1 partial signature
    pub fn extract_half_signed_legacy_tx(&self) -> Result<Vec<u8>, WasmUtxoError> {
        self.psbt
            .extract_half_signed_legacy_tx()
            .map_err(|e| WasmUtxoError::new(&e))
    }
}
