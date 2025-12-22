//! BitGo-specific PSBT parsing that handles multiple network formats
//!
//! This module provides PSBT deserialization that works across different
//! bitcoin-like networks, including those with non-standard transaction formats.

pub mod p2tr_musig2_input;
#[cfg(test)]
mod p2tr_musig2_input_utxolib;
mod propkv;
pub mod psbt_wallet_input;
pub mod psbt_wallet_output;
mod sighash;
pub mod zcash_psbt;

use crate::Network;
use miniscript::bitcoin::{psbt::Psbt, secp256k1, CompressedPublicKey, Txid};
pub use propkv::{BitGoKeyValue, ProprietaryKeySubtype, BITGO};
pub use sighash::validate_sighash_type;
pub use zcash_psbt::{
    decode_zcash_transaction_meta, ZcashBitGoPsbt, ZcashTransactionMeta,
    ZCASH_SAPLING_VERSION_GROUP_ID,
};

#[derive(Debug)]
pub enum DeserializeError {
    /// Standard bitcoin consensus decoding error
    Consensus(miniscript::bitcoin::consensus::encode::Error),
    /// PSBT-specific error
    Psbt(miniscript::bitcoin::psbt::Error),
    /// Network-specific error message
    Network(String),
}

impl std::fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeserializeError::Consensus(e) => write!(f, "{}", e),
            DeserializeError::Psbt(e) => write!(f, "{}", e),
            DeserializeError::Network(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DeserializeError {}

impl From<miniscript::bitcoin::consensus::encode::Error> for DeserializeError {
    fn from(e: miniscript::bitcoin::consensus::encode::Error) -> Self {
        DeserializeError::Consensus(e)
    }
}

impl From<miniscript::bitcoin::psbt::Error> for DeserializeError {
    fn from(e: miniscript::bitcoin::psbt::Error) -> Self {
        DeserializeError::Psbt(e)
    }
}

#[derive(Debug)]
pub enum SerializeError {
    /// Standard bitcoin consensus encoding error
    Consensus(std::io::Error),
    /// Network-specific error message
    Network(String),
}

impl std::fmt::Display for SerializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SerializeError::Consensus(e) => write!(f, "{}", e),
            SerializeError::Network(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for SerializeError {}

impl From<std::io::Error> for SerializeError {
    fn from(e: std::io::Error) -> Self {
        SerializeError::Consensus(e)
    }
}

impl From<DeserializeError> for SerializeError {
    fn from(e: DeserializeError) -> Self {
        match e {
            DeserializeError::Consensus(ce) => {
                // Convert consensus encode error to io error
                SerializeError::Network(format!("Consensus error: {}", ce))
            }
            DeserializeError::Psbt(pe) => SerializeError::Network(format!("PSBT error: {}", pe)),
            DeserializeError::Network(msg) => SerializeError::Network(msg),
        }
    }
}

#[derive(Debug, Clone)]
pub enum BitGoPsbt {
    BitcoinLike(Psbt, Network),
    Zcash(ZcashBitGoPsbt, Network),
}

/// Options for creating a new Zcash PSBT
#[derive(Debug, Clone, Copy)]
struct ZcashNewOptions {
    /// Zcash consensus branch ID (required for sighash computation)
    consensus_branch_id: u32,
    /// Version group ID (defaults to Sapling: 0x892F2085)
    version_group_id: Option<u32>,
    /// Transaction expiry height
    expiry_height: Option<u32>,
}

// Re-export types from submodules for convenience
pub use psbt_wallet_input::{
    InputScriptType, ParsedInput, ReplayProtectionOptions, ScriptId, WalletInputOptions,
};
pub use psbt_wallet_output::ParsedOutput;

/// Parsed transaction with wallet information
#[derive(Debug, Clone)]
pub struct ParsedTransaction {
    pub inputs: Vec<ParsedInput>,
    pub outputs: Vec<ParsedOutput>,
    pub spend_amount: u64,
    pub miner_fee: u64,
    pub virtual_size: u32,
}

/// Error type for transaction parsing
#[derive(Debug)]
pub enum ParseTransactionError {
    /// Failed to parse input
    Input {
        index: usize,
        error: psbt_wallet_input::ParseInputError,
    },
    /// Input value overflow when adding to total
    InputValueOverflow { index: usize },
    /// Failed to parse output
    Output {
        index: usize,
        error: psbt_wallet_output::ParseOutputError,
    },
    /// Output value overflow when adding to total
    OutputValueOverflow { index: usize },
    /// Spend amount overflow
    SpendAmountOverflow { index: usize },
    /// Fee calculation error (outputs exceed inputs)
    FeeCalculation,
}

impl std::fmt::Display for ParseTransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseTransactionError::Input { index, error } => {
                write!(f, "Input {}: {}", index, error)
            }
            ParseTransactionError::InputValueOverflow { index } => {
                write!(f, "Input {}: value overflow", index)
            }
            ParseTransactionError::Output { index, error } => {
                write!(f, "Output {}: {}", index, error)
            }
            ParseTransactionError::OutputValueOverflow { index } => {
                write!(f, "Output {}: value overflow", index)
            }
            ParseTransactionError::SpendAmountOverflow { index } => {
                write!(f, "Output {}: spend amount overflow", index)
            }
            ParseTransactionError::FeeCalculation => {
                write!(f, "Fee calculation error: outputs exceed inputs")
            }
        }
    }
}

impl std::error::Error for ParseTransactionError {}

/// Get the default sighash type for a network and chain type
fn get_default_sighash_type(
    network: Network,
    chain: crate::fixed_script_wallet::wallet_scripts::Chain,
) -> miniscript::bitcoin::psbt::PsbtSighashType {
    use crate::fixed_script_wallet::wallet_scripts::Chain;
    use miniscript::bitcoin::sighash::{EcdsaSighashType, TapSighashType};

    // For taproot, always use Default
    if matches!(
        chain,
        Chain::P2trInternal
            | Chain::P2trExternal
            | Chain::P2trMusig2Internal
            | Chain::P2trMusig2External
    ) {
        return TapSighashType::Default.into();
    }

    // For non-taproot, check if network uses FORKID
    let uses_forkid = matches!(
        network.mainnet(),
        Network::BitcoinCash | Network::BitcoinGold | Network::BitcoinSV | Network::Ecash
    );

    if uses_forkid {
        // BCH/BSV/BTG/Ecash: SIGHASH_ALL | SIGHASH_FORKID = 0x41
        miniscript::bitcoin::psbt::PsbtSighashType::from_u32(0x41)
    } else {
        // Standard Bitcoin: SIGHASH_ALL
        EcdsaSighashType::All.into()
    }
}

/// Create BIP32 derivation map for all 3 wallet keys
fn create_bip32_derivation(
    wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
    chain: u32,
    index: u32,
) -> std::collections::BTreeMap<
    miniscript::bitcoin::secp256k1::PublicKey,
    (
        miniscript::bitcoin::bip32::Fingerprint,
        miniscript::bitcoin::bip32::DerivationPath,
    ),
> {
    use crate::fixed_script_wallet::derivation_path;
    use miniscript::bitcoin::secp256k1::{PublicKey, Secp256k1};
    use std::collections::BTreeMap;

    let secp = Secp256k1::new();
    let mut map = BTreeMap::new();

    for (i, xpub) in wallet_keys.xpubs.iter().enumerate() {
        let path = derivation_path(&wallet_keys.derivation_prefixes[i], chain, index);
        let derived = xpub.derive_pub(&secp, &path).expect("valid derivation");
        // Convert CompressedPublicKey to secp256k1::PublicKey
        let pubkey = PublicKey::from_slice(&derived.to_pub().to_bytes()).expect("valid public key");
        map.insert(pubkey, (xpub.fingerprint(), path));
    }

    map
}

/// Create tap key origins for specified key indices
fn create_tap_bip32_derivation(
    wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
    chain: u32,
    index: u32,
    key_indices: &[usize],
    leaf_hash: Option<miniscript::bitcoin::taproot::TapLeafHash>,
) -> std::collections::BTreeMap<
    miniscript::bitcoin::XOnlyPublicKey,
    (
        Vec<miniscript::bitcoin::taproot::TapLeafHash>,
        (
            miniscript::bitcoin::bip32::Fingerprint,
            miniscript::bitcoin::bip32::DerivationPath,
        ),
    ),
> {
    use crate::fixed_script_wallet::derivation_path;
    use miniscript::bitcoin::secp256k1::{PublicKey, Secp256k1};
    use std::collections::BTreeMap;

    let secp = Secp256k1::new();
    let mut map = BTreeMap::new();

    for &i in key_indices {
        let xpub = &wallet_keys.xpubs[i];
        let path = derivation_path(&wallet_keys.derivation_prefixes[i], chain, index);
        let derived = xpub.derive_pub(&secp, &path).expect("valid derivation");
        // Convert CompressedPublicKey to secp256k1::PublicKey, then get x-only
        let pubkey = PublicKey::from_slice(&derived.to_pub().to_bytes()).expect("valid public key");
        let (x_only, _parity) = pubkey.x_only_public_key();

        let leaf_hashes = match leaf_hash {
            Some(hash) => vec![hash],
            None => vec![],
        };

        map.insert(x_only, (leaf_hashes, (xpub.fingerprint(), path)));
    }

    map
}

impl BitGoPsbt {
    /// Deserialize a PSBT from bytes, using network-specific logic
    pub fn deserialize(psbt_bytes: &[u8], network: Network) -> Result<BitGoPsbt, DeserializeError> {
        match network {
            Network::Zcash | Network::ZcashTestnet => {
                // Zcash uses overwintered transaction format which is not compatible
                // with standard Bitcoin transaction deserialization
                let zcash_psbt = ZcashBitGoPsbt::deserialize(psbt_bytes, network)?;
                Ok(BitGoPsbt::Zcash(zcash_psbt, network))
            }

            // All other networks use standard Bitcoin transaction format
            Network::Bitcoin
            | Network::BitcoinTestnet3
            | Network::BitcoinTestnet4
            | Network::BitcoinPublicSignet
            | Network::BitcoinBitGoSignet
            | Network::BitcoinCash
            | Network::BitcoinCashTestnet
            | Network::Ecash
            | Network::EcashTestnet
            | Network::BitcoinGold
            | Network::BitcoinGoldTestnet
            | Network::BitcoinSV
            | Network::BitcoinSVTestnet
            | Network::Dash
            | Network::DashTestnet
            | Network::Dogecoin
            | Network::DogecoinTestnet
            | Network::Litecoin
            | Network::LitecoinTestnet => Ok(BitGoPsbt::BitcoinLike(
                Psbt::deserialize(psbt_bytes)?,
                network,
            )),
        }
    }

    /// Create an empty PSBT with the given network and wallet keys
    ///
    /// For Zcash networks, use [`BitGoPsbt::new_zcash`] instead which requires
    /// the consensus branch ID.
    ///
    /// # Arguments
    /// * `network` - The network this PSBT is for (must not be Zcash)
    /// * `wallet_keys` - The wallet's root keys (used to set global xpubs)
    /// * `version` - Transaction version (default: 2)
    /// * `lock_time` - Lock time (default: 0)
    ///
    /// # Panics
    /// Panics if called with a Zcash network. Use `new_zcash` instead.
    pub fn new(
        network: Network,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        version: Option<i32>,
        lock_time: Option<u32>,
    ) -> Self {
        if matches!(network, Network::Zcash | Network::ZcashTestnet) {
            panic!(
                "Use BitGoPsbt::new_zcash() for Zcash networks - consensus_branch_id is required"
            );
        }

        Self::new_internal(network, wallet_keys, version, lock_time, None)
    }

    /// Create an empty Zcash PSBT with the required consensus branch ID
    ///
    /// # Arguments
    /// * `network` - The Zcash network (Zcash or ZcashTestnet)
    /// * `wallet_keys` - The wallet's root keys (used to set global xpubs)
    /// * `consensus_branch_id` - The Zcash consensus branch ID (e.g., 0xC2D6D0B4 for NU5)
    /// * `version` - Transaction version (default: 4 for Zcash Sapling+)
    /// * `lock_time` - Lock time (default: 0)
    /// * `version_group_id` - Optional version group ID (defaults to Sapling: 0x892F2085)
    /// * `expiry_height` - Optional expiry height
    ///
    /// # Panics
    /// Panics if called with a non-Zcash network.
    pub fn new_zcash(
        network: Network,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        consensus_branch_id: u32,
        version: Option<i32>,
        lock_time: Option<u32>,
        version_group_id: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Self {
        if !matches!(network, Network::Zcash | Network::ZcashTestnet) {
            panic!("new_zcash() can only be used with Zcash networks");
        }

        let zcash_options = ZcashNewOptions {
            consensus_branch_id,
            version_group_id,
            expiry_height,
        };

        Self::new_internal(
            network,
            wallet_keys,
            Some(version.unwrap_or(4)), // Zcash Sapling+ uses version 4
            lock_time,
            Some(zcash_options),
        )
    }

    /// Create an empty Zcash PSBT with consensus branch ID determined from block height
    ///
    /// This method automatically determines the correct consensus branch ID based on
    /// the network and block height using the network upgrade activation heights.
    ///
    /// # Arguments
    /// * `network` - The Zcash network (Zcash or ZcashTestnet)
    /// * `wallet_keys` - The wallet's root keys (used to set global xpubs)
    /// * `block_height` - Block height to determine consensus rules
    /// * `version` - Transaction version (default: 4 for Zcash Sapling+)
    /// * `lock_time` - Lock time (default: 0)
    /// * `version_group_id` - Optional version group ID (defaults to Sapling: 0x892F2085)
    /// * `expiry_height` - Optional expiry height
    ///
    /// # Returns
    /// * `Ok(Self)` - Successfully created PSBT with appropriate consensus branch ID
    /// * `Err(String)` - If the block height is before Overwinter activation
    ///
    /// # Panics
    /// Panics if called with a non-Zcash network.
    #[allow(clippy::too_many_arguments)]
    pub fn new_zcash_at_height(
        network: Network,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        block_height: u32,
        version: Option<i32>,
        lock_time: Option<u32>,
        version_group_id: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Result<Self, String> {
        if !matches!(network, Network::Zcash | Network::ZcashTestnet) {
            panic!("new_zcash_at_height() can only be used with Zcash networks");
        }

        // Determine if this is mainnet or testnet
        let is_mainnet = matches!(network, Network::Zcash);

        // Get the consensus branch ID for this block height
        let consensus_branch_id = crate::zcash::branch_id_for_height(block_height, is_mainnet)
            .ok_or_else(|| {
                format!(
                    "Block height {} is before Overwinter activation on {}",
                    block_height,
                    if is_mainnet { "mainnet" } else { "testnet" }
                )
            })?;

        // Call the existing new_zcash with the computed branch ID
        Ok(Self::new_zcash(
            network,
            wallet_keys,
            consensus_branch_id,
            version,
            lock_time,
            version_group_id,
            expiry_height,
        ))
    }

    fn new_internal(
        network: Network,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        version: Option<i32>,
        lock_time: Option<u32>,
        zcash_options: Option<ZcashNewOptions>,
    ) -> Self {
        use miniscript::bitcoin::{
            absolute::LockTime, bip32::DerivationPath, transaction::Version, Transaction,
        };
        use std::collections::BTreeMap;
        use std::str::FromStr;

        let tx = Transaction {
            version: Version(version.unwrap_or(2)),
            lock_time: LockTime::from_consensus(lock_time.unwrap_or(0)),
            input: vec![],
            output: vec![],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("empty transaction should be valid");

        // Set global xpubs from wallet keys
        // Each xpub is mapped to (master_fingerprint, derivation_path)
        // We use 'm' as the path since these are the root wallet keys
        let mut xpub_map = BTreeMap::new();
        for xpub in &wallet_keys.xpubs {
            let fingerprint = xpub.fingerprint();
            let path = DerivationPath::from_str("m").expect("'m' is a valid path");
            xpub_map.insert(*xpub, (fingerprint, path));
        }
        psbt.xpub = xpub_map;

        match network {
            Network::Zcash | Network::ZcashTestnet => {
                let opts = zcash_options.expect("ZcashNewOptions required for Zcash networks");

                // Store consensus branch ID in PSBT proprietary map
                propkv::set_zec_consensus_branch_id(&mut psbt, opts.consensus_branch_id);

                // Initialize sapling_fields for transparent-only transactions:
                // valueBalance (8 bytes, 0) + nShieldedSpend (1 byte, 0) +
                // nShieldedOutput (1 byte, 0) + nJoinSplit (1 byte, 0)
                let sapling_fields = vec![0u8; 11];

                BitGoPsbt::Zcash(
                    ZcashBitGoPsbt {
                        psbt,
                        network,
                        version_group_id: opts.version_group_id,
                        expiry_height: opts.expiry_height,
                        sapling_fields,
                    },
                    network,
                )
            }
            _ => BitGoPsbt::BitcoinLike(psbt, network),
        }
    }

    /// Add an input to the PSBT
    ///
    /// This adds a transaction input and corresponding PSBT input metadata.
    /// The witness_utxo is automatically populated for modern signing compatibility.
    ///
    /// # Arguments
    /// * `txid` - The transaction ID of the output being spent
    /// * `vout` - The output index being spent
    /// * `value` - The value in satoshis of the output being spent
    /// * `script` - The output script (scriptPubKey) of the output being spent
    /// * `sequence` - Optional sequence number (default: 0xFFFFFFFE for RBF)
    ///
    /// # Returns
    /// The index of the newly added input
    pub fn add_input(
        &mut self,
        txid: Txid,
        vout: u32,
        value: u64,
        script: miniscript::bitcoin::ScriptBuf,
        sequence: Option<u32>,
        prev_tx: Option<miniscript::bitcoin::Transaction>,
    ) -> usize {
        use miniscript::bitcoin::{transaction::Sequence, Amount, OutPoint, TxIn, TxOut};

        let psbt = self.psbt_mut();

        // Create the transaction input
        let tx_in = TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: miniscript::bitcoin::ScriptBuf::new(),
            sequence: Sequence(sequence.unwrap_or(0xFFFFFFFE)),
            witness: miniscript::bitcoin::Witness::default(),
        };

        // Create the PSBT input with witness_utxo populated
        let psbt_input = miniscript::bitcoin::psbt::Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(value),
                script_pubkey: script,
            }),
            non_witness_utxo: prev_tx,
            ..Default::default()
        };

        // Add to the PSBT
        psbt.unsigned_tx.input.push(tx_in);
        psbt.inputs.push(psbt_input);

        psbt.inputs.len() - 1
    }

    /// Add a replay protection input (p2shP2pk) to the PSBT
    ///
    /// This creates a Pay-to-Script-Hash wrapped Pay-to-Public-Key input,
    /// commonly used for replay protection on forked networks (BCH, BTG, etc.).
    ///
    /// # Arguments
    /// * `pubkey` - The public key for the p2pk script
    /// * `txid` - The transaction ID of the output being spent
    /// * `vout` - The output index being spent
    /// * `value` - The value in satoshis of the output being spent
    /// * `options` - Optional parameters (sequence, sighash_type, prev_tx)
    ///
    /// # Returns
    /// The index of the newly added input
    pub fn add_replay_protection_input(
        &mut self,
        pubkey: miniscript::bitcoin::CompressedPublicKey,
        txid: Txid,
        vout: u32,
        value: u64,
        options: ReplayProtectionOptions,
    ) -> usize {
        use crate::fixed_script_wallet::wallet_scripts::ScriptP2shP2pk;
        use miniscript::bitcoin::consensus::Decodable;
        use miniscript::bitcoin::psbt::{Input, PsbtSighashType};
        use miniscript::bitcoin::{
            transaction::Sequence, Amount, OutPoint, Transaction, TxIn, TxOut,
        };

        let network = self.network();
        let psbt = self.psbt_mut();

        // Create the p2shP2pk script
        let script = ScriptP2shP2pk::new(pubkey);
        let output_script = script.output_script();
        let redeem_script = script.redeem_script;

        // Create the transaction input
        let tx_in = TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: miniscript::bitcoin::ScriptBuf::new(),
            sequence: Sequence(options.sequence.unwrap_or(0xFFFFFFFE)),
            witness: miniscript::bitcoin::Witness::default(),
        };

        // Determine sighash type: use provided value or default based on network
        // Networks with SIGHASH_FORKID use SIGHASH_ALL | SIGHASH_FORKID (0x41)
        let sighash_type = options.sighash_type.unwrap_or_else(|| {
            match network.mainnet() {
                Network::BitcoinCash
                | Network::Ecash
                | Network::BitcoinSV
                | Network::BitcoinGold => {
                    PsbtSighashType::from_u32(0x41) // SIGHASH_ALL | SIGHASH_FORKID
                }
                _ => PsbtSighashType::from_u32(0x01), // SIGHASH_ALL
            }
        });

        // Create the PSBT input
        let mut psbt_input = Input {
            redeem_script: Some(redeem_script),
            sighash_type: Some(sighash_type),
            ..Default::default()
        };

        // Set utxo: either non_witness_utxo (full tx) or witness_utxo (output only)
        if let Some(tx_bytes) = options.prev_tx {
            let tx = Transaction::consensus_decode(&mut &tx_bytes[..])
                .expect("Failed to decode prev_tx");
            psbt_input.non_witness_utxo = Some(tx);
        } else {
            psbt_input.witness_utxo = Some(TxOut {
                value: Amount::from_sat(value),
                script_pubkey: output_script,
            });
        }

        // Add to the PSBT
        psbt.unsigned_tx.input.push(tx_in);
        psbt.inputs.push(psbt_input);

        psbt.inputs.len() - 1
    }

    /// Add an output to the PSBT
    ///
    /// # Arguments
    /// * `script` - The output script (scriptPubKey)
    /// * `value` - The value in satoshis
    ///
    /// # Returns
    /// The index of the newly added output
    pub fn add_output(&mut self, script: miniscript::bitcoin::ScriptBuf, value: u64) -> usize {
        use miniscript::bitcoin::{Amount, TxOut};

        let psbt = self.psbt_mut();

        // Create the transaction output
        let tx_out = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script,
        };

        // Create the PSBT output
        let psbt_output = miniscript::bitcoin::psbt::Output::default();

        // Add to the PSBT
        psbt.unsigned_tx.output.push(tx_out);
        psbt.outputs.push(psbt_output);

        psbt.outputs.len() - 1
    }

    /// Add a wallet input with full PSBT metadata
    ///
    /// This is a higher-level method that adds an input and populates all required
    /// PSBT fields (scripts, derivation info, etc.) based on the wallet's chain type.
    ///
    /// # Arguments
    /// * `txid` - The transaction ID of the output being spent
    /// * `vout` - The output index being spent
    /// * `value` - The value in satoshis
    /// * `wallet_keys` - The root wallet keys
    /// * `script_id` - The chain and index identifying the script
    /// * `options` - Optional parameters (sign_path, sequence, prev_tx)
    ///
    /// # Returns
    /// The index of the newly added input
    pub fn add_wallet_input(
        &mut self,
        txid: Txid,
        vout: u32,
        value: u64,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        script_id: psbt_wallet_input::ScriptId,
        options: WalletInputOptions,
    ) -> Result<usize, String> {
        use crate::fixed_script_wallet::to_pub_triple;
        use crate::fixed_script_wallet::wallet_scripts::{Chain, WalletScripts};
        use miniscript::bitcoin::psbt::Input;
        use miniscript::bitcoin::taproot::{LeafVersion, TapLeafHash};
        use miniscript::bitcoin::{transaction::Sequence, Amount, OutPoint, TxIn, TxOut};
        use p2tr_musig2_input::Musig2Participants;
        use std::convert::TryFrom;

        let network = self.network();
        let psbt = self.psbt_mut();

        let chain = script_id.chain;
        let index = script_id.index;

        // Parse chain
        let chain_enum = Chain::try_from(chain)?;

        // Derive wallet keys for this chain/index
        let derived_keys = wallet_keys
            .derive_for_chain_and_index(chain, index)
            .map_err(|e| format!("Failed to derive keys: {}", e))?;
        let pub_triple = to_pub_triple(&derived_keys);

        // Create wallet scripts
        let script_support = network.output_script_support();
        let scripts = WalletScripts::new(&pub_triple, chain_enum, &script_support)
            .map_err(|e| format!("Failed to create wallet scripts: {}", e))?;

        // Get the output script
        let output_script = scripts.output_script();

        // Create the transaction input
        let tx_in = TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: miniscript::bitcoin::ScriptBuf::new(),
            sequence: Sequence(options.sequence.unwrap_or(0xFFFFFFFE)),
            witness: miniscript::bitcoin::Witness::default(),
        };

        // Create the PSBT input
        let mut psbt_input = Input::default();

        // Determine if segwit based on chain type
        let is_segwit = matches!(
            chain_enum,
            Chain::P2shP2wshExternal
                | Chain::P2shP2wshInternal
                | Chain::P2wshExternal
                | Chain::P2wshInternal
                | Chain::P2trInternal
                | Chain::P2trExternal
                | Chain::P2trMusig2Internal
                | Chain::P2trMusig2External
        );

        if let (false, Some(tx_bytes)) = (is_segwit, options.prev_tx) {
            // Non-segwit with prev_tx: use non_witness_utxo
            psbt_input.non_witness_utxo = Some(
                miniscript::bitcoin::consensus::deserialize(tx_bytes)
                    .map_err(|e| format!("Failed to deserialize previous transaction: {}", e))?,
            );
        } else {
            // Segwit or non-segwit without prev_tx: use witness_utxo
            psbt_input.witness_utxo = Some(TxOut {
                value: Amount::from_sat(value),
                script_pubkey: output_script.clone(),
            });
        }

        // Set sighash type based on network
        let sighash_type = get_default_sighash_type(network, chain_enum);
        psbt_input.sighash_type = Some(sighash_type);

        // Populate script-type-specific metadata
        match &scripts {
            WalletScripts::P2sh(script) => {
                // bip32_derivation for all 3 keys
                psbt_input.bip32_derivation = create_bip32_derivation(wallet_keys, chain, index);
                // redeem_script
                psbt_input.redeem_script = Some(script.redeem_script.clone());
            }
            WalletScripts::P2shP2wsh(script) => {
                // bip32_derivation for all 3 keys
                psbt_input.bip32_derivation = create_bip32_derivation(wallet_keys, chain, index);
                // witness_script and redeem_script
                psbt_input.witness_script = Some(script.witness_script.clone());
                psbt_input.redeem_script = Some(script.redeem_script.clone());
            }
            WalletScripts::P2wsh(script) => {
                // bip32_derivation for all 3 keys
                psbt_input.bip32_derivation = create_bip32_derivation(wallet_keys, chain, index);
                // witness_script
                psbt_input.witness_script = Some(script.witness_script.clone());
            }
            WalletScripts::P2trLegacy(script) | WalletScripts::P2trMusig2(script) => {
                // For taproot, sign_path is required
                let sign_path = options.sign_path.ok_or_else(|| {
                    "sign_path is required for p2tr/p2trMusig2 inputs".to_string()
                })?;
                let signer_idx = sign_path.signer.index();
                let cosigner_idx = sign_path.cosigner.index();

                let is_musig2 = matches!(scripts, WalletScripts::P2trMusig2(_));
                let is_backup_flow = sign_path.signer.is_backup() || sign_path.cosigner.is_backup();

                if !is_musig2 || is_backup_flow {
                    // Script path spending (p2tr or p2trMusig2 with backup)
                    // Get the leaf script for signer/cosigner pair
                    let signer_keys = [pub_triple[signer_idx], pub_triple[cosigner_idx]];
                    let leaf_script =
                        crate::fixed_script_wallet::wallet_scripts::build_p2tr_ns_script(
                            &signer_keys,
                        );
                    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);

                    // Find the control block for this leaf
                    let control_block = script
                        .spend_info
                        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
                        .ok_or_else(|| {
                            "Could not find control block for leaf script".to_string()
                        })?;

                    // Set tap_leaf_script
                    psbt_input.tap_scripts.insert(
                        control_block.clone(),
                        (leaf_script.clone(), LeafVersion::TapScript),
                    );

                    // Set tap_bip32_derivation for signer and cosigner
                    psbt_input.tap_key_origins = create_tap_bip32_derivation(
                        wallet_keys,
                        chain,
                        index,
                        &[signer_idx, cosigner_idx],
                        Some(leaf_hash),
                    );
                } else {
                    // Key path spending (p2trMusig2 with user/bitgo)
                    let internal_key = script.spend_info.internal_key();
                    let merkle_root = script.spend_info.merkle_root();

                    // Set tap_internal_key
                    psbt_input.tap_internal_key = Some(internal_key);

                    // Set tap_merkle_root
                    psbt_input.tap_merkle_root = merkle_root;

                    // Set tap_bip32_derivation for signer and cosigner (no leaf hashes for key path)
                    psbt_input.tap_key_origins = create_tap_bip32_derivation(
                        wallet_keys,
                        chain,
                        index,
                        &[signer_idx, cosigner_idx],
                        None,
                    );

                    // Set musig2 participant pubkeys (proprietary field)
                    let user_key = pub_triple[0]; // user is index 0
                    let bitgo_key = pub_triple[2]; // bitgo is index 2

                    // Create musig2 participants
                    let tap_output_key = script.spend_info.output_key().to_x_only_public_key();
                    let musig2_participants = Musig2Participants {
                        tap_output_key,
                        tap_internal_key: internal_key,
                        participant_pub_keys: [user_key, bitgo_key],
                    };

                    // Add to proprietary keys
                    let (key, value) = musig2_participants.to_key_value().to_key_value();
                    psbt_input.proprietary.insert(key, value);
                }
            }
        }

        // Add to PSBT
        psbt.unsigned_tx.input.push(tx_in);
        psbt.inputs.push(psbt_input);

        Ok(psbt.inputs.len() - 1)
    }

    /// Add a wallet output with full PSBT metadata
    ///
    /// This creates a verifiable wallet output (typically for change) with all required
    /// PSBT fields (scripts, derivation info) based on the wallet's chain type.
    ///
    /// # Arguments
    /// * `chain` - The chain code (determines script type: 0/1=p2sh, 10/11=p2shP2wsh, etc.)
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
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
    ) -> Result<usize, String> {
        use crate::fixed_script_wallet::to_pub_triple;
        use crate::fixed_script_wallet::wallet_scripts::{
            build_tap_tree_for_output, create_tap_bip32_derivation_for_output, Chain, WalletScripts,
        };
        use miniscript::bitcoin::psbt::Output;
        use miniscript::bitcoin::{Amount, TxOut};
        use std::convert::TryFrom;

        let network = self.network();
        let psbt = self.psbt_mut();

        // Parse chain
        let chain_enum = Chain::try_from(chain)?;

        // Derive wallet keys for this chain/index
        let derived_keys = wallet_keys
            .derive_for_chain_and_index(chain, index)
            .map_err(|e| format!("Failed to derive keys: {}", e))?;
        let pub_triple = to_pub_triple(&derived_keys);

        // Create wallet scripts
        let script_support = network.output_script_support();
        let scripts = WalletScripts::new(&pub_triple, chain_enum, &script_support)
            .map_err(|e| format!("Failed to create wallet scripts: {}", e))?;

        // Get the output script
        let output_script = scripts.output_script();

        // Create the transaction output
        let tx_out = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: output_script,
        };

        // Create the PSBT output with metadata
        let mut psbt_output = Output::default();

        // Populate script-type-specific metadata
        match &scripts {
            WalletScripts::P2sh(script) => {
                // bip32_derivation for all 3 keys
                psbt_output.bip32_derivation = create_bip32_derivation(wallet_keys, chain, index);
                // redeem_script
                psbt_output.redeem_script = Some(script.redeem_script.clone());
            }
            WalletScripts::P2shP2wsh(script) => {
                // bip32_derivation for all 3 keys
                psbt_output.bip32_derivation = create_bip32_derivation(wallet_keys, chain, index);
                // witness_script and redeem_script
                psbt_output.witness_script = Some(script.witness_script.clone());
                psbt_output.redeem_script = Some(script.redeem_script.clone());
            }
            WalletScripts::P2wsh(script) => {
                // bip32_derivation for all 3 keys
                psbt_output.bip32_derivation = create_bip32_derivation(wallet_keys, chain, index);
                // witness_script
                psbt_output.witness_script = Some(script.witness_script.clone());
            }
            WalletScripts::P2trLegacy(script) | WalletScripts::P2trMusig2(script) => {
                let is_musig2 = matches!(scripts, WalletScripts::P2trMusig2(_));

                // Set tap_internal_key
                let internal_key = script.spend_info.internal_key();
                psbt_output.tap_internal_key = Some(internal_key);

                // Set tap_tree for the output
                psbt_output.tap_tree = Some(build_tap_tree_for_output(&pub_triple, is_musig2));

                // Set tap_bip32_derivation with correct leaf hashes for each key
                psbt_output.tap_key_origins = create_tap_bip32_derivation_for_output(
                    wallet_keys,
                    chain,
                    index,
                    &pub_triple,
                    is_musig2,
                );
            }
        }

        // Add to PSBT
        psbt.unsigned_tx.output.push(tx_out);
        psbt.outputs.push(psbt_output);

        Ok(psbt.outputs.len() - 1)
    }

    pub fn network(&self) -> Network {
        match self {
            BitGoPsbt::BitcoinLike(_, network) => *network,
            BitGoPsbt::Zcash(_, network) => *network,
        }
    }

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
    pub fn combine_musig2_nonces(&mut self, source_psbt: &BitGoPsbt) -> Result<(), String> {
        // Check network match
        if self.network() != source_psbt.network() {
            return Err(format!(
                "Network mismatch: destination is {}, source is {}",
                self.network(),
                source_psbt.network()
            ));
        }

        let source = source_psbt.psbt();
        let dest = self.psbt_mut();

        // Check that both PSBTs have the same number of inputs
        if source.inputs.len() != dest.inputs.len() {
            return Err(format!(
                "PSBT input count mismatch: source has {} inputs, destination has {}",
                source.inputs.len(),
                dest.inputs.len()
            ));
        }

        // Copy MuSig2 nonces and partial signatures (proprietary key-values with BITGO identifier)
        for (source_input, dest_input) in source.inputs.iter().zip(dest.inputs.iter_mut()) {
            // Only process if the input is a MuSig2 input
            if !p2tr_musig2_input::Musig2Input::is_musig2_input(source_input) {
                continue;
            }

            // Parse nonces from source input using native Musig2 functions
            let nonces = p2tr_musig2_input::parse_musig2_nonces(source_input)
                .map_err(|e| format!("Failed to parse MuSig2 nonces from source: {}", e))?;

            // Copy each nonce to the destination input
            for nonce in nonces {
                let (key, value) = nonce.to_key_value().to_key_value();
                dest_input.proprietary.insert(key, value);
            }

            // Also copy partial signatures if present
            // Partial sigs are stored as tap_script_sigs in the PSBT input
            for (control_block, leaf_script) in &source_input.tap_script_sigs {
                dest_input
                    .tap_script_sigs
                    .insert(*control_block, *leaf_script);
            }
        }

        Ok(())
    }

    /// Serialize the PSBT to bytes, using network-specific logic
    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        match self {
            BitGoPsbt::BitcoinLike(psbt, _network) => Ok(psbt.serialize()),
            BitGoPsbt::Zcash(zcash_psbt, _network) => Ok(zcash_psbt.serialize()?),
        }
    }

    pub fn into_psbt(self) -> Psbt {
        match self {
            BitGoPsbt::BitcoinLike(psbt, _network) => psbt,
            BitGoPsbt::Zcash(zcash_psbt, _network) => zcash_psbt.into_bitcoin_psbt(),
        }
    }

    /// Get a reference to the underlying PSBT
    ///
    /// This works for both BitcoinLike and Zcash PSBTs, returning a reference
    /// to the inner Bitcoin-compatible PSBT structure.
    pub fn psbt(&self) -> &Psbt {
        match self {
            BitGoPsbt::BitcoinLike(ref psbt, _network) => psbt,
            BitGoPsbt::Zcash(ref zcash_psbt, _network) => &zcash_psbt.psbt,
        }
    }

    /// Get a mutable reference to the underlying PSBT
    ///
    /// This works for both BitcoinLike and Zcash PSBTs, returning a reference
    /// to the inner Bitcoin-compatible PSBT structure.
    pub fn psbt_mut(&mut self) -> &mut Psbt {
        match self {
            BitGoPsbt::BitcoinLike(ref mut psbt, _network) => psbt,
            BitGoPsbt::Zcash(ref mut zcash_psbt, _network) => &mut zcash_psbt.psbt,
        }
    }

    pub fn finalize_input<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
    ) -> Result<(), String> {
        use miniscript::psbt::PsbtExt;

        match self {
            BitGoPsbt::BitcoinLike(ref mut psbt, network) => {
                // Use custom bitgo p2trMusig2 input finalization for MuSig2 inputs
                if p2tr_musig2_input::Musig2Input::is_musig2_input(&psbt.inputs[input_index]) {
                    let mut ctx = p2tr_musig2_input::Musig2Context::new(psbt, input_index)
                        .map_err(|e| e.to_string())?;
                    ctx.finalize_input(secp).map_err(|e| e.to_string())?;
                    return Ok(());
                }

                let fork_id = sighash::get_sighash_fork_id(*network);

                // Finalize with fork_id support for FORKID networks
                psbt.finalize_inp_mut_with_fork_id(secp, input_index, fork_id)
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            BitGoPsbt::Zcash(ref mut zcash_psbt, _network) => {
                use miniscript::psbt::PsbtExt;

                // Extract consensus branch ID from PSBT proprietary map
                let branch_id = propkv::get_zec_consensus_branch_id(&zcash_psbt.psbt)
                    .ok_or_else(|| "Missing ZecConsensusBranchId in PSBT".to_string())?;

                // Extract version group ID and expiry height from ZcashPsbt
                let version_group_id = zcash_psbt
                    .version_group_id
                    .unwrap_or(zcash_psbt::ZCASH_SAPLING_VERSION_GROUP_ID);
                let expiry_height = zcash_psbt.expiry_height.unwrap_or(0);

                // Finalize using ZIP-243 sighash verification
                zcash_psbt
                    .psbt
                    .finalize_inp_mut_with_zcash(
                        secp,
                        input_index,
                        branch_id,
                        version_group_id,
                        expiry_height,
                    )
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
        }
    }

    /// Finalize all inputs in the PSBT, attempting each input even if some fail.
    /// Similar to miniscript::psbt::PsbtExt::finalize_mut.
    ///
    /// # Returns
    /// - `Ok(())` if all inputs were successfully finalized
    /// - `Err(Vec<String>)` containing error messages for each failed input
    ///
    /// # Note
    /// This method will attempt to finalize ALL inputs, collecting errors for any that fail.
    /// It does not stop at the first error.
    pub fn finalize_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<(), Vec<String>> {
        let num_inputs = self.psbt().inputs.len();

        let errors: Vec<String> = (0..num_inputs)
            .filter_map(|index| {
                self.finalize_input(secp, index)
                    .err()
                    .map(|e| format!("Input {}: {}", index, e))
            })
            .collect();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Finalize all inputs and consume the PSBT, returning the finalized PSBT.
    /// Similar to miniscript::psbt::PsbtExt::finalize.
    ///
    /// # Returns
    /// - `Ok(Psbt)` if all inputs were successfully finalized
    /// - `Err(String)` containing a formatted error message if any input failed
    pub fn finalize<C: secp256k1::Verification>(
        mut self,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<Psbt, String> {
        match self.finalize_mut(secp) {
            Ok(()) => Ok(self.into_psbt()),
            Err(errors) => Err(format!(
                "Failed to finalize {} input(s): {}",
                errors.len(),
                errors.join("; ")
            )),
        }
    }

    /// Get the unsigned transaction ID
    ///
    /// For Zcash, this computes the txid over the full Zcash transaction bytes
    /// (including version_group_id, expiry_height, and sapling_fields).
    pub fn unsigned_txid(&self) -> Txid {
        match self {
            BitGoPsbt::BitcoinLike(psbt, _) => psbt.unsigned_tx.compute_txid(),
            BitGoPsbt::Zcash(zcash_psbt, _) => {
                use miniscript::bitcoin::hashes::{sha256d, Hash};
                // Compute txid from full Zcash transaction bytes
                let txid_bytes = zcash_psbt
                    .compute_txid()
                    .expect("Failed to compute Zcash txid");
                let hash = sha256d::Hash::from_byte_array(txid_bytes);
                Txid::from_raw_hash(hash)
            }
        }
    }

    /// Add a PayGo attestation to a PSBT output
    ///
    /// # Arguments
    /// * `output_index` - The index of the output to add the attestation to
    /// * `entropy` - 64 bytes of entropy
    /// * `signature` - ECDSA signature bytes
    ///
    /// # Returns
    /// * `Ok(())` if the attestation was successfully added
    /// * `Err(String)` if the output index is out of bounds or entropy is invalid
    pub fn add_paygo_attestation(
        &mut self,
        output_index: usize,
        entropy: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), String> {
        let psbt = self.psbt_mut();

        // Check output index bounds
        if output_index >= psbt.outputs.len() {
            return Err(format!(
                "Output index {} out of bounds (total outputs: {})",
                output_index,
                psbt.outputs.len()
            ));
        }

        // Add the attestation
        crate::paygo::add_paygo_attestation(&mut psbt.outputs[output_index], entropy, signature)
    }

    /// Helper function to create a MuSig2 context for an input
    ///
    /// This validates that:
    /// 1. The PSBT is BitcoinLike (not Zcash)
    /// 2. The input index is valid
    /// 3. The input is a MuSig2 input
    ///
    /// Returns a Musig2Context for the specified input
    fn musig2_context<'a>(
        &'a mut self,
        input_index: usize,
    ) -> Result<p2tr_musig2_input::Musig2Context<'a>, String> {
        if self.network().mainnet() != Network::Bitcoin {
            return Err("MuSig2 not supported for non-Bitcoin networks".to_string());
        }

        if matches!(self, BitGoPsbt::Zcash(_, _)) {
            return Err("MuSig2 not supported for Zcash".to_string());
        }

        let psbt = self.psbt_mut();
        if input_index >= psbt.inputs.len() {
            return Err(format!("Input index {} out of bounds", input_index));
        }

        // Validate this is a MuSig2 input
        if !p2tr_musig2_input::Musig2Input::is_musig2_input(&psbt.inputs[input_index]) {
            return Err(format!("Input {} is not a MuSig2 input", input_index));
        }

        // Create and return the context
        p2tr_musig2_input::Musig2Context::new(psbt, input_index).map_err(|e| e.to_string())
    }

    /// Set the counterparty's (BitGo's) nonce in the PSBT
    ///
    /// # Arguments
    /// * `input_index` - The index of the MuSig2 input
    /// * `participant_pub_key` - The counterparty's public key
    /// * `pub_nonce` - The counterparty's public nonce
    pub fn set_counterparty_nonce(
        &mut self,
        input_index: usize,
        participant_pub_key: CompressedPublicKey,
        pub_nonce: musig2::PubNonce,
    ) -> Result<(), String> {
        let mut ctx = self.musig2_context(input_index)?;
        let tap_output_key = ctx.musig2_input().participants.tap_output_key;

        // Set the nonce
        ctx.set_nonce(participant_pub_key, tap_output_key, pub_nonce)
            .map_err(|e| e.to_string())
    }

    /// Generate and set a user nonce for a MuSig2 input using State-Machine API
    ///
    /// This method uses the State-Machine API from the musig2 crate, which encapsulates
    /// the SecNonce internally to prevent accidental reuse. This is the recommended
    /// production API.
    ///
    /// # Arguments
    /// * `input_index` - The index of the MuSig2 input
    /// * `xpriv` - The user's extended private key (will be derived for the input)
    /// * `session_id` - 32-byte session ID (use rand::thread_rng().gen() in production)
    ///
    /// # Returns
    /// A tuple of (FirstRound, PubNonce) - keep FirstRound secret for signing later,
    /// send PubNonce to the counterparty
    pub fn generate_nonce_first_round(
        &mut self,
        input_index: usize,
        xpriv: &miniscript::bitcoin::bip32::Xpriv,
        session_id: [u8; 32],
    ) -> Result<(musig2::FirstRound, musig2::PubNonce), String> {
        let mut ctx = self.musig2_context(input_index)?;
        ctx.generate_nonce_first_round(xpriv, session_id)
            .map_err(|e| e.to_string())
    }

    /// Sign a MuSig2 input using State-Machine API
    ///
    /// This method uses the State-Machine API from the musig2 crate. The FirstRound
    /// from nonce generation encapsulates the secret nonce, preventing reuse.
    ///
    /// # Arguments
    /// * `input_index` - The index of the MuSig2 input
    /// * `first_round` - The FirstRound from generate_nonce_first_round()
    /// * `xpriv` - The user's extended private key
    ///
    /// # Returns
    /// Ok(()) if the signature was successfully created and added to the PSBT
    pub fn sign_with_first_round(
        &mut self,
        input_index: usize,
        first_round: musig2::FirstRound,
        xpriv: &miniscript::bitcoin::bip32::Xpriv,
    ) -> Result<(), String> {
        let mut ctx = self.musig2_context(input_index)?;
        ctx.sign_with_first_round(first_round, xpriv)
            .map_err(|e| e.to_string())
    }

    /// Sign a single input with a raw private key
    ///
    /// This method signs a specific input using the provided private key. It automatically
    /// detects the input type and uses the appropriate signing method:
    /// - Replay protection inputs (P2SH-P2PK): Signs with legacy P2SH sighash
    /// - Regular inputs: Uses standard PSBT signing
    /// - MuSig2 inputs: Returns error (requires FirstRound state, use sign_with_first_round)
    ///
    /// # Arguments
    /// - `input_index`: The index of the input to sign
    /// - `privkey`: The private key to sign with
    ///
    /// # Returns
    /// - `Ok(())` if signing was successful
    /// - `Err(String)` if signing fails or input type is not supported
    pub fn sign_with_privkey(
        &mut self,
        input_index: usize,
        privkey: &secp256k1::SecretKey,
    ) -> Result<(), String> {
        use miniscript::bitcoin::PublicKey;

        // Get network before mutable borrow
        let network = self.network();
        let is_testnet = network.is_testnet();

        let psbt = self.psbt_mut();

        // Check bounds
        if input_index >= psbt.inputs.len() {
            return Err(format!(
                "Input index {} out of bounds (total inputs: {})",
                input_index,
                psbt.inputs.len()
            ));
        }

        // Check if this is a MuSig2 input
        if p2tr_musig2_input::Musig2Input::is_musig2_input(&psbt.inputs[input_index]) {
            return Err(
                "MuSig2 inputs cannot be signed with raw privkey. Use sign_with_first_round instead."
                    .to_string(),
            );
        }

        let secp = secp256k1::Secp256k1::new();

        // Derive public key from private key
        let public_key = PublicKey::from_slice(
            &secp256k1::PublicKey::from_secret_key(&secp, privkey).serialize(),
        )
        .map_err(|e| format!("Failed to derive public key: {}", e))?;

        // Check if this is a replay protection input (P2SH-P2PK)
        if let Some(redeem_script) = &psbt.inputs[input_index].redeem_script.clone() {
            // Try to extract pubkey from redeem script
            if let Ok(redeem_pubkey) = Self::extract_pubkey_from_p2pk_redeem_script(redeem_script) {
                // This is a replay protection input - verify the derived pubkey matches
                if public_key != redeem_pubkey {
                    return Err(
                        "Public key mismatch: derived pubkey does not match redeem_script pubkey"
                            .to_string(),
                    );
                }

                // Zcash needs special handling due to ZcashPsbt fields
                // (consensus_branch_id, version_group_id, expiry_height)
                // So we skip this block and let it fall through to the match below
                if matches!(network.mainnet(), Network::Zcash) {
                    // Fall through to BitGoPsbt::Zcash match arm
                } else {
                    // Sign using the appropriate sighash algorithm for this network
                    let ecdsa_sig = Self::sign_p2sh_p2pk_input(
                        psbt,
                        input_index,
                        redeem_script,
                        privkey,
                        network,
                        &secp,
                    )?;

                    // Add signature to partial_sigs
                    psbt.inputs[input_index]
                        .partial_sigs
                        .insert(public_key, ecdsa_sig);

                    return Ok(());
                }
            }
        }

        // For regular inputs (non-RP, non-MuSig2), use standard signing via miniscript
        // This will handle legacy, SegWit, and Taproot script path inputs
        match self {
            BitGoPsbt::BitcoinLike(ref mut psbt, _network) => {
                // Create a key provider that returns our single key
                // Convert SecretKey to PrivateKey for the GetKey trait
                // Note: The network parameter is only used for WIF serialization, not for signing
                let bitcoin_network = if is_testnet {
                    miniscript::bitcoin::Network::Testnet
                } else {
                    miniscript::bitcoin::Network::Bitcoin
                };
                let private_key = miniscript::bitcoin::PrivateKey::new(*privkey, bitcoin_network);
                let key_map = std::collections::BTreeMap::from_iter([(public_key, private_key)]);

                // Sign the PSBT
                let result = psbt.sign(&key_map, &secp);

                // Check if our specific input was signed
                match result {
                    Ok(signing_keys) => {
                        if signing_keys.contains_key(&input_index) {
                            Ok(())
                        } else {
                            Err(format!(
                                "Input {} was not signed (no key found or already signed)",
                                input_index
                            ))
                        }
                    }
                    Err((partial_success, errors)) => {
                        // Check if there's an error for our specific input
                        if let Some(error) = errors.get(&input_index) {
                            Err(format!("Failed to sign input {}: {:?}", input_index, error))
                        } else if partial_success.contains_key(&input_index) {
                            // Input was signed successfully despite other errors
                            Ok(())
                        } else {
                            Err(format!("Input {} was not signed", input_index))
                        }
                    }
                }
            }
            BitGoPsbt::Zcash(ref mut zcash_psbt, network) => {
                // Extract consensus branch ID from PSBT proprietary map
                let branch_id = propkv::get_zec_consensus_branch_id(&zcash_psbt.psbt)
                    .ok_or_else(|| "Missing ZecConsensusBranchId in PSBT".to_string())?;
                let version_group_id = zcash_psbt
                    .version_group_id
                    .unwrap_or(zcash_psbt::ZCASH_SAPLING_VERSION_GROUP_ID);
                let expiry_height = zcash_psbt.expiry_height.unwrap_or(0);

                let psbt = &mut zcash_psbt.psbt;

                // Check bounds
                if input_index >= psbt.inputs.len() {
                    return Err(format!(
                        "Input index {} out of bounds (total inputs: {})",
                        input_index,
                        psbt.inputs.len()
                    ));
                }

                // Check if this is a replay protection input (P2SH-P2PK)
                // These need direct signing since sign_zcash iterates over bip32_derivation
                if let Some(redeem_script) = &psbt.inputs[input_index].redeem_script.clone() {
                    if let Ok(redeem_pubkey) =
                        Self::extract_pubkey_from_p2pk_redeem_script(redeem_script)
                    {
                        // Verify the provided key matches the redeem script pubkey
                        if public_key != redeem_pubkey {
                            return Err(
                                "Public key mismatch: derived pubkey does not match redeem_script pubkey"
                                    .to_string(),
                            );
                        }

                        // Sign directly using ZIP-243 sighash
                        let ecdsa_sig = Self::sign_p2sh_p2pk_input_zcash(
                            psbt,
                            input_index,
                            redeem_script,
                            privkey,
                            branch_id,
                            version_group_id,
                            expiry_height,
                            &secp,
                        )?;

                        // Add signature to partial_sigs
                        psbt.inputs[input_index]
                            .partial_sigs
                            .insert(public_key, ecdsa_sig);

                        return Ok(());
                    }
                }

                // For regular inputs, use standard Zcash signing
                let bitcoin_network = if network.is_testnet() {
                    miniscript::bitcoin::Network::Testnet
                } else {
                    miniscript::bitcoin::Network::Bitcoin
                };
                let private_key = miniscript::bitcoin::PrivateKey::new(*privkey, bitcoin_network);
                let key_map = std::collections::BTreeMap::from_iter([(public_key, private_key)]);

                // Sign with Zcash-specific sighash
                let result =
                    psbt.sign_zcash(&key_map, &secp, branch_id, version_group_id, expiry_height);

                // Check if our specific input was signed
                match result {
                    Ok(signing_keys) => {
                        if signing_keys.contains_key(&input_index) {
                            Ok(())
                        } else {
                            Err(format!(
                                "Input {} was not signed (no key found or already signed)",
                                input_index
                            ))
                        }
                    }
                    Err((partial_success, errors)) => {
                        if let Some(error) = errors.get(&input_index) {
                            Err(format!("Failed to sign input {}: {:?}", input_index, error))
                        } else if partial_success.contains_key(&input_index) {
                            Ok(())
                        } else {
                            Err(format!("Input {} was not signed", input_index))
                        }
                    }
                }
            }
        }
    }

    /// Sign the PSBT with the provided key.
    /// Wraps the underlying PSBT's sign method from miniscript::psbt::PsbtExt.
    ///
    /// # Type Parameters
    /// - `C`: Signing context from secp256k1
    /// - `K`: Key type that implements `psbt::GetKey` trait
    ///
    /// # Returns
    /// - `Ok(SigningKeysMap)` on success, mapping input index to keys used for signing
    /// - `Err((SigningKeysMap, SigningErrors))` on failure, containing both partial success info and errors
    pub fn sign<C, K>(
        &mut self,
        k: &K,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<
        miniscript::bitcoin::psbt::SigningKeysMap,
        (
            miniscript::bitcoin::psbt::SigningKeysMap,
            miniscript::bitcoin::psbt::SigningErrors,
        ),
    >
    where
        C: secp256k1::Signing + secp256k1::Verification,
        K: miniscript::bitcoin::psbt::GetKey,
    {
        match self {
            BitGoPsbt::BitcoinLike(ref mut psbt, network) => {
                // Check if this network uses SIGHASH_FORKID
                // BCH, XEC, BSV: fork_id = 0
                // BTG: fork_id = 79
                match network.mainnet() {
                    Network::BitcoinCash | Network::Ecash | Network::BitcoinSV => {
                        psbt.sign_forkid(k, secp, 0)
                    }
                    Network::BitcoinGold => psbt.sign_forkid(k, secp, 79),
                    _ => psbt.sign(k, secp),
                }
            }
            BitGoPsbt::Zcash(ref mut zcash_psbt, _network) => {
                // Extract consensus branch ID from PSBT proprietary map
                let branch_id =
                    propkv::get_zec_consensus_branch_id(&zcash_psbt.psbt).ok_or_else(|| {
                        (
                            Default::default(),
                            std::collections::BTreeMap::from_iter([(
                                0,
                                miniscript::bitcoin::psbt::SignError::KeyNotFound,
                            )]),
                        )
                    })?;

                // Extract version group ID and expiry height from ZcashPsbt
                let version_group_id = zcash_psbt
                    .version_group_id
                    .unwrap_or(zcash_psbt::ZCASH_SAPLING_VERSION_GROUP_ID);
                let expiry_height = zcash_psbt.expiry_height.unwrap_or(0);

                // Sign using ZIP-243 sighash
                zcash_psbt
                    .psbt
                    .sign_zcash(k, secp, branch_id, version_group_id, expiry_height)
            }
        }
    }

    /// Parse inputs with wallet keys and replay protection
    ///
    /// # Arguments
    /// - `wallet_keys`: The wallet's root keys for deriving scripts
    /// - `replay_protection`: Scripts that are allowed as inputs without wallet validation
    ///
    /// # Returns
    /// - `Ok(Vec<ParsedInput>)` with parsed inputs
    /// - `Err(ParseTransactionError)` if input parsing fails
    fn parse_inputs(
        &self,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        replay_protection: &crate::fixed_script_wallet::ReplayProtection,
    ) -> Result<Vec<ParsedInput>, ParseTransactionError> {
        let psbt = self.psbt();
        let network = self.network();

        psbt.unsigned_tx
            .input
            .iter()
            .zip(psbt.inputs.iter())
            .enumerate()
            .map(|(input_index, (tx_input, psbt_input))| {
                ParsedInput::parse(
                    psbt_input,
                    tx_input,
                    wallet_keys,
                    replay_protection,
                    network,
                )
                .map_err(|error| ParseTransactionError::Input {
                    index: input_index,
                    error,
                })
            })
            .collect()
    }

    /// Parse outputs with wallet keys to identify which outputs belong to the wallet
    ///
    /// # Arguments
    /// - `wallet_keys`: The wallet's root keys for deriving scripts
    /// - `paygo_pubkeys`: Public keys for PayGo attestation verification
    ///
    /// # Returns
    /// - `Ok(Vec<ParsedOutput>)` with parsed outputs
    /// - `Err(ParseTransactionError)` if output parsing fails
    ///
    /// # Note
    /// This method does NOT validate wallet inputs. It only parses outputs to identify
    /// which ones belong to the provided wallet keys.
    fn parse_outputs(
        &self,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        paygo_pubkeys: &[secp256k1::PublicKey],
    ) -> Result<Vec<ParsedOutput>, ParseTransactionError> {
        let psbt = self.psbt();
        let network = self.network();

        psbt.unsigned_tx
            .output
            .iter()
            .zip(psbt.outputs.iter())
            .enumerate()
            .map(|(output_index, (tx_output, psbt_output))| {
                ParsedOutput::parse(psbt_output, tx_output, wallet_keys, network, paygo_pubkeys)
                    .map_err(|error| ParseTransactionError::Output {
                        index: output_index,
                        error,
                    })
            })
            .collect()
    }

    /// Calculate total input value from parsed inputs
    ///
    /// # Returns
    /// - `Ok(u64)` with total input value
    /// - `Err(ParseTransactionError)` if overflow occurs
    fn sum_input_values(parsed_inputs: &[ParsedInput]) -> Result<u64, ParseTransactionError> {
        parsed_inputs
            .iter()
            .enumerate()
            .try_fold(0u64, |total, (index, input)| {
                total
                    .checked_add(input.value)
                    .ok_or(ParseTransactionError::InputValueOverflow { index })
            })
    }

    /// Calculate total output value and spend amount from transaction outputs and parsed outputs
    ///
    /// # Returns
    /// - `Ok((total_value, spend_amount))` with total output value and external spend amount
    /// - `Err(ParseTransactionError)` if overflow occurs
    fn sum_output_values(
        tx_outputs: &[miniscript::bitcoin::TxOut],
        parsed_outputs: &[ParsedOutput],
    ) -> Result<(u64, u64), ParseTransactionError> {
        tx_outputs
            .iter()
            .zip(parsed_outputs.iter())
            .enumerate()
            .try_fold(
                (0u64, 0u64),
                |(total_value, spend), (index, (tx_output, parsed_output))| {
                    let new_total = total_value
                        .checked_add(tx_output.value.to_sat())
                        .ok_or(ParseTransactionError::OutputValueOverflow { index })?;

                    let new_spend = if parsed_output.is_external() {
                        spend
                            .checked_add(tx_output.value.to_sat())
                            .ok_or(ParseTransactionError::SpendAmountOverflow { index })?
                    } else {
                        spend
                    };

                    Ok((new_total, new_spend))
                },
            )
    }

    /// Helper function to extract public key from a P2PK redeem script
    ///
    /// # Arguments
    /// - `redeem_script`: The redeem script to parse (expected format: <pubkey> OP_CHECKSIG)
    ///
    /// # Returns
    /// - `Ok(PublicKey)` if parsing succeeds
    /// - `Err(String)` if the script format is invalid
    fn extract_pubkey_from_p2pk_redeem_script(
        redeem_script: &miniscript::bitcoin::ScriptBuf,
    ) -> Result<miniscript::bitcoin::PublicKey, String> {
        use miniscript::bitcoin::{opcodes::all::OP_CHECKSIG, script::Instruction, PublicKey};

        // Extract public key from redeem script
        // For P2SH(P2PK), redeem_script is: <pubkey> OP_CHECKSIG
        let mut redeem_instructions = redeem_script.instructions();
        let public_key_bytes = match redeem_instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes(),
            _ => return Err("Invalid redeem script format: missing public key".to_string()),
        };

        // Verify the script ends with OP_CHECKSIG
        match redeem_instructions.next() {
            Some(Ok(Instruction::Op(op))) if op == OP_CHECKSIG => {}
            _ => return Err("Redeem script does not end with OP_CHECKSIG".to_string()),
        }

        PublicKey::from_slice(public_key_bytes).map_err(|e| format!("Invalid public key: {}", e))
    }

    /// Helper function to parse an ECDSA signature from final_script_sig
    ///
    /// # Returns
    /// - `Ok(bitcoin::ecdsa::Signature)` if parsing succeeds
    /// - `Err(String)` if parsing fails
    fn parse_signature_from_script_sig(
        final_script_sig: &miniscript::bitcoin::ScriptBuf,
    ) -> Result<miniscript::bitcoin::ecdsa::Signature, String> {
        use miniscript::bitcoin::{ecdsa::Signature, script::Instruction};

        // Extract signature from final_script_sig
        // For P2SH(P2PK), the scriptSig is: <signature> <redeemScript>
        let mut instructions = final_script_sig.instructions();
        let signature_bytes = match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes(),
            _ => return Err("Invalid final_script_sig format".to_string()),
        };

        if signature_bytes.is_empty() {
            return Err("Empty signature in final_script_sig".to_string());
        }

        Signature::from_slice(signature_bytes)
            .map_err(|e| format!("Invalid signature in final_script_sig: {}", e))
    }

    /// Sign a P2SH-P2PK (replay protection) input with the appropriate sighash algorithm.
    ///
    /// This computes the correct sighash based on network type:
    /// - FORKID networks (BCH, BTG, etc.): BIP143-style with SIGHASH_FORKID
    /// - Standard networks (BTC, LTC, etc.): Legacy P2SH sighash
    ///
    /// # Arguments
    /// - `psbt`: The PSBT containing the input to sign
    /// - `input_index`: Index of the input to sign
    /// - `redeem_script`: The P2PK redeem script
    /// - `privkey`: The private key to sign with
    /// - `network`: The network to determine sighash algorithm
    ///
    /// # Returns
    /// - `Ok(EcdsaSignature)` containing the signature and sighash type
    /// - `Err(String)` if sighash computation fails
    fn sign_p2sh_p2pk_input<C: secp256k1::Signing>(
        psbt: &Psbt,
        input_index: usize,
        redeem_script: &miniscript::bitcoin::ScriptBuf,
        privkey: &secp256k1::SecretKey,
        network: Network,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<miniscript::bitcoin::ecdsa::Signature, String> {
        use miniscript::bitcoin::{
            ecdsa::Signature as EcdsaSignature, hashes::Hash, sighash::SighashCache,
        };

        // Get input value for sighash computation
        let input = &psbt.inputs[input_index];
        let prevout = psbt.unsigned_tx.input[input_index].previous_output;
        let value = psbt_wallet_input::get_output_script_and_value(input, prevout)
            .map(|(_, v)| v)
            .unwrap_or(miniscript::bitcoin::Amount::ZERO);

        let fork_id = sighash::get_sighash_fork_id(network);

        // Compute sighash based on network type
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let (message, sighash_type) = if let Some(fork_id) = fork_id {
            // BCH-style BIP143 sighash with FORKID
            // SIGHASH_ALL | SIGHASH_FORKID = 0x01 | 0x40 = 0x41
            let sighash_type = 0x41u32;
            let sighash = cache
                .p2wsh_signature_hash_forkid(
                    input_index,
                    redeem_script,
                    value,
                    sighash_type,
                    Some(fork_id),
                )
                .map_err(|e| format!("Failed to compute FORKID sighash: {}", e))?;
            (
                secp256k1::Message::from_digest(sighash.to_byte_array()),
                sighash_type,
            )
        } else {
            // Legacy P2SH sighash for standard Bitcoin
            let sighash_type = miniscript::bitcoin::sighash::EcdsaSighashType::All;
            let sighash = cache
                .legacy_signature_hash(input_index, redeem_script, sighash_type.to_u32())
                .map_err(|e| format!("Failed to compute sighash: {}", e))?;
            (
                secp256k1::Message::from_digest(sighash.to_byte_array()),
                sighash_type.to_u32(),
            )
        };

        // Create ECDSA signature
        let signature = secp.sign_ecdsa(&message, privkey);
        Ok(EcdsaSignature {
            signature,
            sighash_type,
        })
    }

    /// Sign a P2SH-P2PK (replay protection) input using Zcash ZIP-243 sighash.
    ///
    /// # Arguments
    /// - `psbt`: The PSBT containing the input to sign
    /// - `input_index`: Index of the input to sign
    /// - `redeem_script`: The P2PK redeem script
    /// - `privkey`: The private key to sign with
    /// - `branch_id`: Zcash consensus branch ID
    /// - `version_group_id`: Zcash version group ID
    /// - `expiry_height`: Zcash transaction expiry height
    ///
    /// # Returns
    /// - `Ok(EcdsaSignature)` containing the signature and sighash type
    /// - `Err(String)` if sighash computation fails
    fn sign_p2sh_p2pk_input_zcash<C: secp256k1::Signing>(
        psbt: &Psbt,
        input_index: usize,
        redeem_script: &miniscript::bitcoin::ScriptBuf,
        privkey: &secp256k1::SecretKey,
        branch_id: u32,
        version_group_id: u32,
        expiry_height: u32,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<miniscript::bitcoin::ecdsa::Signature, String> {
        use miniscript::bitcoin::{
            ecdsa::Signature as EcdsaSignature, sighash::SighashCache,
            sighash::SighashCacheZcashExt,
        };

        // Get input value for sighash computation
        let input = &psbt.inputs[input_index];
        let prevout = psbt.unsigned_tx.input[input_index].previous_output;
        let value = psbt_wallet_input::get_output_script_and_value(input, prevout)
            .map(|(_, v)| v)
            .unwrap_or(miniscript::bitcoin::Amount::ZERO);

        // Compute ZIP-243 sighash
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let sighash_type = 0x01u32; // SIGHASH_ALL for Zcash
        let sighash = cache
            .p2sh_signature_hash_zcash(
                input_index,
                redeem_script,
                value,
                sighash_type,
                branch_id,
                version_group_id,
                expiry_height,
            )
            .map_err(|e| format!("Failed to compute Zcash sighash: {}", e))?;

        let message = secp256k1::Message::from_digest(sighash.to_byte_array());

        // Create ECDSA signature
        let signature = secp.sign_ecdsa(&message, privkey);
        Ok(EcdsaSignature {
            signature,
            sighash_type,
        })
    }

    /// Verify if a replay protection input has a valid signature
    ///
    /// This method checks if a given input is a replay protection input and verifies the signature.
    /// Replay protection inputs (like P2shP2pk) don't use standard derivation paths,
    /// so this method verifies signatures without deriving from xpub.
    ///
    /// For P2PK replay protection inputs:
    /// - Extracts public key from `redeem_script`
    /// - Checks for signature in `partial_sigs` (non-finalized) or `final_script_sig` (finalized)
    /// - Computes the legacy P2SH sighash using the redeem script
    /// - Verifies the ECDSA signature
    ///
    /// # Arguments
    /// - `secp`: Secp256k1 context for signature verification
    /// - `input_index`: The index of the input to check
    /// - `replay_protection`: Replay protection configuration
    ///
    /// # Returns
    /// - `Ok(true)` if the input is a replay protection input and has a valid signature
    /// - `Ok(false)` if the input is a replay protection input but has no valid signature
    /// - `Err(String)` if the input is not a replay protection input, index is out of bounds, or verification fails
    pub fn verify_replay_protection_signature<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
        replay_protection: &crate::fixed_script_wallet::ReplayProtection,
    ) -> Result<bool, String> {
        use miniscript::bitcoin::{hashes::Hash, sighash::SighashCache};

        let psbt = self.psbt();
        let network = self.network();

        // Check input index bounds
        if input_index >= psbt.inputs.len() {
            return Err(format!("Input index {} out of bounds", input_index));
        }

        let input = &psbt.inputs[input_index];
        let prevout = psbt.unsigned_tx.input[input_index].previous_output;

        // Get output script and value from input
        let (output_script, value) = psbt_wallet_input::get_output_script_and_value(input, prevout)
            .map_err(|e| format!("Failed to get output script: {}", e))?;

        // Verify this is a replay protection input
        if !replay_protection.is_replay_protection_input(output_script) {
            return Err(format!(
                "Input {} is not a replay protection input",
                input_index
            ));
        }

        // Get redeem script and extract public key
        let redeem_script = input
            .redeem_script
            .as_ref()
            .ok_or_else(|| "Missing redeem_script for replay protection input".to_string())?;
        let public_key = Self::extract_pubkey_from_p2pk_redeem_script(redeem_script)?;

        // Get signature from partial_sigs (non-finalized) or final_script_sig (finalized)
        // The bitcoin crate's ecdsa::Signature type contains both .signature and .sighash_type
        let ecdsa_sig = if let Some(&partial_sig) = input.partial_sigs.get(&public_key) {
            partial_sig
        } else if let Some(final_script_sig) = &input.final_script_sig {
            Self::parse_signature_from_script_sig(final_script_sig)?
        } else {
            // No signature present (neither partial nor final)
            return Ok(false);
        };

        // Compute sighash based on network type
        let mut cache = SighashCache::new(&psbt.unsigned_tx);

        // Handle Zcash specially - use ZIP-243 sighash
        if let BitGoPsbt::Zcash(zcash_psbt, _) = self {
            use miniscript::bitcoin::sighash::SighashCacheZcashExt;

            let branch_id = propkv::get_zec_consensus_branch_id(&zcash_psbt.psbt)
                .ok_or("Missing ZecConsensusBranchId in PSBT")?;
            let version_group_id = zcash_psbt
                .version_group_id
                .unwrap_or(zcash_psbt::ZCASH_SAPLING_VERSION_GROUP_ID);
            let expiry_height = zcash_psbt.expiry_height.unwrap_or(0);

            let sighash = cache
                .p2sh_signature_hash_zcash(
                    input_index,
                    redeem_script,
                    value,
                    ecdsa_sig.sighash_type as u32,
                    branch_id,
                    version_group_id,
                    expiry_height,
                )
                .map_err(|e| format!("Failed to compute Zcash sighash: {}", e))?;

            let message = secp256k1::Message::from_digest(sighash.to_byte_array());
            return match secp.verify_ecdsa(&message, &ecdsa_sig.signature, &public_key.inner) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            };
        }

        let fork_id = sighash::get_sighash_fork_id(network);

        let message = if let Some(fork_id) = fork_id {
            // BCH-style BIP143 sighash with FORKID
            // Use p2wsh_signature_hash_forkid which handles the forkid encoding
            let sighash = cache
                .p2wsh_signature_hash_forkid(
                    input_index,
                    redeem_script,
                    value,
                    ecdsa_sig.sighash_type as u32,
                    Some(fork_id),
                )
                .map_err(|e| format!("Failed to compute FORKID sighash: {}", e))?;
            secp256k1::Message::from_digest(sighash.to_byte_array())
        } else {
            // Legacy P2SH sighash for standard Bitcoin
            let sighash = cache
                .legacy_signature_hash(input_index, redeem_script, ecdsa_sig.sighash_type)
                .map_err(|e| format!("Failed to compute sighash: {}", e))?;
            secp256k1::Message::from_digest(sighash.to_byte_array())
        };

        // Verify the signature
        match secp.verify_ecdsa(&message, &ecdsa_sig.signature, &public_key.inner) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Helper method to verify signature with a compressed public key
    ///
    /// This method checks if a signature exists for the given public key.
    /// It handles both ECDSA and Taproot script path signatures.
    ///
    /// # Arguments
    /// - `secp`: Secp256k1 context for signature verification
    /// - `input_index`: The index of the input to check
    /// - `public_key`: The compressed public key to verify the signature for
    ///
    /// # Returns
    /// - `Ok(true)` if a valid signature exists for the public key
    /// - `Ok(false)` if no signature exists for the public key
    /// - `Err(String)` if verification fails
    fn verify_signature_with_pubkey<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
        public_key: CompressedPublicKey,
    ) -> Result<bool, String> {
        match self {
            BitGoPsbt::BitcoinLike(psbt, network) => {
                let input = &psbt.inputs[input_index];

                // Check for Taproot script path signatures first
                if !input.tap_script_sigs.is_empty() {
                    return psbt_wallet_input::verify_taproot_script_signature(
                        secp,
                        psbt,
                        input_index,
                        public_key,
                    );
                }

                let fork_id = sighash::get_sighash_fork_id(*network);

                // Fall back to ECDSA signature verification for legacy/SegWit inputs
                psbt_wallet_input::verify_ecdsa_signature(
                    secp,
                    psbt,
                    input_index,
                    public_key,
                    fork_id,
                )
            }
            BitGoPsbt::Zcash(zcash_psbt, _network) => {
                // Use Zcash-specific signature verification with ZIP-243 sighash
                let branch_id = propkv::get_zec_consensus_branch_id(&zcash_psbt.psbt)
                    .ok_or("Missing ZecConsensusBranchId in PSBT")?;
                let version_group_id = zcash_psbt
                    .version_group_id
                    .unwrap_or(zcash_psbt::ZCASH_SAPLING_VERSION_GROUP_ID);
                let expiry_height = zcash_psbt.expiry_height.unwrap_or(0);

                psbt_wallet_input::verify_ecdsa_signature_zcash(
                    secp,
                    &zcash_psbt.psbt,
                    input_index,
                    public_key,
                    branch_id,
                    version_group_id,
                    expiry_height,
                )
            }
        }
    }

    /// Verify if a valid signature exists for a given extended public key at the specified input index
    ///
    /// This method derives the public key from the xpub using the derivation path found in the
    /// PSBT input, then verifies the signature. It supports:
    /// - ECDSA signatures (for legacy/SegWit inputs)
    /// - Schnorr signatures (for Taproot script path inputs)
    /// - MuSig2 partial signatures (for Taproot keypath MuSig2 inputs)
    ///
    /// # Arguments
    /// - `secp`: Secp256k1 context for signature verification and key derivation
    /// - `input_index`: The index of the input to check
    /// - `xpub`: The extended public key to derive from and verify the signature for
    ///
    /// # Returns
    /// - `Ok(true)` if a valid signature exists for the derived public key
    /// - `Ok(false)` if no signature exists for the derived public key
    /// - `Err(String)` if the input index is out of bounds, derivation fails, or verification fails
    pub fn verify_signature_with_xpub<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
        xpub: &miniscript::bitcoin::bip32::Xpub,
    ) -> Result<bool, String> {
        let psbt = self.psbt();

        // Check input index bounds
        if input_index >= psbt.inputs.len() {
            return Err(format!("Input index {} out of bounds", input_index));
        }

        let input = &psbt.inputs[input_index];

        // Handle MuSig2 inputs early - they use proprietary fields for partial signatures
        if p2tr_musig2_input::Musig2Input::is_musig2_input(input) {
            // Parse MuSig2 data from input
            let musig2_input = p2tr_musig2_input::Musig2Input::from_input(input)
                .map_err(|e| format!("Failed to parse MuSig2 input: {}", e))?;

            // Derive the public key for this input using tap_key_origins
            // If this xpub doesn't match any tap_key_origins, return false (e.g., backup key)
            let derived_xpub =
                match p2tr_musig2_input::derive_xpub_for_input_tap(xpub, &input.tap_key_origins) {
                    Ok(xpub) => xpub,
                    Err(_) => return Ok(false), // This xpub doesn't match
                };
            let derived_pubkey = derived_xpub.to_pub();

            // Check if this public key has a partial signature in the MuSig2 proprietary fields
            let has_partial_sig = musig2_input
                .partial_sigs
                .iter()
                .any(|sig| sig.participant_pub_key == derived_pubkey);

            return Ok(has_partial_sig);
        }

        // For non-MuSig2 inputs, use standard derivation
        // Derive the public key from xpub using derivation path in PSBT
        let derived_pubkey = match psbt_wallet_input::derive_pubkey_from_input(secp, xpub, input)? {
            Some(pubkey) => pubkey,
            None => return Ok(false), // No matching derivation path for this xpub
        };

        // Convert to CompressedPublicKey for verification
        let public_key = CompressedPublicKey::from_slice(&derived_pubkey.serialize())
            .map_err(|e| format!("Failed to convert derived key: {}", e))?;

        // Verify signature with the derived public key
        self.verify_signature_with_pubkey(secp, input_index, public_key)
    }

    /// Verify if a valid signature exists for a given public key at the specified input index
    ///
    /// This method verifies the signature directly with the provided public key. It supports:
    /// - ECDSA signatures (for legacy/SegWit inputs)
    /// - Schnorr signatures (for Taproot script path inputs)
    ///
    /// Note: This method does NOT support MuSig2 inputs, as MuSig2 requires derivation from xpubs.
    /// Use `verify_signature_with_xpub` for MuSig2 inputs.
    ///
    /// # Arguments
    /// - `secp`: Secp256k1 context for signature verification
    /// - `input_index`: The index of the input to check
    /// - `pubkey`: The secp256k1 public key
    ///
    /// # Returns
    /// - `Ok(true)` if a valid signature exists for the public key
    /// - `Ok(false)` if no signature exists for the public key
    /// - `Err(String)` if the input index is out of bounds or verification fails
    pub fn verify_signature_with_pub<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
        pubkey: &secp256k1::PublicKey,
    ) -> Result<bool, String> {
        let psbt = self.psbt();

        // Check input index bounds
        if input_index >= psbt.inputs.len() {
            return Err(format!("Input index {} out of bounds", input_index));
        }

        // Convert secp256k1::PublicKey to CompressedPublicKey
        let public_key = CompressedPublicKey::from_slice(&pubkey.serialize())
            .map_err(|e| format!("Failed to convert public key: {}", e))?;

        // Verify signature with the public key
        self.verify_signature_with_pubkey(secp, input_index, public_key)
    }

    /// Parse outputs with wallet keys to identify which outputs belong to a particular wallet.
    ///
    /// This is useful in cases where we want to identify outputs that belong to a different
    /// wallet than the inputs.
    ///
    /// If you only want to identify change outputs, use `parse_transaction_with_wallet_keys` instead.
    ///
    /// # Arguments
    /// - `wallet_keys`: A wallet's root keys for deriving scripts (can be different wallet than the inputs)
    /// - `paygo_pubkeys`: Public keys for PayGo attestation verification (empty slice to skip verification)
    ///
    /// # Returns
    /// - `Ok(Vec<ParsedOutput>)` with parsed outputs
    /// - `Err(ParseTransactionError)` if output parsing fails
    ///
    /// # Note
    /// This method does NOT validate wallet inputs. It only parses outputs to identify
    /// which ones belong to the provided wallet keys.
    pub fn parse_outputs_with_wallet_keys(
        &self,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        paygo_pubkeys: &[secp256k1::PublicKey],
    ) -> Result<Vec<ParsedOutput>, ParseTransactionError> {
        self.parse_outputs(wallet_keys, paygo_pubkeys)
    }

    /// Parse transaction with wallet keys to identify wallet inputs/outputs and calculate metrics
    ///
    /// # Arguments
    /// - `wallet_keys`: The wallet's root keys for deriving scripts
    /// - `replay_protection`: Scripts that are allowed as inputs without wallet validation
    /// - `paygo_pubkeys`: Public keys for PayGo attestation verification (empty slice to skip verification)
    ///
    /// # Returns
    /// - `Ok(ParsedTransaction)` with parsed inputs, outputs, spend amount, fee, and size
    /// - `Err(ParseTransactionError)` if input validation fails or required data is missing
    pub fn parse_transaction_with_wallet_keys(
        &self,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        replay_protection: &crate::fixed_script_wallet::ReplayProtection,
        paygo_pubkeys: &[secp256k1::PublicKey],
    ) -> Result<ParsedTransaction, ParseTransactionError> {
        let psbt = self.psbt();

        // Parse inputs and outputs
        let parsed_inputs = self.parse_inputs(wallet_keys, replay_protection)?;
        let parsed_outputs = self.parse_outputs(wallet_keys, paygo_pubkeys)?;

        // Calculate totals
        let total_input_value = Self::sum_input_values(&parsed_inputs)?;
        let (total_output_value, spend_amount) =
            Self::sum_output_values(&psbt.unsigned_tx.output, &parsed_outputs)?;

        // Calculate miner fee
        let miner_fee = total_input_value
            .checked_sub(total_output_value)
            .ok_or(ParseTransactionError::FeeCalculation)?;

        // Calculate virtual size from unsigned transaction weight
        // TODO: Consider using finalized transaction size estimate for more accurate fee calculation
        let weight = psbt.unsigned_tx.weight();
        let virtual_size = weight.to_vbytes_ceil();

        Ok(ParsedTransaction {
            inputs: parsed_inputs,
            outputs: parsed_outputs,
            spend_amount,
            miner_fee,
            virtual_size: virtual_size as u32,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_script_wallet::Chain;
    use crate::fixed_script_wallet::RootWalletKeys;
    use crate::fixed_script_wallet::WalletScripts;
    use crate::test_utils::fixtures;
    use crate::test_utils::fixtures::assert_hex_eq;
    use base64::engine::{general_purpose::STANDARD as BASE64_STANDARD, Engine};
    use miniscript::bitcoin::consensus::Decodable;
    use miniscript::bitcoin::Transaction;

    use std::str::FromStr;

    crate::test_all_networks!(test_deserialize_invalid_bytes, network, {
        // Invalid PSBT bytes should fail with either consensus, PSBT, or network error
        let result = BitGoPsbt::deserialize(&[0x00], network);
        assert!(
            matches!(
                result,
                Err(DeserializeError::Consensus(_)
                    | DeserializeError::Psbt(_)
                    | DeserializeError::Network(_))
            ),
            "Expected error for network {:?}, got {:?}",
            network,
            result
        );
    });

    fn test_parse_with_format(format: fixtures::TxFormat, network: Network) {
        let fixture = fixtures::load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            fixtures::SignatureState::Unsigned,
            format,
        )
        .unwrap();
        match fixture.to_bitgo_psbt(network) {
            Ok(_) => {}
            Err(e) => panic!("Failed on network: {:?} with error: {:?}", network, e),
        }
    }

    crate::test_psbt_fixtures!(test_parse_network_mainnet_only, network, format, {
        test_parse_with_format(format, network);
    });

    #[test]
    fn test_zcash_deserialize_error() {
        // Invalid bytes should return an error (not panic)
        let result = BitGoPsbt::deserialize(&[0x00], Network::Zcash);
        assert!(result.is_err());
    }

    #[test]
    fn test_zcash_testnet_deserialize_error() {
        // Invalid bytes should return an error (not panic)
        let result = BitGoPsbt::deserialize(&[0x00], Network::ZcashTestnet);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_zcash_at_height_mainnet() {
        use crate::fixed_script_wallet::test_utils::get_test_wallet_keys;
        use crate::zcash::NetworkUpgrade;

        let keys = RootWalletKeys::new(get_test_wallet_keys("test_zcash_at_height"));

        // Test with Nu5 activation height (mainnet)
        let nu5_height = NetworkUpgrade::Nu5.mainnet_activation_height();
        let result = BitGoPsbt::new_zcash_at_height(
            Network::Zcash,
            &keys,
            nu5_height,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_ok(), "Should succeed for Nu5 height");
        let psbt = result.unwrap();
        // Verify it's a Zcash PSBT
        assert!(matches!(psbt, BitGoPsbt::Zcash(_, Network::Zcash)));

        // Test with Nu6 activation height
        let nu6_height = NetworkUpgrade::Nu6.mainnet_activation_height();
        let result = BitGoPsbt::new_zcash_at_height(
            Network::Zcash,
            &keys,
            nu6_height,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_ok(), "Should succeed for Nu6 height");

        // Test with pre-Overwinter height (should fail)
        let pre_overwinter_height = NetworkUpgrade::Overwinter.mainnet_activation_height() - 1;
        let result = BitGoPsbt::new_zcash_at_height(
            Network::Zcash,
            &keys,
            pre_overwinter_height,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_err(), "Should fail for pre-Overwinter height");
        assert!(
            result.unwrap_err().contains("before Overwinter activation"),
            "Error message should mention Overwinter"
        );
    }

    #[test]
    fn test_new_zcash_at_height_testnet() {
        use crate::fixed_script_wallet::test_utils::get_test_wallet_keys;
        use crate::zcash::NetworkUpgrade;

        let keys = RootWalletKeys::new(get_test_wallet_keys("test_zcash_at_height"));

        // Test with Nu5 activation height (testnet)
        let nu5_height = NetworkUpgrade::Nu5.testnet_activation_height();
        let result = BitGoPsbt::new_zcash_at_height(
            Network::ZcashTestnet,
            &keys,
            nu5_height,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_ok(), "Should succeed for Nu5 height on testnet");
        let psbt = result.unwrap();
        // Verify it's a Zcash testnet PSBT
        assert!(matches!(psbt, BitGoPsbt::Zcash(_, Network::ZcashTestnet)));

        // Test with pre-Overwinter height (should fail)
        let pre_overwinter_height = NetworkUpgrade::Overwinter.testnet_activation_height() - 1;
        let result = BitGoPsbt::new_zcash_at_height(
            Network::ZcashTestnet,
            &keys,
            pre_overwinter_height,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_err(), "Should fail for pre-Overwinter height");
        assert!(
            result.unwrap_err().contains("testnet"),
            "Error message should mention testnet"
        );
    }

    fn test_round_trip_with_format(format: fixtures::TxFormat, network: Network) {
        let fixture = fixtures::load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            fixtures::SignatureState::Unsigned,
            format,
        )
        .unwrap();

        // Deserialize from fixture
        let original_bytes = BASE64_STANDARD
            .decode(&fixture.psbt_base64)
            .expect("Failed to decode base64");
        let psbt =
            BitGoPsbt::deserialize(&original_bytes, network).expect("Failed to deserialize PSBT");

        // Serialize back
        let serialized = psbt.serialize().expect("Failed to serialize PSBT");

        // Deserialize again
        let round_trip =
            BitGoPsbt::deserialize(&serialized, network).expect("Failed to deserialize round-trip");

        // Verify the data matches by comparing the underlying PSBTs
        match (&psbt, &round_trip) {
            (BitGoPsbt::BitcoinLike(psbt1, net1), BitGoPsbt::BitcoinLike(psbt2, net2)) => {
                assert_eq!(net1, net2, "Networks should match");
                assert_eq!(psbt1, psbt2);
            }
            (BitGoPsbt::Zcash(zpsbt1, net1), BitGoPsbt::Zcash(zpsbt2, net2)) => {
                assert_eq!(net1, net2, "Networks should match");
                assert_eq!(zpsbt1, zpsbt2);
            }
            _ => panic!(
                "PSBT type mismatch after round-trip: {:?} vs {:?}",
                psbt, round_trip
            ),
        }
    }

    crate::test_psbt_fixtures!(test_round_trip_mainnet_only, network, format, {
        test_round_trip_with_format(format, network);
    });

    fn parse_derivation_path(path: &str) -> Result<(u32, u32), String> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != 4 {
            return Err(format!("Invalid path length: {}", path));
        }
        let chain = u32::from_str(parts[2]).map_err(|e| e.to_string())?;
        let index = u32::from_str(parts[3]).map_err(|e| e.to_string())?;
        Ok((chain, index))
    }

    fn parse_fixture_paths(
        fixture_input: &fixtures::PsbtInputFixture,
    ) -> Result<(Chain, u32), String> {
        let bip32_path = match fixture_input {
            fixtures::PsbtInputFixture::P2sh(i) => i.bip32_derivation[0].path.to_string(),
            fixtures::PsbtInputFixture::P2shP2pk(_) => {
                // P2shP2pk doesn't have derivation paths in the fixture, use a dummy path
                return Err("P2shP2pk does not use chain-based derivation".to_string());
            }
            fixtures::PsbtInputFixture::P2shP2wsh(i) => i.bip32_derivation[0].path.to_string(),
            fixtures::PsbtInputFixture::P2wsh(i) => i.bip32_derivation[0].path.to_string(),
            fixtures::PsbtInputFixture::P2trLegacy(i) => i.tap_bip32_derivation[0].path.to_string(),
            fixtures::PsbtInputFixture::P2trMusig2ScriptPath(i) => {
                i.tap_bip32_derivation[0].path.to_string()
            }
            fixtures::PsbtInputFixture::P2trMusig2KeyPath(i) => {
                i.tap_bip32_derivation[0].path.to_string()
            }
        };
        let (chain_num, index) = parse_derivation_path(&bip32_path).expect("Failed to parse path");
        let chain = Chain::try_from(chain_num).expect("Invalid chain");
        Ok((chain, index))
    }

    fn get_output_script_from_non_witness_utxo(
        input: &fixtures::P2shInput,
        index: usize,
    ) -> String {
        use miniscript::bitcoin::hashes::hex::FromHex;
        let tx_bytes = Vec::<u8>::from_hex(
            input
                .non_witness_utxo
                .as_ref()
                .expect("expected non-witness utxo for legacy inputs"),
        )
        .expect("Failed to decode hex");
        let prev_tx: Transaction = Decodable::consensus_decode(&mut tx_bytes.as_slice())
            .expect("Failed to decode non-witness utxo");
        let output = &prev_tx.output[index];
        output.script_pubkey.to_hex_string()
    }

    type PartialSignatures =
        std::collections::BTreeMap<crate::bitcoin::PublicKey, crate::bitcoin::ecdsa::Signature>;

    fn assert_eq_partial_signatures(
        actual: &PartialSignatures,
        expected: &PartialSignatures,
    ) -> Result<(), String> {
        assert_eq!(
            actual.len(),
            expected.len(),
            "Partial signatures should match"
        );
        for (actual_sig, expected_sig) in actual.iter().zip(expected.iter()) {
            assert_eq!(actual_sig.0, expected_sig.0, "Public key should match");
            assert_hex_eq(
                &hex::encode(actual_sig.1.serialize()),
                &hex::encode(expected_sig.1.serialize()),
                "Signature",
            )?;
        }
        Ok(())
    }

    // ensure we can put the first signature (user signature) on an unsigned PSBT
    fn assert_half_sign(
        script_type: fixtures::ScriptType,
        unsigned_bitgo_psbt: &BitGoPsbt,
        halfsigned_bitgo_psbt: &BitGoPsbt,
        xpriv_triple: &fixtures::XprvTriple,
        input_index: usize,
    ) -> Result<(), String> {
        let user_xpriv = xpriv_triple.user_key();

        // Clone the unsigned PSBT and sign with user key
        let mut unsigned_bitgo_psbt = unsigned_bitgo_psbt.clone();
        let secp = secp256k1::Secp256k1::new();

        if script_type == fixtures::ScriptType::P2trMusig2TaprootKeypath {
            // MuSig2 keypath: set nonces and sign with user key
            p2tr_musig2_input::assert_set_nonce_and_sign_musig2_keypath(
                xpriv_triple,
                &mut unsigned_bitgo_psbt,
                halfsigned_bitgo_psbt,
                input_index,
            )?;

            // MuSig2 inputs use proprietary key values for partial signatures,
            // not standard PSBT partial_sigs, so we're done
            return Ok(());
        }

        // Sign with user key using the new sign method
        unsigned_bitgo_psbt
            .sign(user_xpriv, &secp)
            .map_err(|(_num_keys, errors)| format!("Failed to sign PSBT: {:?}", errors))?;

        // Extract partial signatures from the signed input
        let signed_input = match &unsigned_bitgo_psbt {
            BitGoPsbt::BitcoinLike(psbt, _) => &psbt.inputs[input_index],
            BitGoPsbt::Zcash(zcash_psbt, _) => &zcash_psbt.psbt.inputs[input_index],
        };

        match script_type {
            fixtures::ScriptType::P2shP2pk => {
                // In production, these will be signed by BitGo
                assert_eq!(signed_input.partial_sigs.len(), 0);
            }
            fixtures::ScriptType::P2trLegacyScriptPath
            | fixtures::ScriptType::P2trMusig2ScriptPath => {
                assert_eq!(signed_input.tap_script_sigs.len(), 1);
                // Get expected tap script sig from halfsigned fixture
                let expected_tap_script_sig = halfsigned_bitgo_psbt.clone().into_psbt().inputs
                    [input_index]
                    .tap_script_sigs
                    .clone();
                assert_eq!(signed_input.tap_script_sigs, expected_tap_script_sig);
            }
            _ => {
                let actual_partial_sigs = signed_input.partial_sigs.clone();
                // Get expected partial signatures from halfsigned fixture
                let expected_partial_sigs = halfsigned_bitgo_psbt.clone().into_psbt().inputs
                    [input_index]
                    .partial_sigs
                    .clone();

                assert_eq!(actual_partial_sigs.len(), 1);
                assert_eq_partial_signatures(&actual_partial_sigs, &expected_partial_sigs)?;
            }
        }

        Ok(())
    }

    fn assert_full_signed_matches_wallet_scripts(
        network: Network,
        tx_format: fixtures::TxFormat,
        fixture: &fixtures::PsbtFixture,
        wallet_keys: &fixtures::XprvTriple,
        input_index: usize,
        input_fixture: &fixtures::PsbtInputFixture,
    ) -> Result<(), String> {
        let (chain, index) =
            parse_fixture_paths(input_fixture).expect("Failed to parse fixture paths");
        let scripts = WalletScripts::from_wallet_keys(
            &wallet_keys.to_root_wallet_keys(),
            chain,
            index,
            &network.output_script_support(),
        )
        .expect("Failed to create wallet scripts");

        // Use the new helper methods for validation
        match (scripts, input_fixture) {
            (WalletScripts::P2sh(scripts), fixtures::PsbtInputFixture::P2sh(fixture_input)) => {
                let vout = fixture.inputs[input_index].index as usize;
                let output_script =
                    if tx_format == fixtures::TxFormat::PsbtLite || network == Network::Zcash {
                        // Zcash only supports PSBT-lite
                        fixture_input
                            .witness_utxo
                            .as_ref()
                            .expect("expected witness utxo for zcash")
                            .script
                            .clone()
                    } else {
                        get_output_script_from_non_witness_utxo(fixture_input, vout)
                    };
                fixture_input
                    .assert_matches_wallet_scripts(&scripts, &output_script, network)
                    .expect("P2sh validation failed");
            }
            (
                WalletScripts::P2shP2wsh(scripts),
                fixtures::PsbtInputFixture::P2shP2wsh(fixture_input),
            ) => {
                fixture_input
                    .assert_matches_wallet_scripts(
                        &scripts,
                        &fixture_input.witness_utxo.script,
                        network,
                    )
                    .expect("P2shP2wsh validation failed");
            }
            (WalletScripts::P2wsh(scripts), fixtures::PsbtInputFixture::P2wsh(fixture_input)) => {
                fixture_input
                    .assert_matches_wallet_scripts(
                        &scripts,
                        &fixture_input.witness_utxo.script,
                        network,
                    )
                    .expect("P2wsh validation failed");
            }
            (
                WalletScripts::P2trLegacy(scripts),
                fixtures::PsbtInputFixture::P2trLegacy(fixture_input),
            ) => {
                fixture_input
                    .assert_matches_wallet_scripts(&scripts, network)
                    .expect("P2trLegacy validation failed");
            }
            (
                WalletScripts::P2trMusig2(scripts),
                fixtures::PsbtInputFixture::P2trMusig2ScriptPath(fixture_input),
            ) => {
                fixture_input
                    .assert_matches_wallet_scripts(&scripts, network)
                    .expect("P2trMusig2ScriptPath validation failed");
            }
            (
                WalletScripts::P2trMusig2(scripts),
                fixtures::PsbtInputFixture::P2trMusig2KeyPath(fixture_input),
            ) => {
                fixture_input
                    .assert_matches_wallet_scripts(&scripts, network)
                    .expect("P2trMusig2KeyPath validation failed");
            }
            (scripts, input_fixture) => {
                return Err(format!(
                    "Mismatched input and scripts: {:?} and {:?}",
                    scripts, input_fixture
                ));
            }
        }
        Ok(())
    }

    fn assert_finalize_input(
        mut bitgo_psbt: BitGoPsbt,
        input_index: usize,
        _network: Network,
        _tx_format: fixtures::TxFormat,
    ) -> Result<(), String> {
        let secp = crate::bitcoin::secp256k1::Secp256k1::new();
        bitgo_psbt
            .finalize_input(&secp, input_index)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn assert_replay_protection_signature(
        bitgo_psbt: &BitGoPsbt,
        _wallet_keys: &fixtures::XprvTriple,
        input_index: usize,
    ) -> Result<(), String> {
        let secp = secp256k1::Secp256k1::new();
        let psbt = bitgo_psbt.psbt();

        if input_index >= psbt.inputs.len() {
            return Err(format!("Input index {} out of bounds", input_index));
        }

        let input = &psbt.inputs[input_index];
        let prevout = psbt.unsigned_tx.input[input_index].previous_output;

        // Get the output script from the input
        let (output_script, _value) =
            psbt_wallet_input::get_output_script_and_value(input, prevout)
                .map_err(|e| format!("Failed to get output script: {}", e))?;

        // Create replay protection with this output script
        let replay_protection =
            crate::fixed_script_wallet::ReplayProtection::new(vec![output_script.clone()]);

        // Verify the signature exists and is valid
        let has_valid_signature = bitgo_psbt.verify_replay_protection_signature(
            &secp,
            input_index,
            &replay_protection,
        )?;

        if !has_valid_signature {
            return Err(format!(
                "Replay protection input {} does not have a valid signature",
                input_index
            ));
        }

        Ok(())
    }

    /// Test that sign_with_privkey → verify_replay_protection_signature roundtrip works.
    ///
    /// This test guards against sighash algorithm mismatches between signing and verification.
    /// Specifically, it catches the bug where sign_with_privkey used legacy_signature_hash
    /// for all networks, but verify_replay_protection_signature used p2wsh_signature_hash_forkid
    /// for BCH-like networks (BitcoinCash, BitcoinGold, Ecash).
    fn assert_p2shp2pk_sign_verify_roundtrip(
        unsigned_fixture: &fixtures::PsbtFixture,
        wallet_keys: &fixtures::XprvTriple,
        input_index: usize,
        network: Network,
    ) -> Result<(), String> {
        // Get the xpriv for signing (user key)
        let xpriv = wallet_keys.user_key();
        let privkey = xpriv.private_key;

        // Deserialize the unsigned PSBT
        let original_bytes = BASE64_STANDARD
            .decode(&unsigned_fixture.psbt_base64)
            .map_err(|e| format!("Failed to decode base64: {}", e))?;
        let mut psbt = BitGoPsbt::deserialize(&original_bytes, network)
            .map_err(|e| format!("Failed to deserialize PSBT: {:?}", e))?;

        // Sign the p2shP2pk input
        psbt.sign_with_privkey(input_index, &privkey)
            .map_err(|e| format!("Failed to sign p2shP2pk input: {}", e))?;

        // Get the output script for replay protection verification
        let psbt_ref = psbt.psbt();
        let input = &psbt_ref.inputs[input_index];
        let prevout = psbt_ref.unsigned_tx.input[input_index].previous_output;
        let (output_script, _value) =
            psbt_wallet_input::get_output_script_and_value(input, prevout)
                .map_err(|e| format!("Failed to get output script: {}", e))?;

        let replay_protection =
            crate::fixed_script_wallet::ReplayProtection::new(vec![output_script.clone()]);

        // Verify the signature
        let secp = secp256k1::Secp256k1::new();
        let has_valid_signature = psbt
            .verify_replay_protection_signature(&secp, input_index, &replay_protection)
            .map_err(|e| format!("Failed to verify signature: {}", e))?;

        if !has_valid_signature {
            return Err(format!(
                "p2shP2pk sign→verify roundtrip failed for {:?}. \
                 This indicates a sighash mismatch between sign_with_privkey and \
                 verify_replay_protection_signature (e.g., SIGHASH_FORKID handling).",
                network
            ));
        }

        Ok(())
    }

    fn assert_signature_count(
        bitgo_psbt: &BitGoPsbt,
        wallet_keys: &RootWalletKeys,
        input_index: usize,
        expected_count: usize,
        stage_name: &str,
    ) -> Result<(), String> {
        // Use verify_signature_with_xpub to count valid signatures for all input types
        // This now handles MuSig2, ECDSA, and Schnorr signatures uniformly
        let secp = secp256k1::Secp256k1::new();
        let mut signature_count = 0;
        for xpub in &wallet_keys.xpubs {
            match bitgo_psbt.verify_signature_with_xpub(&secp, input_index, xpub) {
                Ok(true) => signature_count += 1,
                Ok(false) => {}          // No signature for this key
                Err(e) => return Err(e), // Propagate other errors
            }
        }

        if signature_count != expected_count {
            return Err(format!(
                "{} input {} should have {} signature(s), found {}",
                stage_name, input_index, expected_count, signature_count
            ));
        }

        Ok(())
    }

    fn test_wallet_script_type(
        script_type: fixtures::ScriptType,
        network: Network,
        tx_format: fixtures::TxFormat,
    ) -> Result<(), String> {
        let psbt_stages = fixtures::PsbtStages::load(network, tx_format)?;
        let psbt_input_stages =
            fixtures::PsbtInputStages::from_psbt_stages(&psbt_stages, script_type);

        // Check if the script type is supported by the network
        let output_script_support = network.output_script_support();
        if !script_type.is_supported_by(&output_script_support) {
            // Script type not supported by network - skip test (no fixture expected)
            assert!(
                psbt_input_stages.is_err(),
                "Expected error for unsupported script type"
            );
            return Ok(());
        }

        let psbt_input_stages = psbt_input_stages.unwrap();

        let halfsigned_bitgo_psbt = psbt_stages
            .halfsigned
            .to_bitgo_psbt(network)
            .expect("Failed to convert to BitGo PSBT");

        let fullsigned_bitgo_psbt = psbt_stages
            .fullsigned
            .to_bitgo_psbt(network)
            .expect("Failed to convert to BitGo PSBT");

        assert_half_sign(
            script_type,
            &psbt_stages
                .unsigned
                .to_bitgo_psbt(network)
                .expect("Failed to convert to BitGo PSBT"),
            &halfsigned_bitgo_psbt,
            &psbt_input_stages.wallet_keys,
            psbt_input_stages.input_index,
        )?;

        let wallet_keys = psbt_input_stages.wallet_keys.to_root_wallet_keys();

        // Verify halfsigned PSBT has exactly 1 signature
        assert_signature_count(
            &halfsigned_bitgo_psbt,
            &wallet_keys,
            psbt_input_stages.input_index,
            if matches!(script_type, fixtures::ScriptType::P2shP2pk) {
                // p2shP2pk inputs are signed at the halfsigned stage with replay protection
                0
            } else {
                1
            },
            "Halfsigned",
        )?;

        if matches!(script_type, fixtures::ScriptType::P2shP2pk) {
            // Replay protection inputs are signed at the halfsigned stage
            assert_replay_protection_signature(
                &halfsigned_bitgo_psbt,
                &psbt_input_stages.wallet_keys,
                psbt_input_stages.input_index,
            )?;
            // They remain signed at the fullsigned stage
            assert_replay_protection_signature(
                &fullsigned_bitgo_psbt,
                &psbt_input_stages.wallet_keys,
                psbt_input_stages.input_index,
            )?;

            // Test sign→verify roundtrip from unsigned state.
            // This verifies that sign_with_privkey uses the correct sighash algorithm:
            // - BCH-like networks (BitcoinCash, BitcoinGold, Ecash): SIGHASH_FORKID | SIGHASH_ALL
            // - Standard networks: SIGHASH_ALL (legacy)
            assert_p2shp2pk_sign_verify_roundtrip(
                &psbt_stages.unsigned,
                &psbt_input_stages.wallet_keys,
                psbt_input_stages.input_index,
                network,
            )?;
        } else {
            assert_full_signed_matches_wallet_scripts(
                network,
                tx_format,
                &psbt_stages.fullsigned,
                &psbt_input_stages.wallet_keys,
                psbt_input_stages.input_index,
                &psbt_input_stages.input_fixture_fullsigned,
            )?;
        }

        // Verify fullsigned PSBT has exactly 2 signatures
        assert_signature_count(
            &fullsigned_bitgo_psbt,
            &wallet_keys,
            psbt_input_stages.input_index,
            if matches!(script_type, fixtures::ScriptType::P2shP2pk) {
                0
            } else {
                2
            },
            "Fullsigned",
        )?;

        assert_finalize_input(
            fullsigned_bitgo_psbt,
            psbt_input_stages.input_index,
            network,
            tx_format,
        )?;

        Ok(())
    }

    // P2SH-P2PK: Zcash now uses ZIP-243 sighash for replay protection signing/verification
    crate::test_psbt_fixtures!(test_p2sh_p2pk_suite, network, format, {
        test_wallet_script_type(fixtures::ScriptType::P2shP2pk, network, format).unwrap();
    });

    // P2SH: Zcash now uses ZIP-243 sighash for signing/verification
    crate::test_psbt_fixtures!(test_p2sh_suite, network, format, {
        test_wallet_script_type(fixtures::ScriptType::P2sh, network, format).unwrap();
    });

    crate::test_psbt_fixtures!(test_p2sh_p2wsh_suite, network, format, {
        test_wallet_script_type(fixtures::ScriptType::P2shP2wsh, network, format).unwrap();
    });

    crate::test_psbt_fixtures!(test_p2wsh_suite, network, format, {
        test_wallet_script_type(fixtures::ScriptType::P2wsh, network, format).unwrap();
    });

    crate::test_psbt_fixtures!(
        test_p2tr_legacy_script_path_suite,
        network,
        format,
        {
            test_wallet_script_type(fixtures::ScriptType::P2trLegacyScriptPath, network, format)
                .unwrap();
        },
        ignore: [BitcoinCash, Ecash, BitcoinGold, Dash, Dogecoin, Litecoin, Zcash]
    );

    crate::test_psbt_fixtures!(
        test_p2tr_musig2_script_path_suite,
        network,
        format,
        {
            test_wallet_script_type(fixtures::ScriptType::P2trMusig2ScriptPath, network, format)
                .unwrap();
        },
        ignore: [BitcoinCash, Ecash, BitcoinGold, Dash, Dogecoin, Litecoin, Zcash]
    );

    crate::test_psbt_fixtures!(
        test_p2tr_musig2_key_path_suite,
        network,
        format,
        {
            test_wallet_script_type(
                fixtures::ScriptType::P2trMusig2TaprootKeypath,
                network,
                format,
            )
            .unwrap();
        },
        ignore: [BitcoinCash, Ecash, BitcoinGold, Dash, Dogecoin, Litecoin, Zcash]
    );

    crate::test_psbt_fixtures!(test_extract_transaction, network, format, {
        let fixture = fixtures::load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            fixtures::SignatureState::Fullsigned,
            format,
        )
        .expect("Failed to load fixture");
        let bitgo_psbt = fixture
            .to_bitgo_psbt(network)
            .expect("Failed to convert to BitGo PSBT");
        let fixture_extracted_transaction = fixture
            .extracted_transaction
            .expect("Failed to extract transaction");

        // // Use BitGoPsbt::finalize() which handles MuSig2 inputs
        let secp = crate::bitcoin::secp256k1::Secp256k1::new();
        let finalized_psbt = bitgo_psbt.finalize(&secp).expect("Failed to finalize PSBT");
        let extracted_transaction = finalized_psbt
            .extract_tx()
            .expect("Failed to extract transaction");
        use miniscript::bitcoin::consensus::serialize;
        let extracted_transaction_hex = hex::encode(serialize(&extracted_transaction));
        assert_eq!(
            extracted_transaction_hex, fixture_extracted_transaction,
            "Extracted transaction should match"
        );
    // Zcash fixtures were created with legacy Bitcoin sighash; implementation uses ZIP-243
    }, ignore: [Zcash]);

    #[test]
    fn test_add_paygo_attestation() {
        use crate::test_utils::fixtures;

        // Load a test fixture
        let fixture = fixtures::load_psbt_fixture_with_network(
            Network::Bitcoin,
            fixtures::SignatureState::Unsigned,
        )
        .unwrap();
        let mut bitgo_psbt = fixture
            .to_bitgo_psbt(Network::Bitcoin)
            .expect("Failed to convert to BitGo PSBT");

        // Add an output to the PSBT for testing
        let psbt = bitgo_psbt.psbt_mut();
        let output_index = psbt.outputs.len();
        psbt.outputs
            .push(miniscript::bitcoin::psbt::Output::default());
        psbt.unsigned_tx.output.push(miniscript::bitcoin::TxOut {
            value: miniscript::bitcoin::Amount::from_sat(10000),
            script_pubkey: miniscript::bitcoin::ScriptBuf::from_hex(
                "76a91479b000887626b294a914501a4cd226b58b23598388ac",
            )
            .unwrap(),
        });

        // Test fixtures
        let entropy = vec![0u8; 64];
        let signature = hex::decode(
            "1fd62abac20bb963f5150aa4b3f4753c5f2f53ced5183ab7761d0c95c2820f6b\
             b722b6d0d9adbab782d2d0d66402794b6bd6449dc26f634035ee388a2b5e7b53f6",
        )
        .unwrap();

        // Add PayGo attestation
        let result =
            bitgo_psbt.add_paygo_attestation(output_index, entropy.clone(), signature.clone());
        assert!(result.is_ok(), "Should add attestation successfully");

        // Extract and verify
        let address = "1CdWUVacSQQJ617HuNWByGiisEGXGNx2c";
        let psbt = bitgo_psbt.psbt();

        // Verify it was added (with address, no verification)
        let has_attestation = crate::paygo::has_paygo_attestation_verify(
            &psbt.outputs[output_index],
            Some(address),
            &[],
        );
        assert!(has_attestation.is_ok());
        assert!(
            !has_attestation.unwrap(),
            "Should be false when no pubkeys provided"
        );

        let attestation =
            crate::paygo::extract_paygo_attestation(&psbt.outputs[output_index], address).unwrap();
        assert_eq!(attestation.entropy, entropy);
        assert_eq!(attestation.signature, signature);
        assert_eq!(attestation.address, address);
    }

    #[test]
    fn test_add_paygo_attestation_invalid_index() {
        use crate::test_utils::fixtures;

        let fixture = fixtures::load_psbt_fixture_with_network(
            Network::Bitcoin,
            fixtures::SignatureState::Unsigned,
        )
        .unwrap();
        let mut bitgo_psbt = fixture
            .to_bitgo_psbt(Network::Bitcoin)
            .expect("Failed to convert to BitGo PSBT");

        let entropy = vec![0u8; 64];
        let signature = vec![1u8; 65];

        // Try to add to invalid index
        let result = bitgo_psbt.add_paygo_attestation(999, entropy, signature);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("out of bounds"));
    }

    #[test]
    fn test_add_paygo_attestation_invalid_entropy() {
        use crate::test_utils::fixtures;

        let fixture = fixtures::load_psbt_fixture_with_network(
            Network::Bitcoin,
            fixtures::SignatureState::Unsigned,
        )
        .unwrap();
        let mut bitgo_psbt = fixture
            .to_bitgo_psbt(Network::Bitcoin)
            .expect("Failed to convert to BitGo PSBT");

        // Add an output
        let psbt = bitgo_psbt.psbt_mut();
        psbt.outputs
            .push(miniscript::bitcoin::psbt::Output::default());

        let entropy = vec![0u8; 32]; // Wrong length
        let signature = vec![1u8; 65];

        // Try to add with invalid entropy
        let result = bitgo_psbt.add_paygo_attestation(0, entropy, signature);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid entropy length"));
    }

    #[test]
    fn test_paygo_parse_outputs_integration() {
        use crate::test_utils::fixtures;

        // Load fixture
        let fixture = fixtures::load_psbt_fixture_with_network(
            Network::Bitcoin,
            fixtures::SignatureState::Unsigned,
        )
        .unwrap();
        let mut bitgo_psbt = fixture
            .to_bitgo_psbt(Network::Bitcoin)
            .expect("Failed to convert to BitGo PSBT");

        // Add an output with a known address
        let psbt = bitgo_psbt.psbt_mut();
        let output_index = psbt.outputs.len();
        psbt.outputs
            .push(miniscript::bitcoin::psbt::Output::default());
        psbt.unsigned_tx.output.push(miniscript::bitcoin::TxOut {
            value: miniscript::bitcoin::Amount::from_sat(10000),
            script_pubkey: miniscript::bitcoin::ScriptBuf::from_hex(
                "76a91479b000887626b294a914501a4cd226b58b23598388ac",
            )
            .unwrap(), // Address: 1CdWUVacSQQJ617HuNWByGiisEGXGNx2c
        });

        // Add PayGo attestation
        let entropy = vec![0u8; 64];
        let signature = hex::decode(
            "1fd62abac20bb963f5150aa4b3f4753c5f2f53ced5183ab7761d0c95c2820f6b\
             b722b6d0d9adbab782d2d0d66402794b6bd6449dc26f634035ee388a2b5e7b53f6",
        )
        .unwrap();
        bitgo_psbt
            .add_paygo_attestation(output_index, entropy, signature)
            .unwrap();

        // Parse outputs without PayGo pubkeys - should detect but not verify
        let wallet_keys = fixture.get_wallet_xprvs().unwrap().to_root_wallet_keys();
        let parsed_outputs = bitgo_psbt
            .parse_outputs_with_wallet_keys(&wallet_keys, &[])
            .unwrap();

        // The PayGo output should have paygo: false (not verified)
        assert!(!parsed_outputs[output_index].paygo);

        // Parse outputs WITH PayGo pubkey - should verify
        let pubkey_bytes =
            hex::decode("02456f4f788b6af55eb9c54d88692cadef4babdbc34cde75218cc1d6b6de3dea2d")
                .unwrap();
        let pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes).unwrap();

        // Note: Signature verification with bitcoinjs-message format is not fully working yet
        // So parsing with pubkey will fail validation
        let parsed_result = bitgo_psbt.parse_outputs_with_wallet_keys(&wallet_keys, &[pubkey]);

        // We expect this to fail validation for now
        assert!(
            parsed_result.is_err(),
            "Expected verification to fail with current signature format"
        );
    }

    crate::test_psbt_fixtures!(test_parse_transaction_with_wallet_keys, network, format, {
        // Load fixture and get PSBT
        let fixture = fixtures::load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            fixtures::SignatureState::Unsigned,
            format,
        )
        .expect("Failed to load fixture");
        
        let bitgo_psbt = fixture
            .to_bitgo_psbt(network)
            .expect("Failed to convert to BitGo PSBT");
        
        // Get wallet keys from fixture
        let wallet_xprv = fixture
            .get_wallet_xprvs()
            .expect("Failed to get wallet keys");
        let wallet_keys = wallet_xprv.to_root_wallet_keys();
        
        // Create replay protection with the replay protection script from fixture
        let replay_protection = crate::fixed_script_wallet::ReplayProtection::new(vec![
            miniscript::bitcoin::ScriptBuf::from_hex("a91420b37094d82a513451ff0ccd9db23aba05bc5ef387")
                .expect("Failed to parse replay protection output script"),
        ]);
        
        // Parse the transaction (no PayGo verification in tests)
        let parsed = bitgo_psbt
            .parse_transaction_with_wallet_keys(&wallet_keys, &replay_protection, &[])
            .expect("Failed to parse transaction");
        
        // Basic validations
        assert!(!parsed.inputs.is_empty(), "Should have at least one input");
        assert!(!parsed.outputs.is_empty(), "Should have at least one output");
        
        // Verify at least one replay protection input exists
        let replay_protection_inputs = parsed
            .inputs
            .iter()
            .filter(|i| i.script_id.is_none())
            .count();
        assert!(
            replay_protection_inputs > 0,
            "Should have at least one replay protection input"
        );
        
        // Verify at least one wallet input exists
        let wallet_inputs = parsed
            .inputs
            .iter()
            .filter(|i| i.script_id.is_some())
            .count();
        assert!(
            wallet_inputs > 0,
            "Should have at least one wallet input"
        );
        
        // Count internal (wallet) and external outputs
        let internal_outputs = parsed
            .outputs
            .iter()
            .filter(|o| o.script_id.is_some())
            .count();
        let external_outputs = parsed
            .outputs
            .iter()
            .filter(|o| o.script_id.is_none())
            .count();
        
        assert_eq!(
            internal_outputs + external_outputs,
            parsed.outputs.len(),
            "All outputs should be either internal or external"
        );
        
        // Verify spend amount only includes external outputs
        let calculated_spend_amount: u64 = parsed
            .outputs
            .iter()
            .filter(|o| o.script_id.is_none())
            .map(|o| o.value)
            .sum();
        assert_eq!(
            parsed.spend_amount, calculated_spend_amount,
            "Spend amount should equal sum of external output values"
        );
        
        // Verify total values
        let total_input_value: u64 = parsed.inputs.iter().map(|i| i.value).sum();
        let total_output_value: u64 = parsed.outputs.iter().map(|o| o.value).sum();
        
        assert_eq!(
            parsed.miner_fee,
            total_input_value - total_output_value,
            "Miner fee should equal inputs minus outputs"
        );
        
        // Verify virtual size is reasonable
        assert!(
            parsed.virtual_size > 0,
            "Virtual size should be greater than 0"
        );
        
        // Verify outputs (fixtures now have 3 external outputs)
        assert_eq!(
            external_outputs, 3,
            "Test fixtures should have 3 external outputs"
        );
        assert_eq!(
            internal_outputs + external_outputs,
            parsed.outputs.len(),
            "Internal + external should equal total outputs"
        );
        assert!(
            parsed.spend_amount > 0,
            "Spend amount should be greater than 0 when there are external outputs"
        );
    }, ignore: []);

    #[test]
    fn test_serialize_bitcoin_psbt() {
        // Test that Bitcoin-like PSBTs can be serialized
        let fixture = fixtures::load_psbt_fixture_with_network(
            Network::Bitcoin,
            fixtures::SignatureState::Unsigned,
        )
        .unwrap();
        let psbt = fixture
            .to_bitgo_psbt(Network::Bitcoin)
            .expect("Failed to convert to BitGo PSBT");

        // Serialize should succeed
        let serialized = psbt.serialize();
        assert!(serialized.is_ok(), "Serialization should succeed");
    }

    #[test]
    fn test_serialize_zcash_psbt() {
        // Test that Zcash PSBTs can be serialized
        let fixture = fixtures::load_psbt_fixture_with_network(
            Network::Zcash,
            fixtures::SignatureState::Unsigned,
        )
        .unwrap();
        let original_bytes = BASE64_STANDARD
            .decode(&fixture.psbt_base64)
            .expect("Failed to decode base64");
        let psbt = BitGoPsbt::deserialize(&original_bytes, Network::Zcash)
            .expect("Failed to deserialize PSBT");

        // Serialize should succeed
        let serialized = psbt.serialize();
        assert!(serialized.is_ok(), "Serialization should succeed");
    }

    /// Test reconstructing PSBTs from fixture data using builder methods
    fn test_psbt_reconstruction_for_network(network: Network, format: fixtures::TxFormat) {
        use crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::InputScriptType;
        use crate::fixed_script_wallet::ReplayProtection;

        // Load fixture with specified format
        let fixture = fixtures::load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            fixtures::SignatureState::Unsigned,
            format,
        )
        .expect("Failed to load fixture");

        // Get wallet keys (main wallet from fixture)
        let wallet_xprvs = fixture.get_wallet_xprvs().expect("Failed to get xprvs");
        let wallet_keys = wallet_xprvs.to_root_wallet_keys();

        // Create other wallet keys for outputs from different wallet
        // This matches utxo-lib's getWalletKeysForSeed('too many secrets')
        use crate::fixed_script_wallet::test_utils::get_test_wallet_keys;
        let other_wallet_keys = crate::fixed_script_wallet::RootWalletKeys::new(
            get_test_wallet_keys("too many secrets"),
        );

        // Load the original PSBT and parse inputs/outputs using existing methods
        let original_psbt = fixture
            .to_bitgo_psbt(network)
            .expect("Failed to load original");

        // Extract replay protection output scripts from inputs without derivation info
        // These are typically p2shP2pk inputs used for replay protection on forks
        // Handle both witness_utxo (psbt-lite) and non_witness_utxo (full psbt) formats
        let replay_protection_scripts: Vec<miniscript::bitcoin::ScriptBuf> = original_psbt
            .psbt()
            .inputs
            .iter()
            .zip(original_psbt.psbt().unsigned_tx.input.iter())
            .filter(|(input, _)| {
                input.bip32_derivation.is_empty() && input.tap_key_origins.is_empty()
            })
            .filter_map(|(input, tx_in)| {
                // Try witness_utxo first, then fall back to non_witness_utxo
                input
                    .witness_utxo
                    .as_ref()
                    .map(|utxo| utxo.script_pubkey.clone())
                    .or_else(|| {
                        input.non_witness_utxo.as_ref().and_then(|prev_tx| {
                            prev_tx
                                .output
                                .get(tx_in.previous_output.vout as usize)
                                .map(|out| out.script_pubkey.clone())
                        })
                    })
            })
            .collect();

        let replay_protection = ReplayProtection::new(replay_protection_scripts);
        let parsed_inputs = original_psbt
            .parse_inputs(&wallet_keys, &replay_protection)
            .expect("Failed to parse inputs");

        // Parse outputs with main wallet keys
        let parsed_outputs = original_psbt
            .parse_outputs(&wallet_keys, &[])
            .expect("Failed to parse outputs");

        // Parse outputs with other wallet keys to identify outputs from different wallet
        let parsed_outputs_other = original_psbt
            .parse_outputs(&other_wallet_keys, &[])
            .expect("Failed to parse outputs with other wallet keys");

        // Create empty PSBT with same version and locktime as original
        let original_version = original_psbt.psbt().unsigned_tx.version.0 as i32;
        let original_locktime = original_psbt
            .psbt()
            .unsigned_tx
            .lock_time
            .to_consensus_u32();
        let mut reconstructed = BitGoPsbt::new(
            network,
            &wallet_keys,
            Some(original_version),
            Some(original_locktime),
        );

        // Track which inputs are wallet inputs vs replay protection
        let mut wallet_input_indices = Vec::new();
        // Track which outputs are from our wallet keys
        let mut wallet_output_indices = Vec::new();

        // Add inputs using parsed data
        let original_tx = original_psbt.psbt().unsigned_tx.clone();
        let original_psbt_inputs = &original_psbt.psbt().inputs;
        for (input_idx, ((tx_in, parsed_input), orig_psbt_input)) in original_tx
            .input
            .iter()
            .zip(parsed_inputs.iter())
            .zip(original_psbt_inputs.iter())
            .enumerate()
        {
            let txid = tx_in.previous_output.txid;
            let vout = tx_in.previous_output.vout;
            let value = parsed_input.value;
            let sequence = tx_in.sequence.0;

            if let Some(script_id) = parsed_input.script_id {
                wallet_input_indices.push(input_idx);

                // Determine sign_path based on script type (required for Taproot)
                use psbt_wallet_input::SignerKey;
                let sign_path = match parsed_input.script_type {
                    InputScriptType::P2trLegacy => Some(psbt_wallet_input::SignPath {
                        signer: SignerKey::User,
                        cosigner: SignerKey::Bitgo,
                    }),
                    InputScriptType::P2trMusig2ScriptPath => Some(psbt_wallet_input::SignPath {
                        signer: SignerKey::User,
                        cosigner: SignerKey::Backup,
                    }),
                    InputScriptType::P2trMusig2KeyPath => Some(psbt_wallet_input::SignPath {
                        signer: SignerKey::User,
                        cosigner: SignerKey::Bitgo,
                    }),
                    _ => None,
                };

                // For full PSBT format, non-segwit inputs need non_witness_utxo
                // Serialize the prev_tx from the original input if present
                let prev_tx: Option<Vec<u8>> = orig_psbt_input
                    .non_witness_utxo
                    .as_ref()
                    .map(|tx| miniscript::bitcoin::consensus::serialize(tx));

                let result = reconstructed.add_wallet_input(
                    txid,
                    vout,
                    value,
                    &wallet_keys,
                    script_id,
                    WalletInputOptions {
                        sign_path,
                        sequence: Some(sequence),
                        prev_tx: prev_tx.as_deref(),
                    },
                );
                assert!(
                    result.is_ok(),
                    "Failed to add wallet input {}: {:?}",
                    input_idx,
                    result
                );
            } else {
                // Non-wallet input (replay protection) - extract pubkey and use add_replay_protection_input
                let redeem_script = orig_psbt_input
                    .redeem_script
                    .as_ref()
                    .expect("Replay protection input should have redeem_script");
                let pubkey = BitGoPsbt::extract_pubkey_from_p2pk_redeem_script(redeem_script)
                    .expect("Failed to extract pubkey from redeem_script");
                let compressed_pubkey = miniscript::bitcoin::CompressedPublicKey(pubkey.inner);

                // For full PSBT format, serialize the non_witness_utxo
                let prev_tx = orig_psbt_input
                    .non_witness_utxo
                    .as_ref()
                    .map(|tx| miniscript::bitcoin::consensus::encode::serialize(tx));

                reconstructed.add_replay_protection_input(
                    compressed_pubkey,
                    txid,
                    vout,
                    value,
                    ReplayProtectionOptions {
                        sequence: Some(sequence),
                        sighash_type: orig_psbt_input.sighash_type,
                        prev_tx: prev_tx.as_deref(),
                    },
                );
            }
        }

        // Add outputs using parsed data from both wallet key sets
        for (output_idx, ((tx_out, parsed_output), parsed_output_other)) in original_tx
            .output
            .iter()
            .zip(parsed_outputs.iter())
            .zip(parsed_outputs_other.iter())
            .enumerate()
        {
            let value = parsed_output.value;

            if let Some(script_id) = &parsed_output.script_id {
                // Output belongs to main wallet
                wallet_output_indices.push(output_idx);
                let result = reconstructed.add_wallet_output(
                    script_id.chain,
                    script_id.index,
                    value,
                    &wallet_keys,
                );
                assert!(
                    result.is_ok(),
                    "Failed to add wallet output {}: {:?}",
                    output_idx,
                    result
                );
            } else if let Some(script_id) = &parsed_output_other.script_id {
                // Output belongs to other wallet (from seed "too many secrets")
                wallet_output_indices.push(output_idx);
                let result = reconstructed.add_wallet_output(
                    script_id.chain,
                    script_id.index,
                    value,
                    &other_wallet_keys,
                );
                assert!(
                    result.is_ok(),
                    "Failed to add other wallet output {}: {:?}",
                    output_idx,
                    result
                );
            } else {
                // External output - use add_output
                let _idx = reconstructed.add_output(tx_out.script_pubkey.clone(), value);
            }
        }

        // Compare the unsigned transactions
        let reconstructed_tx = &reconstructed.psbt().unsigned_tx;

        // Compare input count
        assert_eq!(
            original_tx.input.len(),
            reconstructed_tx.input.len(),
            "Input count mismatch"
        );

        // Compare output count
        assert_eq!(
            original_tx.output.len(),
            reconstructed_tx.output.len(),
            "Output count mismatch"
        );

        // Compare each input (transaction-level)
        for (idx, (orig, recon)) in original_tx
            .input
            .iter()
            .zip(reconstructed_tx.input.iter())
            .enumerate()
        {
            assert_eq!(
                orig.previous_output, recon.previous_output,
                "Input {} previous_output mismatch",
                idx
            );
            assert_eq!(
                orig.sequence, recon.sequence,
                "Input {} sequence mismatch",
                idx
            );
        }

        // Compare each output (transaction-level)
        for (idx, (orig, recon)) in original_tx
            .output
            .iter()
            .zip(reconstructed_tx.output.iter())
            .enumerate()
        {
            assert_eq!(
                orig.script_pubkey, recon.script_pubkey,
                "Output {} script_pubkey mismatch",
                idx
            );
            assert_eq!(orig.value, recon.value, "Output {} value mismatch", idx);
        }

        // Compare PSBT input metadata (only for wallet inputs)
        let original_psbt_inputs = &original_psbt.psbt().inputs;
        let reconstructed_inputs = &reconstructed.psbt().inputs;

        for (idx, (orig, recon)) in original_psbt_inputs
            .iter()
            .zip(reconstructed_inputs.iter())
            .enumerate()
        {
            // Compare utxo fields - either witness_utxo or non_witness_utxo should match
            // For segwit: witness_utxo is used
            // For non-segwit with prev_tx: non_witness_utxo is used
            // For non-segwit without prev_tx: witness_utxo is used as fallback
            let orig_has_utxo = orig.witness_utxo.is_some() || orig.non_witness_utxo.is_some();
            let recon_has_utxo = recon.witness_utxo.is_some() || recon.non_witness_utxo.is_some();
            assert!(
                orig_has_utxo && recon_has_utxo,
                "Input {} missing utxo data",
                idx
            );

            // If both have witness_utxo, compare them
            if orig.witness_utxo.is_some() && recon.witness_utxo.is_some() {
                assert_eq!(
                    orig.witness_utxo, recon.witness_utxo,
                    "Input {} witness_utxo mismatch",
                    idx
                );
            }

            // If both have non_witness_utxo, compare the relevant output
            if orig.non_witness_utxo.is_some() && recon.non_witness_utxo.is_some() {
                let orig_tx = orig.non_witness_utxo.as_ref().unwrap();
                let recon_tx = recon.non_witness_utxo.as_ref().unwrap();
                let vout = original_tx.input[idx].previous_output.vout as usize;
                assert_eq!(
                    orig_tx.output.get(vout),
                    recon_tx.output.get(vout),
                    "Input {} non_witness_utxo output mismatch",
                    idx
                );
            }

            // Skip detailed metadata comparison for non-wallet inputs
            if !wallet_input_indices.contains(&idx) {
                continue;
            }

            // For non-taproot wallet inputs, compare witness_script and redeem_script
            if orig.witness_script.is_some() || orig.redeem_script.is_some() {
                assert_eq!(
                    orig.witness_script, recon.witness_script,
                    "Input {} witness_script mismatch",
                    idx
                );
                assert_eq!(
                    orig.redeem_script, recon.redeem_script,
                    "Input {} redeem_script mismatch",
                    idx
                );
            }

            // For taproot wallet inputs, compare tap_internal_key
            // (but not tap_leaf_script which depends on signer/cosigner choice)
            if orig.tap_internal_key.is_some() {
                assert_eq!(
                    orig.tap_internal_key, recon.tap_internal_key,
                    "Input {} tap_internal_key mismatch",
                    idx
                );
            }
        }

        // Compare PSBT output metadata (only for our wallet outputs)
        let original_psbt_outputs = &original_psbt.psbt().outputs;
        let reconstructed_outputs = &reconstructed.psbt().outputs;

        for (idx, (orig, recon)) in original_psbt_outputs
            .iter()
            .zip(reconstructed_outputs.iter())
            .enumerate()
        {
            // Skip metadata comparison for non-wallet outputs (external or from different keys)
            if !wallet_output_indices.contains(&idx) {
                continue;
            }

            // For non-taproot wallet outputs, compare witness_script and redeem_script
            if orig.witness_script.is_some() || orig.redeem_script.is_some() {
                assert_eq!(
                    orig.witness_script, recon.witness_script,
                    "Output {} witness_script mismatch",
                    idx
                );
                assert_eq!(
                    orig.redeem_script, recon.redeem_script,
                    "Output {} redeem_script mismatch",
                    idx
                );
            }

            // For taproot wallet outputs, compare tap_internal_key
            if orig.tap_internal_key.is_some() {
                assert_eq!(
                    orig.tap_internal_key, recon.tap_internal_key,
                    "Output {} tap_internal_key mismatch",
                    idx
                );
            }
        }

        // Compare PSBTs at the key-value pair level for detailed error messages
        use crate::fixed_script_wallet::test_utils::psbt_compare::assert_equal_psbt;
        let original_bytes = original_psbt
            .serialize()
            .expect("Failed to serialize original");
        let reconstructed_bytes = reconstructed
            .serialize()
            .expect("Failed to serialize reconstructed");
        assert_equal_psbt(&original_bytes, &reconstructed_bytes);
    }

    // Note: Only testing PsbtLite format for now because full PSBT format
    // uses non_witness_utxo instead of witness_utxo for non-segwit inputs
    // Zcash: Transaction decoding fails because Zcash tx format differs from Bitcoin
    crate::test_psbt_fixtures!(test_psbt_reconstruction, network, format, {
        test_psbt_reconstruction_for_network(network, format);
    }, ignore: [Zcash]);
}
