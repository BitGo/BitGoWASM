//! Zcash PSBT deserialization
//!
//! Zcash uses an "overwintered transaction format" that includes additional fields
//! not present in standard Bitcoin transactions.

use miniscript::bitcoin::consensus::{Decodable, Encodable};
use miniscript::bitcoin::psbt::Psbt;
use miniscript::bitcoin::{secp256k1, Transaction, VarInt};
use std::io::Read;

pub use crate::zcash::transaction::{
    decode_zcash_transaction_meta, ZcashTransactionMeta, ZCASH_SAPLING_VERSION_GROUP_ID,
};

pub(crate) mod ironwood;
pub(crate) mod parse;
pub(crate) mod propkv;
pub(crate) mod v6;

pub use ironwood::{
    IronwoodBundleInfo, IronwoodOutputRequest, IronwoodSpendInfo, IronwoodSpendRequest,
};
pub use v6::VerifyV6SignatureError;

use super::{psbt_wallet_input, BitGoPsbt, DeserializeError};

/// Tests for the Zcash modules, split by subject in [`tests`].
#[cfg(test)]
mod tests;

/// A Zcash-compatible PSBT that can handle overwintered transactions
///
/// This struct handles Zcash-specific transaction formats including
/// version_group_id, expiry_height, and sapling fields.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZcashBitGoPsbt {
    /// The underlying Bitcoin-compatible PSBT
    pub psbt: Psbt,
    /// The network this PSBT is for (Zcash or ZcashTestnet)
    pub(crate) network: crate::Network,
    /// Zcash-specific: Version group ID for overwintered transactions
    pub version_group_id: Option<u32>,
    /// Zcash-specific: Expiry height
    pub expiry_height: Option<u32>,
    /// Zcash-specific: Additional Sapling fields (valueBalance, nShieldedSpend, nShieldedOutput, etc.)
    /// These are preserved as-is to maintain exact serialization
    pub sapling_fields: Vec<u8>,
}

/// Error returned when a v4/Sapling-shaped code path is handed a v6 (Ironwood) PSBT. The v4 wire
/// encoding and ZIP-243 sighash are both wrong for v6, so these paths fail loudly rather than
/// silently producing an unbroadcastable transaction or an unverifiable signature. Use the
/// dedicated `*_v6` / `*_ironwood_*` methods instead.
pub(crate) const V6_NOT_SUPPORTED_BY_V4_PATH: &str =
    "this is a v6 (Ironwood) PSBT; use the dedicated v6 methods \
     (serialize_v6/deserialize_v6, v6_transparent_sighash, add_v6_transparent_signature, \
     combine_ironwood_proof) — the v4 path would produce an invalid transaction";

impl ZcashBitGoPsbt {
    /// Create an empty Zcash PSBT directly without going through `BitGoPsbt`.
    pub(crate) fn new(
        network: crate::Network,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        consensus_branch_id: u32,
        version: Option<i32>,
        lock_time: Option<u32>,
        version_group_id: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Self {
        let mut psbt =
            super::make_psbt_with_xpubs(version.unwrap_or(4), lock_time.unwrap_or(0), wallet_keys);
        propkv::set_zec_consensus_branch_id(&mut psbt, consensus_branch_id);
        Self {
            psbt,
            network,
            version_group_id,
            expiry_height,
            sapling_fields: vec![0u8; 11],
        }
    }

    /// Create an empty Zcash PSBT with consensus branch ID resolved from `block_height`.
    ///
    /// Rejects a v4 build at or after NU7 activation: per ZIP-2003 a version 4 transaction is
    /// invalid once NU7 activates, and the node only reports that at broadcast ("transaction
    /// version 4 not supported by the network upgrade Nu7"), after the transaction has been
    /// signed and queued. This path only ever builds v4/Sapling, so at those heights it has no
    /// valid output to produce and must fail loudly instead.
    pub(crate) fn new_at_height(
        network: crate::Network,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        block_height: u32,
        version: Option<i32>,
        lock_time: Option<u32>,
        version_group_id: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Result<Self, String> {
        let is_mainnet = matches!(network, crate::Network::Zcash);
        let network_name = if is_mainnet { "mainnet" } else { "testnet" };
        let consensus_branch_id = crate::zcash::branch_id_for_height(block_height, is_mainnet)
            .ok_or_else(|| {
                format!(
                    "Block height {block_height} is before Overwinter activation on {network_name}"
                )
            })?;

        if version.unwrap_or(4) == 4 {
            let nu7 = crate::zcash::NetworkUpgrade::Nu7.activation_height(is_mainnet);
            if block_height >= nu7 {
                return Err(format!(
                    "Block height {block_height} is at or after NU7 activation ({nu7}) on \
                     {network_name}; version 4 transactions are invalid under NU7 (ZIP-2003). \
                     Build a v6 (Ironwood) transaction with new_v6_at_height instead"
                ));
            }
        }

        Ok(Self::new(
            network,
            wallet_keys,
            consensus_branch_id,
            version,
            lock_time,
            version_group_id,
            expiry_height,
        ))
    }

    /// Get the network this PSBT is for
    pub fn network(&self) -> crate::Network {
        self.network
    }

    /// Assemble a Zcash PSBT from a transaction and unspents — no signatures.
    pub fn from_tx_parts(
        network: crate::Network,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        tx: &miniscript::bitcoin::Transaction,
        unspents: &[super::HydrationUnspentInput],
        consensus_branch_id: u32,
        version_group_id: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Result<Self, String> {
        let mut z = Self::new(
            network,
            wallet_keys,
            consensus_branch_id,
            Some(tx.version.0),
            Some(tx.lock_time.to_consensus_u32()),
            version_group_id,
            expiry_height,
        );
        super::BitGoPsbt::hydrate_psbt(&mut z.psbt, network, wallet_keys, tx, unspents)?;
        Ok(z)
    }

    /// Insert signatures from a parsed `FixedScriptInput` into this Zcash PSBT at `index`.
    pub(crate) fn add_input_signatures(
        &mut self,
        index: usize,
        input: &super::FixedScriptInput,
    ) -> Result<(), String> {
        if self.is_ironwood_v6() {
            return Err(V6_NOT_SUPPORTED_BY_V4_PATH.to_string());
        }
        let branch_id = propkv::get_zec_consensus_branch_id(&self.psbt)
            .ok_or_else(|| "missing consensus_branch_id".to_string())?;
        let ctx = super::SighashContext::Zcash {
            consensus_branch_id: branch_id,
            version_group_id: self
                .version_group_id
                .unwrap_or(ZCASH_SAPLING_VERSION_GROUP_ID),
            expiry_height: self.expiry_height.unwrap_or(0),
        };
        input.apply_signatures(&mut self.psbt, index, &ctx)
    }

    /// Serialize a transaction with Zcash-specific fields (version_group_id, expiry_height, sapling_fields)
    fn serialize_as_zcash_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<Vec<u8>, super::DeserializeError> {
        // Chokepoint for the v4 wire encoding — also covers
        // `extract_unsigned_zcash_transaction`, `compute_txid` and `serialize`.
        if self.is_ironwood_v6() {
            return Err(super::DeserializeError::Network(
                V6_NOT_SUPPORTED_BY_V4_PATH.to_string(),
            ));
        }
        let parts = crate::zcash::transaction::ZcashTransactionParts {
            transaction: tx.clone(),
            is_overwintered: true,
            version_group_id: Some(
                self.version_group_id
                    .unwrap_or(ZCASH_SAPLING_VERSION_GROUP_ID),
            ),
            expiry_height: Some(self.expiry_height.unwrap_or(0)),
            sapling_fields: self.sapling_fields.clone(),
        };
        crate::zcash::transaction::encode_zcash_transaction_parts(&parts)
            .map_err(super::DeserializeError::Network)
    }

    /// Reconstruct the unsigned Zcash transaction bytes from the PSBT
    pub fn extract_unsigned_zcash_transaction(&self) -> Result<Vec<u8>, super::DeserializeError> {
        self.serialize_as_zcash_transaction(&self.psbt.unsigned_tx)
    }

    /// Extract the finalized Zcash transaction bytes from the PSBT
    ///
    /// This extracts the fully-signed transaction with Zcash-specific fields.
    /// Must be called after all inputs have been finalized.
    ///
    /// This method consumes the PSBT to avoid cloning.
    pub fn extract_tx(self) -> Result<Vec<u8>, super::DeserializeError> {
        self.extract_tx_with_fee_policy(super::ExtractFeePolicy::Default)
    }

    /// Extract the finalized Zcash transaction bytes from the PSBT with an
    /// explicit fee-rate [`policy`][super::ExtractFeePolicy].
    ///
    /// This method consumes the PSBT to avoid cloning.
    pub fn extract_tx_with_fee_policy(
        self,
        policy: super::ExtractFeePolicy,
    ) -> Result<Vec<u8>, super::DeserializeError> {
        use miniscript::bitcoin::psbt::ExtractTxError;

        if self.is_ironwood_v6() {
            return Err(super::DeserializeError::Network(
                V6_NOT_SUPPORTED_BY_V4_PATH.to_string(),
            ));
        }

        // Capture Zcash-specific fields before consuming psbt
        let version_group_id = self
            .version_group_id
            .unwrap_or(ZCASH_SAPLING_VERSION_GROUP_ID);
        let expiry_height = self.expiry_height.unwrap_or(0);
        let sapling_fields = self.sapling_fields;

        let map_extract_err = |e: ExtractTxError| match e {
            ExtractTxError::AbsurdFeeRate { .. } => {
                super::DeserializeError::Network(format!("Absurd fee rate: {}", e))
            }
            ExtractTxError::MissingInputValue { .. } => {
                super::DeserializeError::Network(format!("Missing input value: {}", e))
            }
            ExtractTxError::SendingTooMuch { .. } => {
                super::DeserializeError::Network(format!("Sending too much: {}", e))
            }
            _ => super::DeserializeError::Network(format!("Failed to extract transaction: {}", e)),
        };

        let tx = match policy {
            super::ExtractFeePolicy::Default => self.psbt.extract_tx().map_err(map_extract_err)?,
            super::ExtractFeePolicy::Unchecked => self.psbt.extract_tx_unchecked_fee_rate(),
            super::ExtractFeePolicy::Limited(max_fee_rate_sat_per_vb) => self
                .psbt
                .extract_tx_with_fee_rate_limit(max_fee_rate_sat_per_vb)
                .map_err(map_extract_err)?,
        };

        let parts = crate::zcash::transaction::ZcashTransactionParts {
            transaction: tx,
            is_overwintered: true,
            version_group_id: Some(version_group_id),
            expiry_height: Some(expiry_height),
            sapling_fields,
        };
        crate::zcash::transaction::encode_zcash_transaction_parts(&parts)
            .map_err(super::DeserializeError::Network)
    }

    /// Compute the transaction ID for the unsigned Zcash transaction
    ///
    /// The txid is the double SHA256 of the full Zcash transaction bytes.
    pub fn compute_txid(&self) -> Result<[u8; 32], super::DeserializeError> {
        use miniscript::bitcoin::hashes::{sha256d, Hash};
        let tx_bytes = self.extract_unsigned_zcash_transaction()?;
        let hash = sha256d::Hash::hash(&tx_bytes);
        Ok(hash.to_byte_array())
    }

    /// Deserialize a Zcash PSBT from bytes without requiring the ZecConsensusBranchId
    /// proprietary key.  Used when combining with a stripped HSM response that may not
    /// carry the branch ID (the key is only needed for sighash, not for merging sigs).
    pub(crate) fn deserialize_stripped(
        bytes: &[u8],
        network: crate::Network,
    ) -> Result<Self, super::DeserializeError> {
        Self::decode_with_zcash_tx(bytes, network, false)
    }

    /// Deserialize the PSBT by converting the Zcash transaction to Bitcoin format first
    fn decode_with_zcash_tx(
        bytes: &[u8],
        network: crate::Network,
        require_branch_id: bool,
    ) -> Result<Self, super::DeserializeError> {
        // A v6 (Ironwood) PSBT is a plain PSBT carrying the transparent skeleton, so it parses
        // directly; the presence of the ZecV6Params proprietary key distinguishes it from the v4
        // path (whose embedded overwintered tx a plain PSBT decoder cannot parse). Both share the
        // `psbt\xff` magic, so a failed parse here is not conclusive — fall through to the v4 path
        // and let it report the real error.
        //
        // Delegate to the pre-shield v6 decoder rather than constructing the struct inline. A PSBT
        // can be serialized between building its transparent skeleton and adding the PCZT, so the
        // generic entry point must accept both states. The decoder still validates the declared
        // version group id and consensus branch id.
        if let Ok(psbt) = Psbt::deserialize(bytes) {
            if propkv::get_zec_v6_params(&psbt).is_some() {
                return Self::deserialize_v6_pre_shield(bytes, network);
            }
        }

        let mut r = bytes;

        // Read magic bytes
        let magic: [u8; 4] = Decodable::consensus_decode(&mut r)?;
        if &magic != b"psbt" {
            return Err(super::DeserializeError::Network(
                "Invalid PSBT magic".to_string(),
            ));
        }

        // Read separator
        let separator: u8 = Decodable::consensus_decode(&mut r)?;
        if separator != 0xff {
            return Err(super::DeserializeError::Network(
                "Invalid PSBT separator".to_string(),
            ));
        }

        // Find and replace the transaction in the PSBT
        let mut modified_psbt = Vec::new();
        modified_psbt.extend_from_slice(b"psbt\xff");

        let mut version_group_id = None;
        let mut expiry_height = None;
        let mut sapling_fields = Vec::new();
        let mut found_tx = false;

        // Decode global map - we'll copy everything byte-by-byte while transforming the TX
        loop {
            // Read key length
            let key_len: VarInt = Decodable::consensus_decode(&mut r)?;
            if key_len.0 == 0 {
                // End of global map
                0u8.consensus_encode(&mut modified_psbt).map_err(|e| {
                    super::DeserializeError::Network(format!("Failed to encode separator: {}", e))
                })?;
                break;
            }

            // Read key
            let mut key_data = vec![0u8; key_len.0 as usize];
            r.read_exact(&mut key_data)
                .map_err(|_| super::DeserializeError::Network("Failed to read key".to_string()))?;

            // Read value length
            let val_len: VarInt = Decodable::consensus_decode(&mut r)?;

            // Read value
            let mut val_data = vec![0u8; val_len.0 as usize];
            r.read_exact(&mut val_data).map_err(|_| {
                super::DeserializeError::Network("Failed to read value".to_string())
            })?;

            // Check if this is the unsigned transaction (key type 0x00 with empty key)
            if !key_data.is_empty() && key_data[0] == 0x00 && key_data.len() == 1 {
                // This is the unsigned transaction
                found_tx = true;
                let parts = crate::zcash::transaction::decode_zcash_transaction_parts(&val_data)
                    .map_err(super::DeserializeError::Network)?;
                version_group_id = parts.version_group_id;
                expiry_height = parts.expiry_height;
                sapling_fields = parts.sapling_fields;

                // Serialize the modified transaction without the segwit marker/flag. The
                // transaction is embedded in a PSBT global map and must use the legacy unsigned
                // transaction encoding, including for an empty transaction.
                let tx_bytes = crate::zcash::transaction::encode_zcash_transaction_parts(
                    &crate::zcash::transaction::ZcashTransactionParts {
                        transaction: parts.transaction,
                        is_overwintered: false,
                        version_group_id: None,
                        expiry_height: None,
                        sapling_fields: Vec::new(),
                    },
                )
                .map_err(super::DeserializeError::Network)?;

                // Write key
                VarInt(key_data.len() as u64)
                    .consensus_encode(&mut modified_psbt)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode key length: {}",
                            e
                        ))
                    })?;
                modified_psbt.extend_from_slice(&key_data);

                // Write new value
                VarInt(tx_bytes.len() as u64)
                    .consensus_encode(&mut modified_psbt)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode value length: {}",
                            e
                        ))
                    })?;
                modified_psbt.extend_from_slice(&tx_bytes);
            } else {
                // Copy key-value pair as-is
                VarInt(key_data.len() as u64)
                    .consensus_encode(&mut modified_psbt)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode key length: {}",
                            e
                        ))
                    })?;
                modified_psbt.extend_from_slice(&key_data);

                VarInt(val_data.len() as u64)
                    .consensus_encode(&mut modified_psbt)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode value length: {}",
                            e
                        ))
                    })?;
                modified_psbt.extend_from_slice(&val_data);
            }
        }

        if !found_tx {
            return Err(super::DeserializeError::Network(
                "Missing unsigned transaction".to_string(),
            ));
        }

        // Append the rest of the PSBT (inputs and outputs)
        modified_psbt.extend_from_slice(r);

        // Now deserialize as a standard PSBT
        let psbt = Psbt::deserialize(&modified_psbt)?;

        // Consensus branch ID must be set in the PSBT proprietary map
        if require_branch_id && propkv::get_zec_consensus_branch_id(&psbt).is_none() {
            return Err(super::DeserializeError::Network(
                "Missing ZecConsensusBranchId in PSBT proprietary map".to_string(),
            ));
        }

        Ok(ZcashBitGoPsbt {
            psbt,
            network,
            version_group_id,
            expiry_height,
            sapling_fields,
        })
    }

    /// Deserialize a Zcash PSBT from bytes
    ///
    /// # Arguments
    /// * `bytes` - The serialized PSBT bytes
    /// * `network` - The network (must be Zcash or ZcashTestnet)
    pub fn deserialize(
        bytes: &[u8],
        network: crate::Network,
    ) -> Result<Self, super::DeserializeError> {
        Self::decode_with_zcash_tx(bytes, network, true)
    }

    /// Convert to a standard Bitcoin PSBT (losing Zcash-specific fields)
    pub fn into_bitcoin_psbt(self) -> Psbt {
        self.psbt
    }

    /// Serialize the Zcash PSBT back to bytes, including Zcash-specific fields
    pub fn serialize(&self) -> Result<Vec<u8>, super::DeserializeError> {
        // A v6 (Ironwood) PSBT keeps its transparent skeleton in the PSBT's own tx and its shielded
        // state in the proprietary map, so it serializes as a plain PSBT.
        if self.is_ironwood_v6() {
            return Ok(self.serialize_v6());
        }

        // First serialize as standard Bitcoin PSBT
        let bitcoin_psbt_bytes = self.psbt.serialize();

        // Now we need to replace the transaction in the serialized PSBT
        // Parse the Bitcoin PSBT to find where the transaction is
        let mut result = Vec::new();
        let mut r = bitcoin_psbt_bytes.as_slice();

        // Copy magic and separator
        result.extend_from_slice(&bitcoin_psbt_bytes[0..5]); // "psbt\xff"
        r = &r[5..];

        // Now process the global map, replacing the transaction
        let zcash_tx_bytes = self.extract_unsigned_zcash_transaction()?;
        let mut found_tx = false;

        loop {
            // Read key length
            let key_len: VarInt = Decodable::consensus_decode(&mut r)?;
            if key_len.0 == 0 {
                // End of global map
                0u8.consensus_encode(&mut result).map_err(|e| {
                    super::DeserializeError::Network(format!("Failed to encode separator: {}", e))
                })?;
                break;
            }

            // Read key
            let mut key_data = vec![0u8; key_len.0 as usize];
            r.read_exact(&mut key_data)
                .map_err(|_| super::DeserializeError::Network("Failed to read key".to_string()))?;

            // Read value length
            let val_len: VarInt = Decodable::consensus_decode(&mut r)?;

            // Read value
            let mut val_data = vec![0u8; val_len.0 as usize];
            r.read_exact(&mut val_data).map_err(|_| {
                super::DeserializeError::Network("Failed to read value".to_string())
            })?;

            // Check if this is the unsigned transaction
            if !key_data.is_empty() && key_data[0] == 0x00 && key_data.len() == 1 {
                found_tx = true;
                // Write key
                VarInt(key_data.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode key length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&key_data);

                // Write Zcash transaction instead
                VarInt(zcash_tx_bytes.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode value length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&zcash_tx_bytes);
            } else {
                // Copy key-value pair as-is
                VarInt(key_data.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode key length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&key_data);

                VarInt(val_data.len() as u64)
                    .consensus_encode(&mut result)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode value length: {}",
                            e
                        ))
                    })?;
                result.extend_from_slice(&val_data);
            }
        }

        if !found_tx {
            return Err(super::DeserializeError::Network(
                "Missing unsigned transaction in PSBT".to_string(),
            ));
        }

        // Copy the rest (inputs and outputs)
        result.extend_from_slice(r);

        Ok(result)
    }

    /// Convert a network-format Zcash transaction (0, 1, or 2 sigs) to a `ZcashBitGoPsbt`.
    ///
    /// Accepts unsigned, half-signed, and fully-signed Zcash transactions. The caller is
    /// responsible for checking the signature count if a specific signing state is required.
    pub fn from_network_format(
        parts: &crate::zcash::transaction::ZcashTransactionParts,
        network: crate::Network,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        unspents: &[super::HydrationUnspentInput],
        consensus_branch_id: u32,
    ) -> Result<Self, String> {
        let tx = &parts.transaction;
        let inputs = super::FixedScriptInput::parse_all(tx)?;
        let mut z = Self::from_tx_parts(
            network,
            wallet_keys,
            tx,
            unspents,
            consensus_branch_id,
            parts.version_group_id,
            parts.expiry_height,
        )?;
        for (i, input) in inputs.iter().enumerate() {
            z.add_input_signatures(i, input)?;
        }
        z.sapling_fields = parts.sapling_fields.clone();
        Ok(z)
    }

    /// Convert to the underlying Bitcoin PSBT, consuming self
    pub fn into_psbt(self) -> Psbt {
        self.psbt
    }
}

/// [`BitGoPsbt::new_zcash`]: an empty v4 Zcash PSBT. Delegates to [`ZcashBitGoPsbt::new`].
pub(crate) fn new_bitgo_psbt_zcash(
    network: crate::Network,
    wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
    consensus_branch_id: u32,
    version: Option<i32>,
    lock_time: Option<u32>,
    version_group_id: Option<u32>,
    expiry_height: Option<u32>,
) -> BitGoPsbt {
    BitGoPsbt::Zcash(
        ZcashBitGoPsbt::new(
            network,
            wallet_keys,
            consensus_branch_id,
            version,
            lock_time,
            version_group_id,
            expiry_height,
        ),
        network,
    )
}

/// [`BitGoPsbt::new_zcash_at_height`]: an empty v4 Zcash PSBT with the consensus branch ID
/// resolved from block height. Delegates to [`ZcashBitGoPsbt::new_at_height`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn new_bitgo_psbt_zcash_at_height(
    network: crate::Network,
    wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
    block_height: u32,
    version: Option<i32>,
    lock_time: Option<u32>,
    version_group_id: Option<u32>,
    expiry_height: Option<u32>,
) -> Result<BitGoPsbt, String> {
    Ok(BitGoPsbt::Zcash(
        ZcashBitGoPsbt::new_at_height(
            network,
            wallet_keys,
            block_height,
            version,
            lock_time,
            version_group_id,
            expiry_height,
        )?,
        network,
    ))
}

/// The v4/Sapling (ZIP-243) arms of the generic [`BitGoPsbt`] signing, finalization and
/// verification methods. `BitGoPsbt` dispatches its `Zcash` variant here.
impl ZcashBitGoPsbt {
    /// The ZIP-243 sighash parameters: `(consensus_branch_id, version_group_id, expiry_height)`.
    /// `None` when the PSBT carries no `ZecConsensusBranchId`.
    fn zip243_sighash_params(&self) -> Option<(u32, u32, u32)> {
        let branch_id = propkv::get_zec_consensus_branch_id(&self.psbt)?;
        let version_group_id = self
            .version_group_id
            .unwrap_or(ZCASH_SAPLING_VERSION_GROUP_ID);
        let expiry_height = self.expiry_height.unwrap_or(0);
        Some((branch_id, version_group_id, expiry_height))
    }

    /// A new empty Zcash PSBT with the same consensus parameters as `self`.
    pub(crate) fn new_like(
        &self,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        version: i32,
        lock_time: u32,
    ) -> Result<Self, String> {
        let branch_id = propkv::get_zec_consensus_branch_id(&self.psbt)
            .ok_or("Template PSBT missing ZecConsensusBranchId")?;
        Ok(Self::new(
            self.network,
            wallet_keys,
            branch_id,
            Some(version),
            Some(lock_time),
            self.version_group_id,
            self.expiry_height,
        ))
    }

    /// Serialize a half-signed transaction in the legacy format, with the Zcash-specific fields.
    pub(crate) fn extract_half_signed_legacy_tx(&self) -> Result<Vec<u8>, String> {
        let tx = super::legacy_txformat::build_half_signed_legacy_tx(&self.psbt)
            .map_err(|e| e.to_string())?;

        // Serialize with Zcash-specific fields
        let parts = crate::zcash::transaction::ZcashTransactionParts {
            transaction: tx,
            is_overwintered: true,
            version_group_id: Some(
                self.version_group_id
                    .unwrap_or(ZCASH_SAPLING_VERSION_GROUP_ID),
            ),
            expiry_height: Some(self.expiry_height.unwrap_or(0)),
            sapling_fields: self.sapling_fields.clone(),
        };
        crate::zcash::transaction::encode_zcash_transaction_parts(&parts)
    }

    /// Finalize one input using ZIP-243 sighash verification.
    pub(crate) fn finalize_input<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
    ) -> Result<(), String> {
        use miniscript::psbt::PsbtExt;

        let (branch_id, version_group_id, expiry_height) = self
            .zip243_sighash_params()
            .ok_or_else(|| "Missing ZecConsensusBranchId in PSBT".to_string())?;

        self.psbt
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

    /// Sign one input with a raw private key over the ZIP-243 sighash. Replay protection
    /// (P2SH-P2PK) inputs are signed directly, since `sign_zcash` iterates over
    /// `bip32_derivation`.
    pub(crate) fn sign_with_privkey<C: secp256k1::Signing + secp256k1::Verification>(
        &mut self,
        input_index: usize,
        privkey: &secp256k1::SecretKey,
        public_key: miniscript::bitcoin::PublicKey,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<(), String> {
        let network = self.network;
        let (branch_id, version_group_id, expiry_height) = self
            .zip243_sighash_params()
            .ok_or_else(|| "Missing ZecConsensusBranchId in PSBT".to_string())?;

        let psbt = &mut self.psbt;

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
                BitGoPsbt::extract_pubkey_from_p2pk_redeem_script(redeem_script)
            {
                // Verify the provided key matches the redeem script pubkey
                if public_key != redeem_pubkey {
                    return Err(
                        "Public key mismatch: derived pubkey does not match redeem_script pubkey"
                            .to_string(),
                    );
                }

                // Sign directly using ZIP-243 sighash
                let ecdsa_sig = sign_p2sh_p2pk_input_zcash(
                    psbt,
                    input_index,
                    redeem_script,
                    privkey,
                    branch_id,
                    version_group_id,
                    expiry_height,
                    secp,
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
        let result = psbt.sign_zcash(&key_map, secp, branch_id, version_group_id, expiry_height);

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

    /// Sign every input `k` has a key for, over the ZIP-243 sighash.
    pub(crate) fn sign<C, K>(
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
        // v6 (Ironwood) inputs are signed over the ZIP-244 digest, not ZIP-243. Signing
        // here would put a signature into `partial_sigs` that no verifier can satisfy, and
        // nothing downstream re-checks it — so refuse. `SignError` carries no message, so
        // callers going through the `String`-returning wrappers get the detail from
        // `ensure_not_ironwood_v6`. Use `add_v6_transparent_signature` instead.
        if self.is_ironwood_v6() {
            return Err((
                Default::default(),
                std::collections::BTreeMap::from_iter([(
                    0,
                    miniscript::bitcoin::psbt::SignError::UnknownOutputType,
                )]),
            ));
        }

        let (branch_id, version_group_id, expiry_height) =
            self.zip243_sighash_params().ok_or_else(|| {
                (
                    Default::default(),
                    std::collections::BTreeMap::from_iter([(
                        0,
                        miniscript::bitcoin::psbt::SignError::KeyNotFound,
                    )]),
                )
            })?;

        // Sign using ZIP-243 sighash
        self.psbt
            .sign_zcash(k, secp, branch_id, version_group_id, expiry_height)
    }

    /// Verify a replay protection (P2SH-P2PK) input's signature over the ZIP-243 sighash.
    pub(crate) fn verify_replay_protection_signature<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
        redeem_script: &miniscript::bitcoin::ScriptBuf,
        value: miniscript::bitcoin::Amount,
        ecdsa_sig: &miniscript::bitcoin::ecdsa::Signature,
        public_key: &miniscript::bitcoin::PublicKey,
    ) -> Result<bool, String> {
        use miniscript::bitcoin::sighash::{SighashCache, SighashCacheZcashExt};

        let (branch_id, version_group_id, expiry_height) = self
            .zip243_sighash_params()
            .ok_or("Missing ZecConsensusBranchId in PSBT")?;

        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);
        let sighash = cache
            .p2sh_signature_hash_zcash(
                input_index,
                redeem_script,
                value,
                ecdsa_sig.sighash_type,
                branch_id,
                version_group_id,
                expiry_height,
            )
            .map_err(|e| format!("Failed to compute Zcash sighash: {}", e))?;

        let message = secp256k1::Message::from_digest(sighash.to_byte_array());
        match secp.verify_ecdsa(&message, &ecdsa_sig.signature, &public_key.inner) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify an ECDSA signature for `public_key` on a v4/Sapling input (ZIP-243 sighash).
    pub(crate) fn verify_signature_with_pubkey<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
        public_key: miniscript::bitcoin::CompressedPublicKey,
    ) -> Result<bool, String> {
        // v6 (Ironwood) transparent inputs are signed over the ZIP-244 digest, not ZIP-243.
        // Verifying here would compute a meaningless Sapling digest and report Ok(false) for
        // a valid v6 signature — a wrong false that downstream signature counting reads as
        // "not signed yet" — so fail loudly instead, matching `ensure_not_ironwood_v6`.
        if self.is_ironwood_v6() {
            return Err(V6_NOT_SUPPORTED_BY_V4_PATH.to_string());
        }
        // Use Zcash-specific signature verification with ZIP-243 sighash
        let (branch_id, version_group_id, expiry_height) = self
            .zip243_sighash_params()
            .ok_or("Missing ZecConsensusBranchId in PSBT")?;

        verify_ecdsa_signature_zcash(
            secp,
            &self.psbt,
            input_index,
            public_key,
            branch_id,
            version_group_id,
            expiry_height,
        )
    }
}

/// Verify an ECDSA signature for a Zcash PSBT input using ZIP-243 sighash.
///
/// # Arguments
/// - `secp`: Secp256k1 context for verification
/// - `psbt`: The PSBT containing the signature
/// - `input_index`: Index of the input to verify
/// - `public_key`: The public key to check for a signature
/// - `consensus_branch_id`: Zcash network upgrade branch ID
/// - `version_group_id`: Zcash transaction version group ID
/// - `expiry_height`: Transaction expiry height
///
/// # Returns
/// - `Ok(true)` if a valid ECDSA signature exists for the public key
/// - `Ok(false)` if no signature exists or verification fails
/// - `Err(String)` if sighash computation fails
pub fn verify_ecdsa_signature_zcash<C: secp256k1::Verification>(
    secp: &secp256k1::Secp256k1<C>,
    psbt: &miniscript::bitcoin::psbt::Psbt,
    input_index: usize,
    public_key: miniscript::bitcoin::CompressedPublicKey,
    consensus_branch_id: u32,
    version_group_id: u32,
    expiry_height: u32,
) -> Result<bool, String> {
    use miniscript::bitcoin::{sighash::SighashCache, PublicKey};

    let input = &psbt.inputs[input_index];

    // Convert to PublicKey for ECDSA
    let public_key_inner = PublicKey::from_slice(&public_key.to_bytes())
        .map_err(|e| format!("Failed to convert public key: {}", e))?;

    // Check if there's a partial signature for this public key
    if let Some(signature) = input.partial_sigs.get(&public_key_inner) {
        // Create sighash cache and compute sighash for this input using ZIP-243
        let mut cache = SighashCache::new(&psbt.unsigned_tx);

        let (sighash_msg, _) = psbt
            .sighash_zcash(
                input_index,
                &mut cache,
                consensus_branch_id,
                version_group_id,
                expiry_height,
            )
            .map_err(|e| format!("Failed to compute Zcash sighash: {}", e))?;

        // Verify the signature
        match secp.verify_ecdsa(&sighash_msg, &signature.signature, &public_key_inner.inner) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    } else {
        // No signature found for this public key
        Ok(false)
    }
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_p2sh_p2pk_input_zcash<C: secp256k1::Signing>(
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
        ecdsa::Signature as EcdsaSignature, sighash::SighashCache, sighash::SighashCacheZcashExt,
    };

    // v6 (Ironwood) inputs are signed over the ZIP-244 digest, not ZIP-243. Signing here would
    // insert a signature into `partial_sigs` that no verifier can ever satisfy, and nothing
    // downstream re-checks it — so refuse instead.
    if version_group_id == crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID {
        return Err(V6_NOT_SUPPORTED_BY_V4_PATH.to_string());
    }

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
