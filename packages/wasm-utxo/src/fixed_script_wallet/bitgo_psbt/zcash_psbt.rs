//! Zcash PSBT deserialization
//!
//! Zcash uses an "overwintered transaction format" that includes additional fields
//! not present in standard Bitcoin transactions.

use miniscript::bitcoin::consensus::{Decodable, Encodable};
use miniscript::bitcoin::psbt::Psbt;
use miniscript::bitcoin::{Transaction, VarInt};
use std::io::Read;

pub use crate::zcash::transaction::{
    decode_zcash_transaction_meta, ZcashTransactionMeta, ZCASH_SAPLING_VERSION_GROUP_ID,
};

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
        super::propkv::set_zec_consensus_branch_id(&mut psbt, consensus_branch_id);
        Self {
            psbt,
            network,
            version_group_id,
            expiry_height,
            sapling_fields: vec![0u8; 11],
        }
    }

    /// Create an empty Zcash PSBT with consensus branch ID resolved from `block_height`.
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
        let consensus_branch_id = crate::zcash::branch_id_for_height(block_height, is_mainnet)
            .ok_or_else(|| {
                format!(
                    "Block height {} is before Overwinter activation on {}",
                    block_height,
                    if is_mainnet { "mainnet" } else { "testnet" }
                )
            })?;
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
        let branch_id = super::propkv::get_zec_consensus_branch_id(&self.psbt)
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

                // Serialize the modified transaction
                let mut tx_bytes = Vec::new();
                parts
                    .transaction
                    .consensus_encode(&mut tx_bytes)
                    .map_err(|e| {
                        super::DeserializeError::Network(format!(
                            "Failed to encode transaction: {}",
                            e
                        ))
                    })?;

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
        if require_branch_id && super::propkv::get_zec_consensus_branch_id(&psbt).is_none() {
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

// ---- Zcash v6 (Ironwood / NU6.3) shielding ----
//
// A v6 shielding PSBT keeps its transparent inputs/outputs in `psbt.unsigned_tx` (a version-6
// rust-bitcoin `Transaction`) exactly like the v4 path, and carries the shielded side as an
// `orchard` PCZT in the proprietary map, under the `BITGO_ZEC_V6` namespace's `IronwoodPczt`
// subtype. The v6 header params (`version_group_id`, `expiry_height`) live under that same
// namespace's `VersionGroupId`/`ExpiryHeight` subtypes; `version_group_id`'s presence marks the
// PSBT as v6 so it round-trips through a plain PSBT serialization without the v4 tx-replacement
// dance.
//
// The lifecycle mirrors the microservice PSBT flow: the server builds (Constructor, no keys), the
// client + HSM sign the transparent inputs over the ZIP-244 sighash this module exposes, the signed
// PSBT goes to the external proof service for the Halo2 `zkproof`, and `combine_ironwood_proof`
// finalizes the transparent inputs and splices in the proof + shielded bundle to produce the
// broadcast-ready v6 transaction. See `crate::zcash::ironwood_build` for the PCZT role bridge.
impl ZcashBitGoPsbt {
    /// Create an empty Zcash **v6 (Ironwood)** shielding PSBT, with the consensus branch id resolved
    /// from `block_height`, which must be at or after NU6.3 activation.
    ///
    /// The height is checked against NU6.3 rather than merely Overwinter: a v6 transaction stamped
    /// with a pre-NU6.3 branch id is only rejected at broadcast, long after signing.
    pub fn new_v6_at_height(
        network: crate::Network,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        block_height: u32,
        lock_time: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Result<Self, String> {
        let is_mainnet = matches!(network, crate::Network::Zcash);
        let nu6_3 = crate::zcash::NetworkUpgrade::Nu6_3.activation_height(is_mainnet);
        if block_height < nu6_3 {
            return Err(format!(
                "Block height {} is before NU6.3 (Ironwood) activation ({}) on {}; \
                 v6 transactions are not valid before then",
                block_height,
                nu6_3,
                if is_mainnet { "mainnet" } else { "testnet" }
            ));
        }
        let consensus_branch_id = crate::zcash::branch_id_for_height(block_height, is_mainnet)
            .ok_or_else(|| {
                format!(
                    "Block height {} is before Overwinter activation on {}",
                    block_height,
                    if is_mainnet { "mainnet" } else { "testnet" }
                )
            })?;
        Ok(Self::new_v6(
            network,
            wallet_keys,
            consensus_branch_id,
            lock_time,
            expiry_height,
        ))
    }

    /// Create an empty Zcash **v6 (Ironwood)** shielding PSBT with an explicit consensus branch id.
    pub fn new_v6(
        network: crate::Network,
        wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
        consensus_branch_id: u32,
        lock_time: Option<u32>,
        expiry_height: Option<u32>,
    ) -> Self {
        let version_group_id = crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID;
        let expiry_height = expiry_height.unwrap_or(0);
        let mut z = Self::new(
            network,
            wallet_keys,
            consensus_branch_id,
            Some(6),
            lock_time,
            Some(version_group_id),
            Some(expiry_height),
        );
        // v6 has no Sapling fields; the v6 codec writes the empty Sapling/Orchard slots itself.
        z.sapling_fields = Vec::new();
        super::propkv::set_zec_v6_params(&mut z.psbt, version_group_id, expiry_height);
        super::propkv::set_zec_v6_consensus_branch_id(&mut z.psbt, consensus_branch_id);
        z
    }

    /// Whether this PSBT is a v6 (Ironwood) PSBT.
    pub fn is_ironwood_v6(&self) -> bool {
        self.version_group_id == Some(crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID)
    }

    /// Constructor role: build the shielded output (one Ironwood note to `recipient`) as an orchard
    /// PCZT and store it in the PSBT. `recipient` is a 43-byte raw Orchard/Ironwood address,
    /// `anchor` the current Ironwood note-commitment-tree root, `ovk` an optional raw outgoing
    /// viewing key, `memo` the 512-byte memo field.
    ///
    /// Ordering relative to the transparent inputs/outputs does not matter — the shielded action
    /// data does not depend on them — but the sighash does, so all transparent I/O must be in place
    /// before signing.
    ///
    /// Exactly one shielded output is supported; calling this twice is an error rather than a silent
    /// overwrite of the first note (whose value the transparent side would still be funding).
    pub fn add_ironwood_output<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        recipient: &[u8; crate::zcash::ironwood_build::ORCHARD_ADDRESS_SIZE],
        amount: u64,
        ovk: Option<[u8; 32]>,
        anchor: &[u8; 32],
        memo: &[u8; 512],
        rng: R,
    ) -> Result<(), String> {
        if super::propkv::get_ironwood_pczt(&self.psbt).is_some() {
            return Err(
                "an Ironwood shielded output is already present; only one is supported".to_string(),
            );
        }
        let pczt = crate::zcash::ironwood_build::construct_shield_pczt(
            recipient, amount, ovk, anchor, memo, rng,
        )
        .map_err(|e| e.to_string())?;
        let bytes =
            crate::zcash::ironwood_pczt::serialize_pczt(&pczt).map_err(|e| e.to_string())?;
        super::propkv::set_ironwood_pczt(&mut self.psbt, bytes);
        Ok(())
    }

    /// Deserialize the stored orchard PCZT.
    fn ironwood_pczt(&self) -> Result<orchard::pczt::Bundle, String> {
        let bytes = super::propkv::get_ironwood_pczt(&self.psbt)
            .ok_or_else(|| "no Ironwood PCZT stored in PSBT".to_string())?;
        crate::zcash::ironwood_pczt::deserialize_pczt(&bytes).map_err(|e| e.to_string())
    }

    /// The shielded action-data view of the stored PCZT (commitments/ciphertexts/flags/value/anchor;
    /// no proof or signatures). This is what the ZIP-244 txid and sighash commit to.
    pub fn ironwood_action_data(&self) -> Result<crate::zcash::v6::IronwoodBundle, String> {
        crate::zcash::ironwood_build::pczt_action_data(&self.ironwood_pczt()?)
            .map_err(|e| e.to_string())
    }

    /// The spent-output value (zatoshi, as i64) and scriptPubKey of every transparent input, in
    /// input order — the amounts/scripts ZIP-244 commits to.
    fn transparent_input_amounts_and_scripts(
        &self,
    ) -> Result<(Vec<i64>, Vec<miniscript::bitcoin::ScriptBuf>), String> {
        let mut amounts = Vec::with_capacity(self.psbt.inputs.len());
        let mut scripts = Vec::with_capacity(self.psbt.inputs.len());
        for (i, input) in self.psbt.inputs.iter().enumerate() {
            // `psbt.inputs` and `unsigned_tx.input` are parallel vectors by PSBT invariant, but a
            // skew here would be a WASM abort rather than a JS exception, so surface it as an error.
            let prevout = self
                .psbt
                .unsigned_tx
                .input
                .get(i)
                .ok_or_else(|| format!("input {i}: no matching tx input"))?
                .previous_output;
            let (script, value) =
                super::psbt_wallet_input::get_output_script_and_value(input, prevout)
                    .map_err(|e| format!("input {i}: missing UTXO value/script: {e}"))?;
            amounts.push(value.to_sat() as i64);
            scripts.push(script.clone());
        }
        Ok((amounts, scripts))
    }

    /// Assemble a [`ZcashV6Transaction`] from the transparent skeleton plus the given Ironwood
    /// bundle (action-data-only for digests, or fully authorized for extraction).
    fn to_v6_transaction(
        &self,
        transparent: Transaction,
        ironwood_bundle: Option<crate::zcash::v6::IronwoodBundle>,
    ) -> Result<crate::zcash::v6::ZcashV6Transaction, String> {
        let consensus_branch_id = super::propkv::get_zec_v6_consensus_branch_id(&self.psbt)
            .ok_or_else(|| "missing consensus_branch_id".to_string())?;
        Ok(crate::zcash::v6::ZcashV6Transaction {
            version_group_id: crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID,
            consensus_branch_id,
            transparent,
            expiry_height: self.expiry_height.unwrap_or(0),
            sapling_value_balance: 0,
            ironwood_bundle,
        })
    }

    /// The ZIP-244 v6 txid (internal byte order — reverse for display) of the transaction as it
    /// currently stands (transparent skeleton + shielded action data).
    pub fn v6_txid(&self) -> Result<[u8; 32], String> {
        let bundle = self.ironwood_action_data()?;
        let tx = self.to_v6_transaction(self.psbt.unsigned_tx.clone(), Some(bundle))?;
        Ok(crate::zcash::v6::compute_v6_txid(&tx))
    }

    /// ZIP-244 per-input transparent sighash for transparent input `index` (SIGHASH_ALL) — the
    /// message the key controlling that input must sign.
    pub fn v6_transparent_sighash(&self, index: usize) -> Result<[u8; 32], String> {
        let (amounts, scripts) = self.transparent_input_amounts_and_scripts()?;
        let bundle = self.ironwood_action_data()?;
        let tx = self.to_v6_transaction(self.psbt.unsigned_tx.clone(), Some(bundle))?;
        let input = self
            .psbt
            .inputs
            .get(index)
            .ok_or_else(|| format!("input {index} out of range"))?;
        let script_code = input
            .witness_script
            .as_ref()
            .or(input.redeem_script.as_ref())
            .ok_or_else(|| format!("input {index}: no redeem/witness script"))?;
        crate::zcash::v6::compute_v6_transparent_sighash(
            &tx,
            index,
            script_code.as_script(),
            &amounts,
            &scripts,
        )
        .map_err(|e| e.to_string())
    }

    /// Ingest a transparent-input signature returned by the client/HSM into `partial_sigs`, after
    /// verifying it against [`Self::v6_transparent_sighash`] for that input. `sig` is a DER ECDSA
    /// signature with the trailing SIGHASH_ALL byte (as it appears in a scriptSig).
    pub fn add_v6_transparent_signature(
        &mut self,
        index: usize,
        pubkey: miniscript::bitcoin::PublicKey,
        sig: &[u8],
    ) -> Result<(), String> {
        use miniscript::bitcoin::ecdsa::Signature as EcdsaSig;
        use miniscript::bitcoin::secp256k1::{Message, Secp256k1};

        // Reject a key the input's redeem script does not contain: such a signature would be
        // silently dropped at finalization, so fail at ingest where the caller can see it.
        let redeem_script = self
            .psbt
            .inputs
            .get(index)
            .ok_or_else(|| format!("input {index} out of range"))?
            .redeem_script
            .as_ref()
            .ok_or_else(|| format!("input {index}: no redeem script"))?;
        let script_pubkeys =
            crate::fixed_script_wallet::wallet_scripts::parse_multisig_script_2_of_3(redeem_script)
                .map_err(|e| format!("input {index}: {e}"))?;
        if !script_pubkeys
            .iter()
            .any(|pk| miniscript::bitcoin::PublicKey::from(*pk) == pubkey)
        {
            return Err(format!(
                "input {index}: pubkey is not one of the redeem script's keys"
            ));
        }

        let sighash = self.v6_transparent_sighash(index)?;
        let ecdsa_sig =
            EcdsaSig::from_slice(sig).map_err(|e| format!("input {index}: bad signature: {e}"))?;
        // `v6_transparent_sighash` always digests as SIGHASH_ALL; any other type byte would be
        // re-emitted verbatim by `finalized_transparent_tx`, producing a scriptSig whose signature
        // doesn't match the sighash a verifier recomputes for that type — fail at ingest instead.
        const SIGHASH_ALL: u32 = miniscript::bitcoin::sighash::EcdsaSighashType::All as u32;
        if ecdsa_sig.sighash_type != SIGHASH_ALL {
            return Err(format!(
                "input {index}: signature sighash type must be SIGHASH_ALL (0x{SIGHASH_ALL:02x}), got 0x{:02x}",
                ecdsa_sig.sighash_type
            ));
        }
        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest(sighash);
        secp.verify_ecdsa(&msg, &ecdsa_sig.signature, &pubkey.inner)
            .map_err(|e| {
                format!("input {index}: signature does not verify against v6 sighash: {e}")
            })?;
        self.psbt.inputs[index]
            .partial_sigs
            .insert(pubkey, ecdsa_sig);
        Ok(())
    }

    /// Build the finalized transparent transaction: clone the skeleton and fill each input's
    /// scriptSig from the collected `partial_sigs`, in the redeem script's pubkey order
    /// (`OP_0 <sig> <sig> <redeemScript>` for a 2-of-3 P2SH multisig). Zcash transparent inputs are
    /// non-segwit, so this produces a complete scriptSig with no witness.
    fn finalized_transparent_tx(&self) -> Result<Transaction, String> {
        use crate::fixed_script_wallet::wallet_scripts::parse_multisig_script_2_of_3;
        use miniscript::bitcoin::blockdata::opcodes::all::OP_PUSHBYTES_0;
        use miniscript::bitcoin::script::{Builder, PushBytesBuf};

        let mut tx = self.psbt.unsigned_tx.clone();
        for (i, txin) in tx.input.iter_mut().enumerate() {
            let input = self
                .psbt
                .inputs
                .get(i)
                .ok_or_else(|| format!("input {i}: no matching PSBT input"))?;
            let redeem_script = input
                .redeem_script
                .as_ref()
                .ok_or_else(|| format!("input {i}: no redeem script (expected P2SH multisig)"))?;
            let pubkeys = parse_multisig_script_2_of_3(redeem_script)
                .map_err(|e| format!("input {i}: {e}"))?;
            const REQUIRED_SIGS: usize = 2;

            // OP_0 (the multisig off-by-one dummy), then exactly REQUIRED_SIGS signatures in pubkey
            // order. Pushing every collected signature would break a 2-of-3 input signed by all
            // three keys: OP_CHECKMULTISIG pops exactly 2 and the extra push fails the script.
            let mut builder = Builder::new().push_opcode(OP_PUSHBYTES_0);
            let mut sig_count = 0usize;
            for pk in &pubkeys {
                if sig_count == REQUIRED_SIGS {
                    break;
                }
                if let Some(sig) = input
                    .partial_sigs
                    .get(&miniscript::bitcoin::PublicKey::from(*pk))
                {
                    let mut buf = PushBytesBuf::new();
                    buf.extend_from_slice(&sig.to_vec())
                        .map_err(|e| format!("input {i}: sig too large: {e}"))?;
                    builder = builder.push_slice(&buf);
                    sig_count += 1;
                }
            }
            if sig_count < REQUIRED_SIGS {
                return Err(format!(
                    "input {i}: only {sig_count} of {REQUIRED_SIGS} required signatures collected"
                ));
            }
            let mut rs = PushBytesBuf::new();
            rs.extend_from_slice(redeem_script.as_bytes())
                .map_err(|e| format!("input {i}: redeem script too large: {e}"))?;
            builder = builder.push_slice(&rs);
            txin.script_sig = builder.into_script();
        }
        Ok(tx)
    }

    /// Transaction Extractor role: given the external prover's `proof` bytes, finalize the
    /// transparent inputs, apply the shielded binding signature, and produce the broadcast-ready v6
    /// transaction bytes.
    ///
    /// The PSBT must already carry every transparent input's signatures (via
    /// [`Self::add_v6_transparent_signature`]) and the PCZT (from [`Self::add_ironwood_output`]).
    /// `rng` seeds both the dummy spend-auth signature (in the IO finalizer) and the binding
    /// signature (in the Transaction Extractor). Consumes `self`.
    pub fn combine_ironwood_proof<R: rand::RngCore + rand::CryptoRng>(
        self,
        proof: Vec<u8>,
        mut rng: R,
    ) -> Result<Vec<u8>, String> {
        use crate::zcash::{ironwood_build, ironwood_pczt};

        // Finalize the transparent inputs first: it enforces the 2-of-3 signature threshold, so an
        // under-signed PSBT fails here instead of after the (expensive) shielded finalize/combine.
        let transparent = self.finalized_transparent_tx()?;

        // The shielded binding signature signs the ZIP-244 sig digest over the complete tx
        // (transparent I/O + shielded action data). Signatures/proof are excluded from that digest,
        // so it is stable regardless of transparent-input signing.
        let (amounts, scripts) = self.transparent_input_amounts_and_scripts()?;
        let action_bundle = self.ironwood_action_data()?;
        let sig_tx = self.to_v6_transaction(self.psbt.unsigned_tx.clone(), Some(action_bundle))?;
        let sighash = crate::zcash::v6::compute_v6_sig_digest(&sig_tx, &amounts, &scripts);

        // Signer + IO finalizer: sign the dummy spend(s) and derive the binding signing key.
        let mut pczt = self.ironwood_pczt()?;
        ironwood_build::finalize_shield_io(&mut pczt, sighash, &mut rng)
            .map_err(|e| e.to_string())?;

        // Splice in the external proof, then run the Transaction Extractor.
        let signed_bytes = ironwood_pczt::serialize_pczt(&pczt).map_err(|e| e.to_string())?;
        let proven = ironwood_pczt::deserialize_pczt(
            &ironwood_pczt::with_zkproof(&signed_bytes, proof).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let full_bundle =
            ironwood_build::combine(&proven, sighash, &mut rng).map_err(|e| e.to_string())?;

        let tx = self.to_v6_transaction(transparent, Some(full_bundle))?;
        crate::zcash::v6::encode_v6_transaction(&tx).map_err(|e| e.to_string())
    }

    /// Serialize a v6 PSBT to bytes: a plain PSBT carrying the transparent skeleton in
    /// `unsigned_tx` and the shielded state (PCZT, branch id, v6 params) in the proprietary map.
    pub fn serialize_v6(&self) -> Vec<u8> {
        self.psbt.serialize()
    }

    /// Deserialize a v6 PSBT produced by [`Self::serialize_v6`], restoring the v6 header params from
    /// the proprietary map.
    pub fn deserialize_v6(
        bytes: &[u8],
        network: crate::Network,
    ) -> Result<Self, super::DeserializeError> {
        let psbt = Psbt::deserialize(bytes)?;
        let (version_group_id, expiry_height) = super::propkv::get_zec_v6_params(&psbt)
            .ok_or_else(|| {
                super::DeserializeError::Network(
                    "PSBT is missing the ZecV6Params proprietary key (not a v6 PSBT)".to_string(),
                )
            })?;
        // Validate rather than trust: an unchecked version_group_id would leave
        // `is_ironwood_v6()` false on a PSBT that just came out of `deserialize_v6`, which would
        // then route `serialize` back down the v4 path.
        if version_group_id != crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID {
            return Err(super::DeserializeError::Network(format!(
                "PSBT declares version_group_id {:#010x}, expected the Ironwood id {:#010x}",
                version_group_id,
                crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID
            )));
        }
        // Defense-in-depth: a v6 PSBT missing these would otherwise deserialize fine and only fail
        // later, in v6_txid/combine_ironwood_proof, with a less obvious error.
        if super::propkv::get_zec_v6_consensus_branch_id(&psbt).is_none() {
            return Err(super::DeserializeError::Network(
                "v6 PSBT is missing its consensus branch id".to_string(),
            ));
        }
        if super::propkv::get_ironwood_pczt(&psbt).is_none() {
            return Err(super::DeserializeError::Network(
                "v6 PSBT is missing its Ironwood PCZT".to_string(),
            ));
        }
        Ok(ZcashBitGoPsbt {
            psbt,
            network,
            version_group_id: Some(version_group_id),
            expiry_height: Some(expiry_height),
            sapling_fields: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::{general_purpose::STANDARD as BASE64_STANDARD, Engine};

    #[test]
    fn test_decode_zcash_transaction() {
        // Version with overwintered bit
        let version = 0x80000004u32;
        let mut tx_bytes = Vec::new();

        // Version
        version.consensus_encode(&mut tx_bytes).unwrap();

        // Version group ID
        ZCASH_SAPLING_VERSION_GROUP_ID
            .consensus_encode(&mut tx_bytes)
            .unwrap();

        // Empty inputs
        0u8.consensus_encode(&mut tx_bytes).unwrap();

        // Empty outputs
        0u8.consensus_encode(&mut tx_bytes).unwrap();

        // Lock time
        0u32.consensus_encode(&mut tx_bytes).unwrap();

        // Expiry height
        0u32.consensus_encode(&mut tx_bytes).unwrap();

        let parts = crate::zcash::transaction::decode_zcash_transaction_parts(&tx_bytes).unwrap();

        assert_eq!(parts.version_group_id, Some(ZCASH_SAPLING_VERSION_GROUP_ID));
        assert_eq!(parts.expiry_height, Some(0));
        assert_eq!(parts.transaction.input.len(), 0);
        assert_eq!(parts.transaction.output.len(), 0);
        // Should be empty for this simple test tx
        assert!(parts.sapling_fields.is_empty());
    }

    #[test]
    fn test_round_trip_zcash_psbt() {
        use crate::fixed_script_wallet::test_utils::fixtures::{
            load_psbt_fixture_with_format_and_namespace, FixtureNamespace, SignatureState, TxFormat,
        };
        use crate::networks::Network;

        // Load the Zcash fixture from utxolib-compat
        let fixture = load_psbt_fixture_with_format_and_namespace(
            "zcash",
            SignatureState::Unsigned,
            TxFormat::Psbt,
            FixtureNamespace::UtxolibCompat,
        )
        .expect("Failed to load Zcash fixture");

        // Deserialize from fixture
        let original_bytes = BASE64_STANDARD.decode(&fixture.psbt_base64).unwrap();
        let zcash_psbt = ZcashBitGoPsbt::deserialize(&original_bytes, Network::Zcash).unwrap();

        // Verify Zcash-specific fields were extracted
        assert!(zcash_psbt.version_group_id.is_some());
        assert!(zcash_psbt.expiry_height.is_some());

        // Verify transaction was parsed
        assert_eq!(zcash_psbt.psbt.unsigned_tx.input.len(), 2);
        assert_eq!(zcash_psbt.psbt.unsigned_tx.output.len(), 4);

        // Serialize back
        let serialized = zcash_psbt.serialize().unwrap();

        // Note: We don't assert byte-for-byte equality because PSBT serialization may reorder
        // global map entries. Instead, we verify that deserializing the serialized PSBT
        // produces the same data.

        // Deserialize again
        let round_trip = ZcashBitGoPsbt::deserialize(&serialized, Network::Zcash).unwrap();

        // Verify the data matches
        assert_eq!(
            zcash_psbt.version_group_id, round_trip.version_group_id,
            "Version group ID should match"
        );
        assert_eq!(
            zcash_psbt.expiry_height, round_trip.expiry_height,
            "Expiry height should match"
        );
        assert_eq!(
            zcash_psbt.psbt.unsigned_tx.input.len(),
            round_trip.psbt.unsigned_tx.input.len(),
            "Input count should match"
        );
        assert_eq!(
            zcash_psbt.psbt.unsigned_tx.output.len(),
            round_trip.psbt.unsigned_tx.output.len(),
            "Output count should match"
        );
        assert_eq!(
            zcash_psbt.psbt.inputs.len(),
            round_trip.psbt.inputs.len(),
            "PSBT input count should match"
        );
        assert_eq!(
            zcash_psbt.psbt.outputs.len(),
            round_trip.psbt.outputs.len(),
            "PSBT output count should match"
        );
    }
}

/// End-to-end v6 (Ironwood) shielding through the PSBT layer. Native-only (orchard + zebra).
#[cfg(all(test, not(target_arch = "wasm32")))]
mod ironwood_v6_tests {
    use super::*;
    use crate::bitcoin::bip32::{DerivationPath, Xpriv};
    use crate::bitcoin::hashes::{sha256, Hash};
    use crate::bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use crate::bitcoin::{CompressedPublicKey, Network as BtcNetwork, PublicKey, Txid};
    use crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::WalletInputOptions;
    use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt;
    use crate::fixed_script_wallet::script_id::ScriptId;
    use crate::fixed_script_wallet::test_utils::get_test_wallet_keys;
    use crate::fixed_script_wallet::wallet_scripts::chain_index_path;
    use crate::fixed_script_wallet::RootWalletKeys;
    use crate::networks::Network;
    use crate::zcash::NetworkUpgrade;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use orchard::tree::Anchor;
    use orchard::Proof;
    use rand::rngs::OsRng;
    use std::str::FromStr;

    /// A deterministic Ironwood receiver derived from a fixed spending key.
    fn test_recipient() -> [u8; 43] {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        FullViewingKey::from(&sk)
            .address_at(0u32, Scope::External)
            .to_raw_address_bytes()
    }

    /// The three wallet signing keys derived at `chain/index`, matching `get_test_wallet_keys`
    /// (same `seed.N` scheme), so their pubkeys equal the multisig redeem script's.
    ///
    /// `RootWalletKeys::new` derives every (chain, index) key under a fixed `m/0/0` prefix (see
    /// `RootWalletKeys::new`), so the path here must match: `m/0/0/<chain>/<index>`.
    fn signing_secret_keys(seed: &str, chain: u32, index: u32) -> [SecretKey; 3] {
        let secp = Secp256k1::new();
        let prefix = DerivationPath::from_str("m/0/0").unwrap();
        let path = prefix.extend(chain_index_path(chain, index));
        let mut keys = Vec::with_capacity(3);
        for i in 0..3u8 {
            let hash = sha256::Hash::hash(format!("{seed}.{i}").as_bytes()).to_byte_array();
            let master = Xpriv::new_master(BtcNetwork::Testnet, &hash).unwrap();
            keys.push(master.derive_priv(&secp, &path).unwrap().private_key);
        }
        keys.try_into().unwrap()
    }

    #[test]
    fn build_sign_combine_produces_valid_v6_tx() {
        let seed = "ironwood_v6_psbt";
        let wallet_keys = RootWalletKeys::new(get_test_wallet_keys(seed));
        let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();

        // Build: one 2-of-3 P2SH transparent input (2 ZEC), a transparent change output, and a
        // shielded Ironwood output (1 ZEC).
        let mut psbt = BitGoPsbt::new_zcash_v6_at_height(
            Network::ZcashTestnet,
            &wallet_keys,
            nu6_3,
            None,
            None,
        )
        .unwrap();
        psbt.add_wallet_input(
            Txid::from_byte_array([0x22u8; 32]),
            0,
            200_000_000,
            &wallet_keys,
            ScriptId { chain: 0, index: 0 },
            WalletInputOptions::default(),
        )
        .unwrap();
        psbt.add_wallet_output(0, 1, 99_900_000, &wallet_keys)
            .unwrap();

        let BitGoPsbt::Zcash(mut z, _) = psbt else {
            panic!("expected Zcash PSBT");
        };
        assert!(z.is_ironwood_v6());
        z.add_ironwood_output(
            &test_recipient(),
            100_000_000,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();

        // The v6 txid is defined at build time (before signing/proving).
        let txid = z.v6_txid().unwrap();

        // Serialize → deserialize preserves the transparent skeleton, PCZT, branch id, and v6 params.
        let bytes = z.serialize_v6();
        let z2 = ZcashBitGoPsbt::deserialize_v6(&bytes, Network::ZcashTestnet).unwrap();
        assert!(z2.is_ironwood_v6());
        assert_eq!(z2.v6_txid().unwrap(), txid, "txid survives PSBT round-trip");

        // Sign the transparent input with user + bitgo (keys 0 and 2) over the ZIP-244 sighash.
        let secp = Secp256k1::new();
        let sighash = z.v6_transparent_sighash(0).unwrap();
        let msg = Message::from_digest(sighash);
        for i in [0usize, 2] {
            let sk = signing_secret_keys(seed, 0, 0)[i];
            let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
            let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
            let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
            der.push(0x01); // SIGHASH_ALL
            z.add_v6_transparent_signature(0, pubkey, &der).unwrap();
        }

        // Combine with a canonical-length placeholder proof (stands in for the external prover).
        let proof = vec![0u8; Proof::expected_proof_size(1)];
        let raw = z.combine_ironwood_proof(proof, OsRng).unwrap();

        // The result is a well-formed v6 transaction with a finalized transparent input and the
        // shielded bundle.
        let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
        assert_eq!(tx.transparent.input.len(), 1);
        assert_eq!(tx.transparent.output.len(), 1);
        assert!(
            !tx.transparent.input[0].script_sig.is_empty(),
            "input finalized"
        );
        let bundle = tx.ironwood_bundle.as_ref().unwrap();
        assert_eq!(bundle.actions.len(), 1);
        assert_eq!(bundle.spend_auth_sigs.len(), 1);
        assert_eq!(bundle.proof.len(), Proof::expected_proof_size(1));

        // txid is unchanged by signing/proving (ZIP-244 excludes scriptSigs, proof, and sigs).
        let mut internal = crate::zcash::v6::compute_v6_txid(&tx);
        assert_eq!(internal, txid);

        // zebra-chain independently decodes the combined tx and agrees on the txid.
        use zebra_chain::serialization::ZcashDeserialize;
        use zebra_chain::transaction::Transaction as ZebraTx;
        let zebra = ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes v6 tx");
        assert_eq!(zebra.version(), 6);
        assert_eq!(zebra.ironwood_actions().count(), 1);
        internal.reverse();
        assert_eq!(
            zebra.hash().to_string(),
            hex::encode(internal),
            "zebra txid == ours"
        );
    }

    /// The root `Xpriv` behind key `i` of `get_test_wallet_keys(seed)` (same `seed.N` scheme).
    fn test_wallet_xpriv(seed: &str, i: u8) -> Xpriv {
        let hash = sha256::Hash::hash(format!("{seed}.{i}").as_bytes()).to_byte_array();
        Xpriv::new_master(BtcNetwork::Testnet, &hash).unwrap()
    }

    /// A minimal v6 PSBT with one 2-of-3 P2SH input, a change output, and a shielded output.
    fn build_shield_psbt(seed: &str) -> ZcashBitGoPsbt {
        let wallet_keys = RootWalletKeys::new(get_test_wallet_keys(seed));
        let mut psbt = BitGoPsbt::new_zcash_v6_at_height(
            Network::ZcashTestnet,
            &wallet_keys,
            NetworkUpgrade::Nu6_3.testnet_activation_height(),
            None,
            None,
        )
        .unwrap();
        psbt.add_wallet_input(
            Txid::from_byte_array([0x33u8; 32]),
            0,
            200_000_000,
            &wallet_keys,
            ScriptId { chain: 0, index: 0 },
            WalletInputOptions::default(),
        )
        .unwrap();
        psbt.add_wallet_output(0, 1, 99_900_000, &wallet_keys)
            .unwrap();
        let BitGoPsbt::Zcash(mut z, _) = psbt else {
            panic!("expected Zcash PSBT");
        };
        z.add_ironwood_output(
            &test_recipient(),
            100_000_000,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        z
    }

    /// `new_v6_at_height` rejects a height before NU6.3 rather than stamping the transaction with a
    /// branch id that only fails at broadcast.
    #[test]
    fn new_v6_at_height_rejects_pre_nu6_3_height() {
        let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("v6_height"));
        let nu6_3 = NetworkUpgrade::Nu6_3.testnet_activation_height();
        let err = ZcashBitGoPsbt::new_v6_at_height(
            Network::ZcashTestnet,
            &wallet_keys,
            nu6_3 - 1,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("NU6.3"), "unexpected error: {err}");
        // The activation height itself is accepted.
        assert!(ZcashBitGoPsbt::new_v6_at_height(
            Network::ZcashTestnet,
            &wallet_keys,
            nu6_3,
            None,
            None
        )
        .is_ok());
    }

    /// A second shielded output is an error, not a silent overwrite of the first note.
    #[test]
    fn add_ironwood_output_twice_is_rejected() {
        let mut z = build_shield_psbt("v6_double_output");
        let err = z
            .add_ironwood_output(
                &test_recipient(),
                1,
                None,
                &Anchor::empty_tree().to_bytes(),
                &[0u8; 512],
                OsRng,
            )
            .unwrap_err();
        assert!(err.contains("already present"), "unexpected error: {err}");
    }

    /// A signature from a key outside the input's redeem script is rejected at ingest, rather than
    /// being silently dropped at finalization.
    #[test]
    fn add_v6_signature_rejects_foreign_pubkey() {
        let mut z = build_shield_psbt("v6_foreign_key");
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
        let msg = Message::from_digest(z.v6_transparent_sighash(0).unwrap());
        let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
        der.push(0x01);
        let err = z.add_v6_transparent_signature(0, pubkey, &der).unwrap_err();
        assert!(
            err.contains("not one of the redeem script's keys"),
            "unexpected error: {err}"
        );
    }

    /// A signature tagged with a sighash type other than SIGHASH_ALL is rejected at ingest: the
    /// sighash it was verified against is always the SIGHASH_ALL digest, so re-emitting it with a
    /// different type byte would make a verifier recompute a different (mismatching) digest.
    #[test]
    fn add_v6_signature_rejects_non_sighash_all() {
        let mut z = build_shield_psbt("v6_wrong_sighash_type");
        let seed = "v6_wrong_sighash_type";
        let secp = Secp256k1::new();
        let sk = signing_secret_keys(seed, 0, 0)[0];
        let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
        let msg = Message::from_digest(z.v6_transparent_sighash(0).unwrap());
        let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
        der.push(0x02); // SIGHASH_NONE, not SIGHASH_ALL
        let err = z.add_v6_transparent_signature(0, pubkey, &der).unwrap_err();
        assert!(err.contains("SIGHASH_ALL"), "unexpected error: {err}");
    }

    /// A 2-of-3 input signed by all three keys still produces a 2-signature scriptSig;
    /// `OP_CHECKMULTISIG` pops exactly two, so a third push would fail the script.
    #[test]
    fn combine_uses_only_required_signatures() {
        let seed = "v6_three_sigs";
        let mut z = build_shield_psbt(seed);
        let secp = Secp256k1::new();
        let msg = Message::from_digest(z.v6_transparent_sighash(0).unwrap());
        for sk in signing_secret_keys(seed, 0, 0) {
            let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
            let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
            let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
            der.push(0x01);
            z.add_v6_transparent_signature(0, pubkey, &der).unwrap();
        }
        assert_eq!(z.psbt.inputs[0].partial_sigs.len(), 3);
        let redeem_script = z.psbt.inputs[0].redeem_script.clone().unwrap();

        let raw = z
            .combine_ironwood_proof(vec![0u8; Proof::expected_proof_size(1)], OsRng)
            .unwrap();
        let tx = crate::zcash::v6::decode_v6_transaction(&raw).unwrap();
        // rust-bitcoin decodes OP_0 as a zero-length push, so the expected shape is
        // `<empty> <sig> <sig> <redeemScript>` — four pushes, two of them signatures. A third
        // signature here would make OP_CHECKMULTISIG fail on the leftover stack element.
        let pushes: Vec<Vec<u8>> = tx.transparent.input[0]
            .script_sig
            .instructions()
            .map(|i| i.expect("valid scriptSig"))
            .filter_map(|i| match i {
                crate::bitcoin::script::Instruction::PushBytes(pb) => Some(pb.as_bytes().to_vec()),
                crate::bitcoin::script::Instruction::Op(_) => None,
            })
            .collect();
        assert_eq!(pushes.len(), 4, "OP_0 <sig> <sig> <redeemScript>");
        assert!(pushes[0].is_empty(), "OP_0 dummy");
        assert_eq!(pushes[3], redeem_script.as_bytes());
        // The two signatures are the first two redeem-script keys that signed, in script order.
        for sig in &pushes[1..3] {
            assert_eq!(*sig.last().unwrap(), 0x01, "SIGHASH_ALL");
        }
    }

    /// An under-signed transparent input is rejected before the (expensive) shielded
    /// finalize/combine work runs, not after.
    #[test]
    fn combine_ironwood_proof_fails_fast_on_missing_signatures() {
        let mut z = build_shield_psbt("v6_undersigned");
        let seed = "v6_undersigned";
        let secp = Secp256k1::new();
        let msg = Message::from_digest(z.v6_transparent_sighash(0).unwrap());
        // Only one of the required two signatures.
        let sk = signing_secret_keys(seed, 0, 0)[0];
        let secp_pk = crate::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pubkey = PublicKey::from(CompressedPublicKey(secp_pk));
        let mut der = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
        der.push(0x01);
        z.add_v6_transparent_signature(0, pubkey, &der).unwrap();

        let err = z
            .combine_ironwood_proof(vec![0u8; Proof::expected_proof_size(1)], OsRng)
            .unwrap_err();
        assert!(
            err.contains("required signatures collected"),
            "unexpected error: {err}"
        );
    }

    /// The v4 code paths refuse a v6 PSBT instead of emitting a v4-shaped transaction (which would
    /// be unbroadcastable) or a ZIP-243 signature (which could never verify).
    #[test]
    fn v4_paths_reject_a_v6_psbt() {
        let z = build_shield_psbt("v6_v4_guard");
        for err in [
            z.serialize().unwrap_err().to_string(),
            z.extract_unsigned_zcash_transaction()
                .unwrap_err()
                .to_string(),
            z.compute_txid().unwrap_err().to_string(),
            z.clone().extract_tx().unwrap_err().to_string(),
        ] {
            assert!(
                err.contains("v6 (Ironwood) PSBT"),
                "unexpected error: {err}"
            );
        }

        // The generic sign path refuses too, so no ZIP-243 signature can reach `partial_sigs`.
        let mut generic = BitGoPsbt::Zcash(z, Network::ZcashTestnet);
        let err = generic
            .sign_all_with_xpriv(&test_wallet_xpriv("v6_v4_guard", 0))
            .unwrap_err();
        assert!(
            err.contains("v6 (Ironwood) PSBT"),
            "unexpected error: {err}"
        );
        assert!(
            generic.psbt().inputs[0].partial_sigs.is_empty(),
            "no ZIP-243 signature reached partial_sigs"
        );
    }

    /// `deserialize_v6` validates the version group id rather than trusting it — an unchecked value
    /// would leave `is_ironwood_v6()` false and route `serialize` back down the v4 path.
    #[test]
    fn deserialize_v6_rejects_a_non_ironwood_version_group_id() {
        let mut z = build_shield_psbt("v6_bad_vgid");
        crate::fixed_script_wallet::bitgo_psbt::propkv::set_zec_v6_params(
            &mut z.psbt,
            ZCASH_SAPLING_VERSION_GROUP_ID,
            0,
        );
        let err = ZcashBitGoPsbt::deserialize_v6(&z.serialize_v6(), Network::ZcashTestnet)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("expected the Ironwood id"),
            "unexpected error: {err}"
        );
    }

    /// `deserialize_v6` rejects a PSBT missing its consensus branch id, rather than deserializing
    /// successfully and failing later (with a less obvious error) in v6_txid/combine.
    #[test]
    fn deserialize_v6_rejects_a_missing_branch_id() {
        let z = build_shield_psbt("v6_missing_branch_id");
        let mut psbt = z.psbt.clone();
        psbt.proprietary.retain(|k, _| {
            !(k.prefix == crate::fixed_script_wallet::bitgo_psbt::propkv::BITGO_ZEC_V6
                && k.subtype == 0x00)
        });
        let err = ZcashBitGoPsbt::deserialize_v6(&psbt.serialize(), Network::ZcashTestnet)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("missing its consensus branch id"),
            "unexpected error: {err}"
        );
    }

    /// `deserialize_v6` rejects a PSBT missing its Ironwood PCZT, rather than deserializing
    /// successfully and failing later (with a less obvious error) in v6_txid/combine.
    #[test]
    fn deserialize_v6_rejects_a_missing_pczt() {
        let z = build_shield_psbt("v6_missing_pczt");
        let mut psbt = z.psbt.clone();
        psbt.proprietary.retain(|k, _| {
            !(k.prefix == crate::fixed_script_wallet::bitgo_psbt::propkv::BITGO_ZEC_V6
                && k.subtype == 0x01)
        });
        let err = ZcashBitGoPsbt::deserialize_v6(&psbt.serialize(), Network::ZcashTestnet)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("missing its Ironwood PCZT"),
            "unexpected error: {err}"
        );
    }

    /// Build a PCZT whose action data equals the given bundle's, with all witness fields absent —
    /// enough for the effects-only (action-data) view the sighash/txid need. Used to reconstruct
    /// the on-chain fixture's shielded state inside a PSBT.
    fn pczt_bytes_from_action_data(bundle: &crate::zcash::v6::IronwoodBundle) -> Vec<u8> {
        use orchard::bundle::BundleVersion;
        use orchard::note::Nullifier;
        use orchard::pczt::{
            Action as PcztAction, Bundle as PcztBundle, Output as PcztOutput, Spend as PcztSpend,
        };
        use std::collections::BTreeMap;

        let bundle_version = BundleVersion::ironwood_v3();
        let note_version = bundle_version.note_version();

        let actions = bundle
            .actions
            .iter()
            .map(|a| {
                let spend = PcztSpend::parse(
                    a.nullifier,
                    a.rk,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    note_version,
                    BTreeMap::new(),
                )
                .expect("valid spend");
                let spend_nullifier =
                    Option::<Nullifier>::from(Nullifier::from_bytes(&a.nullifier)).unwrap();
                let output = PcztOutput::parse(
                    spend_nullifier,
                    a.cmx,
                    a.ephemeral_key,
                    a.enc_ciphertext.to_vec(),
                    a.out_ciphertext.to_vec(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    note_version,
                    BTreeMap::new(),
                )
                .expect("valid output");
                PcztAction::parse(a.cv, spend, output, None).expect("valid action")
            })
            .collect::<Vec<_>>();

        let magnitude = bundle.value_balance.unsigned_abs();
        let negative = bundle.value_balance.is_negative();
        let pczt = PcztBundle::parse(
            actions,
            bundle.flags,
            bundle_version,
            (magnitude, negative),
            bundle.anchor,
            None,
            None,
        )
        .expect("valid pczt bundle");
        crate::zcash::ironwood_pczt::serialize_pczt(&pczt).unwrap()
    }

    /// The public/consensus-committed values from the reference build of the on-chain `shield1zec`
    /// transaction. The spent output's value and scriptPubKey are committed by ZIP-244 but are not
    /// on the wire, so they can only come from the reference — hence the fixture rather than
    /// literals in the test body.
    #[derive(serde::Deserialize)]
    struct Shield1ZecDetails {
        txid: String,
        expiry_height: u32,
        lock_time: u32,
        transparent_utxos_spent: Vec<Shield1ZecUtxo>,
        value_balance_zat: i64,
        flags_byte: u8,
        num_actions: usize,
        transparent_public_key_sec1: String,
    }

    #[derive(serde::Deserialize)]
    struct Shield1ZecUtxo {
        txid: String,
        index: u32,
        value_zat: i64,
        script_pubkey: String,
    }

    fn shield1zec_details() -> Shield1ZecDetails {
        serde_json::from_str(
            &crate::fixed_script_wallet::test_utils::fixtures::load_fixture(
                "zcash/v6_shield1zec_details.json",
            )
            .unwrap(),
        )
        .unwrap()
    }

    /// Golden PSBT-level oracle: the `v6_transparent_sighash` the PSBT produces from the on-chain
    /// `shield1zec` transaction verifies the transaction's **real** ECDSA signature, and the PSBT's
    /// `v6_txid` reproduces the transaction's **real** txid.
    ///
    /// This closes a gap the synthetic end-to-end test cannot: there the sighash is computed for
    /// both signing and verifying by the same code, so a consistently-wrong spent-output
    /// value/script would still verify. Here the signature was produced by an **external** signer
    /// using the true amount + scriptPubKey, so it only verifies if the PSBT threaded the real
    /// spent-output value and scriptCode into the sighash correctly.
    ///
    /// The txid assertion is the complementary half: the ZIP-244 txid does not commit to input
    /// amounts/scripts (so it cannot catch what the sighash check catches), but it does commit to
    /// the shielded action data, which pins `pczt_bytes_from_action_data` → `ironwood_action_data`
    /// → `to_v6_transaction` against a value produced entirely outside this codebase.
    #[test]
    fn golden_shield1zec_psbt_sighash_verifies_real_signature() {
        use crate::bitcoin::script::Instruction;
        use crate::bitcoin::secp256k1::{
            ecdsa::Signature, Message, PublicKey as SecpPk, Secp256k1,
        };
        use crate::bitcoin::{Amount, ScriptBuf, TxOut};
        use crate::zcash::v6::{compute_v6_transparent_sighash, decode_v6_transaction};

        let raw = hex::decode(
            crate::fixed_script_wallet::test_utils::fixtures::load_fixture(
                "zcash/v6_shield1zec_rawtx.hex",
            )
            .unwrap()
            .trim(),
        )
        .unwrap();
        let tx = decode_v6_transaction(&raw).unwrap();
        let bundle = tx.ironwood_bundle.clone().expect("ironwood bundle");
        assert_eq!(tx.transparent.input.len(), 1);

        // Cross-check the decoded tx against the reference's record of it, so a fixture/raw-tx
        // mismatch fails here rather than as a confusing sighash mismatch below.
        let details = shield1zec_details();
        assert_eq!(details.transparent_utxos_spent.len(), 1);
        let spent = &details.transparent_utxos_spent[0];
        assert_eq!(tx.expiry_height, details.expiry_height);
        assert_eq!(
            tx.transparent.lock_time.to_consensus_u32(),
            details.lock_time
        );
        assert_eq!(
            tx.transparent.input[0].previous_output.txid.to_string(),
            spent.txid
        );
        assert_eq!(tx.transparent.input[0].previous_output.vout, spent.index);
        assert_eq!(bundle.actions.len(), details.num_actions);
        assert_eq!(bundle.value_balance, details.value_balance_zat);
        assert_eq!(bundle.flags, details.flags_byte);

        // Spent output committed by ZIP-244 but absent from the wire (from the reference build).
        let prevout_value: i64 = spent.value_zat;
        let prevout_script = ScriptBuf::from(hex::decode(&spent.script_pubkey).unwrap());

        // The real P2PKH signature + pubkey from the on-chain scriptSig.
        let pushes: Vec<Vec<u8>> = tx.transparent.input[0]
            .script_sig
            .instructions()
            .map(|i| i.expect("valid scriptSig"))
            .filter_map(|i| match i {
                Instruction::PushBytes(pb) => Some(pb.as_bytes().to_vec()),
                Instruction::Op(_) => None,
            })
            .collect();
        assert_eq!(pushes.len(), 2);
        let der = &pushes[0][..pushes[0].len() - 1]; // strip trailing SIGHASH_ALL byte
        let pubkey_bytes = &pushes[1];
        assert_eq!(
            hex::encode(pubkey_bytes),
            details.transparent_public_key_sec1,
            "on-chain scriptSig pubkey == the reference's signing key"
        );

        // Reconstruct the fixture's state inside a v6 PSBT: transparent skeleton (scriptSigs
        // stripped), the spent output hydrated as witness_utxo (this is the extraction under test),
        // and the shielded action data as a stored PCZT.
        let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("shield1zec_psbt"));
        let mut z = ZcashBitGoPsbt::new_v6(
            Network::ZcashTestnet,
            &wallet_keys,
            tx.consensus_branch_id,
            Some(tx.transparent.lock_time.to_consensus_u32()),
            Some(tx.expiry_height),
        );
        let mut skeleton = tx.transparent.clone();
        for i in skeleton.input.iter_mut() {
            i.script_sig = ScriptBuf::new();
        }
        z.psbt.unsigned_tx = skeleton;
        let mut input = crate::bitcoin::psbt::Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(prevout_value as u64),
                script_pubkey: prevout_script.clone(),
            }),
            ..Default::default()
        };
        // `redeem_script` is overloaded here to carry the scriptCode, not a real P2SH redeem
        // script: for a P2PKH input the scriptCode is just the scriptPubKey, and the wrapper below
        // reads scriptCode from redeem/witness_script.
        input.redeem_script = Some(prevout_script.clone());
        z.psbt.inputs = vec![input];
        z.psbt.outputs = vec![crate::bitcoin::psbt::Output::default(); tx.transparent.output.len()];
        crate::fixed_script_wallet::bitgo_psbt::propkv::set_ironwood_pczt(
            &mut z.psbt,
            pczt_bytes_from_action_data(&bundle),
        );

        // The PSBT-derived sighash must equal the codec's (PR1-golden) sighash — i.e. the PSBT
        // threaded the spent-output value + script through correctly.
        let psbt_sighash = z.v6_transparent_sighash(0).unwrap();
        let codec_sighash = compute_v6_transparent_sighash(
            &tx,
            0,
            prevout_script.as_script(),
            &[prevout_value],
            std::slice::from_ref(&prevout_script),
        )
        .unwrap();
        assert_eq!(psbt_sighash, codec_sighash, "PSBT sighash == codec golden");

        // And the transaction's real signature verifies against the PSBT-derived sighash.
        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest(psbt_sighash);
        let mut sig = Signature::from_der(der).expect("DER signature");
        sig.normalize_s();
        let pk = SecpPk::from_slice(pubkey_bytes).expect("valid pubkey");
        secp.verify_ecdsa(&msg, &sig, &pk)
            .expect("real signature verifies against the PSBT-derived v6 sighash");

        // And the PSBT reproduces the transaction's real, externally-produced txid — the shielded
        // action data survived the PCZT round-trip byte-for-byte. `v6_txid` is internal byte order;
        // the fixture records the display order.
        let mut psbt_txid = z.v6_txid().unwrap();
        psbt_txid.reverse();
        assert_eq!(
            hex::encode(psbt_txid),
            details.txid,
            "PSBT-derived v6 txid == the on-chain txid"
        );
    }
}
