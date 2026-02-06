//! Versioned transaction building from raw MessageV0 data.
//!
//! This module provides `build_from_raw_versioned_data` for building versioned
//! transactions from pre-compiled MessageV0 data. This is used for:
//! - WalletConnect/Jupiter pre-compiled versioned transactions
//! - Custom transaction pass-through (customTx intent)
//!
//! Unlike the intent-based builder, this takes already-compiled instruction
//! data with account indexes, not high-level instructions.

use crate::error::WasmSolanaError;
use serde::Deserialize;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_message::v0::Message as MessageV0;
use solana_message::v0::MessageAddressTableLookup;
use solana_message::MessageHeader;
use solana_sdk::bs58;
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_transaction::versioned::VersionedTransaction;
use std::str::FromStr;

// =============================================================================
// Types for Raw Versioned Transaction Data
// =============================================================================

/// Raw versioned transaction data for direct serialization.
/// This is used when we have pre-formed MessageV0 data that just needs to be serialized.
/// No instruction compilation is needed - just serialize the raw structure.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawVersionedTransactionData {
    /// Static account keys (base58 encoded public keys)
    #[serde(rename = "staticAccountKeys")]
    pub static_account_keys: Vec<String>,

    /// Address lookup tables
    #[serde(rename = "addressLookupTables")]
    pub address_lookup_tables: Vec<AddressLookupTable>,

    /// Pre-compiled instructions with index-based account references
    #[serde(rename = "versionedInstructions")]
    pub versioned_instructions: Vec<VersionedInstruction>,

    /// Message header
    #[serde(rename = "messageHeader")]
    pub message_header: RawMessageHeader,

    /// Recent blockhash (base58)
    #[serde(rename = "recentBlockhash")]
    pub recent_blockhash: String,
}

/// Address Lookup Table data for versioned transactions.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressLookupTable {
    /// The lookup table account address (base58)
    #[serde(rename = "accountKey")]
    pub account_key: String,
    /// Indices of writable accounts in the lookup table
    #[serde(rename = "writableIndexes")]
    pub writable_indexes: Vec<u8>,
    /// Indices of readonly accounts in the lookup table
    #[serde(rename = "readonlyIndexes")]
    pub readonly_indexes: Vec<u8>,
}

/// A pre-compiled versioned instruction (uses indexes, not pubkeys)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionedInstruction {
    /// Index into the account keys array for the program ID
    #[serde(rename = "programIdIndex")]
    pub program_id_index: u8,

    /// Indexes into the account keys array for instruction accounts
    #[serde(rename = "accountKeyIndexes")]
    pub account_key_indexes: Vec<u8>,

    /// Instruction data (base58 encoded)
    pub data: String,
}

/// Message header for versioned transactions
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawMessageHeader {
    /// Number of required signatures
    #[serde(rename = "numRequiredSignatures")]
    pub num_required_signatures: u8,

    /// Number of readonly signed accounts
    #[serde(rename = "numReadonlySignedAccounts")]
    pub num_readonly_signed_accounts: u8,

    /// Number of readonly unsigned accounts
    #[serde(rename = "numReadonlyUnsignedAccounts")]
    pub num_readonly_unsigned_accounts: u8,
}

// =============================================================================
// Build Function
// =============================================================================

/// Build a versioned transaction directly from raw MessageV0 data.
///
/// This function is used for the `fromVersionedTransactionData()` path where we already
/// have pre-compiled versioned data (indexes + ALT refs). No instruction compilation
/// is needed - we just serialize the raw structure to bytes.
///
/// # Arguments
///
/// * `data` - Raw versioned transaction data with pre-compiled instructions
///
/// # Returns
///
/// Serialized versioned transaction bytes (unsigned)
pub fn build_from_raw_versioned_data(
    data: &RawVersionedTransactionData,
) -> Result<Vec<u8>, WasmSolanaError> {
    // Parse static account keys
    let static_account_keys: Vec<Pubkey> = data
        .static_account_keys
        .iter()
        .map(|key| {
            key.parse().map_err(|e| {
                WasmSolanaError::new(&format!("Invalid static account key '{}': {}", key, e))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Parse blockhash
    let recent_blockhash = Hash::from_str(&data.recent_blockhash)
        .map_err(|e| WasmSolanaError::new(&format!("Invalid blockhash: {}", e)))?;

    // Convert instructions to compiled format
    let compiled_instructions: Vec<CompiledInstruction> = data
        .versioned_instructions
        .iter()
        .map(|ix| {
            // Decode base58 instruction data
            let instruction_data = bs58::decode(&ix.data)
                .into_vec()
                .map_err(|e| WasmSolanaError::new(&format!("Invalid instruction data: {}", e)))?;

            Ok(CompiledInstruction {
                program_id_index: ix.program_id_index,
                accounts: ix.account_key_indexes.clone(),
                data: instruction_data,
            })
        })
        .collect::<Result<Vec<_>, WasmSolanaError>>()?;

    // Convert address lookup tables
    let address_table_lookups: Vec<MessageAddressTableLookup> =
        data.address_lookup_tables
            .iter()
            .map(|alt| {
                let account_key: Pubkey = alt.account_key.parse().map_err(|e| {
                    WasmSolanaError::new(&format!("Invalid ALT account key: {}", e))
                })?;

                Ok(MessageAddressTableLookup {
                    account_key,
                    writable_indexes: alt.writable_indexes.clone(),
                    readonly_indexes: alt.readonly_indexes.clone(),
                })
            })
            .collect::<Result<Vec<_>, WasmSolanaError>>()?;

    // Create MessageV0 directly (no compilation needed)
    let message = MessageV0 {
        header: MessageHeader {
            num_required_signatures: data.message_header.num_required_signatures,
            num_readonly_signed_accounts: data.message_header.num_readonly_signed_accounts,
            num_readonly_unsigned_accounts: data.message_header.num_readonly_unsigned_accounts,
        },
        account_keys: static_account_keys,
        recent_blockhash,
        instructions: compiled_instructions,
        address_table_lookups,
    };

    // Create versioned transaction with placeholder signatures
    // The number of signatures is determined by num_required_signatures
    let signatures = vec![
        solana_sdk::signature::Signature::default();
        data.message_header.num_required_signatures as usize
    ];

    let versioned_tx = VersionedTransaction {
        signatures,
        message: solana_message::VersionedMessage::V0(message),
    };

    // Serialize to bytes
    bincode::serialize(&versioned_tx).map_err(|e| {
        WasmSolanaError::new(&format!("Failed to serialize versioned transaction: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_from_raw_versioned_data() {
        let data = RawVersionedTransactionData {
            static_account_keys: vec![
                "2gCzKgSETrQ74HZfisZUENTLyNhV6cAgV77xDMhxmHg2".to_string(),
                "11111111111111111111111111111111".to_string(),
            ],
            address_lookup_tables: vec![],
            versioned_instructions: vec![VersionedInstruction {
                program_id_index: 1,
                account_key_indexes: vec![0],
                data: "3Bxs4ThwQbE4vyj".to_string(), // base58 encoded
            }],
            message_header: RawMessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            recent_blockhash: "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi".to_string(),
        };

        let result = build_from_raw_versioned_data(&data);
        assert!(result.is_ok());

        let bytes = result.unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_build_with_alts() {
        let data = RawVersionedTransactionData {
            static_account_keys: vec![
                "35aKHPPJqb7qVNAaUb8DQLRC3Njp5RJZJSQM3v2PZhM7".to_string(),
                "ESuE8KSzSHBRCtgDwauL7vCR2ohxrWXf8rw75vVbNFvL".to_string(),
                "11111111111111111111111111111111".to_string(),
            ],
            address_lookup_tables: vec![AddressLookupTable {
                account_key: "2immgwYNHBbyVQKVGCEkgWpi53bLwWNRMB5G2nbgYV17".to_string(),
                writable_indexes: vec![0, 16],
                readonly_indexes: vec![1, 4],
            }],
            versioned_instructions: vec![VersionedInstruction {
                program_id_index: 2,
                account_key_indexes: vec![0, 1],
                data: "3Bxs4ThwQbE4vyj".to_string(),
            }],
            message_header: RawMessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            recent_blockhash: "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi".to_string(),
        };

        let result = build_from_raw_versioned_data(&data);
        assert!(result.is_ok());
    }
}
