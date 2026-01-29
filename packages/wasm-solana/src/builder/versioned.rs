//! Versioned transaction building (MessageV0).
//!
//! This module handles building versioned transactions with Address Lookup Tables (ALTs).
//! Versioned transactions use MessageV0 which supports referencing accounts from ALTs,
//! allowing transactions with more accounts than the legacy format.
//!
//! # When to Use
//!
//! Build a versioned transaction when:
//! - The `TransactionIntent` has `address_lookup_tables` field set
//! - Round-tripping a parsed versioned transaction
//!
//! # Wire Format
//!
//! MessageV0 transactions have a version byte (0x80) followed by the message.
//! The ALT references allow account indices beyond 255.

use crate::builder::types::{
    AddressLookupTable, Nonce, RawVersionedTransactionData, TransactionIntent,
};
use crate::error::WasmSolanaError;
use solana_message::v0::Message as MessageV0;
use solana_message::AddressLookupTableAccount;
use solana_sdk::bs58;
use solana_sdk::hash::Hash;
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use solana_transaction::versioned::VersionedTransaction;
use std::str::FromStr;

/// Build a versioned transaction (MessageV0) from an intent.
///
/// This is called when the intent has `address_lookup_tables` set.
/// The ALTs must include the actual account keys for proper compilation.
///
/// # Arguments
///
/// * `intent` - The transaction intent with ALT data
/// * `instructions` - Pre-built instructions (built by build.rs)
///
/// # Returns
///
/// Serialized versioned transaction bytes
pub fn build_versioned_transaction(
    intent: &TransactionIntent,
    instructions: Vec<Instruction>,
) -> Result<Vec<u8>, WasmSolanaError> {
    // Parse fee payer
    let fee_payer: Pubkey = intent
        .fee_payer
        .parse()
        .map_err(|e| WasmSolanaError::new(&format!("Invalid fee payer: {}", e)))?;

    // Parse blockhash
    let blockhash_str = match &intent.nonce {
        Nonce::Blockhash { value } => value.clone(),
        Nonce::Durable { value, .. } => value.clone(),
    };
    let blockhash = Hash::from_str(&blockhash_str)
        .map_err(|e| WasmSolanaError::new(&format!("Invalid blockhash: {}", e)))?;

    // Convert ALT data to AddressLookupTableAccount format
    // Note: For compilation, we need the actual account keys from the ALT.
    // Since we don't have them, we use a simplified approach that works for
    // round-tripping pre-built versioned transactions.
    let alt_accounts = convert_alts_for_compile(&intent.address_lookup_tables)?;

    // Try to compile the MessageV0
    let message = MessageV0::try_compile(&fee_payer, &instructions, &alt_accounts, blockhash)
        .map_err(|e| WasmSolanaError::new(&format!("Failed to compile MessageV0: {:?}", e)))?;

    // Create versioned transaction with empty signatures
    let versioned_tx = VersionedTransaction {
        signatures: vec![],
        message: solana_message::VersionedMessage::V0(message),
    };

    // Serialize to bytes
    bincode::serialize(&versioned_tx).map_err(|e| {
        WasmSolanaError::new(&format!("Failed to serialize versioned transaction: {}", e))
    })
}

/// Convert AddressLookupTable data to AddressLookupTableAccount for compilation.
///
/// Note: This is a simplified conversion. For full ALT support, we'd need
/// the actual account keys stored in each ALT. For now, this supports
/// transactions where all accounts are in static_account_keys.
fn convert_alts_for_compile(
    alts: &Option<Vec<AddressLookupTable>>,
) -> Result<Vec<AddressLookupTableAccount>, WasmSolanaError> {
    let Some(alts) = alts else {
        return Ok(vec![]);
    };

    let mut accounts = Vec::with_capacity(alts.len());

    for alt in alts {
        let key: Pubkey = alt
            .account_key
            .parse()
            .map_err(|e| WasmSolanaError::new(&format!("Invalid ALT account key: {}", e)))?;

        // For now, we create empty address lists.
        // Full ALT support would require fetching ALT account data.
        accounts.push(AddressLookupTableAccount {
            key,
            addresses: vec![], // Would need actual ALT data for new transactions
        });
    }

    Ok(accounts)
}

/// Check if an intent should be built as a versioned transaction.
pub fn should_build_versioned(intent: &TransactionIntent) -> bool {
    intent.address_lookup_tables.is_some()
}

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
    use solana_message::compiled_instruction::CompiledInstruction;
    use solana_message::v0::MessageAddressTableLookup;
    use solana_message::MessageHeader;

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

    // Create versioned transaction with empty signatures
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
    fn test_should_build_versioned_with_alts() {
        let intent = TransactionIntent {
            fee_payer: "11111111111111111111111111111111".to_string(),
            nonce: Nonce::Blockhash {
                value: "11111111111111111111111111111111".to_string(),
            },
            instructions: vec![],
            address_lookup_tables: Some(vec![AddressLookupTable {
                account_key: "11111111111111111111111111111111".to_string(),
                writable_indexes: vec![0],
                readonly_indexes: vec![1],
            }]),
            static_account_keys: None,
        };

        assert!(should_build_versioned(&intent));
    }

    #[test]
    fn test_should_not_build_versioned_without_alts() {
        let intent = TransactionIntent {
            fee_payer: "11111111111111111111111111111111".to_string(),
            nonce: Nonce::Blockhash {
                value: "11111111111111111111111111111111".to_string(),
            },
            instructions: vec![],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        assert!(!should_build_versioned(&intent));
    }
}
