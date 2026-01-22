//! High-level transaction parser.
//!
//! Provides a single `parse_transaction` function that deserializes transaction bytes
//! and decodes all instructions into semantic types matching BitGoJS's TxData format.
//!
//! The parser performs post-processing to combine sequential instructions into
//! compound types that match BitGoJS's semantic representation:
//! - CreateAccount + NonceInitialize → CreateNonceAccount
//! - CreateAccount + StakeInitialize + StakingDelegate → StakingActivate

use crate::instructions::{
    decode_instruction, CreateNonceAccountParams, InstructionContext, ParsedInstruction,
    StakingActivateParams, STAKE_PROGRAM_ID, SYSTEM_PROGRAM_ID,
};
use crate::transaction::{Transaction, TransactionExt};
use serde::Serialize;

/// A fully parsed Solana transaction with decoded instructions.
///
/// This structure matches BitGoJS's `TxData` interface for seamless integration.
#[derive(Debug, Clone, Serialize)]
pub struct ParsedTransaction {
    /// The fee payer address (base58).
    #[serde(rename = "feePayer")]
    pub fee_payer: String,

    /// Number of required signatures.
    #[serde(rename = "numSignatures")]
    pub num_signatures: u8,

    /// The blockhash or nonce (base58).
    pub nonce: String,

    /// If this is a durable nonce transaction, contains the nonce info.
    #[serde(rename = "durableNonce", skip_serializing_if = "Option::is_none")]
    pub durable_nonce: Option<DurableNonce>,

    /// All decoded instructions.
    #[serde(rename = "instructionsData")]
    pub instructions_data: Vec<ParsedInstruction>,

    /// All signatures (as bytes, base64-encoded for JSON).
    #[serde(with = "signatures_serde")]
    pub signatures: Vec<Vec<u8>>,

    /// All account keys (base58 strings).
    #[serde(rename = "accountKeys")]
    pub account_keys: Vec<String>,
}

/// Durable nonce information for nonce-based transactions.
#[derive(Debug, Clone, Serialize)]
pub struct DurableNonce {
    /// The nonce account address (base58).
    #[serde(rename = "walletNonceAddress")]
    pub wallet_nonce_address: String,

    /// The nonce authority address (base58).
    #[serde(rename = "authWalletAddress")]
    pub auth_wallet_address: String,
}

/// Parse a serialized Solana transaction into structured data.
///
/// # Arguments
/// * `bytes` - The raw transaction bytes (wire format)
///
/// # Returns
/// A `ParsedTransaction` with all instructions decoded to semantic types.
pub fn parse_transaction(bytes: &[u8]) -> Result<ParsedTransaction, String> {
    // Deserialize the transaction
    let tx = Transaction::from_bytes(bytes).map_err(|e| e.to_string())?;

    let message = &tx.message;

    // Extract fee payer (first account key)
    let fee_payer = message
        .account_keys
        .first()
        .map(|k| k.to_string())
        .ok_or("Transaction has no account keys")?;

    // Extract all account keys as base58 strings
    let account_keys: Vec<String> = message.account_keys.iter().map(|k| k.to_string()).collect();

    // Extract signatures as byte arrays
    let signatures: Vec<Vec<u8>> = tx.signatures.iter().map(|s| s.as_ref().to_vec()).collect();

    // Decode all instructions
    let mut instructions_data = Vec::with_capacity(message.instructions.len());
    let mut durable_nonce = None;

    for (idx, instruction) in message.instructions.iter().enumerate() {
        // Get program ID
        let program_id = message
            .account_keys
            .get(instruction.program_id_index as usize)
            .map(|k| k.to_string())
            .ok_or_else(|| format!("Invalid program_id_index in instruction {}", idx))?;

        // Resolve account indices to addresses
        let accounts: Vec<String> = instruction
            .accounts
            .iter()
            .filter_map(|&i| message.account_keys.get(i as usize).map(|k| k.to_string()))
            .collect();

        // Decode the instruction
        let ctx = InstructionContext {
            program_id: &program_id,
            accounts: &accounts,
            data: &instruction.data,
        };
        let parsed = decode_instruction(ctx);

        // Check if this is a NonceAdvance instruction (first instruction = durable nonce tx)
        if idx == 0 {
            if let ParsedInstruction::NonceAdvance(ref params) = parsed {
                durable_nonce = Some(DurableNonce {
                    wallet_nonce_address: params.wallet_nonce_address.clone(),
                    auth_wallet_address: params.auth_wallet_address.clone(),
                });
            }
        }

        instructions_data.push(parsed);
    }

    // Post-process: combine sequential instructions into compound types
    let instructions_data = combine_instructions(instructions_data);

    // The nonce is either the blockhash or, for durable nonce txs, still the blockhash
    // (which is the nonce value from the nonce account)
    let nonce = message.recent_blockhash.to_string();

    Ok(ParsedTransaction {
        fee_payer,
        num_signatures: message.header.num_required_signatures,
        nonce,
        durable_nonce,
        instructions_data,
        signatures,
        account_keys,
    })
}

/// Combine sequential instructions into compound semantic types.
///
/// This matches BitGoJS's behavior where certain instruction sequences are
/// represented as a single high-level instruction:
/// - CreateAccount + NonceInitialize → CreateNonceAccount
/// - CreateAccount + StakeInitialize + StakingDelegate → StakingActivate
fn combine_instructions(instructions: Vec<ParsedInstruction>) -> Vec<ParsedInstruction> {
    let mut result = Vec::with_capacity(instructions.len());
    let mut i = 0;

    while i < instructions.len() {
        // Try to match CreateAccount patterns
        if let ParsedInstruction::CreateAccount(ref create) = instructions[i] {
            // Pattern 1: CreateAccount + NonceInitialize → CreateNonceAccount
            if i + 1 < instructions.len() {
                if let ParsedInstruction::NonceInitialize(ref nonce_init) = instructions[i + 1] {
                    // Check if CreateAccount target matches NonceInitialize nonce address
                    // and owner is System Program (nonce accounts owned by system program)
                    if create.new_address == nonce_init.nonce_address
                        && create.owner == SYSTEM_PROGRAM_ID
                    {
                        result.push(ParsedInstruction::CreateNonceAccount(
                            CreateNonceAccountParams {
                                from_address: create.from_address.clone(),
                                nonce_address: nonce_init.nonce_address.clone(),
                                auth_address: nonce_init.auth_address.clone(),
                                amount: create.amount.clone(),
                            },
                        ));
                        i += 2; // Skip both instructions
                        continue;
                    }
                }
            }

            // Pattern 2: CreateAccount + StakeInitialize + StakingDelegate → StakingActivate
            if i + 2 < instructions.len() {
                if let (
                    ParsedInstruction::StakeInitialize(ref stake_init),
                    ParsedInstruction::StakingDelegate(ref delegate),
                ) = (&instructions[i + 1], &instructions[i + 2])
                {
                    // Check if CreateAccount target matches StakeInitialize staking address
                    // and owner is Stake Program
                    if create.new_address == stake_init.staking_address
                        && create.owner == STAKE_PROGRAM_ID
                        && stake_init.staking_address == delegate.staking_address
                    {
                        result.push(ParsedInstruction::StakingActivate(StakingActivateParams {
                            from_address: create.from_address.clone(),
                            staking_address: stake_init.staking_address.clone(),
                            amount: create.amount.clone(),
                            validator: delegate.validator.clone(),
                            staking_type: "NATIVE".to_string(),
                        }));
                        i += 3; // Skip all three instructions
                        continue;
                    }
                }
            }
        }

        // No pattern matched, keep the instruction as-is
        result.push(instructions[i].clone());
        i += 1;
    }

    result
}

/// Serialize signatures as base64 strings for JSON output.
mod signatures_serde {
    use base64::prelude::*;
    use serde::{Serialize, Serializer};

    pub fn serialize<S>(signatures: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: Vec<String> = signatures
            .iter()
            .map(|s| BASE64_STANDARD.encode(s))
            .collect();
        encoded.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    // Test transaction from @solana/web3.js - a simple SOL transfer
    const TEST_TX_BASE64: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDFVMqpim7tqEi2XL8R6KKkP0DYJvY3eiRXLlL1P9EjYgXKQC+k0FKnqyC4AZGJR7OhJXfpPP3NHOhS8t/6G7bLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/1c7Oaj3RbyLIjU0/ZPpsmVfVUWAzc8g36fK5g6A0JoBAgIAAQwCAAAAoIYBAAAAAAA=";

    #[test]
    fn test_parse_transfer_transaction() {
        let bytes = BASE64_STANDARD.decode(TEST_TX_BASE64).unwrap();
        let parsed = parse_transaction(&bytes).unwrap();

        // Check basic structure
        assert_eq!(parsed.num_signatures, 1);
        assert!(!parsed.fee_payer.is_empty());
        assert!(!parsed.nonce.is_empty());
        assert_eq!(parsed.instructions_data.len(), 1);

        // Check the instruction is a Transfer
        match &parsed.instructions_data[0] {
            ParsedInstruction::Transfer(params) => {
                // Amount should be 100000 lamports (from the test tx)
                assert_eq!(params.amount, "100000");
            }
            other => panic!("Expected Transfer instruction, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_invalid_bytes() {
        let result = parse_transaction(&[0, 1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parsed_transaction_serializes_to_json() {
        let bytes = BASE64_STANDARD.decode(TEST_TX_BASE64).unwrap();
        let parsed = parse_transaction(&bytes).unwrap();

        // Should serialize to valid JSON
        let json = serde_json::to_string(&parsed).unwrap();
        assert!(json.contains("feePayer"));
        assert!(json.contains("instructionsData"));
        assert!(json.contains("Transfer"));
    }
}
