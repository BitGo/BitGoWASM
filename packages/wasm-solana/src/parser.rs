//! High-level transaction parser.
//!
//! Provides a single `parse_transaction` function that deserializes transaction bytes
//! and decodes all instructions into semantic types matching BitGoJS's TxData format.
//!
//! This parser returns raw decoded instructions. Instruction combining (e.g.,
//! CreateAccount + NonceInitialize → CreateNonceAccount) is handled by the
//! TypeScript consumer (mapWasmInstructionsToBitGoJS in BitGoJS).

use crate::instructions::{decode_instruction, InstructionContext, ParsedInstruction};
use crate::js_obj;
use crate::versioned::VersionedTransactionExt;
use crate::wasm::try_into_js_value::{JsConversionError, TryIntoJsValue};
use solana_message::VersionedMessage;
use solana_transaction::versioned::VersionedTransaction;
use wasm_bindgen::JsValue;

/// A fully parsed Solana transaction with decoded instructions.
///
/// This structure matches BitGoJS's `TxData` interface for seamless integration.
#[derive(Debug, Clone)]
pub struct ParsedTransaction {
    /// The fee payer address (base58).
    pub fee_payer: String,

    /// Number of required signatures.
    pub num_signatures: u8,

    /// The blockhash or nonce (base58).
    pub nonce: String,

    /// If this is a durable nonce transaction, contains the nonce info.
    pub durable_nonce: Option<DurableNonce>,

    /// All decoded instructions.
    pub instructions_data: Vec<ParsedInstruction>,

    /// All account keys (base58 strings).
    pub account_keys: Vec<String>,

    /// All signatures (base58 strings). Non-empty signatures indicate signed transaction.
    pub signatures: Vec<String>,
}

/// Durable nonce information for nonce-based transactions.
#[derive(Debug, Clone)]
pub struct DurableNonce {
    /// The nonce account address (base58).
    pub wallet_nonce_address: String,

    /// The nonce authority address (base58).
    pub auth_wallet_address: String,
}

impl TryIntoJsValue for DurableNonce {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "walletNonceAddress" => self.wallet_nonce_address,
            "authWalletAddress" => self.auth_wallet_address
        )
    }
}

impl TryIntoJsValue for ParsedTransaction {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "feePayer" => self.fee_payer,
            "numSignatures" => self.num_signatures,
            "nonce" => self.nonce,
            "durableNonce" => self.durable_nonce,
            "instructionsData" => self.instructions_data,
            "accountKeys" => self.account_keys,
            "signatures" => self.signatures
        )
    }
}

/// Parse a serialized Solana transaction into structured data.
///
/// # Arguments
/// * `bytes` - The raw transaction bytes (wire format)
///
/// # Returns
/// A `ParsedTransaction` with all instructions decoded to semantic types.
pub fn parse_transaction(bytes: &[u8]) -> Result<ParsedTransaction, String> {
    // Deserialize the transaction - VersionedTransaction handles both legacy and V0
    let tx = VersionedTransaction::from_bytes(bytes).map_err(|e| e.to_string())?;

    // Extract account keys and instructions based on message type
    let (account_keys, instructions, recent_blockhash, num_required_signatures) = match &tx.message
    {
        VersionedMessage::Legacy(msg) => (
            msg.account_keys.iter().map(|k| k.to_string()).collect(),
            &msg.instructions,
            msg.recent_blockhash.to_string(),
            msg.header.num_required_signatures,
        ),
        VersionedMessage::V0(msg) => (
            msg.account_keys.iter().map(|k| k.to_string()).collect(),
            &msg.instructions,
            msg.recent_blockhash.to_string(),
            msg.header.num_required_signatures,
        ),
    };

    let account_keys: Vec<String> = account_keys;

    // Extract fee payer (first account key)
    let fee_payer = account_keys
        .first()
        .cloned()
        .ok_or("Transaction has no account keys")?;

    // Decode all instructions
    let mut instructions_data = Vec::with_capacity(instructions.len());
    let mut durable_nonce = None;

    for (idx, instruction) in instructions.iter().enumerate() {
        // Get program ID
        let program_id = account_keys
            .get(instruction.program_id_index as usize)
            .cloned()
            .ok_or_else(|| format!("Invalid program_id_index in instruction {}", idx))?;

        // Resolve account indices to addresses
        let accounts: Vec<String> = instruction
            .accounts
            .iter()
            .filter_map(|&i| account_keys.get(i as usize).cloned())
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

    // Note: Instruction combining (e.g., CreateAccount + StakeInitialize → StakingActivate)
    // is handled by TypeScript in mapWasmInstructionsToBitGoJS for flexibility

    // Extract signatures as base58 strings.
    // All-zeros signatures (unsigned placeholder slots) are returned as empty strings
    // so the JS side can simply use `signatures[0] || 'UNAVAILABLE'`.
    let signatures: Vec<String> = tx
        .signatures
        .iter()
        .map(|s| {
            let bytes: &[u8] = s.as_ref();
            if bytes.iter().all(|&b| b == 0) {
                String::new()
            } else {
                s.to_string()
            }
        })
        .collect();

    Ok(ParsedTransaction {
        fee_payer,
        num_signatures: num_required_signatures,
        nonce: recent_blockhash,
        durable_nonce,
        instructions_data,
        account_keys,
        signatures,
    })
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
                assert_eq!(params.amount, 100000);
            }
            other => panic!("Expected Transfer instruction, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_invalid_bytes() {
        let result = parse_transaction(&[0, 1, 2, 3]);
        assert!(result.is_err());
    }

    // Marinade staking activate transaction (CreateAccount + StakeInitialize without Delegate)
    // Note: Combining is now done in TypeScript, so we expect raw instructions here
    const MARINADE_STAKING_ACTIVATE: &str = "AuRFS0r7hJ+/+WuDQbbwdjSgxfnKOWi94EnWEha9uaBPt8VZOXiOoSiSoES34VkyBNLlLqlfK0fP3d5eJR+srQvN04gqzpOZPTVzqiomyMXqwQ6FYoQg5nEkdiDVny8SsyhRnAeDMzexkKD+3rwSGP0E+XN/2crTL6PZRnip42YFAgADBUXlebz5JTz2i0ff8fs6OlwsIbrFsjwJrhKm4FVr8ItBYnsvugEnYfm5Gbz5TLtMncgFHZ8JMpkxTTlJIzJovekAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAah2BeRN1QqmDQ3vf4qerJVf1NcinhyK2ikncAAAAAABqfVFxksXFEhjMlMPUrxf1ja7gibof1E49vZigAAAADjMtr5L6vs6LY/96RABeX9/Zr6FYdWthxalfkEs7jQgQICAgABNAAAAADgkwQAAAAAAMgAAAAAAAAABqHYF5E3VCqYNDe9/ip6slV/U1yKeHIraKSdwAAAAAADAgEEdAAAAACx+Xl4mhxH0TxI2HovJxcQ63+TJglRFzFikL1sKdr12UXlebz5JTz2i0ff8fs6OlwsIbrFsjwJrhKm4FVr8ItBAAAAAAAAAAAAAAAAAAAAAEXlebz5JTz2i0ff8fs6OlwsIbrFsjwJrhKm4FVr8ItB";

    #[test]
    fn test_parse_marinade_staking_activate() {
        let bytes = BASE64_STANDARD.decode(MARINADE_STAKING_ACTIVATE).unwrap();
        let parsed = parse_transaction(&bytes).unwrap();

        println!("Parsed instructions: {:?}", parsed.instructions_data);

        // WASM returns raw instructions; combining is done in TypeScript
        // Expect: CreateAccount + StakeInitialize (2 instructions)
        assert_eq!(
            parsed.instructions_data.len(),
            2,
            "Expected 2 raw instructions"
        );

        // First instruction: CreateAccount
        match &parsed.instructions_data[0] {
            ParsedInstruction::CreateAccount(params) => {
                assert_eq!(
                    params.from_address,
                    "5hr5fisPi6DXNuuRpm5XUbzpiEnmdyxXuBDTwzwZj5Pe"
                );
                assert_eq!(
                    params.new_address,
                    "7dRuGFbU2y2kijP6o1LYNzVyz4yf13MooqoionCzv5Za"
                );
                assert_eq!(params.amount, 300000);
            }
            other => panic!("Expected CreateAccount instruction, got {:?}", other),
        }

        // Second instruction: StakeInitialize
        match &parsed.instructions_data[1] {
            ParsedInstruction::StakeInitialize(params) => {
                assert_eq!(
                    params.staking_address,
                    "7dRuGFbU2y2kijP6o1LYNzVyz4yf13MooqoionCzv5Za"
                );
                // The staker is the authorized staker for Marinade
                assert_eq!(
                    params.staker,
                    "CyjoLt3kjqB57K7ewCBHmnHq3UgEj3ak6A7m6EsBsuhA"
                );
                assert_eq!(
                    params.withdrawer,
                    "5hr5fisPi6DXNuuRpm5XUbzpiEnmdyxXuBDTwzwZj5Pe"
                );
            }
            other => panic!("Expected StakeInitialize instruction, got {:?}", other),
        }
    }
}
