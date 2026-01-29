//! Solana transaction deserialization and manipulation.
//!
//! Wraps `solana_transaction::Transaction` for WASM compatibility.
//!
//! # Wire Format
//!
//! Solana transactions use a compact binary format:
//! - Signatures (variable length array)
//! - Message (contains instructions, accounts, blockhash)
//!
//! This module deserializes transaction bytes and provides signature
//! manipulation. Base64 encoding/decoding is handled in the TypeScript layer.

use crate::error::WasmSolanaError;
use solana_address::Address;
use solana_signature::Signature;
use std::str::FromStr;

/// Re-export the underlying Solana Transaction type.
pub use solana_transaction::Transaction;

/// Extension trait for Transaction to add WASM-friendly methods.
pub trait TransactionExt {
    /// Deserialize a transaction from raw bytes (wire format).
    fn from_bytes(bytes: &[u8]) -> Result<Transaction, WasmSolanaError>;

    /// Get the fee payer address as base58 string.
    fn fee_payer_string(&self) -> Option<String>;

    /// Get the recent blockhash as base58 string.
    fn blockhash_string(&self) -> String;

    /// Get the number of instructions.
    fn num_instructions(&self) -> usize;

    /// Get the number of signatures.
    fn num_signatures(&self) -> usize;

    /// Get the signable message bytes (what gets signed).
    fn signable_payload(&self) -> Vec<u8>;

    /// Serialize transaction to bytes (wire format).
    fn to_bytes(&self) -> Result<Vec<u8>, WasmSolanaError>;

    /// Add a signature for a given public key.
    ///
    /// The pubkey must be one of the required signers in the transaction.
    /// The signature bytes must be exactly 64 bytes (Ed25519 signature).
    fn add_signature(&mut self, pubkey: &str, signature: &[u8]) -> Result<(), WasmSolanaError>;

    /// Get the index of a pubkey in the account keys, if it's a signer.
    fn signer_index(&self, pubkey: &str) -> Option<usize>;
}

impl TransactionExt for Transaction {
    fn from_bytes(bytes: &[u8]) -> Result<Transaction, WasmSolanaError> {
        bincode::deserialize(bytes)
            .map_err(|e| WasmSolanaError::new(&format!("Failed to deserialize transaction: {}", e)))
    }

    fn fee_payer_string(&self) -> Option<String> {
        self.message.account_keys.first().map(|p| p.to_string())
    }

    fn blockhash_string(&self) -> String {
        self.message.recent_blockhash.to_string()
    }

    fn num_instructions(&self) -> usize {
        self.message.instructions.len()
    }

    fn num_signatures(&self) -> usize {
        self.signatures.len()
    }

    fn signable_payload(&self) -> Vec<u8> {
        self.message.serialize()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, WasmSolanaError> {
        bincode::serialize(self)
            .map_err(|e| WasmSolanaError::new(&format!("Failed to serialize transaction: {}", e)))
    }

    fn signer_index(&self, pubkey: &str) -> Option<usize> {
        let target_address = Address::from_str(pubkey).ok()?;
        let num_signers = self.message.header.num_required_signatures as usize;

        // Use the same pattern as Solana's get_signing_keypair_positions
        let signed_keys = &self.message.account_keys[0..num_signers];
        signed_keys.iter().position(|x| *x == target_address)
    }

    fn add_signature(
        &mut self,
        pubkey: &str,
        signature_bytes: &[u8],
    ) -> Result<(), WasmSolanaError> {
        // Validate signature length (Ed25519 signature is 64 bytes)
        if signature_bytes.len() != 64 {
            return Err(WasmSolanaError::new(&format!(
                "Invalid signature length: expected 64 bytes, got {}",
                signature_bytes.len()
            )));
        }

        // Find the signer index using the same approach as Solana's get_signing_keypair_positions
        let signer_idx = self
            .signer_index(pubkey)
            .ok_or_else(|| WasmSolanaError::new(&format!("unknown signer: {}", pubkey)))?;

        // Create signature from bytes
        let signature = Signature::from(<[u8; 64]>::try_from(signature_bytes).unwrap());

        // Ensure signatures array is properly sized (same as Solana's internal pattern)
        let num_signers = self.message.header.num_required_signatures as usize;
        if self.signatures.len() < num_signers {
            self.signatures.resize(num_signers, Signature::default());
        }

        // Set the signature at the correct index (same pattern as try_partial_sign_unchecked)
        self.signatures[signer_idx] = signature;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    // Test transaction from @solana/web3.js - a simple SOL transfer
    const TEST_TX_BASE64: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDFVMqpim7tqEi2XL8R6KKkP0DYJvY3eiRXLlL1P9EjYgXKQC+k0FKnqyC4AZGJR7OhJXfpPP3NHOhS8t/6G7bLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/1c7Oaj3RbyLIjU0/ZPpsmVfVUWAzc8g36fK5g6A0JoBAgIAAQwCAAAAoIYBAAAAAAA=";

    fn decode_test_tx() -> Transaction {
        let bytes = BASE64_STANDARD.decode(TEST_TX_BASE64).unwrap();
        Transaction::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn test_deserialize_transaction() {
        let tx = decode_test_tx();

        // Check we got valid data
        assert!(tx.num_signatures() > 0);
        assert!(tx.num_instructions() > 0);
    }

    #[test]
    fn test_fee_payer() {
        let tx = decode_test_tx();
        let fee_payer = tx.fee_payer_string();
        assert!(fee_payer.is_some());
        // Fee payer should be a valid base58 Solana address
        let payer = fee_payer.unwrap();
        assert!(payer.len() >= 32 && payer.len() <= 44);
    }

    #[test]
    fn test_blockhash() {
        let tx = decode_test_tx();
        let blockhash = tx.blockhash_string();
        // Blockhash should be a valid base58 string
        assert!(blockhash.len() >= 32 && blockhash.len() <= 44);
    }

    #[test]
    fn test_roundtrip() {
        let tx = decode_test_tx();
        let serialized = tx.to_bytes().unwrap();

        // Deserialize again
        let tx2 = Transaction::from_bytes(&serialized).unwrap();
        assert_eq!(tx.num_signatures(), tx2.num_signatures());
        assert_eq!(tx.num_instructions(), tx2.num_instructions());
        assert_eq!(tx.blockhash_string(), tx2.blockhash_string());
    }

    #[test]
    fn test_signable_payload() {
        let tx = decode_test_tx();
        let payload = tx.signable_payload();
        // Message should have some content
        assert!(!payload.is_empty());
    }

    #[test]
    fn test_invalid_transaction() {
        let result = Transaction::from_bytes(&[0, 1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_signer_index() {
        let tx = decode_test_tx();
        let fee_payer = tx.fee_payer_string().unwrap();

        // Fee payer should be at index 0
        let idx = tx.signer_index(&fee_payer);
        assert_eq!(idx, Some(0));

        // Non-existent pubkey should return None
        let fake_pubkey = "11111111111111111111111111111111";
        assert_eq!(tx.signer_index(fake_pubkey), None);
    }

    #[test]
    fn test_add_signature() {
        let mut tx = decode_test_tx();
        let fee_payer = tx.fee_payer_string().unwrap();

        // Create a dummy 64-byte signature
        let signature = [42u8; 64];

        // Add the signature
        let result = tx.add_signature(&fee_payer, &signature);
        assert!(result.is_ok());

        // Verify the signature was added
        assert_eq!(tx.signatures[0].as_ref(), &signature);
    }

    #[test]
    fn test_add_signature_invalid_length() {
        let mut tx = decode_test_tx();
        let fee_payer = tx.fee_payer_string().unwrap();

        // Try to add a signature with wrong length
        let bad_signature = [0u8; 32];
        let result = tx.add_signature(&fee_payer, &bad_signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_signature_invalid_pubkey() {
        let mut tx = decode_test_tx();
        let signature = [0u8; 64];

        // Try to add signature for non-signer pubkey
        let non_signer = "11111111111111111111111111111111"; // System program
        let result = tx.add_signature(non_signer, &signature);
        assert!(result.is_err());
    }
}
