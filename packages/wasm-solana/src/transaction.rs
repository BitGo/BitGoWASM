//! Solana transaction deserialization.
//!
//! Wraps `solana_transaction::Transaction` for WASM compatibility.
//!
//! # Wire Format
//!
//! Solana transactions use a compact binary format:
//! - Signatures (variable length array)
//! - Message (contains instructions, accounts, blockhash)
//!
//! This module deserializes base64-encoded transactions as used by
//! `@solana/web3.js` `Transaction.from()`.

use crate::error::WasmSolanaError;

/// Re-export the underlying Solana Transaction type.
pub use solana_transaction::Transaction;

/// Extension trait for Transaction to add WASM-friendly methods.
pub trait TransactionExt {
    /// Deserialize a transaction from base64-encoded wire format.
    fn from_base64(base64_str: &str) -> Result<Transaction, WasmSolanaError>;

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

    /// Serialize transaction to base64.
    fn to_base64(&self) -> Result<String, WasmSolanaError>;
}

impl TransactionExt for Transaction {
    fn from_base64(base64_str: &str) -> Result<Transaction, WasmSolanaError> {
        // Decode base64
        use base64::prelude::*;
        let bytes = BASE64_STANDARD
            .decode(base64_str)
            .map_err(|e| WasmSolanaError::new(&format!("Invalid base64: {}", e)))?;

        Self::from_bytes(&bytes)
    }

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

    fn to_base64(&self) -> Result<String, WasmSolanaError> {
        use base64::prelude::*;
        let bytes = self.to_bytes()?;
        Ok(BASE64_STANDARD.encode(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test transaction from @solana/web3.js - a simple SOL transfer
    // This is a real transaction serialized with Transaction.serialize()
    const TEST_TX_BASE64: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDFVMqpim7tqEi2XL8R6KKkP0DYJvY3eiRXLlL1P9EjYgXKQC+k0FKnqyC4AZGJR7OhJXfpPP3NHOhS8t/6G7bLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/1c7Oaj3RbyLIjU0/ZPpsmVfVUWAzc8g36fK5g6A0JoBAgIAAQwCAAAAoIYBAAAAAAA=";

    #[test]
    fn test_deserialize_transaction() {
        let tx = Transaction::from_base64(TEST_TX_BASE64).unwrap();

        // Check we got valid data
        assert!(tx.num_signatures() > 0);
        assert!(tx.num_instructions() > 0);
    }

    #[test]
    fn test_fee_payer() {
        let tx = Transaction::from_base64(TEST_TX_BASE64).unwrap();
        let fee_payer = tx.fee_payer_string();
        assert!(fee_payer.is_some());
        // Fee payer should be a valid base58 Solana address
        let payer = fee_payer.unwrap();
        assert!(payer.len() >= 32 && payer.len() <= 44);
    }

    #[test]
    fn test_blockhash() {
        let tx = Transaction::from_base64(TEST_TX_BASE64).unwrap();
        let blockhash = tx.blockhash_string();
        // Blockhash should be a valid base58 string
        assert!(blockhash.len() >= 32 && blockhash.len() <= 44);
    }

    #[test]
    fn test_roundtrip() {
        let tx = Transaction::from_base64(TEST_TX_BASE64).unwrap();
        let serialized = tx.to_base64().unwrap();

        // Deserialize again
        let tx2 = Transaction::from_base64(&serialized).unwrap();
        assert_eq!(tx.num_signatures(), tx2.num_signatures());
        assert_eq!(tx.num_instructions(), tx2.num_instructions());
        assert_eq!(tx.blockhash_string(), tx2.blockhash_string());
    }

    #[test]
    fn test_signable_payload() {
        let tx = Transaction::from_base64(TEST_TX_BASE64).unwrap();
        let payload = tx.signable_payload();
        // Message should have some content
        assert!(!payload.is_empty());
    }

    #[test]
    fn test_invalid_base64() {
        let result = Transaction::from_base64("not valid base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_transaction() {
        let result = Transaction::from_bytes(&[0, 1, 2, 3]);
        assert!(result.is_err());
    }
}
