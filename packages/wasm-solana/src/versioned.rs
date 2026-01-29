//! Versioned transaction support for Solana.
//!
//! This module handles both legacy and versioned (MessageV0) transactions,
//! providing a unified interface for parsing and building.
//!
//! # Transaction Versions
//!
//! - **Legacy**: Original transaction format with all accounts inline
//! - **V0**: Versioned format with Address Lookup Tables (ALTs) for account compression
//!
//! # Wire Format Detection
//!
//! Legacy transactions start with a compact-u16 signature count.
//! Versioned transactions have a version byte with high bit set (0x80).

use crate::error::WasmSolanaError;
use solana_address::Address;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use std::str::FromStr;

/// Transaction version enumeration.
///
/// Note: Named `TxVersion` to avoid conflict with `solana_transaction::versioned::TxVersion`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxVersion {
    /// Legacy transaction format (pre-versioned)
    Legacy,
    /// Version 0 transaction with Address Lookup Tables
    V0,
}

/// Address Lookup Table data extracted from versioned transactions.
#[derive(Debug, Clone)]
pub struct AddressLookupTableData {
    /// The lookup table account address (base58)
    pub account_key: String,
    /// Indices of writable accounts in the lookup table
    pub writable_indexes: Vec<u8>,
    /// Indices of readonly accounts in the lookup table
    pub readonly_indexes: Vec<u8>,
}

/// Detect the transaction version from raw bytes.
///
/// # Wire Format
///
/// - Legacy: Starts with compact-u16 for signature count (values 0-127 fit in single byte)
/// - Versioned: First byte has high bit set (0x80 = version 0)
///
/// The version byte comes AFTER the signatures array in versioned transactions,
/// but the signature count encoding differs.
pub fn detect_transaction_version(bytes: &[u8]) -> TxVersion {
    // Versioned transactions use a specific serialization format where
    // after the signatures, the message version byte has high bit set.
    //
    // However, detecting this reliably requires parsing the signature count first.
    // For simplicity, we try to deserialize as VersionedTransaction which handles both.
    //
    // The solana-transaction crate's VersionedTransaction can deserialize both formats.
    // We detect based on the deserialized message type.

    if let Ok(tx) = bincode::deserialize::<VersionedTransaction>(bytes) {
        match tx.message {
            VersionedMessage::Legacy(_) => TxVersion::Legacy,
            VersionedMessage::V0(_) => TxVersion::V0,
        }
    } else {
        // If we can't deserialize, assume legacy (will fail later with proper error)
        TxVersion::Legacy
    }
}

/// Extension trait for VersionedTransaction to add WASM-friendly methods.
pub trait VersionedTransactionExt {
    /// Deserialize a transaction from raw bytes (handles both legacy and versioned).
    fn from_bytes(bytes: &[u8]) -> Result<VersionedTransaction, WasmSolanaError>;

    /// Check if this is a versioned transaction (MessageV0).
    fn is_versioned(&self) -> bool;

    /// Get the transaction version as our TxVersion enum.
    fn tx_version(&self) -> TxVersion;

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

    /// Get static account keys (accounts stored directly in the message).
    fn static_account_keys(&self) -> Vec<String>;

    /// Get Address Lookup Table data (empty for legacy transactions).
    fn address_lookup_tables(&self) -> Vec<AddressLookupTableData>;

    /// Add a signature for a given public key.
    fn add_signature(&mut self, pubkey: &str, signature: &[u8]) -> Result<(), WasmSolanaError>;

    /// Get the index of a pubkey in the static account keys, if it's a signer.
    fn signer_index(&self, pubkey: &str) -> Option<usize>;
}

impl VersionedTransactionExt for VersionedTransaction {
    fn from_bytes(bytes: &[u8]) -> Result<VersionedTransaction, WasmSolanaError> {
        bincode::deserialize(bytes).map_err(|e| {
            WasmSolanaError::new(&format!(
                "Failed to deserialize versioned transaction: {}",
                e
            ))
        })
    }

    fn is_versioned(&self) -> bool {
        matches!(self.message, VersionedMessage::V0(_))
    }

    fn tx_version(&self) -> TxVersion {
        match &self.message {
            VersionedMessage::Legacy(_) => TxVersion::Legacy,
            VersionedMessage::V0(_) => TxVersion::V0,
        }
    }

    fn fee_payer_string(&self) -> Option<String> {
        match &self.message {
            VersionedMessage::Legacy(msg) => msg.account_keys.first().map(|p| p.to_string()),
            VersionedMessage::V0(msg) => msg.account_keys.first().map(|p| p.to_string()),
        }
    }

    fn blockhash_string(&self) -> String {
        match &self.message {
            VersionedMessage::Legacy(msg) => msg.recent_blockhash.to_string(),
            VersionedMessage::V0(msg) => msg.recent_blockhash.to_string(),
        }
    }

    fn num_instructions(&self) -> usize {
        match &self.message {
            VersionedMessage::Legacy(msg) => msg.instructions.len(),
            VersionedMessage::V0(msg) => msg.instructions.len(),
        }
    }

    fn num_signatures(&self) -> usize {
        self.signatures.len()
    }

    fn signable_payload(&self) -> Vec<u8> {
        self.message.serialize()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, WasmSolanaError> {
        bincode::serialize(self).map_err(|e| {
            WasmSolanaError::new(&format!("Failed to serialize versioned transaction: {}", e))
        })
    }

    fn static_account_keys(&self) -> Vec<String> {
        match &self.message {
            VersionedMessage::Legacy(msg) => {
                msg.account_keys.iter().map(|k| k.to_string()).collect()
            }
            VersionedMessage::V0(msg) => msg.account_keys.iter().map(|k| k.to_string()).collect(),
        }
    }

    fn address_lookup_tables(&self) -> Vec<AddressLookupTableData> {
        match &self.message {
            VersionedMessage::Legacy(_) => Vec::new(),
            VersionedMessage::V0(msg) => msg
                .address_table_lookups
                .iter()
                .map(|alt| AddressLookupTableData {
                    account_key: alt.account_key.to_string(),
                    writable_indexes: alt.writable_indexes.clone(),
                    readonly_indexes: alt.readonly_indexes.clone(),
                })
                .collect(),
        }
    }

    fn signer_index(&self, pubkey: &str) -> Option<usize> {
        let target_address = Address::from_str(pubkey).ok()?;
        let (account_keys, num_signers) = match &self.message {
            VersionedMessage::Legacy(msg) => (
                &msg.account_keys,
                msg.header.num_required_signatures as usize,
            ),
            VersionedMessage::V0(msg) => (
                &msg.account_keys,
                msg.header.num_required_signatures as usize,
            ),
        };

        let signed_keys = &account_keys[0..num_signers];
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

        // Find the signer index
        let signer_idx = self
            .signer_index(pubkey)
            .ok_or_else(|| WasmSolanaError::new(&format!("unknown signer: {}", pubkey)))?;

        // Create signature from bytes
        let signature = Signature::from(<[u8; 64]>::try_from(signature_bytes).unwrap());

        // Ensure signatures array is properly sized
        let num_signers = match &self.message {
            VersionedMessage::Legacy(msg) => msg.header.num_required_signatures as usize,
            VersionedMessage::V0(msg) => msg.header.num_required_signatures as usize,
        };

        if self.signatures.len() < num_signers {
            self.signatures.resize(num_signers, Signature::default());
        }

        // Set the signature at the correct index
        self.signatures[signer_idx] = signature;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    // Legacy transaction from previous tests
    const LEGACY_TX_BASE64: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDFVMqpim7tqEi2XL8R6KKkP0DYJvY3eiRXLlL1P9EjYgXKQC+k0FKnqyC4AZGJR7OhJXfpPP3NHOhS8t/6G7bLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/1c7Oaj3RbyLIjU0/ZPpsmVfVUWAzc8g36fK5g6A0JoBAgIAAQwCAAAAoIYBAAAAAAA=";

    fn decode_legacy_tx() -> VersionedTransaction {
        let bytes = BASE64_STANDARD.decode(LEGACY_TX_BASE64).unwrap();
        VersionedTransaction::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn test_deserialize_legacy_as_versioned() {
        let tx = decode_legacy_tx();

        // Should parse as legacy
        assert!(!tx.is_versioned());
        assert_eq!(tx.tx_version(), TxVersion::Legacy);
    }

    #[test]
    fn test_detect_version_legacy() {
        let bytes = BASE64_STANDARD.decode(LEGACY_TX_BASE64).unwrap();
        let version = detect_transaction_version(&bytes);
        assert_eq!(version, TxVersion::Legacy);
    }

    #[test]
    fn test_static_account_keys_legacy() {
        let tx = decode_legacy_tx();
        let keys = tx.static_account_keys();

        // Legacy transaction should have accounts inline
        assert!(!keys.is_empty());
    }

    #[test]
    fn test_address_lookup_tables_empty_for_legacy() {
        let tx = decode_legacy_tx();
        let alts = tx.address_lookup_tables();

        // Legacy transaction has no ALTs
        assert!(alts.is_empty());
    }

    #[test]
    fn test_fee_payer() {
        let tx = decode_legacy_tx();
        let fee_payer = tx.fee_payer_string();
        assert!(fee_payer.is_some());
    }

    #[test]
    fn test_blockhash() {
        let tx = decode_legacy_tx();
        let blockhash = tx.blockhash_string();
        assert!(!blockhash.is_empty());
    }

    #[test]
    fn test_signable_payload() {
        let tx = decode_legacy_tx();
        let payload = tx.signable_payload();
        assert!(!payload.is_empty());
    }

    #[test]
    fn test_roundtrip() {
        let tx = decode_legacy_tx();
        let serialized = tx.to_bytes().unwrap();

        let tx2 = VersionedTransaction::from_bytes(&serialized).unwrap();
        assert_eq!(tx.num_signatures(), tx2.num_signatures());
        assert_eq!(tx.num_instructions(), tx2.num_instructions());
    }

    #[test]
    fn test_add_signature() {
        let mut tx = decode_legacy_tx();
        let fee_payer = tx.fee_payer_string().unwrap();

        let signature = [42u8; 64];
        let result = tx.add_signature(&fee_payer, &signature);
        assert!(result.is_ok());

        assert_eq!(tx.signatures[0].as_ref(), &signature);
    }
}
