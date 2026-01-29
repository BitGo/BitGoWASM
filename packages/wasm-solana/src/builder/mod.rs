//! Transaction building module.
//!
//! This module provides the `buildTransaction()` function which creates Solana
//! transactions from a high-level `TransactionIntent` structure.
//!
//! # Transaction Types
//!
//! - **Legacy transactions**: Standard format, all accounts inline
//! - **Versioned transactions (MessageV0)**: Supports Address Lookup Tables
//!
//! The builder automatically selects the format based on whether
//! `address_lookup_tables` is provided in the intent.

mod build;
mod types;
mod versioned;

pub use build::build_transaction;
pub use types::{
    AddressLookupTable, Instruction, MessageHeader, Nonce, RawVersionedTransactionData,
    TransactionIntent, VersionedInstruction,
};
pub use versioned::{build_from_raw_versioned_data, should_build_versioned};
