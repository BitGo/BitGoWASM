//! Transaction building module.
//!
//! This module provides the `buildTransaction()` function which creates Solana
//! transactions from a high-level `TransactionIntent` structure.

mod build;
mod types;

pub use build::build_transaction;
pub use types::{Instruction, Nonce, TransactionIntent};
