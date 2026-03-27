//! Intent-based transaction building for TON.
//!
//! Builds unsigned WalletV4R2 external messages from high-level business intents.
//! Each intent represents a user action (payment, staking, etc.), and the
//! builder handles the low-level message composition internally.

mod build;
mod types;

pub use build::build_transaction;
pub use types::*;
