//! Transaction building from intents.
//!
//! Build TON transactions from high-level business intent descriptions.
//! Accepts intents like Payment, Delegate, Undelegate (not low-level opcodes)
//! and handles composition into the correct internal messages.

mod build;
pub mod types;

pub use build::build_transaction;
pub use types::{Recipient, TonBuildContext, TonStakingType, TonTransactionIntent};
