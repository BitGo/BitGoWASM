//! Transaction building from business-level intents.
//!
//! This module provides intent-based transaction building for TON.
//! Each intent represents a user action (payment, stake, etc.),
//! and the builder handles composing the appropriate messages internally.

mod build;
mod jetton;
mod staking;
mod transfer;
pub mod types;

pub use build::build_transaction;
pub use types::{Recipient, TonStakingType, TonTransactionIntent};
