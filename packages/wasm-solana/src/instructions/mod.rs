//! Solana instruction decoders.
//!
//! This module provides decoders for common Solana program instructions:
//! - System Program (transfers, account creation, nonce operations)
//! - Stake Program (staking operations)
//! - ComputeBudget (priority fees, compute limits)

pub mod compute_budget;
pub mod stake;
pub mod system;

pub use compute_budget::{ComputeBudgetInstruction, ComputeBudgetInstructionType};
pub use stake::{StakeAuthorize, StakeInstruction, StakeInstructionType};
pub use system::{SystemInstruction, SystemInstructionType};
