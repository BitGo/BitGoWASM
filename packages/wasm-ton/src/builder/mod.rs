//! Intent-based transaction building for TON.
//!
//! Each intent maps to a single user action (payment, staking, etc.).
//! Low-level cell composition stays inside Rust; callers provide
//! business-level parameters.

mod build;
mod types;

pub use build::build_transaction;
pub use types::*;
