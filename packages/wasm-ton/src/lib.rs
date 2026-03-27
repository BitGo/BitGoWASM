//! wasm-ton: WASM module for TON transaction operations
//!
//! This crate provides:
//! - Address encoding, decoding, and validation
//! - Transaction parsing (Phase 2)
//! - Transaction building from intents (Phase 3)
//!
//! # Architecture
//!
//! The crate follows a two-layer architecture:
//! - **Core layer** (`src/*.rs`): Pure Rust logic, no WASM dependencies
//! - **WASM layer** (`src/wasm/*.rs`): Thin wrappers with `#[wasm_bindgen]`

pub mod address;
pub mod builder;
pub mod error;
pub mod parser;
pub mod transaction;
pub mod wasm;

// Re-export main types for convenience
pub use address::{decode_address, encode_address, validate_address};
pub use builder::{build_transaction, BuildContext, TonStakingType, TonTransactionIntent};
pub use error::WasmTonError;
pub use parser::{parse_transaction, ParsedTransaction, TransactionType};
pub use transaction::Transaction;
