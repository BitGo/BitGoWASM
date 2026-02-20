//! wasm-dot: WASM module for Polkadot/DOT transaction operations
//!
//! This crate provides:
//! - Transaction parsing (decode extrinsics)
//! - Signature operations (add signatures to unsigned transactions)
//! - Transaction building from intents
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
pub mod types;
pub mod wasm;

// Re-export main types for convenience
pub use address::{decode_ss58, encode_ss58, validate_address};
pub use error::WasmDotError;
pub use parser::{parse_transaction, ParsedTransaction};
pub use transaction::Transaction;
pub use types::{Material, ParseContext, Validity};
