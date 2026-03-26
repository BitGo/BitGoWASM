//! wasm-ton: WASM bindings for TON blockchain operations.
//!
//! This crate provides:
//! - Address encoding/decoding/validation (public key -> TON address)
//! - Transaction parsing and signing (BOC deserialization, signable payload, signature injection)
//! - Transaction type classification (Send, SendToken, staking ops)
//!
//! # Architecture
//!
//! The crate follows a two-layer architecture:
//!
//! 1. **Core layer** (`src/*.rs`): Pure Rust logic using `tonlib-core`, no WASM dependencies
//! 2. **WASM layer** (`src/wasm/*.rs`): Thin wrappers with `#[wasm_bindgen]`

pub mod address;
pub mod builder;
pub mod error;
pub mod parser;
pub mod transaction;
pub mod wasm;

// Re-export core types at crate root
pub use address::{decode_address, encode_address, validate_address, WalletVersion};
pub use builder::{
    build_transaction, Recipient, TonBuildContext, TonStakingType, TonTransactionIntent,
};
pub use error::WasmTonError;
pub use parser::{parse_transaction, ParsedTonTransaction, TransactionType};
pub use transaction::TonTransaction;

// Re-export WASM types
pub use wasm::{AddressNamespace, BuilderNamespace, ParserNamespace, WasmTransaction};
