//! wasm-ton: WASM bindings for TON cryptographic operations.
//!
//! This crate wraps the `tlb-ton` and `ton-contracts` crates to provide
//! TON address encoding/decoding, transaction parsing, signing support,
//! and intent-based transaction building via WASM bindings.

mod address;
pub mod builder;
mod error;
mod parser;
mod transaction;
pub mod wasm;

pub use address::{decode_address, encode_address, validate_address};
pub use error::WasmTonError;
pub use parser::{parse_transaction, ParsedTransaction, TransactionType};
pub use transaction::Transaction;

pub use wasm::{AddressNamespace, BuilderNamespace, ParserNamespace, TransactionNamespace};
