//! wasm-ton: WASM bindings for TON cryptographic operations.
//!
//! This crate wraps the toner ecosystem crates (`tlb-ton`, `ton-contracts`)
//! and exposes them via WASM bindings for use in JavaScript/TypeScript.
//!
//! # Architecture
//!
//! The crate follows a two-layer architecture:
//!
//! 1. **Core types** (`address`, `transaction`, `parser`, `types`, `staking`)
//!    — Pure Rust business logic using toner crates
//! 2. **WASM bindings** (`wasm/`) — Thin wrappers that expose core types to JavaScript

pub mod address;
pub mod builder;
mod error;
pub mod parser;
pub mod staking;
pub mod transaction;
pub mod types;
pub mod wasm;

// Re-export core types at crate root
pub use error::WasmTonError;

// Re-export WASM types
pub use wasm::AddressNamespace;
pub use wasm::BuilderNamespace;
pub use wasm::ParserNamespace;
pub use wasm::WasmTransaction;
