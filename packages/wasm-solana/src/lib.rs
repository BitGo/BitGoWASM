//! wasm-solana: WASM bindings for Solana cryptographic operations.
//!
//! This crate wraps the official Solana SDK crates (`solana-pubkey`, `solana-keypair`)
//! and exposes them via WASM bindings for use in JavaScript/TypeScript.
//!
//! # Architecture
//!
//! The crate follows a two-layer architecture:
//!
//! 1. **Core types** (`keypair`, `pubkey`) - Re-exports from Solana SDK with extension traits
//! 2. **WASM bindings** (`wasm/`) - Thin wrappers that expose core types to JavaScript
//!
//! # Usage from Rust
//!
//! ```rust
//! use wasm_solana::{Keypair, Pubkey, KeypairExt, PubkeyExt};
//!
//! // Generate a new keypair
//! let keypair = Keypair::new();
//! let address = keypair.address();
//!
//! // Parse an address
//! let pubkey = Pubkey::from_base58("FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH").unwrap();
//! ```

mod error;
pub mod instructions;
pub mod keypair;
pub mod pubkey;
pub mod transaction;
pub mod wasm;

// Re-export core types at crate root
pub use error::WasmSolanaError;
pub use keypair::{Keypair, KeypairExt};
pub use pubkey::{Pubkey, PubkeyExt};
pub use transaction::{Transaction, TransactionExt};

// Re-export instruction types
pub use instructions::{
    ComputeBudgetInstruction, ComputeBudgetInstructionType, StakeAuthorize, StakeInstruction,
    StakeInstructionType, SystemInstruction, SystemInstructionType,
};

// Re-export WASM types
pub use wasm::{WasmKeypair, WasmPubkey, WasmTransaction};
