//! WASM bindings for wasm-dot
//!
//! This module contains thin wrappers with #[wasm_bindgen] that delegate
//! to the core Rust implementations.

pub mod builder;
pub mod parser;
pub mod transaction;
pub mod try_into_js_value;

// Re-export WASM types
pub use builder::BuilderNamespace;
pub use parser::ParserNamespace;
pub use transaction::{MaterialJs, ParseContextJs, ValidityJs, WasmTransaction};
