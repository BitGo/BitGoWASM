//! Intent-based transaction building.
//!
//! This module provides direct intent → transaction building without
//! an intermediate instruction abstraction.
//!
//! # Usage from TypeScript
//!
//! ```typescript
//! const result = buildFromIntent(intent, { feePayer, nonce });
//! // result.transaction - serialized transaction bytes
//! // result.generatedKeypairs - any keypairs generated (stake accounts, etc.)
//! ```

mod build;
mod types;

pub use build::build_from_intent;
pub use types::*;
