//! Tests for the Zcash PSBT modules, split by subject.
//!
//! - [`v4`]: the v4/Sapling PSBT surface.
//! - [`v6`]: transparent v6 (Ironwood) behavior (sighash, signatures, wire format).
//! - [`ironwood`]: shielded (PCZT) behavior and ZIP-317 accounting. Native-only.

use super::*;

mod v4;

#[cfg(not(target_arch = "wasm32"))]
mod common;
#[cfg(not(target_arch = "wasm32"))]
use common::*;
#[cfg(not(target_arch = "wasm32"))]
mod ironwood;
#[cfg(not(target_arch = "wasm32"))]
mod v6;
