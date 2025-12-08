//! PayGo Address Attestation
//!
//! This module provides utilities for parsing and verifying PayGo address attestations
//! stored in PSBT outputs. PayGo attestations are cryptographic proofs that an address
//! was authorized by a signing authority (typically an HSM).
//!
//! The attestation is stored in PSBT proprietary key-values with:
//! - Identifier: "BITGO"
//! - Subtype: PAYGO_ADDRESS_ATTESTATION_PROOF (0x04)
//! - Keydata: 64 bytes of entropy
//! - Value: ECDSA signature over [ENTROPY][ADDRESS][NIL_UUID]

mod attestation;
mod psbt;
mod verify;

pub use attestation::PayGoAttestation;
pub use psbt::{add_paygo_attestation, extract_paygo_attestation, has_paygo_attestation_verify};
pub use verify::verify_paygo_signature;

/// NIL UUID constant used in PayGo attestation messages
pub const NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

/// Length of entropy in bytes (fixed at 64 bytes)
pub const ENTROPY_LENGTH: usize = 64;
