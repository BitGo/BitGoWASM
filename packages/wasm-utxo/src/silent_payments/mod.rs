//! BIP-352 Silent Payments
//!
//! This module implements BIP-352 Silent Payments for Bitcoin, allowing a recipient
//! to publish a static address from which senders can derive unique, unlinkable
//! P2TR outputs without interaction.
//!
//! Submodules:
//! - `address`: SP address encoding/decoding (sp1q.../tsp1q... bech32m)
//! - `sender`: ECDH output derivation for sending
//! - `scanner`: Transaction scanning for receiving
//! - `spending`: Spend key derivation
//! - `labels`: Label support for sub-addresses

pub mod address;
pub mod labels;
pub mod scanner;
pub mod sender;
pub mod spending;
#[cfg(test)]
mod test_vectors;

use std::fmt;

/// Maximum number of outputs per recipient group (BIP-352 v1.1.0)
pub const K_MAX: u32 = 2323;

/// Error types for Silent Payment operations.
#[derive(Debug)]
pub enum SilentPaymentError {
    /// Invalid SP address format or content
    InvalidAddress(String),
    /// Invalid public or private key
    InvalidKey(String),
    /// Invalid scalar value (zero or >= curve order)
    InvalidScalar(String),
    /// secp256k1 operation failed
    Secp256k1(String),
    /// No eligible inputs for SP derivation
    NoEligibleInputs,
    /// No matching output found during scanning
    NoMatchFound,
    /// Too many recipients in a single group
    TooManyRecipients(usize),
}

impl fmt::Display for SilentPaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SilentPaymentError::InvalidAddress(msg) => write!(f, "Invalid SP address: {}", msg),
            SilentPaymentError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            SilentPaymentError::InvalidScalar(msg) => write!(f, "Invalid scalar: {}", msg),
            SilentPaymentError::Secp256k1(msg) => write!(f, "secp256k1 error: {}", msg),
            SilentPaymentError::NoEligibleInputs => write!(f, "No eligible inputs for SP"),
            SilentPaymentError::NoMatchFound => write!(f, "No matching SP output found"),
            SilentPaymentError::TooManyRecipients(n) => {
                write!(f, "Too many recipients in group: {} (max {})", n, K_MAX)
            }
        }
    }
}

impl std::error::Error for SilentPaymentError {}
