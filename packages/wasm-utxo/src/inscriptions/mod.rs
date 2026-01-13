//! Inscription support for Bitcoin Ordinals
//!
//! This module provides functionality for creating and signing inscription
//! reveal transactions following the Ordinals protocol.
//!
//! See: https://docs.ordinals.com/inscriptions.html

mod envelope;
mod reveal;

pub use envelope::build_inscription_script;
pub use reveal::{
    create_inscription_reveal_data, sign_reveal_transaction, InscriptionRevealData, TapLeafScript,
};
