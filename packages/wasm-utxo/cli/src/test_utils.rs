//! Test utilities for CLI tests
//!
//! This module provides lightweight utilities for loading test fixtures.

use base64::{engine::general_purpose, Engine as _};
use serde::Deserialize;
use wasm_utxo::Network;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureState {
    Unsigned,
    Halfsigned,
    Fullsigned,
}

impl SignatureState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureState::Unsigned => "unsigned",
            SignatureState::Halfsigned => "halfsigned",
            SignatureState::Fullsigned => "fullsigned",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxFormat {
    Psbt,
    PsbtLite,
}

impl TxFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            TxFormat::Psbt => "psbt",
            TxFormat::PsbtLite => "psbt-lite",
        }
    }
}

#[derive(Deserialize)]
struct PsbtFixtureBase64 {
    #[serde(rename = "psbtBase64")]
    psbt_base64: String,
}

#[derive(Deserialize)]
struct TxFixture {
    #[serde(rename = "extractedTransaction")]
    extracted_transaction: String,
}

/// Load PSBT bytes from a fixture file
///
/// # Arguments
/// * `network` - The network type
/// * `signature_state` - The signature state of the PSBT
/// * `tx_format` - The transaction format (Psbt or PsbtLite)
///
/// # Example
/// ```rust,no_run
/// use cli::test_utils::*;
/// use wasm_utxo::Network;
///
/// let psbt_bytes = load_psbt_bytes(
///     Network::Bitcoin,
///     SignatureState::Fullsigned,
///     TxFormat::PsbtLite
/// ).expect("Failed to load fixture");
/// ```
pub fn load_psbt_bytes(
    network: Network,
    signature_state: SignatureState,
    tx_format: TxFormat,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let filename = format!(
        "{}.{}.{}.json",
        tx_format.as_str(),
        network.to_coin_name(),
        signature_state.as_str()
    );
    let path = format!(
        "{}/test/fixtures/fixed-script/{}",
        env!("CARGO_MANIFEST_DIR"),
        filename
    );

    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("Failed to load fixture: {}", path));

    let fixture: PsbtFixtureBase64 = serde_json::from_str(&contents)?;

    let psbt_bytes = general_purpose::STANDARD.decode(&fixture.psbt_base64)?;
    Ok(psbt_bytes)
}

/// Load transaction bytes from a fixture file's extractedTransaction field
///
/// # Arguments
/// * `network` - The network type
/// * `signature_state` - The signature state of the transaction
/// * `tx_format` - The transaction format (Psbt or PsbtLite)
///
/// # Example
/// ```rust,no_run
/// use cli::test_utils::*;
/// use wasm_utxo::Network;
///
/// let tx_bytes = load_tx_bytes(
///     Network::Bitcoin,
///     SignatureState::Fullsigned,
///     TxFormat::PsbtLite
/// ).expect("Failed to load fixture");
/// ```
pub fn load_tx_bytes(
    network: Network,
    signature_state: SignatureState,
    tx_format: TxFormat,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let filename = format!(
        "{}.{}.{}.json",
        tx_format.as_str(),
        network.to_coin_name(),
        signature_state.as_str()
    );
    let path = format!(
        "{}/test/fixtures/fixed-script/{}",
        env!("CARGO_MANIFEST_DIR"),
        filename
    );

    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("Failed to load fixture: {}", path));

    let fixture: TxFixture = serde_json::from_str(&contents)?;

    let tx_bytes = hex::decode(&fixture.extracted_transaction)?;
    Ok(tx_bytes)
}
