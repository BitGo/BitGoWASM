//! Shared types for DOT transactions

use serde::{Deserialize, Serialize};

/// Chain material metadata required for transaction encoding/decoding
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Material {
    /// Chain genesis hash (e.g., "0x91b171bb158e2d...")
    pub genesis_hash: String,
    /// Chain name (e.g., "Polkadot", "Westend")
    pub chain_name: String,
    /// Runtime spec name (e.g., "polkadot", "westmint")
    pub spec_name: String,
    /// Runtime spec version
    pub spec_version: u32,
    /// Transaction format version
    pub tx_version: u32,
    /// Runtime metadata bytes (hex encoded)
    /// Required for encoding calls - handles runtime upgrades automatically
    pub metadata: String,
}

/// Validity window for mortal transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Validity {
    /// Block number when transaction becomes valid
    pub first_valid: u32,
    /// Maximum duration in blocks (default: 2400, ~4 hours)
    #[serde(default = "default_max_duration")]
    pub max_duration: u32,
}

fn default_max_duration() -> u32 {
    2400
}

impl Default for Validity {
    fn default() -> Self {
        Self {
            first_valid: 0,
            max_duration: default_max_duration(),
        }
    }
}

/// Context required for parsing DOT transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParseContext {
    /// Chain material metadata
    pub material: Material,
    /// Sender address (if known, helps with decoding)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
}

/// Transaction era (mortal or immortal)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Era {
    /// Immortal transaction (never expires)
    Immortal,
    /// Mortal transaction with period and phase
    Mortal { period: u32, phase: u32 },
}

impl Era {
    /// Check if this is an immortal era
    pub fn is_immortal(&self) -> bool {
        matches!(self, Era::Immortal)
    }
}

/// SS58 address format prefixes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFormat {
    /// Polkadot mainnet (prefix 0, addresses start with '1')
    Polkadot = 0,
    /// Kusama (prefix 2)
    Kusama = 2,
    /// Substrate generic (prefix 42, addresses start with '5')
    Substrate = 42,
}

impl AddressFormat {
    /// Get the prefix value
    pub fn prefix(self) -> u16 {
        self as u16
    }

    /// Get format from chain name
    pub fn from_chain_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "polkadot" | "statemint" | "polkadot asset hub" => AddressFormat::Polkadot,
            "kusama" | "statemine" | "kusama asset hub" => AddressFormat::Kusama,
            _ => AddressFormat::Substrate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_era_is_immortal() {
        assert!(Era::Immortal.is_immortal());
        assert!(!Era::Mortal {
            period: 64,
            phase: 0
        }
        .is_immortal());
    }

    #[test]
    fn test_address_format_from_chain() {
        assert_eq!(
            AddressFormat::from_chain_name("Polkadot"),
            AddressFormat::Polkadot
        );
        assert_eq!(
            AddressFormat::from_chain_name("westend"),
            AddressFormat::Substrate
        );
    }
}
