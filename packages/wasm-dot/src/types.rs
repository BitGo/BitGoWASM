//! Shared types for DOT transactions

use crate::error::WasmDotError;
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
    /// Runtime metadata as a 0x-prefixed hex string, matching the Substrate
    /// `state_getMetadata` RPC wire format.
    ///
    /// This is a string rather than raw bytes because metadata is returned as hex
    /// from the Substrate RPC and typically stored/transported as hex through JSON
    /// APIs. The hex-to-bytes decode happens once internally (in `decode_metadata`)
    /// right before SCALE decoding.
    pub metadata: String,
    /// Explicit format for chains not in the built-in mapping and optional
    /// generic-prefix acceptance for known chains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ss58_address_policy: Option<Ss58AddressPolicy>,
}

/// Address-domain policy supplied with trusted chain material.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ss58AddressPolicy {
    pub prefix: u16,
    #[serde(default)]
    pub allow_generic: bool,
}

impl Material {
    /// Derive the expected SS58 format; unknown chains must provide a verified prefix.
    pub fn address_policy(&self) -> Result<Ss58AddressPolicy, WasmDotError> {
        let known = AddressFormat::from_chain_name(&self.chain_name);
        let policy = match (known, self.ss58_address_policy) {
            (Some(format), None) => Ss58AddressPolicy {
                prefix: format.prefix(),
                allow_generic: false,
            },
            (Some(format), Some(policy)) if policy.prefix == format.prefix() => policy,
            (Some(format), Some(policy)) => {
                return Err(WasmDotError::InvalidInput(format!(
                    "SS58 prefix {} conflicts with chain {} (prefix {})",
                    policy.prefix, self.chain_name, format.prefix()
                )));
            }
            (None, Some(policy)) => policy,
            (None, None) => {
                return Err(WasmDotError::MissingContext(format!(
                    "SS58 prefix required for chain {}",
                    self.chain_name
                )));
            }
        };
        if policy.prefix >= 16384 {
            return Err(WasmDotError::InvalidInput(format!(
                "Invalid SS58 prefix: {}",
                policy.prefix
            )));
        }
        Ok(policy)
    }
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

    /// Get a format only for known chains; unknown chains require a policy.
    pub fn from_chain_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "polkadot" | "statemint" | "polkadot asset hub" => Some(Self::Polkadot),
            "kusama" | "statemine" | "kusama asset hub" => Some(Self::Kusama),
            "westend" | "substrate" => Some(Self::Substrate),
            _ => None,
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
            Some(AddressFormat::Polkadot)
        );
        assert_eq!(
            AddressFormat::from_chain_name("westend"),
            Some(AddressFormat::Substrate)
        );
        assert_eq!(AddressFormat::from_chain_name("unknown"), None);
    }

    #[test]
    fn test_material_address_policy() {
        let mut material: Material = serde_json::from_value(serde_json::json!({
            "genesisHash": "0x00", "chainName": "Polkadot", "specName": "polkadot",
            "specVersion": 1, "txVersion": 1, "metadata": "0x00"
        }))
        .unwrap();
        assert_eq!(material.address_policy().unwrap().prefix, 0);
        material.chain_name = "Kusama".into();
        assert_eq!(material.address_policy().unwrap().prefix, 2);
        material.chain_name = "Westend".into();
        assert_eq!(material.address_policy().unwrap().prefix, 42);
        material.chain_name = "Custom chain".into();
        assert!(matches!(material.address_policy(), Err(WasmDotError::MissingContext(_))));

        material.ss58_address_policy = Some(Ss58AddressPolicy { prefix: 1000, allow_generic: false });
        assert_eq!(material.address_policy().unwrap().prefix, 1000);
        material.chain_name = "Polkadot".into();
        assert!(matches!(material.address_policy(), Err(WasmDotError::InvalidInput(_))));
        material.chain_name = "Custom chain".into();
        material.ss58_address_policy = Some(Ss58AddressPolicy { prefix: 16384, allow_generic: false });
        assert!(matches!(material.address_policy(), Err(WasmDotError::InvalidInput(_))));
    }
}
