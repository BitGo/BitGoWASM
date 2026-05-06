use std::convert::TryFrom;
use std::str::FromStr;

use super::wallet_scripts::{path_chain_index, OutputScriptType, WalletOutputScript};

/// Whether a chain is for receiving (external) or change (internal) addresses.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Scope {
    /// External chains are for receiving addresses (even chain values: 0, 10, 20, 30, 40).
    External,
    /// Internal chains are for change addresses (odd chain values: 1, 11, 21, 31, 41).
    Internal,
}

/// BitGo-Defined mappings between derivation path component and script type.
///
/// A Chain combines an `OutputScriptType` with a `Scope` (external/internal).
/// The chain value is used in derivation paths: `m/0/0/{chain}/{index}`.
///
/// Chain values are normalized: external = base, internal = base + 1.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Chain {
    pub script_type: OutputScriptType,
    pub scope: Scope,
}

impl Chain {
    /// Create a new Chain from script type and scope.
    pub const fn new(script_type: OutputScriptType, scope: Scope) -> Self {
        Self { script_type, scope }
    }

    /// Get the u32 chain value for derivation paths.
    pub const fn value(&self) -> u32 {
        (match self.script_type {
            OutputScriptType::P2sh => 0,
            OutputScriptType::P2shP2wsh => 10,
            OutputScriptType::P2wsh => 20,
            OutputScriptType::P2trLegacy => 30,
            OutputScriptType::P2trMusig2 => 40,
            OutputScriptType::P2mr => 360,
        }) + match self.scope {
            Scope::External => 0,
            Scope::Internal => 1,
        }
    }
}

impl TryFrom<u32> for Chain {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let (script_type, scope) = match value {
            0 => (OutputScriptType::P2sh, Scope::External),
            1 => (OutputScriptType::P2sh, Scope::Internal),
            10 => (OutputScriptType::P2shP2wsh, Scope::External),
            11 => (OutputScriptType::P2shP2wsh, Scope::Internal),
            20 => (OutputScriptType::P2wsh, Scope::External),
            21 => (OutputScriptType::P2wsh, Scope::Internal),
            30 => (OutputScriptType::P2trLegacy, Scope::External),
            31 => (OutputScriptType::P2trLegacy, Scope::Internal),
            40 => (OutputScriptType::P2trMusig2, Scope::External),
            41 => (OutputScriptType::P2trMusig2, Scope::Internal),
            360 => (OutputScriptType::P2mr, Scope::External),
            361 => (OutputScriptType::P2mr, Scope::Internal),
            _ => return Err(format!("no chain for {}", value)),
        };
        Ok(Chain::new(script_type, scope))
    }
}

impl FromStr for Chain {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let chain: u32 = u32::from_str(s).map_err(|v| v.to_string())?;
        Chain::try_from(chain)
    }
}

/// Identifies a wallet script by its chain and index in the derivation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptId {
    pub chain: u32,
    pub index: u32,
}

/// ScriptId with value — used by `from_half_signed_legacy_transaction`
#[derive(Debug, Clone, Copy)]
pub struct ScriptIdWithValue {
    pub chain: u32,
    pub index: u32,
    pub value: u64,
}

impl WalletOutputScript {
    /// Returns true if the chain component of the derivation path encodes the script type
    /// per BitGo convention (chain 0/1 = P2sh, 20/21 = P2wsh, etc.).
    pub fn chain_standard(&self) -> bool {
        path_chain_index(&self.derivation_path)
            .and_then(|(chain, _)| Chain::try_from(chain).ok())
            .is_some_and(|c| c.script_type == self.script_type)
    }

    /// Returns `Some(ScriptId)` if the derivation path is chain-standard, `None` otherwise.
    pub fn script_id(&self) -> Option<ScriptId> {
        path_chain_index(&self.derivation_path)
            .filter(|_| self.chain_standard())
            .map(|(chain, index)| ScriptId { chain, index })
    }
}
