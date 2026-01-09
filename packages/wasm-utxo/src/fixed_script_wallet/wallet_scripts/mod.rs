/// Code relating to script types of BitGo's 2-of-3 multisig wallets.
pub mod bitgo_musig;
mod checkmultisig;
mod checksigverify;
mod singlesig;

pub use bitgo_musig::BitGoMusigError;
pub use checkmultisig::{
    build_multisig_script_2_of_3, parse_multisig_script_2_of_3, ScriptP2sh, ScriptP2shP2wsh,
    ScriptP2wsh,
};
pub use checksigverify::{
    build_p2tr_ns_script, build_tap_tree_for_output, create_tap_bip32_derivation_for_output,
    ScriptP2tr,
};
pub use singlesig::{build_p2pk_script, ScriptP2shP2pk};

use crate::address::networks::OutputScriptSupport;
use crate::bitcoin::bip32::{ChildNumber, DerivationPath};
use crate::bitcoin::ScriptBuf;
use crate::error::WasmUtxoError;
use crate::fixed_script_wallet::wallet_keys::{
    to_pub_triple, PubTriple, RootWalletKeys, XpubTriple,
};
use std::convert::TryFrom;
use std::str::FromStr;

/// Scripts that belong to fixed-script BitGo wallets.
#[derive(Debug)]
pub enum WalletScripts {
    /// Chains 0 and 1. Legacy Pay-To-Script-Hash.
    P2sh(ScriptP2sh),
    /// Chains 10 and 11. Legacy Wrapped-Segwit Pay-To-Script-Hash.
    P2shP2wsh(ScriptP2shP2wsh),
    /// Chains 20 and 21. Native Wrapped-Segwit Pay-To-Script-Hash.
    P2wsh(ScriptP2wsh),
    /// Chains 30 and 31. Legacy Taproot, only supporting script-path spend.
    P2trLegacy(ScriptP2tr),
    /// Chains 40 and 41. Taproot with Musig2 key-path spend support.
    P2trMusig2(ScriptP2tr),
}

impl std::fmt::Display for WalletScripts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                WalletScripts::P2sh(_) => "P2sh".to_string(),
                WalletScripts::P2shP2wsh(_) => "P2shP2wsh".to_string(),
                WalletScripts::P2wsh(_) => "P2wsh".to_string(),
                WalletScripts::P2trLegacy(_) => "P2trLegacy".to_string(),
                WalletScripts::P2trMusig2(_) => "P2trMusig2".to_string(),
            }
        )
    }
}

impl WalletScripts {
    pub fn new(
        keys: &PubTriple,
        chain: Chain,
        script_support: &OutputScriptSupport,
    ) -> Result<WalletScripts, WasmUtxoError> {
        match chain.script_type {
            OutputScriptType::P2sh => {
                script_support.assert_legacy()?;
                let script = build_multisig_script_2_of_3(keys);
                Ok(WalletScripts::P2sh(ScriptP2sh {
                    redeem_script: script,
                }))
            }
            OutputScriptType::P2shP2wsh => {
                script_support.assert_segwit()?;
                let script = build_multisig_script_2_of_3(keys);
                Ok(WalletScripts::P2shP2wsh(ScriptP2shP2wsh {
                    redeem_script: script.clone().to_p2wsh(),
                    witness_script: script,
                }))
            }
            OutputScriptType::P2wsh => {
                script_support.assert_segwit()?;
                let script = build_multisig_script_2_of_3(keys);
                Ok(WalletScripts::P2wsh(ScriptP2wsh {
                    witness_script: script,
                }))
            }
            OutputScriptType::P2trLegacy => {
                script_support.assert_taproot()?;
                Ok(WalletScripts::P2trLegacy(ScriptP2tr::new(keys, false)))
            }
            OutputScriptType::P2trMusig2 => {
                script_support.assert_taproot()?;
                Ok(WalletScripts::P2trMusig2(ScriptP2tr::new(keys, true)))
            }
        }
    }

    pub fn from_wallet_keys(
        wallet_keys: &RootWalletKeys,
        chain: Chain,
        index: u32,
        script_support: &OutputScriptSupport,
    ) -> Result<WalletScripts, WasmUtxoError> {
        let derived_keys = wallet_keys
            .derive_for_chain_and_index(chain.value(), index)
            .unwrap();
        WalletScripts::new(&to_pub_triple(&derived_keys), chain, script_support)
    }

    pub fn output_script(&self) -> ScriptBuf {
        match self {
            WalletScripts::P2sh(script) => script.redeem_script.to_p2sh(),
            WalletScripts::P2shP2wsh(script) => script.redeem_script.to_p2sh(),
            WalletScripts::P2wsh(script) => script.witness_script.to_p2wsh(),
            WalletScripts::P2trLegacy(script) => script.output_script(),
            WalletScripts::P2trMusig2(script) => script.output_script(),
        }
    }
}

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

/// Fixed-script wallet script types (2-of-3 multisig)
///
/// This enum represents the abstract script type, independent of chain (external/internal).
/// Use this for checking network support or when you need the script type without derivation info.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum OutputScriptType {
    /// Legacy Pay-To-Script-Hash (chains 0, 1)
    P2sh,
    /// Wrapped-Segwit Pay-To-Script-Hash (chains 10, 11)
    P2shP2wsh,
    /// Native Segwit Pay-To-Witness-Script-Hash (chains 20, 21)
    P2wsh,
    /// Legacy Taproot, script-path only (chains 30, 31)
    P2trLegacy,
    /// Taproot with MuSig2 key-path support (chains 40, 41)
    P2trMusig2,
}

/// All OutputScriptType variants for iteration.
const ALL_SCRIPT_TYPES: [OutputScriptType; 5] = [
    OutputScriptType::P2sh,
    OutputScriptType::P2shP2wsh,
    OutputScriptType::P2wsh,
    OutputScriptType::P2trLegacy,
    OutputScriptType::P2trMusig2,
];

impl FromStr for OutputScriptType {
    type Err = String;

    /// Parse a script type string into an OutputScriptType.
    ///
    /// Accepts both output script types and input script types:
    /// - Output types: "p2sh", "p2shP2wsh", "p2wsh", "p2tr"/"p2trLegacy", "p2trMusig2"
    /// - Input types: "p2shP2pk" (→ P2sh), "p2trMusig2ScriptPath"/"p2trMusig2KeyPath" (→ P2trMusig2)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // Output script types
            "p2sh" => Ok(OutputScriptType::P2sh),
            "p2shP2wsh" => Ok(OutputScriptType::P2shP2wsh),
            "p2wsh" => Ok(OutputScriptType::P2wsh),
            // "p2tr" is kept as alias for backwards compatibility
            "p2tr" | "p2trLegacy" => Ok(OutputScriptType::P2trLegacy),
            "p2trMusig2" => Ok(OutputScriptType::P2trMusig2),
            // Input script types (normalized to output types)
            "p2shP2pk" => Ok(OutputScriptType::P2sh),
            "p2trMusig2ScriptPath" | "p2trMusig2KeyPath" => Ok(OutputScriptType::P2trMusig2),
            _ => Err(format!(
                "Unknown script type '{}'. Expected: p2sh, p2shP2wsh, p2wsh, p2trLegacy, p2trMusig2",
                s
            )),
        }
    }
}

impl OutputScriptType {
    /// Returns all possible OutputScriptType values.
    pub fn all() -> &'static [OutputScriptType; 5] {
        &ALL_SCRIPT_TYPES
    }

    /// Get the string representation of the script type
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputScriptType::P2sh => "p2sh",
            OutputScriptType::P2shP2wsh => "p2shP2wsh",
            OutputScriptType::P2wsh => "p2wsh",
            OutputScriptType::P2trLegacy => "p2trLegacy",
            OutputScriptType::P2trMusig2 => "p2trMusig2",
        }
    }
}

impl std::fmt::Display for OutputScriptType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Return derived WalletKeys. All keys are derived with the same path.
#[allow(dead_code)]
pub fn derive_xpubs_with_path(
    xpubs: &XpubTriple,
    ctx: &crate::bitcoin::secp256k1::Secp256k1<crate::bitcoin::secp256k1::All>,
    p: DerivationPath,
) -> XpubTriple {
    let derived = xpubs
        .iter()
        .map(|k| k.derive_pub(ctx, &p).unwrap())
        .collect::<Vec<_>>();
    derived.try_into().expect("could not convert vec to array")
}

pub fn derive_xpubs(
    xpubs: &XpubTriple,
    ctx: &crate::bitcoin::secp256k1::Secp256k1<crate::bitcoin::secp256k1::All>,
    chain: Chain,
    index: u32,
) -> XpubTriple {
    let p = DerivationPath::from_str("m/0/0")
        .unwrap()
        .child(ChildNumber::Normal {
            index: chain.value(),
        })
        .child(ChildNumber::Normal { index });
    derive_xpubs_with_path(xpubs, ctx, p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_script_wallet::wallet_keys::tests::get_test_wallet_keys;
    use crate::Network;

    const ALL_CHAINS: [Chain; 10] = [
        Chain::new(OutputScriptType::P2sh, Scope::External),
        Chain::new(OutputScriptType::P2sh, Scope::Internal),
        Chain::new(OutputScriptType::P2shP2wsh, Scope::External),
        Chain::new(OutputScriptType::P2shP2wsh, Scope::Internal),
        Chain::new(OutputScriptType::P2wsh, Scope::External),
        Chain::new(OutputScriptType::P2wsh, Scope::Internal),
        Chain::new(OutputScriptType::P2trLegacy, Scope::External),
        Chain::new(OutputScriptType::P2trLegacy, Scope::Internal),
        Chain::new(OutputScriptType::P2trMusig2, Scope::External),
        Chain::new(OutputScriptType::P2trMusig2, Scope::Internal),
    ];

    fn assert_output_script(keys: &RootWalletKeys, chain: Chain, expected_script: &str) {
        let scripts = WalletScripts::from_wallet_keys(
            keys,
            chain,
            0,
            &Network::Bitcoin.output_script_support(),
        )
        .unwrap();
        let output_script = scripts.output_script();
        assert_eq!(output_script.to_hex_string(), expected_script);
    }

    fn test_build_multisig_chain_with(keys: &RootWalletKeys, chain: Chain) {
        use OutputScriptType::*;
        use Scope::*;

        let expected = match (chain.script_type, chain.scope) {
            (P2sh, External) => "a914999a8eb861e3fabae1efe4fb16ff4752e1f5976687",
            (P2sh, Internal) => "a914487ca5843f23b9f3b85a00136bec647846d179ab87",
            (P2shP2wsh, External) => "a9141219b6d9430fffb8de14f14969a5c07172c4613b87",
            (P2shP2wsh, Internal) => "a914cbfab1a5a25afab05ff420bd9dd0958c6f1a7a2f87",
            (P2wsh, External) => {
                "0020ce670e65fd69ef2eb1aa6087643a18ae5bff198ca20ef26da546e85962386c76"
            }
            (P2wsh, Internal) => {
                "00209cca08a252f9846a1417afbe46ed96bf09d5ec6d25f0effb7d841188d5992b7c"
            }
            (P2trLegacy, External) => {
                "51203a81504b836967a69399fcf3822adfdb7d61061e42418f6aad0d473cbcc69b86"
            }
            (P2trLegacy, Internal) => {
                "512093e5e3c8885a6f87b4449e1bffa3ba8a45a9ee634dc27408394c7d9b68f01adc"
            }
            (P2trMusig2, External) => {
                "5120c7c4dd55b2bf3cd7ea5b27d3da521699ce761aa345523d8486f0336364957ef2"
            }
            (P2trMusig2, Internal) => {
                "51202629eea5dbef6841160a0b752dedd4b8e206f046835ee944848679d6dea2ac2c"
            }
        };
        assert_output_script(keys, chain, expected);
    }

    #[test]
    fn test_build_multisig_chain() {
        let keys = get_test_wallet_keys("lol");
        for chain in &ALL_CHAINS {
            test_build_multisig_chain_with(&keys, *chain);
        }
    }

    #[test]
    fn test_script_support_rejects_unsupported_script_types() {
        let keys = get_test_wallet_keys("test");

        // Test segwit rejection: try to create P2wsh on a network without segwit support
        let no_segwit_support = OutputScriptSupport {
            segwit: false,
            taproot: false,
        };

        use OutputScriptType::*;
        use Scope::*;

        let result = WalletScripts::from_wallet_keys(
            &keys,
            Chain::new(P2wsh, External),
            0,
            &no_segwit_support,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support segwit"));

        let result = WalletScripts::from_wallet_keys(
            &keys,
            Chain::new(P2shP2wsh, External),
            0,
            &no_segwit_support,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support segwit"));

        // Test taproot rejection: try to create P2tr on a network without taproot support
        let no_taproot_support = OutputScriptSupport {
            segwit: true,
            taproot: false,
        };

        let result = WalletScripts::from_wallet_keys(
            &keys,
            Chain::new(P2trLegacy, External),
            0,
            &no_taproot_support,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support taproot"));

        let result = WalletScripts::from_wallet_keys(
            &keys,
            Chain::new(P2trMusig2, External),
            0,
            &no_taproot_support,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support taproot"));

        // Test that legacy scripts work regardless of support flags
        let result = WalletScripts::from_wallet_keys(
            &keys,
            Chain::new(P2sh, External),
            0,
            &no_segwit_support,
        );
        assert!(result.is_ok());

        // Test real-world network scenarios
        // Dogecoin doesn't support segwit or taproot
        let doge_support = Network::Dogecoin.output_script_support();
        let result =
            WalletScripts::from_wallet_keys(&keys, Chain::new(P2wsh, External), 0, &doge_support);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support segwit"));

        // Litecoin supports segwit but not taproot
        let ltc_support = Network::Litecoin.output_script_support();
        let result = WalletScripts::from_wallet_keys(
            &keys,
            Chain::new(P2trLegacy, External),
            0,
            &ltc_support,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support taproot"));

        // Litecoin should support segwit scripts
        let result =
            WalletScripts::from_wallet_keys(&keys, Chain::new(P2wsh, External), 0, &ltc_support);
        assert!(result.is_ok());

        // Bitcoin should support all script types
        let btc_support = Network::Bitcoin.output_script_support();
        assert!(WalletScripts::from_wallet_keys(
            &keys,
            Chain::new(P2sh, External),
            0,
            &btc_support
        )
        .is_ok());
        assert!(WalletScripts::from_wallet_keys(
            &keys,
            Chain::new(P2wsh, External),
            0,
            &btc_support
        )
        .is_ok());
        assert!(WalletScripts::from_wallet_keys(
            &keys,
            Chain::new(P2trLegacy, External),
            0,
            &btc_support
        )
        .is_ok());
        assert!(WalletScripts::from_wallet_keys(
            &keys,
            Chain::new(P2trMusig2, External),
            0,
            &btc_support
        )
        .is_ok());
    }

    #[test]
    fn test_output_script_type_from_str() {
        use OutputScriptType::*;

        // Output script types
        assert_eq!(OutputScriptType::from_str("p2sh").unwrap(), P2sh);
        assert_eq!(OutputScriptType::from_str("p2shP2wsh").unwrap(), P2shP2wsh);
        assert_eq!(OutputScriptType::from_str("p2wsh").unwrap(), P2wsh);
        assert_eq!(OutputScriptType::from_str("p2tr").unwrap(), P2trLegacy);
        assert_eq!(
            OutputScriptType::from_str("p2trLegacy").unwrap(),
            P2trLegacy
        );
        assert_eq!(
            OutputScriptType::from_str("p2trMusig2").unwrap(),
            P2trMusig2
        );

        // Input script types (normalized to output types)
        assert_eq!(OutputScriptType::from_str("p2shP2pk").unwrap(), P2sh);
        assert_eq!(
            OutputScriptType::from_str("p2trMusig2ScriptPath").unwrap(),
            P2trMusig2
        );
        assert_eq!(
            OutputScriptType::from_str("p2trMusig2KeyPath").unwrap(),
            P2trMusig2
        );

        // Invalid script types
        assert!(OutputScriptType::from_str("invalid").is_err());
        assert!(OutputScriptType::from_str("p2pkh").is_err());
    }
}
