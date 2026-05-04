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
    ScriptP2mr, ScriptP2tr,
};
pub use singlesig::{build_p2pk_script, parse_p2pk_script, ScriptP2shP2pk};

use crate::address::networks::OutputScriptSupport;
use crate::bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use crate::bitcoin::secp256k1::PublicKey as Secp256k1PublicKey;
use crate::bitcoin::{ScriptBuf, TapLeafHash, XOnlyPublicKey};
use crate::error::WasmUtxoError;
use crate::fixed_script_wallet::wallet_keys::{to_pub_triple, PubTriple, RootWalletKeys};
use crate::Network;
use std::collections::BTreeMap;
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
    /// Chains 360 and 361. BIP-360 Pay-to-Merkle-Root (P2MR).
    P2mr(ScriptP2mr),
}

impl WalletScripts {
    pub fn new(
        keys: &PubTriple,
        script_type: OutputScriptType,
        script_support: &OutputScriptSupport,
    ) -> Result<WalletScripts, WasmUtxoError> {
        match script_type {
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
            OutputScriptType::P2mr => {
                script_support.assert_p2mr()?;
                Ok(WalletScripts::P2mr(ScriptP2mr::new(keys)))
            }
        }
    }

    pub fn from_wallet_keys(
        wallet_keys: &RootWalletKeys,
        script_type: OutputScriptType,
        path: &DerivationPath,
        script_support: &OutputScriptSupport,
    ) -> Result<WalletScripts, WasmUtxoError> {
        let derived_keys = wallet_keys.derive_path(path)?;
        WalletScripts::new(&to_pub_triple(&derived_keys), script_type, script_support)
    }

    pub fn output_script(&self) -> ScriptBuf {
        match self {
            WalletScripts::P2sh(script) => script.redeem_script.to_p2sh(),
            WalletScripts::P2shP2wsh(script) => script.redeem_script.to_p2sh(),
            WalletScripts::P2wsh(script) => script.witness_script.to_p2wsh(),
            WalletScripts::P2trLegacy(script) => script.output_script(),
            WalletScripts::P2trMusig2(script) => script.output_script(),
            WalletScripts::P2mr(script) => script.output_script(),
        }
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
    /// BIP-360 Pay-to-Merkle-Root (chains 360, 361)
    P2mr,
}

/// All OutputScriptType variants for iteration.
const ALL_SCRIPT_TYPES: [OutputScriptType; 6] = [
    OutputScriptType::P2sh,
    OutputScriptType::P2shP2wsh,
    OutputScriptType::P2wsh,
    OutputScriptType::P2trLegacy,
    OutputScriptType::P2trMusig2,
    OutputScriptType::P2mr,
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
            "p2mr" => Ok(OutputScriptType::P2mr),
            // Input script types (normalized to output types)
            "p2shP2pk" => Ok(OutputScriptType::P2sh),
            "p2trMusig2ScriptPath" | "p2trMusig2KeyPath" => Ok(OutputScriptType::P2trMusig2),
            _ => Err(format!(
                "Unknown script type '{}'. Expected: p2sh, p2shP2wsh, p2wsh, p2trLegacy, p2trMusig2, p2mr",
                s
            )),
        }
    }
}

impl OutputScriptType {
    /// Returns all possible OutputScriptType values.
    pub fn all() -> &'static [OutputScriptType; 6] {
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
            OutputScriptType::P2mr => "p2mr",
        }
    }
}

impl std::fmt::Display for OutputScriptType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl OutputScriptType {
    fn is_network_supported(self, script_support: &OutputScriptSupport) -> bool {
        match self {
            Self::P2sh => true,
            Self::P2shP2wsh | Self::P2wsh => script_support.segwit,
            Self::P2trLegacy | Self::P2trMusig2 => script_support.taproot,
            Self::P2mr => script_support.p2mr,
        }
    }

    fn is_script_compatible(self, script: &ScriptBuf, has_witness_script: bool) -> bool {
        match self {
            Self::P2wsh => script.is_p2wsh(),
            // Skip plain P2sh only when we know for certain it's P2shP2wsh (witness_script present).
            // When has_witness_script=false (unknown), try both P2sh and P2shP2wsh.
            Self::P2sh => script.is_p2sh() && !has_witness_script,
            Self::P2shP2wsh => script.is_p2sh(),
            Self::P2trLegacy | Self::P2trMusig2 => script.is_p2tr(),
            Self::P2mr => true,
        }
    }

    /// Try to find which script type the wallet uses for `output_script` at `path`.
    /// Iterates all known script types; skips types unsupported by the network or
    /// incompatible with the script shape, then checks by derivation.
    /// Returns the first matching type, or `None` if none match.
    pub fn check(
        wallet_keys: &RootWalletKeys,
        output_script: &ScriptBuf,
        has_witness_script: bool,
        path: &DerivationPath,
        script_support: &OutputScriptSupport,
    ) -> Option<Self> {
        let (chain, index) = path_chain_index(path)?;
        let derived_keys = wallet_keys
            .derive_path(&chain_index_path(chain, index))
            .ok()?;
        let pub_triple = to_pub_triple(&derived_keys);
        for &script_type in Self::all() {
            if !script_type.is_network_supported(script_support) {
                continue;
            }
            if !script_type.is_script_compatible(output_script, has_witness_script) {
                continue;
            }
            if WalletScripts::new(&pub_triple, script_type, script_support)
                .ok()
                .is_some_and(|s| s.output_script() == *output_script)
            {
                return Some(script_type);
            }
        }
        None
    }
}

/// Extract the (chain, index) tail from a derivation path (last two Normal components).
pub(crate) fn path_chain_index(path: &DerivationPath) -> Option<(u32, u32)> {
    let children: Vec<ChildNumber> = path.into_iter().cloned().collect();
    let n = children.len();
    if n < 2 {
        return None;
    }
    match (children[n - 2], children[n - 1]) {
        (ChildNumber::Normal { index: chain }, ChildNumber::Normal { index }) => {
            Some((chain, index))
        }
        _ => None,
    }
}

/// A wallet output script matched to a derivation path.
#[derive(Debug, Clone)]
pub struct WalletOutputScript {
    pub script_type: OutputScriptType,
    /// The BIP32 derivation path; last two Normal components are (chain, index).
    pub derivation_path: DerivationPath,
}

impl WalletOutputScript {
    /// Try to match `output_script` at `path` against all script types supported by `network`.
    /// Returns `None` if no script type produces a match.
    pub fn from(
        wallet_keys: &RootWalletKeys,
        output_script: &ScriptBuf,
        path: DerivationPath,
        network: Network,
    ) -> Option<Self> {
        let script_type = OutputScriptType::check(
            wallet_keys,
            output_script,
            false,
            &path,
            &network.output_script_support(),
        )?;
        Some(Self {
            script_type,
            derivation_path: path,
        })
    }

    /// Match `output_script` against wallet keys using PSBT derivation metadata.
    ///
    /// Returns `Ok(None)` if the derivation maps are empty or belong to a different wallet,
    /// `Ok(Some(wos))` if the script matches, `Err` if keys are ours but no script type fits.
    pub fn from_psbt(
        wallet_keys: &RootWalletKeys,
        bip32_derivation: &BTreeMap<Secp256k1PublicKey, (Fingerprint, DerivationPath)>,
        tap_key_origins: &BTreeMap<
            XOnlyPublicKey,
            (Vec<TapLeafHash>, (Fingerprint, DerivationPath)),
        >,
        has_witness_script: bool,
        output_script: &ScriptBuf,
        network: Network,
    ) -> Result<Option<Self>, String> {
        if bip32_derivation.is_empty() && tap_key_origins.is_empty() {
            return Ok(None);
        }

        let belongs_to_wallet = if !bip32_derivation.is_empty() {
            bip32_derivation.values().all(|(fp, _)| {
                wallet_keys
                    .xpubs
                    .iter()
                    .any(|xpub| xpub.fingerprint() == *fp)
            })
        } else {
            tap_key_origins.values().all(|(_, (fp, _))| {
                wallet_keys
                    .xpubs
                    .iter()
                    .any(|xpub| xpub.fingerprint() == *fp)
            })
        };

        if !belongs_to_wallet {
            return Ok(None);
        }

        let path = if !bip32_derivation.is_empty() {
            bip32_derivation.values().next().map(|(_, path)| path)
        } else {
            tap_key_origins.values().next().map(|(_, (_, path))| path)
        }
        .ok_or_else(|| "no derivation paths".to_string())?
        .clone();

        let script_type = OutputScriptType::check(
            wallet_keys,
            output_script,
            has_witness_script,
            &path,
            &network.output_script_support(),
        )
        .ok_or_else(|| {
            format!(
                "wallet keys match but no script type matches actual script {}",
                output_script
            )
        })?;

        Ok(Some(Self {
            script_type,
            derivation_path: path,
        }))
    }
}

/// Build a 2-component derivation path `[chain, index]` — the standard form for wallet keys.
pub(crate) fn chain_index_path(chain: u32, index: u32) -> DerivationPath {
    DerivationPath::from(vec![
        ChildNumber::Normal { index: chain },
        ChildNumber::Normal { index },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_script_wallet::script_id::{Chain, Scope};
    use crate::fixed_script_wallet::wallet_keys::tests::get_test_wallet_keys;
    use crate::Network;

    const ALL_CHAINS: [Chain; 12] = [
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
        Chain::new(OutputScriptType::P2mr, Scope::External),
        Chain::new(OutputScriptType::P2mr, Scope::Internal),
    ];

    fn assert_output_script(keys: &RootWalletKeys, chain: Chain, expected_script: &str) {
        let scripts = WalletScripts::from_wallet_keys(
            keys,
            chain.script_type,
            &chain_index_path(chain.value(), 0),
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
            (P2mr, External) => {
                "5220e66329f43aaf6a473df4f49636836c651a410f51be31b54069922f0f71613140"
            }
            (P2mr, Internal) => {
                "5220d60831a20b0f5b1ccb9bec86527714199ffd8c00a344c195fa0de8184fbd80e8"
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
            p2mr: false,
        };

        use OutputScriptType::{P2sh, P2shP2wsh, P2trLegacy, P2trMusig2, P2wsh};
        let p = &chain_index_path(0, 0);

        let result = WalletScripts::from_wallet_keys(&keys, P2wsh, p, &no_segwit_support);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support segwit"));

        let result = WalletScripts::from_wallet_keys(&keys, P2shP2wsh, p, &no_segwit_support);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support segwit"));

        // Test taproot rejection: try to create P2tr on a network without taproot support
        let no_taproot_support = OutputScriptSupport {
            segwit: true,
            taproot: false,
            p2mr: false,
        };

        let result = WalletScripts::from_wallet_keys(&keys, P2trLegacy, p, &no_taproot_support);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support taproot"));

        let result = WalletScripts::from_wallet_keys(&keys, P2trMusig2, p, &no_taproot_support);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support taproot"));

        // Test that legacy scripts work regardless of support flags
        assert!(WalletScripts::from_wallet_keys(&keys, P2sh, p, &no_segwit_support).is_ok());

        // Test real-world network scenarios
        let doge_support = Network::Dogecoin.output_script_support();
        let result = WalletScripts::from_wallet_keys(&keys, P2wsh, p, &doge_support);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support segwit"));

        let ltc_support = Network::Litecoin.output_script_support();
        let result = WalletScripts::from_wallet_keys(&keys, P2trLegacy, p, &ltc_support);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support taproot"));

        assert!(WalletScripts::from_wallet_keys(&keys, P2wsh, p, &ltc_support).is_ok());

        let btc_support = Network::Bitcoin.output_script_support();
        assert!(WalletScripts::from_wallet_keys(&keys, P2sh, p, &btc_support).is_ok());
        assert!(WalletScripts::from_wallet_keys(&keys, P2wsh, p, &btc_support).is_ok());
        assert!(WalletScripts::from_wallet_keys(&keys, P2trLegacy, p, &btc_support).is_ok());
        assert!(WalletScripts::from_wallet_keys(&keys, P2trMusig2, p, &btc_support).is_ok());
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
