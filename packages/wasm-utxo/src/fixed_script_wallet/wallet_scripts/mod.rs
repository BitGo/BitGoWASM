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
        match chain {
            Chain::P2shExternal | Chain::P2shInternal => {
                script_support.assert_legacy()?;
                let script = build_multisig_script_2_of_3(keys);
                Ok(WalletScripts::P2sh(ScriptP2sh {
                    redeem_script: script,
                }))
            }
            Chain::P2shP2wshExternal | Chain::P2shP2wshInternal => {
                script_support.assert_segwit()?;
                let script = build_multisig_script_2_of_3(keys);
                Ok(WalletScripts::P2shP2wsh(ScriptP2shP2wsh {
                    redeem_script: script.clone().to_p2wsh(),
                    witness_script: script,
                }))
            }
            Chain::P2wshExternal | Chain::P2wshInternal => {
                script_support.assert_segwit()?;
                let script = build_multisig_script_2_of_3(keys);
                Ok(WalletScripts::P2wsh(ScriptP2wsh {
                    witness_script: script,
                }))
            }
            Chain::P2trInternal | Chain::P2trExternal => {
                script_support.assert_taproot()?;
                Ok(WalletScripts::P2trLegacy(ScriptP2tr::new(keys, false)))
            }
            Chain::P2trMusig2Internal | Chain::P2trMusig2External => {
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
            .derive_for_chain_and_index(chain as u32, index)
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

/// BitGo-Defined mappings between derivation path component and script type
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Chain {
    P2shExternal = 0,
    P2shInternal = 1,
    P2shP2wshExternal = 10,
    P2shP2wshInternal = 11,
    P2wshExternal = 20,
    P2wshInternal = 21,
    P2trExternal = 30,
    P2trInternal = 31,
    P2trMusig2External = 40,
    P2trMusig2Internal = 41,
}

/// Useful for iterating over enum values
const ALL_CHAINS: [Chain; 10] = [
    Chain::P2shExternal,
    Chain::P2shInternal,
    Chain::P2shP2wshExternal,
    Chain::P2shP2wshInternal,
    Chain::P2wshExternal,
    Chain::P2wshInternal,
    Chain::P2trExternal,
    Chain::P2trInternal,
    Chain::P2trMusig2External,
    Chain::P2trMusig2Internal,
];

impl Chain {
    #[allow(dead_code)]
    pub fn all() -> &'static [Chain; 10] {
        &ALL_CHAINS
    }
}

impl TryFrom<u32> for Chain {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        for chain in &ALL_CHAINS {
            if *chain as u32 == value {
                return Ok(*chain);
            }
        }
        Err(format!("no chain for {}", value))
    }
}

impl FromStr for Chain {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let chain: u32 = u32::from_str(s).map_err(|v| v.to_string())?;
        Chain::try_from(chain)
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
            index: chain as u32,
        })
        .child(ChildNumber::Normal { index });
    derive_xpubs_with_path(xpubs, ctx, p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_script_wallet::wallet_keys::tests::get_test_wallet_keys;
    use crate::Network;

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
        match chain {
            Chain::P2shExternal => {
                assert_output_script(
                    keys,
                    chain,
                    "a914999a8eb861e3fabae1efe4fb16ff4752e1f5976687",
                );
            }
            Chain::P2shInternal => {
                assert_output_script(
                    keys,
                    chain,
                    "a914487ca5843f23b9f3b85a00136bec647846d179ab87",
                );
            }
            Chain::P2shP2wshExternal => {
                assert_output_script(
                    keys,
                    chain,
                    "a9141219b6d9430fffb8de14f14969a5c07172c4613b87",
                );
            }
            Chain::P2shP2wshInternal => {
                assert_output_script(
                    keys,
                    chain,
                    "a914cbfab1a5a25afab05ff420bd9dd0958c6f1a7a2f87",
                );
            }
            Chain::P2wshExternal => {
                assert_output_script(
                    keys,
                    chain,
                    "0020ce670e65fd69ef2eb1aa6087643a18ae5bff198ca20ef26da546e85962386c76",
                );
            }
            Chain::P2wshInternal => {
                assert_output_script(
                    keys,
                    chain,
                    "00209cca08a252f9846a1417afbe46ed96bf09d5ec6d25f0effb7d841188d5992b7c",
                );
            }
            Chain::P2trInternal => {
                assert_output_script(
                    keys,
                    chain,
                    "512093e5e3c8885a6f87b4449e1bffa3ba8a45a9ee634dc27408394c7d9b68f01adc",
                );
            }
            Chain::P2trExternal => {
                assert_output_script(
                    keys,
                    chain,
                    "51203a81504b836967a69399fcf3822adfdb7d61061e42418f6aad0d473cbcc69b86",
                );
            }
            Chain::P2trMusig2Internal => {
                assert_output_script(
                    keys,
                    chain,
                    "51202629eea5dbef6841160a0b752dedd4b8e206f046835ee944848679d6dea2ac2c",
                );
            }
            Chain::P2trMusig2External => {
                assert_output_script(
                    keys,
                    chain,
                    "5120c7c4dd55b2bf3cd7ea5b27d3da521699ce761aa345523d8486f0336364957ef2",
                );
            }
        }
    }

    #[test]
    fn test_build_multisig_chain() {
        let keys = get_test_wallet_keys("lol");
        for chain in Chain::all() {
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

        let result =
            WalletScripts::from_wallet_keys(&keys, Chain::P2wshExternal, 0, &no_segwit_support);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support segwit"));

        let result =
            WalletScripts::from_wallet_keys(&keys, Chain::P2shP2wshExternal, 0, &no_segwit_support);
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

        let result =
            WalletScripts::from_wallet_keys(&keys, Chain::P2trExternal, 0, &no_taproot_support);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support taproot"));

        let result = WalletScripts::from_wallet_keys(
            &keys,
            Chain::P2trMusig2External,
            0,
            &no_taproot_support,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support taproot"));

        // Test that legacy scripts work regardless of support flags
        let result =
            WalletScripts::from_wallet_keys(&keys, Chain::P2shExternal, 0, &no_segwit_support);
        assert!(result.is_ok());

        // Test real-world network scenarios
        // Dogecoin doesn't support segwit or taproot
        let doge_support = Network::Dogecoin.output_script_support();
        let result = WalletScripts::from_wallet_keys(&keys, Chain::P2wshExternal, 0, &doge_support);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support segwit"));

        // Litecoin supports segwit but not taproot
        let ltc_support = Network::Litecoin.output_script_support();
        let result = WalletScripts::from_wallet_keys(&keys, Chain::P2trExternal, 0, &ltc_support);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network does not support taproot"));

        // Litecoin should support segwit scripts
        let result = WalletScripts::from_wallet_keys(&keys, Chain::P2wshExternal, 0, &ltc_support);
        assert!(result.is_ok());

        // Bitcoin should support all script types
        let btc_support = Network::Bitcoin.output_script_support();
        assert!(
            WalletScripts::from_wallet_keys(&keys, Chain::P2shExternal, 0, &btc_support).is_ok()
        );
        assert!(
            WalletScripts::from_wallet_keys(&keys, Chain::P2wshExternal, 0, &btc_support).is_ok()
        );
        assert!(
            WalletScripts::from_wallet_keys(&keys, Chain::P2trExternal, 0, &btc_support).is_ok()
        );
        assert!(
            WalletScripts::from_wallet_keys(&keys, Chain::P2trMusig2External, 0, &btc_support)
                .is_ok()
        );
    }
}
