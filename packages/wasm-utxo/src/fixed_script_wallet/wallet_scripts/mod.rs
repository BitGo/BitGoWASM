/// Code relating to script types of BitGo's 2-of-3 multisig wallets.
mod bitgo_musig;
mod checkmultisig;
mod checksigverify;
mod singlesig;

pub use bitgo_musig::{key_agg_bitgo_p2tr_legacy, BitGoMusigError};
pub use checkmultisig::{
    build_multisig_script_2_of_3, parse_multisig_script_2_of_3, ScriptP2sh, ScriptP2shP2wsh,
    ScriptP2wsh,
};
pub use checksigverify::{build_p2tr_ns_script, ScriptP2tr};
pub use singlesig::{build_p2pk_script, ScriptP2shP2pk};

use crate::bitcoin::bip32::{ChildNumber, DerivationPath};
use crate::bitcoin::ScriptBuf;
use crate::fixed_script_wallet::wallet_keys::{to_pub_triple, PubTriple, XpubTriple};
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
    pub fn new(keys: &PubTriple, chain: Chain) -> WalletScripts {
        match chain {
            Chain::P2shExternal | Chain::P2shInternal => {
                let script = build_multisig_script_2_of_3(keys);
                WalletScripts::P2sh(ScriptP2sh {
                    redeem_script: script,
                })
            }
            Chain::P2shP2wshExternal | Chain::P2shP2wshInternal => {
                let script = build_multisig_script_2_of_3(keys);
                WalletScripts::P2shP2wsh(ScriptP2shP2wsh {
                    redeem_script: script.clone().to_p2wsh(),
                    witness_script: script,
                })
            }
            Chain::P2wshExternal | Chain::P2wshInternal => {
                let script = build_multisig_script_2_of_3(keys);
                WalletScripts::P2wsh(ScriptP2wsh {
                    witness_script: script,
                })
            }
            Chain::P2trInternal | Chain::P2trExternal => {
                WalletScripts::P2trLegacy(ScriptP2tr::new(keys, false))
            }
            Chain::P2trMusig2Internal | Chain::P2trMusig2External => {
                WalletScripts::P2trMusig2(ScriptP2tr::new(keys, true))
            }
        }
    }

    pub fn from_xpubs(xpubs: &XpubTriple, chain: Chain, index: u32) -> WalletScripts {
        let ctx = crate::bitcoin::secp256k1::Secp256k1::new();
        let derived_keys = derive_xpubs(xpubs, &ctx, chain, index);
        let pub_triple = to_pub_triple(&derived_keys);
        WalletScripts::new(&pub_triple, chain)
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
    P2trInternal = 30,
    P2trExternal = 31,
    P2trMusig2Internal = 40,
    P2trMusig2External = 41,
}

/// Useful for iterating over enum values
const ALL_CHAINS: [Chain; 10] = [
    Chain::P2shExternal,
    Chain::P2shInternal,
    Chain::P2shP2wshExternal,
    Chain::P2shP2wshInternal,
    Chain::P2wshExternal,
    Chain::P2wshInternal,
    Chain::P2trInternal,
    Chain::P2trExternal,
    Chain::P2trMusig2Internal,
    Chain::P2trMusig2External,
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
    use miniscript::bitcoin::bip32::Xpub;
    use miniscript::bitcoin::consensus::Decodable;
    use miniscript::bitcoin::Transaction;

    use super::*;
    use crate::fixed_script_wallet::test_utils::fixtures;
    use crate::fixed_script_wallet::wallet_keys::tests::get_test_wallet_keys;
    use crate::fixed_script_wallet::wallet_keys::XpubTriple;

    fn assert_output_script(keys: &XpubTriple, chain: Chain, expected_script: &str) {
        let scripts = WalletScripts::from_xpubs(keys, chain, 0);
        let output_script = scripts.output_script();
        assert_eq!(output_script.to_hex_string(), expected_script);
    }

    fn test_build_multisig_chain_with(keys: &XpubTriple, chain: Chain) {
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
                    "51203a81504b836967a69399fcf3822adfdb7d61061e42418f6aad0d473cbcc69b86",
                );
            }
            Chain::P2trExternal => {
                assert_output_script(
                    keys,
                    chain,
                    "512093e5e3c8885a6f87b4449e1bffa3ba8a45a9ee634dc27408394c7d9b68f01adc",
                );
            }
            Chain::P2trMusig2Internal => {
                assert_output_script(
                    keys,
                    chain,
                    "5120c7c4dd55b2bf3cd7ea5b27d3da521699ce761aa345523d8486f0336364957ef2",
                );
            }
            Chain::P2trMusig2External => {
                assert_output_script(
                    keys,
                    chain,
                    "51202629eea5dbef6841160a0b752dedd4b8e206f046835ee944848679d6dea2ac2c",
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

    fn parse_derivation_path(path: &str) -> Result<(u32, u32), String> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != 4 {
            return Err(format!("Invalid path length: {}", path));
        }
        let chain = u32::from_str(parts[2]).map_err(|e| e.to_string())?;
        let index = u32::from_str(parts[3]).map_err(|e| e.to_string())?;
        Ok((chain, index))
    }

    fn xprvs_to_xpubs(xprvs: &[crate::bitcoin::bip32::Xpriv]) -> Result<XpubTriple, String> {
        if xprvs.len() != 3 {
            return Err(format!("Expected 3 xprvs, got {}", xprvs.len()));
        }
        let secp = crate::bitcoin::secp256k1::Secp256k1::new();
        let xpubs: Vec<Xpub> = xprvs
            .iter()
            .map(|xprv| Xpub::from_priv(&secp, xprv))
            .collect();
        xpubs
            .try_into()
            .map_err(|_| "Failed to convert to XpubTriple".to_string())
    }

    fn parse_fixture_paths(
        fixture_input: &fixtures::PsbtInputFixture,
    ) -> Result<(Chain, u32), String> {
        let bip32_path = match fixture_input {
            fixtures::PsbtInputFixture::P2sh(i) => i.bip32_derivation[0].path.to_string(),
            fixtures::PsbtInputFixture::P2shP2pk(_) => {
                // P2shP2pk doesn't have derivation paths in the fixture, use a dummy path
                return Err("P2shP2pk does not use chain-based derivation".to_string());
            }
            fixtures::PsbtInputFixture::P2shP2wsh(i) => i.bip32_derivation[0].path.to_string(),
            fixtures::PsbtInputFixture::P2wsh(i) => i.bip32_derivation[0].path.to_string(),
            fixtures::PsbtInputFixture::P2trLegacy(i) => i.tap_bip32_derivation[0].path.to_string(),
            fixtures::PsbtInputFixture::P2trMusig2ScriptPath(i) => {
                i.tap_bip32_derivation[0].path.to_string()
            }
            fixtures::PsbtInputFixture::P2trMusig2KeyPath(i) => {
                i.tap_bip32_derivation[0].path.to_string()
            }
        };
        let (chain_num, index) = parse_derivation_path(&bip32_path).expect("Failed to parse path");
        let chain = Chain::try_from(chain_num).expect("Invalid chain");
        Ok((chain, index))
    }

    fn find_input_with_script_type<'a>(
        fixture: &'a fixtures::PsbtFixture,
        script_type: &str,
    ) -> Result<(usize, &'a fixtures::PsbtInputFixture), String> {
        let result = fixture
            .psbt_inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| match input {
                fixtures::PsbtInputFixture::P2shP2pk(_) => script_type == "p2shP2pk",
                fixtures::PsbtInputFixture::P2sh(_) => script_type == "p2sh",
                fixtures::PsbtInputFixture::P2shP2wsh(_) => script_type == "p2shP2wsh",
                fixtures::PsbtInputFixture::P2wsh(_) => script_type == "p2wsh",
                fixtures::PsbtInputFixture::P2trLegacy(_) => script_type == "p2tr",
                fixtures::PsbtInputFixture::P2trMusig2ScriptPath(_) => script_type == "p2trMusig2",
                fixtures::PsbtInputFixture::P2trMusig2KeyPath(_) => script_type == "taprootKeypath",
            })
            .collect::<Vec<_>>();
        if result.len() != 1 {
            return Err(format!(
                "Expected 1 input with script type {}, got {}",
                script_type,
                result.len()
            ));
        }
        Ok(result[0])
    }

    fn get_output_script_from_non_witness_utxo(
        input: &fixtures::P2shInput,
        index: usize,
    ) -> String {
        use miniscript::bitcoin::hashes::hex::FromHex;
        let tx_bytes = Vec::<u8>::from_hex(&input.non_witness_utxo).expect("Failed to decode hex");
        let prev_tx: Transaction = Decodable::consensus_decode(&mut tx_bytes.as_slice())
            .expect("Failed to decode non-witness utxo");
        let output = &prev_tx.output[index];
        output.script_pubkey.to_hex_string()
    }

    fn test_wallet_script_type(script_type: &str) -> Result<(), String> {
        let fixture = fixtures::load_psbt_fixture("bitcoin", fixtures::SignatureState::Fullsigned)
            .expect("Failed to load fixture");
        let xprvs = fixtures::parse_wallet_keys(&fixture).expect("Failed to parse wallet keys");
        let xpubs = xprvs_to_xpubs(&xprvs).expect("Failed to convert to xpubs");

        let (input_index, input_fixture) = find_input_with_script_type(&fixture, script_type)
            .expect("Failed to find input with script type");

        let (chain, index) =
            parse_fixture_paths(input_fixture).expect("Failed to parse fixture paths");
        let scripts = WalletScripts::from_xpubs(&xpubs, chain, index);

        // Use the new helper methods for validation
        match (scripts, input_fixture) {
            (WalletScripts::P2sh(scripts), fixtures::PsbtInputFixture::P2sh(fixture_input)) => {
                let vout = fixture.inputs[input_index].index as usize;
                let output_script = get_output_script_from_non_witness_utxo(fixture_input, vout);
                fixture_input
                    .assert_matches_wallet_scripts(&scripts, &output_script)
                    .expect("P2sh validation failed");
            }
            (
                WalletScripts::P2shP2wsh(scripts),
                fixtures::PsbtInputFixture::P2shP2wsh(fixture_input),
            ) => {
                fixture_input
                    .assert_matches_wallet_scripts(&scripts, &fixture_input.witness_utxo.script)
                    .expect("P2shP2wsh validation failed");
            }
            (WalletScripts::P2wsh(scripts), fixtures::PsbtInputFixture::P2wsh(fixture_input)) => {
                fixture_input
                    .assert_matches_wallet_scripts(&scripts, &fixture_input.witness_utxo.script)
                    .expect("P2wsh validation failed");
            }
            (
                WalletScripts::P2trLegacy(scripts),
                fixtures::PsbtInputFixture::P2trLegacy(fixture_input),
            ) => {
                fixture_input
                    .assert_matches_wallet_scripts(&scripts)
                    .expect("P2trLegacy validation failed");
            }
            (
                WalletScripts::P2trMusig2(scripts),
                fixtures::PsbtInputFixture::P2trMusig2ScriptPath(fixture_input),
            ) => {
                fixture_input
                    .assert_matches_wallet_scripts(&scripts)
                    .expect("P2trMusig2ScriptPath validation failed");
            }
            (
                WalletScripts::P2trMusig2(scripts),
                fixtures::PsbtInputFixture::P2trMusig2KeyPath(fixture_input),
            ) => {
                fixture_input
                    .assert_matches_wallet_scripts(&scripts)
                    .expect("P2trMusig2KeyPath validation failed");
            }
            (scripts, input_fixture) => {
                return Err(format!(
                    "Mismatched input and scripts: {:?} and {:?}",
                    scripts, input_fixture
                ));
            }
        }

        Ok(())
    }

    #[test]
    fn test_p2sh_script_generation_from_fixture() {
        test_wallet_script_type("p2sh").unwrap()
    }

    #[test]
    fn test_p2sh_p2wsh_script_generation_from_fixture() {
        test_wallet_script_type("p2shP2wsh").unwrap();
    }

    #[test]
    fn test_p2wsh_script_generation_from_fixture() {
        test_wallet_script_type("p2wsh").unwrap();
    }

    #[test]
    fn test_p2tr_script_generation_from_fixture() {
        test_wallet_script_type("p2tr").unwrap();
    }

    #[test]
    fn test_p2tr_musig2_script_path_generation_from_fixture() {
        test_wallet_script_type("p2trMusig2").unwrap();
    }

    #[test]
    fn test_p2tr_musig2_key_path_spend_script_generation_from_fixture() {
        test_wallet_script_type("taprootKeypath").unwrap();
    }
}
