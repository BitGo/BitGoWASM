use miniscript::bitcoin::bip32::DerivationPath;
use miniscript::bitcoin::psbt::Output;

use crate::fixed_script_wallet::{RootWalletKeys, ScriptId, WalletOutputScript};
use crate::Network;

/// Parsed output from a PSBT transaction
#[derive(Debug, Clone)]
pub struct ParsedOutput {
    pub address: Option<String>,
    pub script: Vec<u8>,
    pub value: u64,
    pub script_id: Option<ScriptId>,
    pub paygo: bool,
    /// Full BIP32 derivation path from the wallet xpub (e.g. `[chain, index]`).
    /// `None` for outputs that do not belong to this wallet.
    pub derivation_path: Option<DerivationPath>,
}

impl ParsedOutput {
    pub fn parse(
        psbt_output: &Output,
        tx_output: &miniscript::bitcoin::TxOut,
        wallet_keys: &RootWalletKeys,
        network: Network,
        paygo_pubkeys: &[miniscript::bitcoin::secp256k1::PublicKey],
    ) -> Result<Self, ParseOutputError> {
        let script = &tx_output.script_pubkey;

        let (script_id, derivation_path) = match WalletOutputScript::from_psbt(
            wallet_keys,
            &psbt_output.bip32_derivation,
            &psbt_output.tap_key_origins,
            false,
            script,
            network,
        )
        .map_err(ParseOutputError::WalletMatch)?
        {
            Some(wos) => (wos.script_id(), Some(wos.derivation_path)),
            None => (None, None),
        };

        let address =
            crate::address::networks::from_output_script_with_network(script.as_script(), network)
                .ok();

        let paygo = crate::paygo::has_paygo_attestation_verify(
            psbt_output,
            address.as_deref(),
            paygo_pubkeys,
        )
        .map_err(ParseOutputError::PayGoAttestation)?;

        Ok(Self {
            address,
            script: script.to_bytes(),
            value: tx_output.value.to_sat(),
            script_id,
            paygo,
            derivation_path,
        })
    }

    /// Returns true if this is an external output (not belonging to the wallet)
    pub fn is_external(&self) -> bool {
        self.derivation_path.is_none()
    }
}

/// Error type for parsing a single PSBT output
#[derive(Debug)]
pub enum ParseOutputError {
    /// Failed to match output to wallet (corruption or validation error)
    WalletMatch(String),
    /// Failed to extract or verify PayGo attestation
    PayGoAttestation(String),
}

impl std::fmt::Display for ParseOutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseOutputError::WalletMatch(error) => write!(f, "{}", error),
            ParseOutputError::PayGoAttestation(error) => {
                write!(f, "PayGo attestation error: {}", error)
            }
        }
    }
}

impl std::error::Error for ParseOutputError {}
