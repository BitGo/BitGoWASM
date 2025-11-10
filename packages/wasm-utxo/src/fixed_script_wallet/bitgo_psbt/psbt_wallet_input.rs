use miniscript::bitcoin::bip32::{ChildNumber, DerivationPath};
use miniscript::bitcoin::psbt::{Input, Psbt};
use miniscript::bitcoin::secp256k1::{self, PublicKey};
use miniscript::bitcoin::{OutPoint, ScriptBuf, TapLeafHash, XOnlyPublicKey};

use crate::bitcoin::bip32::KeySource;
use crate::fixed_script_wallet::{Chain, RootWalletKeys, WalletScripts};
use crate::Network;

#[derive(Debug, Clone)]
pub struct ReplayProtection {
    pub permitted_output_scripts: Vec<ScriptBuf>,
}

impl ReplayProtection {
    pub fn new(permitted_output_scripts: Vec<ScriptBuf>) -> Self {
        Self {
            permitted_output_scripts,
        }
    }

    pub fn is_replay_protection_input(&self, output_script: &ScriptBuf) -> bool {
        self.permitted_output_scripts.contains(output_script)
    }
}

type Bip32DerivationMap = std::collections::BTreeMap<PublicKey, KeySource>;

/// Make sure that deriving from the wallet xpubs matches keys in the derivation map
/// Check if BIP32 derivation info belongs to the wallet keys (non-failing)
/// Returns true if all fingerprints match, false if any don't match (external wallet)
pub fn is_bip32_derivation_for_wallet(
    wallet_keys: &RootWalletKeys,
    derivation_map: &Bip32DerivationMap,
) -> bool {
    derivation_map.iter().all(|(_, (fingerprint, _))| {
        wallet_keys
            .xpubs
            .iter()
            .any(|xpub| xpub.fingerprint() == *fingerprint)
    })
}

fn assert_bip32_derivation_map(
    wallet_keys: &RootWalletKeys,
    derivation_map: &Bip32DerivationMap,
) -> Result<(), String> {
    for (key, (fingerprint, path)) in derivation_map {
        let derived_key = wallet_keys
            .xpubs
            .iter()
            .find(|xpub| xpub.fingerprint() == *fingerprint)
            .ok_or_else(|| format!("No xpub found with fingerprint {}", fingerprint))?;
        let derived_key = derived_key
            .derive_pub(&secp256k1::Secp256k1::new(), path)
            .map_err(|e| format!("Failed to derive pubkey: {}", e))?;
        if derived_key.public_key != *key {
            return Err(format!(
                "Derived pubkey {} does not match derivation map {}",
                derived_key.public_key, key
            ));
        }
    }
    Ok(())
}

type TapKeyOrigins = std::collections::BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>;

/// Check if tap key origins belong to the wallet keys (non-failing)
/// Returns true if all fingerprints match, false if any don't match (external wallet)
pub fn is_tap_key_origins_for_wallet(
    wallet_keys: &RootWalletKeys,
    tap_key_origins: &TapKeyOrigins,
) -> bool {
    tap_key_origins.iter().all(|(_, (_, (fingerprint, _)))| {
        wallet_keys
            .xpubs
            .iter()
            .any(|xpub| xpub.fingerprint() == *fingerprint)
    })
}

fn assert_tap_key_origins(
    wallet_keys: &RootWalletKeys,
    tap_key_origins: &TapKeyOrigins,
) -> Result<(), String> {
    for (key, (_, (fingerprint, path))) in tap_key_origins {
        let derived_key = wallet_keys
            .xpubs
            .iter()
            .find(|xpub| xpub.fingerprint() == *fingerprint)
            .ok_or_else(|| format!("No xpub found with fingerprint {}", fingerprint))?;
        let derived_key = derived_key
            .derive_pub(&secp256k1::Secp256k1::new(), path)
            .map_err(|e| format!("Failed to derive pubkey: {}", e))?
            .to_x_only_pub();
        if derived_key != *key {
            return Err(format!(
                "Derived pubkey {} does not match derivation map {}",
                derived_key, key
            ));
        }
    }
    Ok(())
}

struct WalletDerivationPath {
    #[allow(dead_code)]
    prefix: DerivationPath,
    chain: u32,
    index: u32,
}

fn parse_derivation_path(path: &DerivationPath) -> Result<WalletDerivationPath, String> {
    let length = path.len();
    if length < 2 {
        return Err("Invalid path".to_string());
    }
    let prefix = path[..length - 2].to_vec();
    let chain = path[length - 2];
    let index = path[length - 1];

    let chain = if let ChildNumber::Normal { index } = chain {
        index
    } else {
        return Err("Invalid chain number".to_string());
    };

    let index = if let ChildNumber::Normal { index } = index {
        index
    } else {
        return Err("Invalid index".to_string());
    };

    Ok(WalletDerivationPath {
        prefix: DerivationPath::from_iter(prefix),
        chain,
        index,
    })
}

/// Extract derivation paths from either BIP32 derivation or tap key origins
pub fn get_derivation_paths(input: &Input) -> Vec<&DerivationPath> {
    if !input.bip32_derivation.is_empty() {
        input
            .bip32_derivation
            .values()
            .map(|(_, path)| path)
            .collect()
    } else {
        input
            .tap_key_origins
            .values()
            .map(|(_, (_, path))| path)
            .collect()
    }
}

/// Extract derivation paths from PSBT output metadata
pub fn get_output_derivation_paths(
    output: &miniscript::bitcoin::psbt::Output,
) -> Vec<&DerivationPath> {
    if !output.bip32_derivation.is_empty() {
        output
            .bip32_derivation
            .values()
            .map(|(_, path)| path)
            .collect()
    } else {
        output
            .tap_key_origins
            .values()
            .map(|(_, (_, path))| path)
            .collect()
    }
}

pub fn parse_shared_derivation_path(key_origins: &[&DerivationPath]) -> Result<(u32, u32), String> {
    let paths = key_origins
        .iter()
        .map(|path| parse_derivation_path(path))
        .collect::<Result<Vec<_>, String>>()?;
    if paths.is_empty() {
        return Err("Invalid input".to_string());
    }
    // if chain and index are the same for all paths, return the chain and index
    let chain = paths[0].chain;
    let index = paths[0].index;
    for path in paths {
        if path.chain != chain || path.index != index {
            return Err("Invalid input".to_string());
        }
    }
    Ok((chain, index))
}

pub fn parse_shared_chain_and_index(input: &Input) -> Result<(u32, u32), String> {
    if input.bip32_derivation.is_empty() && input.tap_key_origins.is_empty() {
        return Err(
            "Invalid input: both bip32_derivation and tap_key_origins are empty".to_string(),
        );
    }

    let derivation_paths = get_derivation_paths(input);
    parse_shared_derivation_path(&derivation_paths)
}

fn assert_wallet_output_script(
    wallet_keys: &RootWalletKeys,
    chain: Chain,
    index: u32,
    script_pub_key: &ScriptBuf,
) -> Result<(), String> {
    let derived_scripts = WalletScripts::from_wallet_keys(
        wallet_keys,
        chain,
        index,
        &Network::Bitcoin.output_script_support(),
    )
    .map_err(|e| e.to_string())?;
    if derived_scripts.output_script() != *script_pub_key {
        return Err(format!(
            "Script mismatch: from script {:?} != from path {:?}",
            derived_scripts.output_script(),
            script_pub_key
        ));
    }
    Ok(())
}

/// asserts that the script belongs to the wallet
pub fn assert_wallet_input(
    wallet_keys: &RootWalletKeys,
    input: &Input,
    output_script: &ScriptBuf,
) -> Result<(), String> {
    if input.bip32_derivation.is_empty() {
        assert_tap_key_origins(wallet_keys, &input.tap_key_origins)?;
    } else {
        assert_bip32_derivation_map(wallet_keys, &input.bip32_derivation)?;
    }
    let (chain, index) = parse_shared_chain_and_index(input)?;
    let chain = Chain::try_from(chain).map_err(|e| e.to_string())?;
    assert_wallet_output_script(wallet_keys, chain, index, output_script)?;
    Ok(())
}

#[derive(Debug)]
pub enum OutputScriptError {
    OutputIndexOutOfBounds { vout: u32 },
    BothUtxoFieldsSet,
    NoUtxoFields,
}

impl std::fmt::Display for OutputScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputScriptError::OutputIndexOutOfBounds { vout } => {
                write!(f, "Output index {} out of bounds", vout)
            }
            OutputScriptError::BothUtxoFieldsSet => {
                write!(f, "Both witness_utxo and non_witness_utxo are set")
            }
            OutputScriptError::NoUtxoFields => {
                write!(f, "Neither witness_utxo nor non_witness_utxo is set")
            }
        }
    }
}

impl std::error::Error for OutputScriptError {}

/// Identifies a script by its chain and index in the wallet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptId {
    pub chain: u32,
    pub index: u32,
}

/// Parsed input from a PSBT transaction
#[derive(Debug, Clone)]
pub struct ParsedInput {
    pub address: String,
    pub script: Vec<u8>,
    pub value: u64,
    pub script_id: Option<ScriptId>,
}

impl ParsedInput {
    /// Parse a PSBT input with wallet keys to identify if it belongs to the wallet
    ///
    /// # Arguments
    /// - `psbt_input`: The PSBT input metadata
    /// - `tx_input`: The transaction input
    /// - `wallet_keys`: The wallet's root keys for deriving scripts
    /// - `replay_protection`: Scripts that are allowed as inputs without wallet validation
    /// - `network`: The network for address generation
    ///
    /// # Returns
    /// - `Ok(ParsedInput)` with address, value, and optional script_id
    /// - `Err(ParseInputError)` if validation fails
    pub fn parse(
        psbt_input: &Input,
        tx_input: &miniscript::bitcoin::TxIn,
        wallet_keys: &RootWalletKeys,
        replay_protection: &ReplayProtection,
        network: Network,
    ) -> Result<Self, ParseInputError> {
        // Get output script and value from the UTXO
        let (output_script, value) =
            get_output_script_and_value(psbt_input, tx_input.previous_output)
                .map_err(ParseInputError::Utxo)?;

        // Check if this is a replay protection input
        let is_replay_protection = replay_protection.is_replay_protection_input(output_script);

        let script_id = if is_replay_protection {
            None
        } else {
            // Parse derivation info and validate
            let (chain, index) =
                parse_shared_chain_and_index(psbt_input).map_err(ParseInputError::Derivation)?;

            // Validate that the input belongs to the wallet
            assert_wallet_input(wallet_keys, psbt_input, output_script)
                .map_err(ParseInputError::WalletValidation)?;

            Some(ScriptId { chain, index })
        };

        // Convert script to address
        let address = crate::address::networks::from_output_script_with_network(
            output_script.as_script(),
            network,
        )
        .map_err(ParseInputError::Address)?;

        Ok(Self {
            address,
            script: output_script.to_bytes(),
            value: value.to_sat(),
            script_id,
        })
    }
}

/// Error type for parsing a single PSBT input
#[derive(Debug)]
pub enum ParseInputError {
    /// Failed to extract output script or value from input
    Utxo(OutputScriptError),
    /// Input value overflow when adding to total
    ValueOverflow,
    /// Input missing or has invalid derivation info (and is not replay protection)
    Derivation(String),
    /// Input failed wallet validation
    WalletValidation(String),
    /// Failed to generate address for input
    Address(crate::address::AddressError),
}

impl std::fmt::Display for ParseInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseInputError::Utxo(error) => write!(f, "{}", error),
            ParseInputError::ValueOverflow => write!(f, "value overflow"),
            ParseInputError::Derivation(error) => {
                write!(
                    f,
                    "missing or invalid derivation info (not replay protection): {}",
                    error
                )
            }
            ParseInputError::WalletValidation(error) => {
                write!(f, "wallet validation failed: {}", error)
            }
            ParseInputError::Address(error) => {
                write!(f, "failed to generate address: {}", error)
            }
        }
    }
}

impl std::error::Error for ParseInputError {}

/// Get both output script and value from a PSBT input
pub fn get_output_script_and_value(
    input: &Input,
    prevout: OutPoint,
) -> Result<(&ScriptBuf, miniscript::bitcoin::Amount), OutputScriptError> {
    match (&input.witness_utxo, &input.non_witness_utxo) {
        (Some(witness_utxo), None) => Ok((&witness_utxo.script_pubkey, witness_utxo.value)),
        (None, Some(non_witness_utxo)) => {
            let output = non_witness_utxo
                .output
                .get(prevout.vout as usize)
                .ok_or(OutputScriptError::OutputIndexOutOfBounds { vout: prevout.vout })?;
            Ok((&output.script_pubkey, output.value))
        }
        (Some(_), Some(_)) => Err(OutputScriptError::BothUtxoFieldsSet),
        (None, None) => Err(OutputScriptError::NoUtxoFields),
    }
}

fn get_output_script_from_input(
    input: &Input,
    prevout: OutPoint,
) -> Result<&ScriptBuf, OutputScriptError> {
    // Delegate to get_output_script_and_value and return just the script
    get_output_script_and_value(input, prevout).map(|(script, _value)| script)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputValidationErrorKind {
    /// Failed to extract output script from input
    InvalidOutputScript(String),
    /// Input does not belong to the wallet
    NonWalletInput {
        output_script: ScriptBuf,
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputValidationError {
    pub input_index: usize,
    pub prevout: OutPoint,
    pub kind: InputValidationErrorKind,
}

impl std::fmt::Display for InputValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            InputValidationErrorKind::InvalidOutputScript(error) => {
                write!(
                    f,
                    "Input {} prevout={} failed to extract output script: {}",
                    self.input_index, self.prevout, error
                )
            }
            InputValidationErrorKind::NonWalletInput {
                output_script,
                error,
            } => {
                write!(
                    f,
                    "Input {} prevout={} output_script={:x} does not belong to the wallet: {}",
                    self.input_index, self.prevout, output_script, error
                )
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PsbtValidationError {
    /// Number of prevouts does not match number of PSBT inputs
    InputLengthMismatch {
        prevouts_len: usize,
        inputs_len: usize,
    },
    /// One or more inputs failed validation
    InvalidInputs(Vec<InputValidationError>),
}

impl std::fmt::Display for PsbtValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PsbtValidationError::InputLengthMismatch {
                prevouts_len,
                inputs_len,
            } => {
                write!(
                    f,
                    "Invalid input: prevouts length {} != psbt inputs length {}",
                    prevouts_len, inputs_len
                )
            }
            PsbtValidationError::InvalidInputs(errors) => {
                write!(f, "Validation failed for {} input(s):", errors.len())?;
                for error in errors {
                    write!(f, "\n  - {}", error)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for PsbtValidationError {}

/// Validates that all inputs in a PSBT belong to the wallet
pub fn validate_psbt_wallet_inputs(
    psbt: &Psbt,
    wallet_keys: &RootWalletKeys,
    replay_protection: &ReplayProtection,
) -> Result<(), PsbtValidationError> {
    let prevouts = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect::<Vec<_>>();

    if prevouts.len() != psbt.inputs.len() {
        return Err(PsbtValidationError::InputLengthMismatch {
            prevouts_len: prevouts.len(),
            inputs_len: psbt.inputs.len(),
        });
    }

    let mut validation_errors = Vec::new();

    for (input_index, (prevout, input)) in prevouts.iter().zip(psbt.inputs.iter()).enumerate() {
        let output_script = match get_output_script_from_input(input, *prevout) {
            Ok(script) => script,
            Err(e) => {
                validation_errors.push(InputValidationError {
                    input_index,
                    prevout: *prevout,
                    kind: InputValidationErrorKind::InvalidOutputScript(e.to_string()),
                });
                continue;
            }
        };

        if replay_protection.is_replay_protection_input(output_script) {
            continue;
        }

        if let Err(e) = assert_wallet_input(wallet_keys, input, output_script) {
            validation_errors.push(InputValidationError {
                input_index,
                prevout: *prevout,
                kind: InputValidationErrorKind::NonWalletInput {
                    output_script: output_script.clone(),
                    error: e,
                },
            });
        }
    }

    if !validation_errors.is_empty() {
        return Err(PsbtValidationError::InvalidInputs(validation_errors));
    }

    Ok(())
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use crate::fixed_script_wallet::{RootWalletKeys, XpubTriple};
    use crate::test_utils::fixtures;

    /// Checks if a specific input in a PSBT is protected by replay protection
    pub fn is_replay_protected_input(
        psbt: &Psbt,
        input_index: usize,
        replay_protection: &ReplayProtection,
    ) -> bool {
        if input_index >= psbt.inputs.len() || input_index >= psbt.unsigned_tx.input.len() {
            return false;
        }

        let input = &psbt.inputs[input_index];
        let prevout = psbt.unsigned_tx.input[input_index].previous_output;

        // Try to get output script using the helper function
        let output_script = match get_output_script_from_input(input, prevout) {
            Ok(script) => script,
            Err(_) => return false,
        };

        replay_protection.is_replay_protection_input(output_script)
    }

    /// Creates a list of expected validation errors for all non-replay-protected inputs
    pub fn expected_validation_errors(
        psbt: &Psbt,
        replay_protection: &ReplayProtection,
        error_kind: impl Fn(usize) -> InputValidationErrorKind,
    ) -> Vec<InputValidationError> {
        let mut errors = Vec::new();

        for input_index in 0..psbt.inputs.len() {
            if !is_replay_protected_input(psbt, input_index, replay_protection) {
                let prevout = psbt.unsigned_tx.input[input_index].previous_output;
                errors.push(InputValidationError {
                    input_index,
                    prevout,
                    kind: error_kind(input_index),
                });
            }
        }

        errors
    }

    /// Creates expected validation errors for non-wallet inputs when wallet keys are invalid
    /// This includes all non-replay-protected inputs
    pub fn expected_validation_errors_non_wallet_inputs(
        psbt: &Psbt,
        replay_protection: &ReplayProtection,
    ) -> Vec<InputValidationError> {
        expected_validation_errors(psbt, replay_protection, |_| {
            InputValidationErrorKind::NonWalletInput {
                output_script: ScriptBuf::new(), // Placeholder, we only check the variant
                error: String::new(),
            }
        })
    }

    /// Creates expected validation errors for replay protection inputs when no replay protection is provided
    /// This only includes inputs that would normally be protected by replay protection
    pub fn expected_validation_errors_unexpected_replay_protection(
        psbt: &Psbt,
        replay_protection: &ReplayProtection,
    ) -> Vec<InputValidationError> {
        let mut errors = Vec::new();

        for input_index in 0..psbt.inputs.len() {
            if is_replay_protected_input(psbt, input_index, replay_protection) {
                let prevout = psbt.unsigned_tx.input[input_index].previous_output;
                let output_script =
                    match get_output_script_from_input(&psbt.inputs[input_index], prevout) {
                        Ok(script) => script.clone(),
                        Err(_) => continue,
                    };

                errors.push(InputValidationError {
                    input_index,
                    prevout,
                    kind: InputValidationErrorKind::NonWalletInput {
                        output_script,
                        error: String::new(),
                    },
                });
            }
        }

        errors
    }

    /// Compares actual and expected input validation errors
    /// Only checks structural equality (input_index, prevout, error variant type)
    pub fn assert_error_eq(actual: &InputValidationError, expected: &InputValidationError) {
        assert_eq!(
            actual.input_index, expected.input_index,
            "Input index mismatch"
        );
        assert_eq!(
            actual.prevout, expected.prevout,
            "Prevout mismatch for input {}",
            actual.input_index
        );

        // Only check that the error variant types match, not the full data
        match (&actual.kind, &expected.kind) {
            (
                InputValidationErrorKind::NonWalletInput { .. },
                InputValidationErrorKind::NonWalletInput { .. },
            ) => {
                // Both are NonWalletInput errors, this is what we expect
            }
            (
                InputValidationErrorKind::InvalidOutputScript(_),
                InputValidationErrorKind::InvalidOutputScript(_),
            ) => {
                // Both are InvalidOutputScript errors, this is what we expect
            }
            (actual_kind, expected_kind) => {
                panic!(
                    "Error kind mismatch for input {}: expected {:?}, got {:?}",
                    actual.input_index, expected_kind, actual_kind
                );
            }
        }
    }

    /// Compares actual and expected PSBT validation errors
    pub fn assert_psbt_validation_error_eq(
        actual: &PsbtValidationError,
        expected: &PsbtValidationError,
    ) {
        match (actual, expected) {
            (
                PsbtValidationError::InputLengthMismatch {
                    prevouts_len: actual_prevouts_len,
                    inputs_len: actual_inputs_len,
                },
                PsbtValidationError::InputLengthMismatch {
                    prevouts_len: expected_prevouts_len,
                    inputs_len: expected_inputs_len,
                },
            ) => {
                assert_eq!(actual_prevouts_len, expected_prevouts_len);
                assert_eq!(actual_inputs_len, expected_inputs_len);
            }
            (
                PsbtValidationError::InvalidInputs(actual_errors),
                PsbtValidationError::InvalidInputs(expected_errors),
            ) => {
                assert_eq!(
                    actual_errors.len(),
                    expected_errors.len(),
                    "Number of errors mismatch: expected {} errors, got {}",
                    expected_errors.len(),
                    actual_errors.len()
                );

                for (actual, expected) in actual_errors.iter().zip(expected_errors.iter()) {
                    assert_error_eq(actual, expected);
                }
            }
            (actual_variant, expected_variant) => {
                panic!(
                    "PsbtValidationError variant mismatch: expected {:?}, got {:?}",
                    expected_variant, actual_variant
                );
            }
        }
    }

    fn get_reversed_wallet_keys(wallet_keys: &RootWalletKeys) -> RootWalletKeys {
        let triple: XpubTriple = wallet_keys
            .xpubs
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .try_into()
            .expect("Failed to convert to XpubTriple");
        RootWalletKeys::new(triple)
    }

    crate::test_psbt_fixtures!(test_validate_psbt_wallet_inputs, network, format, {
        let replay_protection = ReplayProtection::new(vec![
            ScriptBuf::from_hex("a91420b37094d82a513451ff0ccd9db23aba05bc5ef387")
                .expect("Failed to parse replay protection output script"),
        ]);

        // Load fixture and extract psbt and wallet keys
        let fixture = fixtures::load_psbt_fixture_with_format(
            network.to_utxolib_name(),
            fixtures::SignatureState::Unsigned,
            format,
        )
        .expect("Failed to load fixture");
        let psbt_bytes = fixture.to_psbt_bytes().expect("Failed to get PSBT bytes");
        let psbt = Psbt::deserialize(&psbt_bytes).expect("Failed to deserialize PSBT");
        let wallet_xprv = fixture
            .get_wallet_xprvs()
            .expect("Failed to get wallet keys");
        let wallet_keys = wallet_xprv.to_root_wallet_keys();

        validate_psbt_wallet_inputs(&psbt, &wallet_keys, &replay_protection).unwrap();

        // should fail with invalid wallet keys - this reverses the keys so ALL inputs should fail
        let reversed_wallet_keys = get_reversed_wallet_keys(&wallet_keys);
        
        let actual_psbt_error = validate_psbt_wallet_inputs(
            &psbt,
            &reversed_wallet_keys,
            &replay_protection,
        )
        .unwrap_err();
        
        // Create expected errors - one for each non-replay-protected input
        let expected_errors = expected_validation_errors_non_wallet_inputs(&psbt, &replay_protection);
        let expected_psbt_error = PsbtValidationError::InvalidInputs(expected_errors);
        assert_psbt_validation_error_eq(&actual_psbt_error, &expected_psbt_error);

        // should fail with a single error for the replay protection input when empty ReplayProtection is passed
        let empty_replay_protection = ReplayProtection::new(vec![]);
        
        let actual_psbt_error = validate_psbt_wallet_inputs(
            &psbt,
            &wallet_keys,
            &empty_replay_protection,
        )
        .unwrap_err();
        
        // Create expected error - one for the replay protection input only
        let expected_errors = expected_validation_errors_unexpected_replay_protection(&psbt, &replay_protection);
        let expected_psbt_error = PsbtValidationError::InvalidInputs(expected_errors);
        assert_psbt_validation_error_eq(&actual_psbt_error, &expected_psbt_error);
    }, ignore: [BitcoinGold, BitcoinCash, Ecash, Zcash]);
}
