use miniscript::bitcoin::bip32::{ChildNumber, DerivationPath};
use miniscript::bitcoin::psbt::{Input, Psbt};
use miniscript::bitcoin::secp256k1::{self, PublicKey};
use miniscript::bitcoin::{OutPoint, ScriptBuf, TapLeafHash, XOnlyPublicKey};

use crate::bitcoin::bip32::KeySource;
use crate::fixed_script_wallet::{
    Chain, OutputScriptType, ReplayProtection, RootWalletKeys, WalletScripts,
};
use crate::Network;

pub type Bip32DerivationMap = std::collections::BTreeMap<PublicKey, KeySource>;

/// Check if a fingerprint matches any xpub in the wallet
fn has_fingerprint(
    wallet_keys: &RootWalletKeys,
    fingerprint: miniscript::bitcoin::bip32::Fingerprint,
) -> bool {
    wallet_keys
        .xpubs
        .iter()
        .any(|xpub| xpub.fingerprint() == fingerprint)
}

/// Find an xpub in the wallet by fingerprint
fn find_xpub_by_fingerprint(
    wallet_keys: &RootWalletKeys,
    fingerprint: miniscript::bitcoin::bip32::Fingerprint,
) -> Option<&miniscript::bitcoin::bip32::Xpub> {
    wallet_keys
        .xpubs
        .iter()
        .find(|xpub| xpub.fingerprint() == fingerprint)
}

/// Make sure that deriving from the wallet xpubs matches keys in the derivation map
/// Check if BIP32 derivation info belongs to the wallet keys (non-failing)
/// Returns true if all fingerprints match, false if any don't match (external wallet)
pub fn is_bip32_derivation_for_wallet(
    wallet_keys: &RootWalletKeys,
    derivation_map: &Bip32DerivationMap,
) -> bool {
    derivation_map
        .iter()
        .all(|(_, (fingerprint, _))| has_fingerprint(wallet_keys, *fingerprint))
}

/// Helper function to derive a public key from an xpub and derivation path
fn derive_pubkey<C: secp256k1::Verification>(
    secp: &secp256k1::Secp256k1<C>,
    xpub: &miniscript::bitcoin::bip32::Xpub,
    derivation_path: &miniscript::bitcoin::bip32::DerivationPath,
) -> Result<PublicKey, String> {
    xpub.derive_pub(secp, derivation_path)
        .map(|derived_xpub| derived_xpub.public_key)
        .map_err(|e| format!("Failed to derive public key: {}", e))
}

/// Find a derivation path in bip32_derivation map by fingerprint
fn find_bip32_derivation_path(
    bip32_derivation: &Bip32DerivationMap,
    fingerprint: miniscript::bitcoin::bip32::Fingerprint,
) -> Option<&DerivationPath> {
    bip32_derivation
        .values()
        .find(|(fp, _)| *fp == fingerprint)
        .map(|(_, path)| path)
}

/// Find a derivation path in tap_key_origins map by fingerprint
fn find_tap_key_origins_path(
    tap_key_origins: &TapKeyOrigins,
    fingerprint: miniscript::bitcoin::bip32::Fingerprint,
) -> Option<&DerivationPath> {
    tap_key_origins
        .values()
        .find(|(_, (fp, _))| *fp == fingerprint)
        .map(|(_, (_, path))| path)
}

/// Derives a public key from an xpub using the derivation path found in a PSBT input
///
/// This function works with both legacy/SegWit inputs (using bip32_derivation) and
/// Taproot inputs (using tap_key_origins). It searches for a derivation path matching
/// the xpub's fingerprint and derives the public key.
///
/// # Arguments
/// - `secp`: Secp256k1 context for key derivation
/// - `xpub`: The extended public key to derive from
/// - `input`: The PSBT input containing derivation information
///
/// # Returns
/// - `Ok(Some(PublicKey))` if a matching derivation path is found and derivation succeeds
/// - `Ok(None)` if no matching derivation path is found or no derivation info exists in the input
/// - `Err(String)` if derivation fails
pub fn derive_pubkey_from_input<C: secp256k1::Verification>(
    secp: &secp256k1::Secp256k1<C>,
    xpub: &miniscript::bitcoin::bip32::Xpub,
    input: &Input,
) -> Result<Option<PublicKey>, String> {
    let xpub_fingerprint = xpub.fingerprint();

    // Try bip32_derivation first (for legacy/SegWit inputs)
    if !input.bip32_derivation.is_empty() {
        let derivation_path = find_bip32_derivation_path(&input.bip32_derivation, xpub_fingerprint);

        return match derivation_path {
            Some(path) => derive_pubkey(secp, xpub, path).map(Some),
            None => Ok(None), // No matching fingerprint found - not an error
        };
    }

    // Try tap_key_origins (for Taproot inputs)
    if !input.tap_key_origins.is_empty() {
        let derivation_path = find_tap_key_origins_path(&input.tap_key_origins, xpub_fingerprint);

        return match derivation_path {
            Some(path) => derive_pubkey(secp, xpub, path).map(Some),
            None => Ok(None), // No matching fingerprint found - not an error
        };
    }

    // No derivation info in input - return None (not an error)
    Ok(None)
}

/// Verifies a Taproot script path signature for a given public key in a PSBT input
///
/// # Arguments
/// - `secp`: Secp256k1 context for signature verification
/// - `psbt`: The PSBT containing the transaction and inputs
/// - `input_index`: The index of the input to verify
/// - `public_key`: The compressed public key to verify the signature for
/// - `cache`: Mutable reference to a SighashCache for computing sighash (can be reused for bulk verification)
///
/// # Returns
/// - `Ok(true)` if a valid Schnorr signature exists for the public key
/// - `Ok(false)` if no signature exists or verification fails
/// - `Err(String)` if required data is missing or computation fails
pub fn verify_taproot_script_signature<
    C: secp256k1::Verification,
    T: std::borrow::Borrow<miniscript::bitcoin::Transaction>,
>(
    secp: &secp256k1::Secp256k1<C>,
    psbt: &miniscript::bitcoin::psbt::Psbt,
    input_index: usize,
    public_key: miniscript::bitcoin::CompressedPublicKey,
    cache: &mut miniscript::bitcoin::sighash::SighashCache<T>,
) -> Result<bool, String> {
    use miniscript::bitcoin::{hashes::Hash, sighash::Prevouts, TapLeafHash, XOnlyPublicKey};

    let input = &psbt.inputs[input_index];

    if input.tap_script_sigs.is_empty() {
        return Ok(false);
    }

    // Convert CompressedPublicKey to XOnlyPublicKey for Taproot
    let x_only_key = XOnlyPublicKey::from_slice(&public_key.to_bytes()[1..])
        .map_err(|e| format!("Failed to convert to x-only public key: {}", e))?;

    // Check all tap_script_sigs for this public key
    for ((sig_pubkey, leaf_hash), signature) in &input.tap_script_sigs {
        if sig_pubkey == &x_only_key {
            // Found a signature for this public key, now verify it
            // Compute taproot script spend sighash
            let prevouts = super::p2tr_musig2_input::collect_prevouts(psbt)
                .map_err(|e| format!("Failed to collect prevouts: {}", e))?;

            // Find the script for this leaf hash
            // tap_scripts is keyed by ControlBlock, so we need to find the matching entry
            let mut found_script = false;
            for (script, leaf_version) in input.tap_scripts.values() {
                // Compute the leaf hash from the script and leaf version
                let computed_leaf_hash = TapLeafHash::from_script(script, *leaf_version);

                if &computed_leaf_hash == leaf_hash {
                    found_script = true;
                    break;
                }
            }

            if !found_script {
                return Err("Tap script not found for leaf hash".to_string());
            }

            let sighash_type = signature.sighash_type;
            let sighash = cache
                .taproot_script_spend_signature_hash(
                    input_index,
                    &Prevouts::All(&prevouts),
                    *leaf_hash,
                    sighash_type,
                )
                .map_err(|e| format!("Failed to compute taproot sighash: {}", e))?;

            // Verify Schnorr signature
            let message = secp256k1::Message::from_digest(sighash.to_byte_array());
            match secp.verify_schnorr(&signature.signature, &message, sig_pubkey) {
                Ok(()) => return Ok(true),
                Err(_) => continue, // Try next signature
            }
        }
    }

    // No valid signature found for this public key in tap_script_sigs
    Ok(false)
}

/// Verifies an ECDSA signature for a given public key in a PSBT input (legacy/SegWit)
///
/// # Arguments
/// - `secp`: Secp256k1 context for signature verification
/// - `psbt`: The PSBT containing the transaction and inputs
/// - `input_index`: The index of the input to verify
/// - `public_key`: The compressed public key to verify the signature for
/// - `fork_id`: Optional fork ID for BCH/BTG/XEC networks (0 for BCH/XEC, 79 for BTG)
///
/// # Returns
/// - `Ok(true)` if a valid ECDSA signature exists for the public key
/// - `Ok(false)` if no signature exists or verification fails
/// - `Err(String)` if sighash computation fails
pub fn verify_ecdsa_signature<C: secp256k1::Verification>(
    secp: &secp256k1::Secp256k1<C>,
    psbt: &miniscript::bitcoin::psbt::Psbt,
    input_index: usize,
    public_key: miniscript::bitcoin::CompressedPublicKey,
    fork_id: Option<u32>,
) -> Result<bool, String> {
    use miniscript::bitcoin::{sighash::SighashCache, PublicKey};

    let input = &psbt.inputs[input_index];

    // Convert to PublicKey for ECDSA
    let public_key_inner = PublicKey::from_slice(&public_key.to_bytes())
        .map_err(|e| format!("Failed to convert public key: {}", e))?;

    // Check if there's a partial signature for this public key
    if let Some(signature) = input.partial_sigs.get(&public_key_inner) {
        // Create sighash cache and compute sighash for this input
        let mut cache = SighashCache::new(&psbt.unsigned_tx);

        // Use appropriate sighash computation based on fork_id
        let sighash_msg = if let Some(fid) = fork_id {
            // BCH/BTG/XEC: use sighash_forkid
            let (msg, _) = psbt
                .sighash_forkid(input_index, &mut cache, fid)
                .map_err(|e| format!("Failed to compute FORKID sighash: {}", e))?;
            msg
        } else {
            // Standard Bitcoin: use sighash_ecdsa
            let (msg, _) = psbt
                .sighash_ecdsa(input_index, &mut cache)
                .map_err(|e| format!("Failed to compute sighash: {}", e))?;
            msg
        };

        // Verify the signature
        match secp.verify_ecdsa(&sighash_msg, &signature.signature, &public_key_inner.inner) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    } else {
        // No signature found for this public key
        Ok(false)
    }
}

/// Verify an ECDSA signature for a Zcash PSBT input using ZIP-243 sighash.
///
/// # Arguments
/// - `secp`: Secp256k1 context for verification
/// - `psbt`: The PSBT containing the signature
/// - `input_index`: Index of the input to verify
/// - `public_key`: The public key to check for a signature
/// - `consensus_branch_id`: Zcash network upgrade branch ID
/// - `version_group_id`: Zcash transaction version group ID
/// - `expiry_height`: Transaction expiry height
///
/// # Returns
/// - `Ok(true)` if a valid ECDSA signature exists for the public key
/// - `Ok(false)` if no signature exists or verification fails
/// - `Err(String)` if sighash computation fails
pub fn verify_ecdsa_signature_zcash<C: secp256k1::Verification>(
    secp: &secp256k1::Secp256k1<C>,
    psbt: &miniscript::bitcoin::psbt::Psbt,
    input_index: usize,
    public_key: miniscript::bitcoin::CompressedPublicKey,
    consensus_branch_id: u32,
    version_group_id: u32,
    expiry_height: u32,
) -> Result<bool, String> {
    use miniscript::bitcoin::{sighash::SighashCache, PublicKey};

    let input = &psbt.inputs[input_index];

    // Convert to PublicKey for ECDSA
    let public_key_inner = PublicKey::from_slice(&public_key.to_bytes())
        .map_err(|e| format!("Failed to convert public key: {}", e))?;

    // Check if there's a partial signature for this public key
    if let Some(signature) = input.partial_sigs.get(&public_key_inner) {
        // Create sighash cache and compute sighash for this input using ZIP-243
        let mut cache = SighashCache::new(&psbt.unsigned_tx);

        let (sighash_msg, _) = psbt
            .sighash_zcash(
                input_index,
                &mut cache,
                consensus_branch_id,
                version_group_id,
                expiry_height,
            )
            .map_err(|e| format!("Failed to compute Zcash sighash: {}", e))?;

        // Verify the signature
        match secp.verify_ecdsa(&sighash_msg, &signature.signature, &public_key_inner.inner) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    } else {
        // No signature found for this public key
        Ok(false)
    }
}

fn assert_bip32_derivation_map(
    wallet_keys: &RootWalletKeys,
    derivation_map: &Bip32DerivationMap,
) -> Result<(), String> {
    for (key, (fingerprint, path)) in derivation_map {
        let xpub = find_xpub_by_fingerprint(wallet_keys, *fingerprint)
            .ok_or_else(|| format!("No xpub found with fingerprint {}", fingerprint))?;
        let derived_key = xpub
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

pub type TapKeyOrigins = std::collections::BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>;

/// Check if tap key origins belong to the wallet keys (non-failing)
/// Returns true if all fingerprints match, false if any don't match (external wallet)
pub fn is_tap_key_origins_for_wallet(
    wallet_keys: &RootWalletKeys,
    tap_key_origins: &TapKeyOrigins,
) -> bool {
    tap_key_origins
        .iter()
        .all(|(_, (_, (fingerprint, _)))| has_fingerprint(wallet_keys, *fingerprint))
}

/// Derives a public key from an xpub using the derivation path found in the input's tap_key_origins
///
/// This searches for a derivation path matching the xpub's fingerprint and derives the public key.
///
/// # Returns
/// - `Ok(PublicKey)` if a matching derivation path is found and derivation succeeds
/// - `Err(String)` if no matching derivation path is found or derivation fails
pub fn derive_pubkey_from_tap_key_origins<C: secp256k1::Verification>(
    secp: &secp256k1::Secp256k1<C>,
    xpub: &miniscript::bitcoin::bip32::Xpub,
    tap_key_origins: &TapKeyOrigins,
) -> Result<PublicKey, String> {
    let xpub_fingerprint = xpub.fingerprint();
    let derivation_path =
        find_tap_key_origins_path(tap_key_origins, xpub_fingerprint).ok_or_else(|| {
            format!(
                "No tap key origin found for xpub fingerprint {}",
                xpub_fingerprint
            )
        })?;

    derive_pubkey(secp, xpub, derivation_path)
}

fn assert_tap_key_origins(
    wallet_keys: &RootWalletKeys,
    tap_key_origins: &TapKeyOrigins,
) -> Result<(), String> {
    for (key, (_, (fingerprint, path))) in tap_key_origins {
        let xpub = find_xpub_by_fingerprint(wallet_keys, *fingerprint)
            .ok_or_else(|| format!("No xpub found with fingerprint {}", fingerprint))?;
        let derived_key = xpub
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

/// Identifies a key in the wallet triple (user, backup, bitgo)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerKey {
    User,
    Backup,
    Bitgo,
}

impl SignerKey {
    /// Returns the index of this key in the wallet triple
    pub fn index(&self) -> usize {
        match self {
            SignerKey::User => 0,
            SignerKey::Backup => 1,
            SignerKey::Bitgo => 2,
        }
    }

    /// Check if this is the backup key
    pub fn is_backup(&self) -> bool {
        matches!(self, SignerKey::Backup)
    }
}

impl std::str::FromStr for SignerKey {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "user" => Ok(SignerKey::User),
            "backup" => Ok(SignerKey::Backup),
            "bitgo" => Ok(SignerKey::Bitgo),
            _ => Err(format!(
                "Invalid key name '{}': expected 'user', 'backup', or 'bitgo'",
                s
            )),
        }
    }
}

/// Specifies the signer and cosigner for Taproot inputs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignPath {
    pub signer: SignerKey,
    pub cosigner: SignerKey,
}

/// Optional parameters for replay protection inputs
#[derive(Debug, Clone, Default)]
pub struct ReplayProtectionOptions<'a> {
    /// Sequence number (default: 0xFFFFFFFE for RBF)
    pub sequence: Option<u32>,
    /// Sighash type override (default: network-appropriate value)
    pub sighash_type: Option<miniscript::bitcoin::psbt::PsbtSighashType>,
    /// Previous transaction bytes; if provided, uses non_witness_utxo
    pub prev_tx: Option<&'a [u8]>,
}

/// Optional parameters for wallet inputs
#[derive(Debug, Clone, Default)]
pub struct WalletInputOptions<'a> {
    /// Signer and cosigner for Taproot inputs (required for p2tr/p2trMusig2)
    pub sign_path: Option<SignPath>,
    /// Sequence number (default: 0xFFFFFFFE for RBF)
    pub sequence: Option<u32>,
    /// Previous transaction bytes; if provided, uses non_witness_utxo
    pub prev_tx: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputScriptType {
    P2shP2pk,
    P2sh,
    P2shP2wsh,
    P2wsh,
    P2trLegacy,
    P2trMusig2ScriptPath,
    P2trMusig2KeyPath,
}

impl InputScriptType {
    pub fn from_script_id(script_id: ScriptId, psbt_input: &Input) -> Result<Self, String> {
        let chain = Chain::try_from(script_id.chain).map_err(|e| e.to_string())?;
        match chain.script_type {
            OutputScriptType::P2sh => Ok(InputScriptType::P2sh),
            OutputScriptType::P2shP2wsh => Ok(InputScriptType::P2shP2wsh),
            OutputScriptType::P2wsh => Ok(InputScriptType::P2wsh),
            OutputScriptType::P2trLegacy => Ok(InputScriptType::P2trLegacy),
            OutputScriptType::P2trMusig2 => {
                // check if tap_script_sigs or tap_scripts are set
                if !psbt_input.tap_script_sigs.is_empty() || !psbt_input.tap_scripts.is_empty() {
                    Ok(InputScriptType::P2trMusig2ScriptPath)
                } else {
                    Ok(InputScriptType::P2trMusig2KeyPath)
                }
            }
        }
    }

    /// Detects the script type from a script_id chain and PSBT input metadata
    ///
    /// # Arguments
    /// - `script_id`: Optional script ID containing chain information (None for replay protection inputs)
    /// - `psbt_input`: The PSBT input containing signature metadata
    /// - `output_script`: The output script being spent
    /// - `replay_protection`: Replay protection configuration
    ///
    /// # Returns
    /// - `Ok(InputScriptType)` with the detected script type
    /// - `Err(String)` if the script type cannot be determined
    pub fn detect(
        script_id: Option<ScriptId>,
        psbt_input: &Input,
        output_script: &ScriptBuf,
        replay_protection: &ReplayProtection,
    ) -> Result<Self, String> {
        // For replay protection inputs (no script_id), detect from output script
        match script_id {
            Some(id) => Self::from_script_id(id, psbt_input),
            None => {
                if replay_protection.is_replay_protection_input(output_script) {
                    Ok(InputScriptType::P2shP2pk)
                } else {
                    Err("Input without script_id is not a replay protection input".to_string())
                }
            }
        }
    }
}

/// Parsed input from a PSBT transaction
#[derive(Debug, Clone)]
pub struct ParsedInput {
    pub previous_output: OutPoint,
    pub address: String,
    pub script: Vec<u8>,
    pub value: u64,
    pub script_id: Option<ScriptId>,
    pub script_type: InputScriptType,
    pub sequence: u32,
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

        // Detect the script type using script_id chain information
        let script_type =
            InputScriptType::detect(script_id, psbt_input, output_script, replay_protection)
                .map_err(ParseInputError::ScriptTypeDetection)?;

        Ok(Self {
            previous_output: tx_input.previous_output,
            address,
            script: output_script.to_bytes(),
            value: value.to_sat(),
            script_id,
            script_type,
            sequence: tx_input.sequence.0,
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
    /// Failed to detect script type for input
    ScriptTypeDetection(String),
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
            ParseInputError::ScriptTypeDetection(error) => {
                write!(f, "failed to detect script type: {}", error)
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
