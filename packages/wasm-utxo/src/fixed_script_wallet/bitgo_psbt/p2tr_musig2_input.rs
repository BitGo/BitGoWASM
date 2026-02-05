//! MuSig2 PSBT proprietary key-value parsing
//!
//! This module provides encoding and decoding of MuSig2-related proprietary
//! key-values in PSBTs, following the format specified in:
//! https://gist.github.com/sanket1729/4b525c6049f4d9e034d27368c49f28a6

use super::propkv::{find_kv, is_musig2_key, BitGoKeyValue, ProprietaryKeySubtype};
use crate::bitcoin::{key::UntweakedPublicKey, CompressedPublicKey};
use crate::fixed_script_wallet::wallet_scripts::bitgo_musig::key_agg_p2tr_musig2;
use miniscript::bitcoin::hashes::{hex, Hash};
use miniscript::bitcoin::{
    bip32::{KeySource, Xpriv, Xpub},
    psbt::Input,
    secp256k1, Psbt, TapLeafHash, XOnlyPublicKey,
};
use musig2::PubNonce;

/// Get the TapSighashType from a PSBT input, defaulting to Default if not set.
///
/// This matches utxo-lib's behavior where `input.sighashType || Transaction.SIGHASH_DEFAULT`
/// is used to determine the sighash type for taproot signing.
fn get_tap_sighash_type_from_input(
    input: &Input,
) -> crate::bitcoin::sighash::TapSighashType {
    use crate::bitcoin::sighash::TapSighashType;

    match input.sighash_type {
        Some(psbt_sighash) => {
            // Try to convert PsbtSighashType to TapSighashType
            // PsbtSighashType can hold either ECDSA or Taproot sighash types
            TapSighashType::from_consensus_u8(psbt_sighash.to_u32() as u8)
                .unwrap_or(TapSighashType::Default)
        }
        None => TapSighashType::Default,
    }
}

#[cfg(test)]
use super::BitGoPsbt;
#[cfg(test)]
use crate::fixed_script_wallet::test_utils::fixtures::XprvTriple;

pub type TapKeyOrigins = std::collections::BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>;

pub fn derive_xpriv_for_input_tap(
    xpriv: &Xpriv,
    tap_key_origins: &TapKeyOrigins,
) -> Result<Xpriv, String> {
    let secp = secp256k1::Secp256k1::new();
    for (_leaf_hashes, (fingerprint, path)) in tap_key_origins.values() {
        if *fingerprint == xpriv.fingerprint(&secp) {
            return xpriv
                .derive_priv(&secp, path)
                .map_err(|e| format!("Failed to derive xpriv: {}", e));
        }
    }
    Err("No xpriv found with fingerprint".to_string())
}

pub fn derive_xpub_for_input_tap(
    xpub: &Xpub,
    tap_key_origins: &TapKeyOrigins,
) -> Result<Xpub, String> {
    let secp = secp256k1::Secp256k1::new();
    for (_leaf_hashes, (fingerprint, path)) in tap_key_origins.values() {
        if *fingerprint == xpub.fingerprint() {
            return xpub
                .derive_pub(&secp, path)
                .map_err(|e| format!("Failed to derive xpub: {}", e));
        }
    }
    Err("No xpub found with fingerprint".to_string())
}

/// Error types for MuSig2 parsing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Musig2Error {
    /// Missing participants
    MissingParticipants,
    /// Invalid identifier (expected BITGO)
    InvalidIdentifier,
    /// Invalid subtype for the operation
    InvalidSubtype { expected: u8, got: u8 },
    /// Invalid keydata length
    InvalidKeydataLength { expected: usize, got: usize },
    /// Invalid value length
    InvalidValueLength { expected: String, got: usize },
    /// Duplicate participant public keys
    DuplicateParticipantKeys,
    /// Too many key-values found
    TooManyKeyValues { expected: usize, got: usize },
    /// Signature aggregation error
    SignatureAggregation(String),
    /// Missing nonces for aggregation
    MissingNonces,
    /// Tap output key mismatch
    TapOutputKeyMismatch { expected: String, got: String },
}

impl std::fmt::Display for Musig2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Musig2Error::MissingParticipants => write!(f, "Missing participants"),
            Musig2Error::InvalidIdentifier => write!(f, "Invalid identifier, expected BITGO"),
            Musig2Error::InvalidSubtype { expected, got } => {
                write!(f, "Invalid subtype: expected {}, got {}", expected, got)
            }
            Musig2Error::InvalidKeydataLength { expected, got } => {
                write!(
                    f,
                    "Invalid keydata length: expected {}, got {}",
                    expected, got
                )
            }
            Musig2Error::InvalidValueLength { expected, got } => {
                write!(
                    f,
                    "Invalid value length: expected {}, got {}",
                    expected, got
                )
            }
            Musig2Error::DuplicateParticipantKeys => {
                write!(f, "Duplicate participant public keys found")
            }
            Musig2Error::TooManyKeyValues { expected, got } => {
                write!(
                    f,
                    "Too many key-values: expected up to {}, got {}",
                    expected, got
                )
            }
            Musig2Error::SignatureAggregation(msg) => {
                write!(f, "Signature aggregation error: {}", msg)
            }
            Musig2Error::MissingNonces => write!(f, "Missing nonces for aggregation"),
            Musig2Error::TapOutputKeyMismatch { expected, got } => {
                write!(
                    f,
                    "Tap output key mismatch: expected {}, got {}",
                    expected, got
                )
            }
        }
    }
}

impl std::error::Error for Musig2Error {}

/// MuSig2 participant data
///
/// Maps: `<tapOutputKey><tapInternalKey>` => `<participantKey1><participantKey2>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Musig2Participants {
    pub tap_output_key: UntweakedPublicKey,
    pub tap_internal_key: UntweakedPublicKey,
    pub participant_pub_keys: [CompressedPublicKey; 2],
}

impl Musig2Participants {
    pub fn aggregate_pub_key(&self) -> Result<CompressedPublicKey, Musig2Error> {
        CompressedPublicKey::from_slice(
            &key_agg_p2tr_musig2(&[self.participant_pub_keys[0], self.participant_pub_keys[1]])
                .map_err(|e| {
                    Musig2Error::SignatureAggregation(format!(
                        "Failed to aggregate public key: {}",
                        e
                    ))
                })?,
        )
        .map_err(|e| {
            Musig2Error::SignatureAggregation(format!(
                "Failed to convert to compressed public key: {}",
                e
            ))
        })
    }
}

/// MuSig2 public nonce data
///
/// Maps: `<participantPubKey><tapOutputKey>` => `<pubNonce>`
#[derive(Debug, Clone)]
pub struct Musig2PubNonce {
    pub participant_pub_key: CompressedPublicKey,
    pub tap_output_key: UntweakedPublicKey,
    pub pub_nonce: PubNonce,
}

impl PartialEq for Musig2PubNonce {
    fn eq(&self, other: &Self) -> bool {
        self.participant_pub_key == other.participant_pub_key
            && self.tap_output_key == other.tap_output_key
            && self.pub_nonce.serialize() == other.pub_nonce.serialize()
    }
}

impl Eq for Musig2PubNonce {}

/// MuSig2 partial signature data
///
/// Maps: `<participantPubKey><tapOutputKey>` => `<partialSig>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Musig2PartialSig {
    pub participant_pub_key: CompressedPublicKey,
    pub tap_output_key: UntweakedPublicKey,
    pub partial_sig: Vec<u8>, // 32 or 33 bytes (with optional sighash byte)
}

impl Musig2Participants {
    /// Convert to proprietary key-value pair
    pub fn to_key_value(&self) -> BitGoKeyValue {
        let mut key_field = Vec::with_capacity(64);
        key_field.extend_from_slice(&self.tap_output_key.serialize());
        key_field.extend_from_slice(&self.tap_internal_key.serialize());

        let mut value = Vec::with_capacity(66);
        value.extend_from_slice(&self.participant_pub_keys[0].to_bytes());
        value.extend_from_slice(&self.participant_pub_keys[1].to_bytes());

        BitGoKeyValue::new(
            ProprietaryKeySubtype::Musig2ParticipantPubKeys,
            key_field,
            value,
        )
    }

    /// Create from proprietary key-value pair
    pub fn from_key_value(kv: &BitGoKeyValue) -> Result<Self, Musig2Error> {
        // Validate keydata length
        if kv.key.len() != 64 {
            return Err(Musig2Error::InvalidKeydataLength {
                expected: 64,
                got: kv.key.len(),
            });
        }

        // Validate value length
        if kv.value.len() != 66 {
            return Err(Musig2Error::InvalidValueLength {
                expected: "66".to_string(),
                got: kv.value.len(),
            });
        }

        // Parse keys
        let tap_output_key_bytes: [u8; 32] = kv.key[0..32].try_into().unwrap();
        let tap_internal_key_bytes: [u8; 32] = kv.key[32..64].try_into().unwrap();

        // Parse tap_output_key as x-only public key
        let tap_output_key =
            UntweakedPublicKey::from_slice(&tap_output_key_bytes).map_err(|e| {
                Musig2Error::InvalidValueLength {
                    expected: "Valid x-only public key".to_string(),
                    got: format!("Parse error: {}", e).len(),
                }
            })?;

        // Parse tap_internal_key as UntweakedPublicKey
        let tap_internal_key =
            UntweakedPublicKey::from_slice(&tap_internal_key_bytes).map_err(|e| {
                Musig2Error::InvalidValueLength {
                    expected: "Valid untweaked public key".to_string(),
                    got: format!("Parse error: {}", e).len(),
                }
            })?;

        // Parse participant keys
        let participant_key1 = CompressedPublicKey::from_slice(&kv.value[0..33]).map_err(|e| {
            Musig2Error::InvalidValueLength {
                expected: "Valid compressed public key".to_string(),
                got: format!("Parse error: {}", e).len(),
            }
        })?;
        let participant_key2 = CompressedPublicKey::from_slice(&kv.value[33..66]).map_err(|e| {
            Musig2Error::InvalidValueLength {
                expected: "Valid compressed public key".to_string(),
                got: format!("Parse error: {}", e).len(),
            }
        })?;

        // Check for duplicate keys
        if participant_key1 == participant_key2 {
            return Err(Musig2Error::DuplicateParticipantKeys);
        }

        Ok(Self {
            tap_output_key,
            tap_internal_key,
            participant_pub_keys: [participant_key1, participant_key2],
        })
    }

    /// Get participant public keys as CompressedPublicKey types
    pub fn get_compressed_pubkeys(&self) -> Vec<CompressedPublicKey> {
        self.participant_pub_keys.to_vec()
    }
}

impl Musig2PubNonce {
    /// Convert to proprietary key-value pair
    pub fn to_key_value(&self) -> BitGoKeyValue {
        let mut key_field = Vec::with_capacity(65);
        key_field.extend_from_slice(&self.participant_pub_key.to_bytes());
        key_field.extend_from_slice(&self.tap_output_key.serialize());

        BitGoKeyValue::new(
            ProprietaryKeySubtype::Musig2PubNonce,
            key_field,
            self.pub_nonce.serialize().to_vec(),
        )
    }

    /// Create from proprietary key-value pair
    pub fn from_key_value(kv: &BitGoKeyValue) -> Result<Self, Musig2Error> {
        // Validate keydata length
        if kv.key.len() != 65 {
            return Err(Musig2Error::InvalidKeydataLength {
                expected: 65,
                got: kv.key.len(),
            });
        }

        // Validate value length
        if kv.value.len() != 66 {
            return Err(Musig2Error::InvalidValueLength {
                expected: "66".to_string(),
                got: kv.value.len(),
            });
        }

        // Parse keys
        let participant_pub_key = CompressedPublicKey::from_slice(&kv.key[0..33]).map_err(|e| {
            Musig2Error::InvalidValueLength {
                expected: "Valid compressed public key".to_string(),
                got: format!("Parse error: {}", e).len(),
            }
        })?;

        let tap_output_key_bytes: [u8; 32] = kv.key[33..65].try_into().unwrap();
        let tap_output_key =
            UntweakedPublicKey::from_slice(&tap_output_key_bytes).map_err(|e| {
                Musig2Error::InvalidValueLength {
                    expected: "Valid x-only public key".to_string(),
                    got: format!("Parse error: {}", e).len(),
                }
            })?;

        let pub_nonce =
            PubNonce::try_from(&kv.value[..]).map_err(|e| Musig2Error::InvalidValueLength {
                expected: "Valid 66-byte public nonce".to_string(),
                got: format!("Parse error: {}", e).len(),
            })?;

        Ok(Self {
            participant_pub_key,
            tap_output_key,
            pub_nonce,
        })
    }
}

impl Musig2PartialSig {
    /// Convert to proprietary key-value pair
    pub fn to_key_value(&self) -> BitGoKeyValue {
        let mut key_field = Vec::with_capacity(65);
        key_field.extend_from_slice(&self.participant_pub_key.to_bytes());
        key_field.extend_from_slice(&self.tap_output_key.serialize());

        BitGoKeyValue::new(
            ProprietaryKeySubtype::Musig2PartialSig,
            key_field,
            self.partial_sig.clone(),
        )
    }

    /// Create from proprietary key-value pair
    pub fn from_key_value(kv: &BitGoKeyValue) -> Result<Self, Musig2Error> {
        // Validate keydata length
        if kv.key.len() != 65 {
            return Err(Musig2Error::InvalidKeydataLength {
                expected: 65,
                got: kv.key.len(),
            });
        }

        // Validate value length (32 or 33 bytes)
        if kv.value.len() != 32 && kv.value.len() != 33 {
            return Err(Musig2Error::InvalidValueLength {
                expected: "32 or 33".to_string(),
                got: kv.value.len(),
            });
        }

        // Parse keys
        let participant_pub_key = CompressedPublicKey::from_slice(&kv.key[0..33]).map_err(|e| {
            Musig2Error::InvalidValueLength {
                expected: "Valid compressed public key".to_string(),
                got: format!("Parse error: {}", e).len(),
            }
        })?;

        let tap_output_key_bytes: [u8; 32] = kv.key[33..65].try_into().unwrap();
        let tap_output_key =
            UntweakedPublicKey::from_slice(&tap_output_key_bytes).map_err(|e| {
                Musig2Error::InvalidValueLength {
                    expected: "Valid x-only public key".to_string(),
                    got: format!("Parse error: {}", e).len(),
                }
            })?;

        Ok(Self {
            participant_pub_key,
            tap_output_key,
            partial_sig: kv.value.clone(),
        })
    }

    /// Get the normalized partial signature (32 bytes, with sighash byte removed if present)
    pub fn normalized_signature(&self) -> Result<musig2::PartialSignature, Musig2Error> {
        let sig_bytes = match self.partial_sig.len() {
            32 => &self.partial_sig[..],
            33 => &self.partial_sig[..32],
            len => {
                return Err(Musig2Error::InvalidValueLength {
                    expected: "32 or 33".to_string(),
                    got: len,
                })
            }
        };

        musig2::PartialSignature::try_from(sig_bytes).map_err(|e| Musig2Error::InvalidValueLength {
            expected: "Valid 32-byte partial signature".to_string(),
            got: format!("Parse error: {}", e).len(),
        })
    }
}

/// Parse MuSig2 participants from PSBT input
///
/// Returns `None` if no participant data is found.
pub fn parse_musig2_participants(input: &Input) -> Result<Option<Musig2Participants>, Musig2Error> {
    let kvs: Vec<_> = find_kv(
        ProprietaryKeySubtype::Musig2ParticipantPubKeys,
        &input.proprietary,
    )
    .collect::<Vec<_>>();

    if kvs.is_empty() {
        return Ok(None);
    }

    if kvs.len() > 1 {
        return Err(Musig2Error::TooManyKeyValues {
            expected: 1,
            got: kvs.len(),
        });
    }

    let kv = &kvs[0];
    Ok(Some(Musig2Participants::from_key_value(kv)?))
}

/// Parse MuSig2 public nonces from PSBT input
///
/// Returns empty vector if no nonces are found.
pub fn parse_musig2_nonces(input: &Input) -> Result<Vec<Musig2PubNonce>, Musig2Error> {
    let kvs: Vec<_> =
        find_kv(ProprietaryKeySubtype::Musig2PubNonce, &input.proprietary).collect::<Vec<_>>();

    if kvs.len() > 2 {
        return Err(Musig2Error::TooManyKeyValues {
            expected: 2,
            got: kvs.len(),
        });
    }

    kvs.iter().map(Musig2PubNonce::from_key_value).collect()
}

/// Parse MuSig2 partial signatures from PSBT input
///
/// Returns empty vector if no partial signatures are found.
pub fn parse_musig2_partial_sigs(input: &Input) -> Result<Vec<Musig2PartialSig>, Musig2Error> {
    let kvs: Vec<_> =
        find_kv(ProprietaryKeySubtype::Musig2PartialSig, &input.proprietary).collect::<Vec<_>>();

    if kvs.len() > 2 {
        return Err(Musig2Error::TooManyKeyValues {
            expected: 2,
            got: kvs.len(),
        });
    }

    kvs.iter().map(Musig2PartialSig::from_key_value).collect()
}

pub struct Musig2Input {
    pub participants: Musig2Participants,
    pub nonces: Vec<Musig2PubNonce>,
    pub partial_sigs: Vec<Musig2PartialSig>,
}

/// Context for MuSig2 operations on a specific PSBT input
///
/// This struct bundles together a mutable reference to a PSBT, the input index,
/// and the parsed MuSig2 data, providing a more ergonomic API that doesn't require
/// passing `(psbt, input_index)` to every method.
pub struct Musig2Context<'a> {
    pub(super) psbt: &'a mut Psbt,
    pub(super) input_index: usize,
    pub(super) musig2_input: Musig2Input,
}

impl<'a> Musig2Context<'a> {
    /// Create a new Musig2Context for a specific PSBT input
    pub fn new(psbt: &'a mut Psbt, input_index: usize) -> Result<Self, Musig2Error> {
        let musig2_input = Musig2Input::from_input(&psbt.inputs[input_index])?;
        Ok(Self {
            psbt,
            input_index,
            musig2_input,
        })
    }

    /// Get a reference to the parsed Musig2Input
    pub fn musig2_input(&self) -> &Musig2Input {
        &self.musig2_input
    }

    /// Finalize a MuSig2 PSBT input by aggregating signatures and delegating to miniscript
    ///
    /// This method:
    /// 1. Parses MuSig2 proprietary data from the input
    /// 2. Aggregates partial signatures into a single Schnorr signature
    /// 3. Places the signature in the standard `tap_key_sig` field (BIP 371)
    /// 4. Clears MuSig2 proprietary fields
    /// 5. Delegates to miniscript's standard finalization to create the witness
    ///
    /// After aggregation, the MuSig2 signature is indistinguishable from a single-key
    /// taproot signature, allowing us to reuse all standard finalization code.
    pub fn finalize_input<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<(), Musig2Error> {
        use crate::bitcoin::sighash::SighashCache;
        use miniscript::psbt::PsbtExt;

        // Step 1: Collect all prevouts for sighash computation
        let prevouts = collect_prevouts(self.psbt)?;

        // Get tap merkle root from input
        use crate::bitcoin::taproot::TapNodeHash;
        let tap_merkle_root = self.psbt.inputs[self.input_index]
            .tap_merkle_root
            .unwrap_or_else(|| TapNodeHash::from_byte_array([0u8; 32]));

        // Step 2: Aggregate signatures
        let mut sighash_cache = SighashCache::new(&self.psbt.unsigned_tx);
        let taproot_sig = self.musig2_input.aggregate_signature(
            &mut sighash_cache,
            &prevouts,
            self.input_index,
            &tap_merkle_root,
        )?;

        // Step 3: Set tap_key_sig
        self.psbt.inputs[self.input_index].tap_key_sig = Some(taproot_sig);

        // Step 4: Clear MuSig2 proprietary fields (they're no longer needed)
        self.psbt.inputs[self.input_index]
            .proprietary
            .retain(|key, _| !is_musig2_key(key));

        // Step 5: Use standard miniscript finalization for the rest!
        self.psbt
            .finalize_inp_mut(secp, self.input_index)
            .map_err(|e| {
                Musig2Error::SignatureAggregation(format!("Finalization failed: {}", e))
            })?;

        Ok(())
    }

    /// Set a public nonce in the PSBT proprietary fields
    ///
    /// # Arguments
    /// * `participant_pub_key` - The public key of the participant providing the nonce
    /// * `tap_output_key` - The taproot output key (x-only tweaked aggregated key)
    /// * `pub_nonce` - The public nonce to set
    pub fn set_nonce(
        &mut self,
        participant_pub_key: CompressedPublicKey,
        tap_output_key: crate::bitcoin::key::UntweakedPublicKey,
        pub_nonce: PubNonce,
    ) -> Result<(), Musig2Error> {
        let musig2_nonce = Musig2PubNonce {
            participant_pub_key,
            tap_output_key,
            pub_nonce,
        };

        let (key, val) = musig2_nonce.to_key_value().to_key_value();
        self.psbt.inputs[self.input_index]
            .proprietary
            .insert(key, val);
        Ok(())
    }

    /// Set a partial signature in the PSBT proprietary fields
    ///
    /// # Arguments
    /// * `participant_pub_key` - The public key of the participant providing the signature
    /// * `tap_output_key` - The taproot output key (x-only tweaked aggregated key)
    /// * `partial_sig` - The partial signature to set
    /// * `sighash_type` - The sighash type used for signing. If not Default, the sighash byte
    ///                    will be appended to the partial signature to match utxo-lib behavior.
    pub fn set_partial_signature(
        &mut self,
        participant_pub_key: CompressedPublicKey,
        tap_output_key: crate::bitcoin::key::UntweakedPublicKey,
        partial_sig: musig2::PartialSignature,
        sighash_type: crate::bitcoin::sighash::TapSighashType,
    ) -> Result<(), Musig2Error> {
        use crate::bitcoin::sighash::TapSighashType;

        // Build the partial signature bytes
        // If sighash type is not Default, append the sighash byte (matches utxo-lib behavior)
        let mut sig_bytes = partial_sig.serialize().to_vec();
        if sighash_type != TapSighashType::Default {
            sig_bytes.push(sighash_type as u8);
        }

        let musig2_partial_sig = Musig2PartialSig {
            participant_pub_key,
            tap_output_key,
            partial_sig: sig_bytes,
        };

        let (key, val) = musig2_partial_sig.to_key_value().to_key_value();
        self.psbt.inputs[self.input_index]
            .proprietary
            .insert(key, val);
        Ok(())
    }

    /// Generate and set a user nonce for a MuSig2 input using State-Machine API (FirstRound)
    ///
    /// This method uses the State-Machine API from the musig2 crate, which encapsulates
    /// the SecNonce internally to prevent accidental reuse. This is the recommended
    /// production API.
    ///
    /// This method:
    /// 1. Derives the signer's key for this input from tap_key_origins
    /// 2. Determines the signer's index in the participant list
    /// 3. Creates a MuSig2 key aggregation context with taproot tweak
    /// 4. Computes the taproot sighash for additional entropy
    /// 5. Creates a FirstRound with the session_id as entropy
    /// 6. Extracts and sets the public nonce in the PSBT proprietary fields
    /// 7. Returns FirstRound (keep for signing) and PubNonce (send to counterparty)
    ///
    /// # Arguments
    /// * `xpriv` - The signer's extended private key
    /// * `session_id` - 32-byte session ID (use rand::thread_rng().gen() in production)
    ///
    /// # Returns
    /// A tuple of (FirstRound, PubNonce) - keep FirstRound secret for signing later,
    /// send PubNonce to the counterparty
    pub fn generate_nonce_first_round(
        &mut self,
        xpriv: &Xpriv,
        session_id: [u8; 32],
    ) -> Result<(musig2::FirstRound, musig2::PubNonce), Musig2Error> {
        use crate::bitcoin::bip32::Xpub;
        use crate::bitcoin::sighash::{Prevouts, SighashCache};
        use crate::bitcoin::taproot::TapNodeHash;
        use musig2::{KeyAggContext, SecNonceSpices};

        // Derive the signer's key for this input
        let tap_key_origins = &self.psbt.inputs[self.input_index].tap_key_origins;
        let derived_xpriv = derive_xpriv_for_input_tap(xpriv, tap_key_origins).map_err(|e| {
            Musig2Error::SignatureAggregation(format!("Failed to derive xpriv: {}", e))
        })?;
        let secp = secp256k1::Secp256k1::new();
        let derived_xpub = Xpub::from_priv(&secp, &derived_xpriv);
        let signer_pub_key = derived_xpub.to_pub();

        // Determine signer index
        let signer_index = self.musig2_input.get_signer_index(&signer_pub_key)?;

        // Get tap merkle root
        let tap_merkle_root = self.psbt.inputs[self.input_index]
            .tap_merkle_root
            .unwrap_or_else(|| TapNodeHash::from_byte_array([0u8; 32]));

        // Create key aggregation context with taproot tweak
        let participant_keys = self.musig2_input.get_participant_pubkeys()?;
        let key_agg_ctx = KeyAggContext::new(participant_keys).map_err(|e| {
            Musig2Error::SignatureAggregation(format!("Failed to create key agg context: {}", e))
        })?;

        let tap_tree_root_bytes = tap_merkle_root.to_byte_array();
        let key_agg_ctx = key_agg_ctx
            .with_taproot_tweak(&tap_tree_root_bytes)
            .map_err(|e| {
                Musig2Error::SignatureAggregation(format!("Failed to apply taproot tweak: {}", e))
            })?;

        // Compute sighash for SecNonceSpices
        // Use the sighash type from the PSBT input (matches utxo-lib behavior)
        let sighash_type = get_tap_sighash_type_from_input(&self.psbt.inputs[self.input_index]);
        let prevouts = collect_prevouts(self.psbt)?;
        let mut sighash_cache = SighashCache::new(&self.psbt.unsigned_tx);
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(
                self.input_index,
                &Prevouts::All(&prevouts),
                sighash_type,
            )
            .map_err(|e| {
                Musig2Error::SignatureAggregation(format!("Failed to compute sighash: {}", e))
            })?;

        // Convert secret key to scalar
        let secret_scalar =
            musig2::secp::Scalar::try_from(&derived_xpriv.private_key.secret_bytes()[..]).map_err(
                |e| Musig2Error::SignatureAggregation(format!("Failed to parse secret key: {}", e)),
            )?;

        // Create SecNonceSpices with message for additional entropy
        let message = sighash.to_byte_array();
        let spices = SecNonceSpices::new()
            .with_seckey(secret_scalar)
            .with_message(&message);

        // Create FirstRound with session_id as the primary entropy source
        let first_round = musig2::FirstRound::new(key_agg_ctx, session_id, signer_index, spices)
            .map_err(|e| {
                Musig2Error::SignatureAggregation(format!("Failed to create FirstRound: {}", e))
            })?;

        // Extract public nonce
        let pub_nonce = first_round.our_public_nonce();

        // Set the public nonce in the PSBT
        let tap_output_key = self.musig2_input.participants.tap_output_key;
        self.set_nonce(signer_pub_key, tap_output_key, pub_nonce.clone())?;

        // Return FirstRound (caller keeps for signing) and PubNonce (send to counterparty)
        Ok((first_round, pub_nonce))
    }

    /// Sign a MuSig2 input using State-Machine API (SecondRound)
    ///
    /// This method uses the State-Machine API from the musig2 crate. The FirstRound
    /// from nonce generation encapsulates the secret nonce, preventing reuse.
    ///
    /// This method:
    /// 1. Derives the signer's key to identify which signature to set
    /// 2. Receives nonces from all other participants into FirstRound
    /// 3. Finalizes FirstRound with seckey and message → SecondRound
    /// 4. Extracts the partial signature from SecondRound
    /// 5. Sets the partial signature in the PSBT proprietary fields
    ///
    /// # Arguments
    /// * `first_round` - The FirstRound from generate_nonce_first_round()
    /// * `xpriv` - The signer's extended private key
    ///
    /// # Returns
    /// Ok(()) if the signature was successfully created and set
    pub fn sign_with_first_round(
        &mut self,
        first_round: musig2::FirstRound,
        xpriv: &Xpriv,
    ) -> Result<(), Musig2Error> {
        use crate::bitcoin::sighash::{Prevouts, SighashCache};

        // Get the sighash type from the PSBT input (matches utxo-lib behavior)
        let sighash_type = get_tap_sighash_type_from_input(&self.psbt.inputs[self.input_index]);

        // Compute sighash message (needed for finalize)
        let prevouts = collect_prevouts(self.psbt)?;
        let mut sighash_cache = SighashCache::new(&self.psbt.unsigned_tx);
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(
                self.input_index,
                &Prevouts::All(&prevouts),
                sighash_type,
            )
            .map_err(|e| {
                Musig2Error::SignatureAggregation(format!("Failed to compute sighash: {}", e))
            })?;

        self.sign_with_first_round_impl(first_round, xpriv, sighash.to_byte_array(), sighash_type)
    }

    /// Sign a MuSig2 input using an externally-provided SighashCache (for efficiency).
    ///
    /// This method is the same as `sign_with_first_round` but accepts an external
    /// SighashCache and prevouts to avoid recomputing sha_prevouts, sha_amounts, etc.
    /// when signing multiple MuSig2 inputs.
    ///
    /// # Arguments
    /// * `first_round` - The FirstRound from generate_nonce_first_round()
    /// * `xpriv` - The signer's extended private key
    /// * `sighash_cache` - External SighashCache (reused across inputs)
    /// * `prevouts` - External prevouts slice (reused across inputs)
    ///
    /// # Returns
    /// Ok(()) if the signature was successfully created and set
    pub fn sign_with_first_round_and_cache<T: std::borrow::Borrow<crate::bitcoin::Transaction>>(
        &mut self,
        first_round: musig2::FirstRound,
        xpriv: &Xpriv,
        sighash_cache: &mut crate::bitcoin::sighash::SighashCache<T>,
        prevouts: &[crate::bitcoin::TxOut],
    ) -> Result<(), Musig2Error> {
        use crate::bitcoin::sighash::Prevouts;

        // Get the sighash type from the PSBT input (matches utxo-lib behavior)
        let sighash_type = get_tap_sighash_type_from_input(&self.psbt.inputs[self.input_index]);

        // Compute sighash using the shared cache
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(
                self.input_index,
                &Prevouts::All(prevouts),
                sighash_type,
            )
            .map_err(|e| {
                Musig2Error::SignatureAggregation(format!("Failed to compute sighash: {}", e))
            })?;

        self.sign_with_first_round_impl(first_round, xpriv, sighash.to_byte_array(), sighash_type)
    }

    /// Internal implementation of MuSig2 signing given a pre-computed sighash message.
    fn sign_with_first_round_impl(
        &mut self,
        mut first_round: musig2::FirstRound,
        xpriv: &Xpriv,
        message: [u8; 32],
        sighash_type: crate::bitcoin::sighash::TapSighashType,
    ) -> Result<(), Musig2Error> {
        use crate::bitcoin::bip32::Xpub;

        // Derive the signer's key for this input
        let tap_key_origins = &self.psbt.inputs[self.input_index].tap_key_origins;
        let derived_xpriv = derive_xpriv_for_input_tap(xpriv, tap_key_origins).map_err(|e| {
            Musig2Error::SignatureAggregation(format!("Failed to derive xpriv: {}", e))
        })?;
        let secp = secp256k1::Secp256k1::new();
        let derived_xpub = Xpub::from_priv(&secp, &derived_xpriv);
        let signer_pub_key = derived_xpub.to_pub();

        // Get signer index to know which nonces to receive
        let signer_index = self.musig2_input.get_signer_index(&signer_pub_key)?;

        // Receive nonces from all other participants
        for nonce_data in &self.musig2_input.nonces {
            let nonce_signer_index = self
                .musig2_input
                .get_signer_index(&nonce_data.participant_pub_key)?;

            // Only receive nonces from other signers (not our own)
            if nonce_signer_index != signer_index {
                first_round
                    .receive_nonce(nonce_signer_index, nonce_data.pub_nonce.clone())
                    .map_err(|e| {
                        Musig2Error::SignatureAggregation(format!(
                            "Failed to receive nonce from signer {}: {}",
                            nonce_signer_index, e
                        ))
                    })?;
            }
        }

        // Convert secret key to scalar
        let secret_scalar =
            musig2::secp::Scalar::try_from(&derived_xpriv.private_key.secret_bytes()[..]).map_err(
                |e| Musig2Error::SignatureAggregation(format!("Failed to parse secret key: {}", e)),
            )?;

        // Finalize FirstRound with seckey and message → SecondRound
        let second_round = first_round.finalize(secret_scalar, message).map_err(|e| {
            Musig2Error::SignatureAggregation(format!("Failed to finalize FirstRound: {}", e))
        })?;

        // Extract our partial signature from SecondRound
        let partial_sig: musig2::PartialSignature = second_round.our_signature();

        // Set the partial signature in the PSBT (with sighash byte if not Default)
        let tap_output_key = self.musig2_input.participants.tap_output_key;
        self.set_partial_signature(signer_pub_key, tap_output_key, partial_sig, sighash_type)
    }
}

/// Collect all prevouts (funding outputs) from PSBT inputs
///
/// This helper extracts the TxOut for each input from either witness_utxo or non_witness_utxo.
/// Required for computing sighashes in taproot transactions.
pub(crate) fn collect_prevouts(psbt: &Psbt) -> Result<Vec<crate::bitcoin::TxOut>, Musig2Error> {
    let tx = &psbt.unsigned_tx;
    psbt.inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            if let Some(witness_utxo) = &input.witness_utxo {
                Ok(witness_utxo.clone())
            } else if let Some(non_witness_utxo) = &input.non_witness_utxo {
                let output_index = tx.input[i].previous_output.vout as usize;
                Ok(non_witness_utxo.output[output_index].clone())
            } else {
                Err(Musig2Error::SignatureAggregation(format!(
                    "Missing UTXO data for input {}",
                    i
                )))
            }
        })
        .collect()
}

impl Musig2Input {
    /// Check if the input is a MuSig2 input
    /// Returns true if the input has any MuSig2 key-value pairs
    pub fn is_musig2_input(input: &Input) -> bool {
        find_kv(
            ProprietaryKeySubtype::Musig2ParticipantPubKeys,
            &input.proprietary,
        )
        .next()
        .is_some()
            || find_kv(ProprietaryKeySubtype::Musig2PubNonce, &input.proprietary)
                .next()
                .is_some()
            || find_kv(ProprietaryKeySubtype::Musig2PartialSig, &input.proprietary)
                .next()
                .is_some()
    }

    pub fn from_input(input: &Input) -> Result<Self, Musig2Error> {
        let participants =
            parse_musig2_participants(input)?.ok_or(Musig2Error::MissingParticipants)?;
        let nonces = parse_musig2_nonces(input)?;
        let partial_sigs = parse_musig2_partial_sigs(input)?;
        Ok(Self {
            participants,
            nonces,
            partial_sigs,
        })
    }

    /// Get public nonces
    pub fn get_pub_nonces(&self) -> Vec<PubNonce> {
        self.nonces.iter().map(|n| n.pub_nonce.clone()).collect()
    }

    /// Get participant public keys as Point types for musig2
    pub fn get_participant_pubkeys(&self) -> Result<Vec<musig2::secp::Point>, Musig2Error> {
        use musig2::secp::Point;

        self.participants
            .participant_pub_keys
            .iter()
            .enumerate()
            .map(|(i, pk)| {
                Point::try_from(&pk.to_bytes()[..]).map_err(|e| {
                    Musig2Error::SignatureAggregation(format!(
                        "Invalid public key at index {}: {}",
                        i, e
                    ))
                })
            })
            .collect()
    }

    /// Get normalized partial signatures (32 bytes each, with sighash byte removed if present)
    pub fn get_normalized_partial_sigs(
        &self,
    ) -> Result<Vec<musig2::PartialSignature>, Musig2Error> {
        self.partial_sigs
            .iter()
            .map(|sig| sig.normalized_signature())
            .collect()
    }

    /// Get the sighash type from the partial signatures.
    ///
    /// This matches utxo-lib's `getSigHashTypeFromSigs` behavior:
    /// - If partial sig is 32 bytes: SIGHASH_DEFAULT (0)
    /// - If partial sig is 33 bytes: the last byte is the sighash type
    /// - All signatures must use the same sighash type
    pub fn get_sighash_type_from_sigs(
        &self,
    ) -> Result<crate::bitcoin::sighash::TapSighashType, Musig2Error> {
        use crate::bitcoin::sighash::TapSighashType;

        if self.partial_sigs.is_empty() {
            return Err(Musig2Error::SignatureAggregation(
                "No partial signatures to extract sighash type from".to_string(),
            ));
        }

        let sighash_types: Vec<TapSighashType> = self
            .partial_sigs
            .iter()
            .map(|sig| match sig.partial_sig.len() {
                32 => TapSighashType::Default,
                33 => TapSighashType::from_consensus_u8(sig.partial_sig[32])
                    .unwrap_or(TapSighashType::Default),
                _ => TapSighashType::Default,
            })
            .collect();

        let first_sighash = sighash_types[0];
        if !sighash_types.iter().all(|&s| s == first_sighash) {
            return Err(Musig2Error::SignatureAggregation(
                "All partial signatures must use the same sighash type".to_string(),
            ));
        }

        Ok(first_sighash)
    }

    /// Get the signer index (0 or 1) for a given public key
    ///
    /// This is needed for the State-Machine API (FirstRound::new) which requires
    /// knowing which position in the participant list corresponds to the signer.
    ///
    /// # Arguments
    /// * `signer_pub_key` - The public key to find in the participant list
    ///
    /// # Returns
    /// The index (0 or 1) of the signer, or an error if the key is not found
    pub fn get_signer_index(
        &self,
        signer_pub_key: &CompressedPublicKey,
    ) -> Result<usize, Musig2Error> {
        for (index, participant_key) in self.participants.participant_pub_keys.iter().enumerate() {
            if participant_key == signer_pub_key {
                return Ok(index);
            }
        }
        Err(Musig2Error::SignatureAggregation(format!(
            "Signer public key {:?} not found in participants",
            signer_pub_key
        )))
    }

    /// Aggregate MuSig2 partial signatures into a final Schnorr signature
    ///
    /// This method:
    /// 1. Validates the input has sufficient nonces and signatures
    /// 2. Computes the taproot sighash from the sighash cache
    /// 3. Creates a MuSig2 signing session using the musig2 crate
    /// 4. Aggregates the partial signatures using BIP-327
    ///
    /// # Arguments
    /// * `sighash_cache` - The sighash cache for computing transaction hashes
    /// * `prevouts` - The prevouts for all inputs (needed for taproot sighash computation)
    /// * `input_index` - The index of this input in the transaction
    /// * `tap_merkle_root` - The taproot merkle root
    ///
    /// # Returns
    /// The aggregated taproot signature
    pub fn aggregate_signature<T: std::borrow::Borrow<crate::bitcoin::Transaction>>(
        &self,
        sighash_cache: &mut crate::bitcoin::sighash::SighashCache<T>,
        prevouts: &[crate::bitcoin::TxOut],
        input_index: usize,
        tap_merkle_root: &crate::bitcoin::taproot::TapNodeHash,
    ) -> Result<crate::bitcoin::taproot::Signature, Musig2Error> {
        use crate::bitcoin::sighash::{Prevouts, TapSighashType};
        use musig2::{AggNonce, BinaryEncoding, KeyAggContext};

        // Validate input
        if self.nonces.len() < 2 {
            return Err(Musig2Error::SignatureAggregation(format!(
                "At least 2 public nonces are required, got {}",
                self.nonces.len()
            )));
        }
        if self.partial_sigs.len() < 2 {
            return Err(Musig2Error::SignatureAggregation(format!(
                "At least 2 partial signatures are required, got {}",
                self.partial_sigs.len()
            )));
        }

        // Extract data
        let pub_nonces = self.get_pub_nonces();
        let parsed_keys = self.get_participant_pubkeys()?;
        let parsed_sigs = self.get_normalized_partial_sigs()?;

        // Get the sighash type from the partial signatures (matches utxo-lib behavior)
        let sighash_type = self.get_sighash_type_from_sigs()?;

        // Compute taproot key spend sighash
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(input_index, &Prevouts::All(prevouts), sighash_type)
            .map_err(|e| {
                Musig2Error::SignatureAggregation(format!("Failed to compute sighash: {}", e))
            })?;

        // Aggregate public nonces
        let agg_nonce = AggNonce::sum(&pub_nonces);

        // Create key aggregation context
        let key_agg_ctx = KeyAggContext::new(parsed_keys).map_err(|e| {
            Musig2Error::SignatureAggregation(format!("Failed to create key agg context: {}", e))
        })?;

        // Apply taproot tweak
        let tap_tree_root_bytes = tap_merkle_root.to_byte_array();
        let key_agg_ctx = key_agg_ctx
            .with_taproot_tweak(&tap_tree_root_bytes)
            .map_err(|e| {
                Musig2Error::SignatureAggregation(format!("Failed to apply taproot tweak: {}", e))
            })?;

        // Validate that computed tap_output_key matches the stored one
        let computed_tap_output_key: musig2::secp::Point = key_agg_ctx.aggregated_pubkey();
        let computed_tap_output_key_bytes = computed_tap_output_key.serialize_xonly();
        let stored_tap_output_key_bytes = self.participants.tap_output_key.serialize();
        if computed_tap_output_key_bytes != stored_tap_output_key_bytes {
            return Err(Musig2Error::TapOutputKeyMismatch {
                expected: hex::DisplayHex::to_lower_hex_string(&stored_tap_output_key_bytes),
                got: hex::DisplayHex::to_lower_hex_string(&computed_tap_output_key_bytes),
            });
        }

        // Aggregate signatures using standard BIP-327
        let sighash_bytes = sighash.to_byte_array();
        let final_sig: musig2::LiftedSignature = musig2::aggregate_partial_signatures(
            &key_agg_ctx,
            &agg_nonce,
            parsed_sigs,
            sighash_bytes,
        )
        .map_err(|e| {
            Musig2Error::SignatureAggregation(format!("Signature aggregation failed: {}", e))
        })?;

        // Convert to taproot signature
        // If sighash type is not Default, append the sighash byte (matches utxo-lib behavior)
        let sig_bytes: [u8; 64] = final_sig.to_bytes();
        if sighash_type == TapSighashType::Default {
            crate::bitcoin::taproot::Signature::from_slice(&sig_bytes)
                .map_err(|e| Musig2Error::SignatureAggregation(format!("Invalid signature: {}", e)))
        } else {
            let mut sig_with_sighash = sig_bytes.to_vec();
            sig_with_sighash.push(sighash_type as u8);
            crate::bitcoin::taproot::Signature::from_slice(&sig_with_sighash)
                .map_err(|e| Musig2Error::SignatureAggregation(format!("Invalid signature: {}", e)))
        }
    }
}

/// Set nonces and sign a MuSig2 keypath input with the user's key using BOTH APIs
///
/// This is a comprehensive test function that validates both the Functional API (against
/// fixtures) and the State-Machine API (for internal consistency). It ensures both
/// implementations work correctly.
///
/// # Arguments
/// * `xpriv_triple` - Triple of extended private keys (user, backup, BitGo)
/// * `unsigned_bitgo_psbt` - Unsigned PSBT (will be mutated to add nonces and signature)
/// * `halfsigned_bitgo_psbt` - Expected halfsigned PSBT for Functional API verification
/// * `input_index` - Index of the MuSig2 input
#[cfg(test)]
pub fn assert_set_nonce_and_sign_musig2_keypath(
    xpriv_triple: &XprvTriple,
    unsigned_bitgo_psbt: &mut BitGoPsbt,
    halfsigned_bitgo_psbt: &BitGoPsbt,
    input_index: usize,
) -> Result<(), String> {
    // Test 1: Functional API (utxolib-compatible, fixture-validated)
    let mut functional_psbt = unsigned_bitgo_psbt.clone();
    super::p2tr_musig2_input_utxolib::assert_set_nonce_and_sign_musig2_keypath_utxolib(
        xpriv_triple,
        &mut functional_psbt,
        halfsigned_bitgo_psbt,
        input_index,
    )?;

    // Test 2: State-Machine API (internal consistency validation, no fixture comparison)
    let mut state_machine_psbt = unsigned_bitgo_psbt.clone();
    assert_set_nonce_and_sign_musig2_keypath_state_machine(
        xpriv_triple,
        &mut state_machine_psbt,
        input_index,
    )?;

    // Update the original PSBT with the functional API result for consistency
    *unsigned_bitgo_psbt = functional_psbt;

    Ok(())
}

/// Test State-Machine API: set nonces and sign a MuSig2 keypath input using FirstRound/SecondRound
///
/// This test helper validates that the State-Machine API works correctly by:
/// 1. Generating nonces for both participants using generate_nonce_first_round()
/// 2. Signing using sign_with_first_round()
/// 3. Finalizing and verifying the aggregated signature is valid
///
/// Unlike the Functional API test which validates against fixtures, this test
/// validates internal consistency (signatures are valid but not deterministic).
///
/// # Arguments
/// * `xpriv_triple` - Triple of extended private keys (user, backup, BitGo)
/// * `unsigned_bitgo_psbt` - Unsigned PSBT (will be mutated to add nonces and signature)
/// * `input_index` - Index of the MuSig2 input
#[cfg(test)]
pub fn assert_set_nonce_and_sign_musig2_keypath_state_machine(
    xpriv_triple: &XprvTriple,
    unsigned_bitgo_psbt: &mut BitGoPsbt,
    input_index: usize,
) -> Result<(), String> {
    // Verify this is actually a MuSig2 input
    let is_musig2 = Musig2Input::is_musig2_input(&unsigned_bitgo_psbt.psbt().inputs[input_index]);

    if !is_musig2 {
        return Err(format!(
            "Expected MuSig2 input at index {} but found non-MuSig2 taproot input",
            input_index
        ));
    }

    // Generate random session IDs for production-like behavior
    let user_session_id: [u8; 32] = [1u8; 32]; // Use fixed for reproducibility in tests
    let bitgo_session_id: [u8; 32] = [2u8; 32];

    // Step 1: Generate user nonce using State-Machine API
    let mut user_ctx = Musig2Context::new(unsigned_bitgo_psbt.psbt_mut(), input_index)
        .map_err(|e| e.to_string())?;
    let (user_first_round, _user_pub_nonce) = user_ctx
        .generate_nonce_first_round(xpriv_triple.user_key(), user_session_id)
        .map_err(|e| e.to_string())?;

    // Step 2: Generate BitGo nonce using State-Machine API
    let mut bitgo_ctx = Musig2Context::new(unsigned_bitgo_psbt.psbt_mut(), input_index)
        .map_err(|e| e.to_string())?;
    let (bitgo_first_round, _bitgo_pub_nonce) = bitgo_ctx
        .generate_nonce_first_round(xpriv_triple.bitgo_key(), bitgo_session_id)
        .map_err(|e| e.to_string())?;

    // Step 3: Verify both nonces are set
    let musig2_input = Musig2Input::from_input(&unsigned_bitgo_psbt.psbt().inputs[input_index])
        .map_err(|e| e.to_string())?;
    if musig2_input.nonces.len() != 2 {
        return Err(format!(
            "Expected 2 nonces after generation, got {}",
            musig2_input.nonces.len()
        ));
    }

    // Step 4: Sign with user key using State-Machine API
    let mut user_sign_ctx = Musig2Context::new(unsigned_bitgo_psbt.psbt_mut(), input_index)
        .map_err(|e| e.to_string())?;
    user_sign_ctx
        .sign_with_first_round(user_first_round, xpriv_triple.user_key())
        .map_err(|e| e.to_string())?;

    // Step 5: Sign with BitGo key using State-Machine API
    let mut bitgo_sign_ctx = Musig2Context::new(unsigned_bitgo_psbt.psbt_mut(), input_index)
        .map_err(|e| e.to_string())?;
    bitgo_sign_ctx
        .sign_with_first_round(bitgo_first_round, xpriv_triple.bitgo_key())
        .map_err(|e| e.to_string())?;

    // Step 6: Verify both partial signatures are set
    let musig2_input = Musig2Input::from_input(&unsigned_bitgo_psbt.psbt().inputs[input_index])
        .map_err(|e| e.to_string())?;
    if musig2_input.partial_sigs.len() != 2 {
        return Err(format!(
            "Expected 2 partial signatures after signing, got {}",
            musig2_input.partial_sigs.len()
        ));
    }

    // Step 7: Finalize the input to verify the signature aggregates correctly
    let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();
    unsigned_bitgo_psbt
        .finalize_input(&secp, input_index)
        .map_err(|e| format!("Finalization failed: {}", e))?;

    // Step 8: Extract transaction to verify signature is valid
    let psbt = unsigned_bitgo_psbt.clone().into_psbt();
    psbt.extract_tx()
        .map_err(|e| format!("Failed to extract transaction: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_script_wallet::test_utils::fixtures;
    use crate::fixed_script_wallet::test_utils::fixtures::{
        load_psbt_fixture_with_format, ScriptType, SignatureState, TxFormat,
    };
    use crate::Network;

    struct Musig2FixtureData {
        fixture: fixtures::PsbtFixture,
        musig2_input: Musig2Input,
        musig2_input_index: usize,
        fixture_keypath_input: fixtures::P2trMusig2KeyPathInput,
        // only set for fullsigned
        fixture_keypath_final_input: Option<fixtures::P2trMusig2KeyPathFinalInput>,
    }

    fn get_musig2_fixture_data(
        signature_state: SignatureState,
    ) -> Result<Musig2FixtureData, String> {
        let fixture = load_psbt_fixture_with_format("bitcoin", signature_state, TxFormat::Psbt)
            .expect("Failed to load fixture");

        let (input_index, input_fixture) = fixture
            .find_input_with_script_type(ScriptType::P2trMusig2TaprootKeypath)
            .expect("Failed to find taprootKeyPathSpend input");

        let finalized_input_fixture = if signature_state == SignatureState::Fullsigned {
            let (finalized_input_index, finalized_input_fixture) = fixture
                .find_finalized_input_with_script_type(ScriptType::P2trMusig2TaprootKeypath)
                .expect("Failed to find taprootKeyPathSpend finalized input");
            assert_eq!(input_index, finalized_input_index);
            Some(finalized_input_fixture)
        } else {
            None
        };

        let bitgo_psbt = fixture
            .to_bitgo_psbt(Network::Bitcoin)
            .expect("Failed to convert to BitGoPsbt");
        let psbt = bitgo_psbt.into_psbt();

        let musig2_input =
            Musig2Input::from_input(&psbt.inputs[input_index]).map_err(|e| e.to_string())?;

        let fixture_keypath_input = match input_fixture {
            fixtures::PsbtInputFixture::P2trMusig2KeyPath(input) => input,
            _ => return Err("Invalid input type".to_string()),
        };
        let fixture_keypath_final_input: Option<fixtures::P2trMusig2KeyPathFinalInput> =
            match finalized_input_fixture.as_ref() {
                Some(fixtures::PsbtFinalInputFixture::P2trMusig2KeyPath(input)) => {
                    Some(input.clone())
                }
                Some(_) => return Err("Invalid finalized input type".to_string()),
                None => None,
            };
        Ok(Musig2FixtureData {
            fixture: fixture.clone(),
            musig2_input,
            musig2_input_index: input_index,
            fixture_keypath_input: fixture_keypath_input.clone(),
            fixture_keypath_final_input: fixture_keypath_final_input.clone(),
        })
    }

    fn test_signature_aggregation(musig2_fixture_data: &Musig2FixtureData) {
        let Musig2FixtureData {
            fixture,
            musig2_input,
            musig2_input_index,
            fixture_keypath_input,
            fixture_keypath_final_input,
        } = musig2_fixture_data;

        // Get the PSBT
        let psbt = fixture
            .to_bitgo_psbt(Network::Bitcoin)
            .expect("Failed to convert to BitGoPsbt")
            .into_psbt();

        // Get expected signature from fixture
        let fixture_keypath_final_input = fixture_keypath_final_input
            .as_ref()
            .expect("Finalized input not found");
        let fixture_witness_hex = &fixture_keypath_final_input.final_script_witness;

        // Parse witness stack: first byte is element count, second byte is signature length
        let fixture_witness_bytes = <Vec<u8> as hex::FromHex>::from_hex(fixture_witness_hex)
            .expect("Failed to decode fixture witness hex");

        // For taproot key path spend: witness should be [num_elements(1), sig_len(64), sig_data...]
        assert_eq!(fixture_witness_bytes[0], 0x01, "Expected 1 witness element");
        assert_eq!(fixture_witness_bytes[1], 0x40, "Expected 64-byte signature");
        let fixture_signature = &fixture_witness_bytes[2..66];

        // Get tap merkle root from fixture
        use crate::bitcoin::sighash::SighashCache;
        use crate::bitcoin::taproot::TapNodeHash;

        let tap_tree_root_bytes =
            <Vec<u8> as hex::FromHex>::from_hex(&fixture_keypath_input.tap_merkle_root)
                .expect("Failed to decode tap merkle root");
        let tap_tree_root_array: [u8; 32] = tap_tree_root_bytes
            .as_slice()
            .try_into()
            .expect("Invalid tap merkle root length");
        let tap_tree_root = TapNodeHash::from_byte_array(tap_tree_root_array);

        // Collect all prevouts for sighash computation
        let prevouts = collect_prevouts(&psbt).expect("Failed to collect prevouts");

        // Create sighash cache
        let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

        // Aggregate the signature using the Musig2Input method
        let aggregated_sig = musig2_input
            .aggregate_signature(
                &mut sighash_cache,
                &prevouts,
                *musig2_input_index,
                &tap_tree_root,
            )
            .expect("Failed to aggregate signatures");

        // Compare with fixture
        let sig_bytes = aggregated_sig.to_vec();
        assert_eq!(sig_bytes.len(), 64, "Expected 64-byte aggregated signature");
        assert_eq!(
            &sig_bytes[..],
            fixture_signature,
            "Aggregated signature does not match fixture"
        );

        println!("✓ Signature aggregation matches fixture");
    }

    fn test_musig2_keypath_matches_fixture(signature_state: SignatureState) {
        let musig2_fixture_data =
            get_musig2_fixture_data(signature_state).expect("Failed to get musig2 input");

        musig2_fixture_data
            .fixture_keypath_input
            .assert_matches_musig2_input(&musig2_fixture_data.musig2_input)
            .expect("Musig2 input validation failed");

        if signature_state == SignatureState::Fullsigned {
            test_signature_aggregation(&musig2_fixture_data);
        }

        println!("✓ All musig2 data matches fixture");
    }

    #[test]
    fn test_musig2_keypath_matches_fixture_unsigned() {
        test_musig2_keypath_matches_fixture(SignatureState::Unsigned);
    }

    #[test]
    fn test_musig2_keypath_matches_fixture_halfsigned() {
        test_musig2_keypath_matches_fixture(SignatureState::Halfsigned);
    }

    #[test]
    fn test_musig2_keypath_matches_fixture_fullsigned() {
        test_musig2_keypath_matches_fixture(SignatureState::Fullsigned);
    }

    #[test]
    fn test_state_machine_api_produces_valid_signature() {
        // Load fixtures using PsbtStages to get wallet keys
        let psbt_stages = fixtures::PsbtStages::load(crate::Network::Bitcoin, TxFormat::Psbt)
            .expect("Failed to load PSBT stages");

        // Find MuSig2 keypath input
        let (input_index, _input_fixture) = psbt_stages
            .unsigned
            .find_input_with_script_type(ScriptType::P2trMusig2TaprootKeypath)
            .expect("Failed to find taprootKeyPathSpend input");

        // Get wallet keys from stages
        let xpriv_triple = &psbt_stages.wallet_keys;

        // Convert to BitGoPsbt
        let mut bitgo_psbt = psbt_stages
            .unsigned
            .to_bitgo_psbt(crate::Network::Bitcoin)
            .expect("Failed to convert to BitGoPsbt");

        // Test State-Machine API
        assert_set_nonce_and_sign_musig2_keypath_state_machine(
            xpriv_triple,
            &mut bitgo_psbt,
            input_index,
        )
        .expect("State-Machine API test failed");

        println!("✓ State-Machine API produced valid signature");
    }

    #[test]
    fn test_both_apis_produce_valid_signatures() {
        // This test validates that both APIs can produce valid signatures on the same input

        // Load fixtures using PsbtStages to get wallet keys
        let psbt_stages = fixtures::PsbtStages::load(crate::Network::Bitcoin, TxFormat::Psbt)
            .expect("Failed to load PSBT stages");

        let (input_index, _) = psbt_stages
            .unsigned
            .find_input_with_script_type(ScriptType::P2trMusig2TaprootKeypath)
            .expect("Failed to find MuSig2 keypath input");

        let xpriv_triple = &psbt_stages.wallet_keys;

        // Test 1: Functional API (deterministic, fixture-validated)
        let mut functional_psbt = psbt_stages
            .unsigned
            .to_bitgo_psbt(crate::Network::Bitcoin)
            .expect("Failed to convert to BitGoPsbt");

        let halfsigned_psbt = psbt_stages
            .halfsigned
            .to_bitgo_psbt(crate::Network::Bitcoin)
            .expect("Failed to convert halfsigned to BitGoPsbt");

        // Use Functional API
        assert_set_nonce_and_sign_musig2_keypath(
            xpriv_triple,
            &mut functional_psbt,
            &halfsigned_psbt,
            input_index,
        )
        .expect("Functional API test failed");

        // Test 2: State-Machine API (non-deterministic, validity-checked)
        let mut state_machine_psbt = psbt_stages
            .unsigned
            .to_bitgo_psbt(crate::Network::Bitcoin)
            .expect("Failed to convert to BitGoPsbt");

        assert_set_nonce_and_sign_musig2_keypath_state_machine(
            xpriv_triple,
            &mut state_machine_psbt,
            input_index,
        )
        .expect("State-Machine API test failed");

        println!("✓ Both Functional and State-Machine APIs produced valid signatures");
    }
}
