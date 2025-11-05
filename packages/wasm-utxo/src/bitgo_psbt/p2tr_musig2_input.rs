//! MuSig2 PSBT proprietary key-value parsing
//!
//! This module provides encoding and decoding of MuSig2-related proprietary
//! key-values in PSBTs, following the format specified in:
//! https://gist.github.com/sanket1729/4b525c6049f4d9e034d27368c49f28a6

use crate::bitgo_psbt::propkv::{find_kv, is_musig2_key, BitGoKeyValue};

use super::propkv::ProprietaryKeySubtype;
use crate::bitcoin::{key::UntweakedPublicKey, CompressedPublicKey};
use miniscript::bitcoin::hashes::{hex, Hash};
use miniscript::bitcoin::{psbt::Input, secp256k1, Psbt};
use musig2::PubNonce;

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

/// Collect all prevouts (funding outputs) from PSBT inputs
///
/// This helper extracts the TxOut for each input from either witness_utxo or non_witness_utxo.
/// Required for computing sighashes in taproot transactions.
fn collect_prevouts(psbt: &Psbt) -> Result<Vec<crate::bitcoin::TxOut>, Musig2Error> {
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
        psbt: &mut Psbt,
        secp: &secp256k1::Secp256k1<C>,
        input_index: usize,
    ) -> Result<(), Musig2Error> {
        use crate::bitcoin::sighash::SighashCache;
        use miniscript::psbt::PsbtExt;

        // Step 1: Parse Musig2Input from PSBT input
        let musig2_input = Self::from_input(&psbt.inputs[input_index])?;

        // Step 2: Collect all prevouts for sighash computation
        let prevouts = collect_prevouts(psbt)?;

        // Get tap merkle root from input
        use crate::bitcoin::taproot::TapNodeHash;
        let tap_merkle_root = psbt.inputs[input_index]
            .tap_merkle_root
            .unwrap_or_else(|| TapNodeHash::from_byte_array([0u8; 32]));

        // Step 3: Aggregate signatures
        let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
        let taproot_sig = musig2_input.aggregate_signature(
            &mut sighash_cache,
            &prevouts,
            input_index,
            &tap_merkle_root,
        )?;

        // Step 4: Set tap_key_sig
        psbt.inputs[input_index].tap_key_sig = Some(taproot_sig);

        // Step 5: Clear MuSig2 proprietary fields (they're no longer needed)
        psbt.inputs[input_index]
            .proprietary
            .retain(|key, _| !is_musig2_key(key));

        // Step 6: Use standard miniscript finalization for the rest!
        psbt.finalize_inp_mut(secp, input_index).map_err(|e| {
            Musig2Error::SignatureAggregation(format!("Finalization failed: {}", e))
        })?;

        Ok(())
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

        // Compute taproot key spend sighash
        let sighash_type = TapSighashType::Default;
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
        let sig_bytes: [u8; 64] = final_sig.to_bytes();
        crate::bitcoin::taproot::Signature::from_slice(&sig_bytes)
            .map_err(|e| Musig2Error::SignatureAggregation(format!("Invalid signature: {}", e)))
    }
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
}
