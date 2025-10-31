//! BitGo-specific MuSig2 implementation
//!
//! This module implements BitGo's non-standard variant of MuSig2 key aggregation
//! that uses x-only (32-byte) pubkeys in the hash computation, which differs from
//! standard BIP327.
//!
//! See bips/bip-0327/README.md for more details.
//!

use miniscript::bitcoin::CompressedPublicKey;
use musig2::KeyAggContext;

use crate::bitcoin::hashes::{sha256, Hash, HashEngine};
use crate::bitcoin::secp256k1::{Parity, PublicKey, Scalar, Secp256k1, XOnlyPublicKey};

/// Error types for BitGo MuSig2 operations
#[derive(Debug)]
pub enum BitGoMusigError {
    InvalidPubkeyCount(String),
    InvalidPubkey(String),
    AggregationFailed(String),
}

impl std::fmt::Display for BitGoMusigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BitGoMusigError::InvalidPubkeyCount(msg) => write!(f, "Invalid pubkey count: {}", msg),
            BitGoMusigError::InvalidPubkey(msg) => write!(f, "Invalid pubkey: {}", msg),
            BitGoMusigError::AggregationFailed(msg) => write!(f, "Aggregation failed: {}", msg),
        }
    }
}

impl std::error::Error for BitGoMusigError {}

/// BIP340-style tagged hash
fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// MuSig2 key aggregation base function.
///
/// This function implements key aggregation as per BIP327 reference.
/// It accepts either 33-byte compressed or 32-byte x-only public keys.
///
/// # Arguments
/// * `pubkey_bytes` - Slice of public key bytes (either 33-byte compressed or 32-byte x-only)
///
/// # Returns
/// The aggregated x-only public key (32 bytes)
///
/// # Errors
/// Returns error if:
/// - Less than 2 pubkeys provided
/// - Any pubkey is invalid
/// - Aggregation results in point at infinity
fn key_agg(pubkey_bytes: &[Vec<u8>]) -> Result<[u8; 32], BitGoMusigError> {
    if pubkey_bytes.len() < 2 {
        return Err(BitGoMusigError::InvalidPubkeyCount(
            "At least two pubkeys are required for MuSig key aggregation".to_string(),
        ));
    }

    let secp = Secp256k1::new();

    // Determine if we're working with xonly keys (32 bytes) or compressed keys (33 bytes)
    let xonly = pubkey_bytes[0].len() == 32;

    // Compute L using the pubkey_bytes
    let mut l_input = Vec::new();
    for pk in pubkey_bytes {
        l_input.extend_from_slice(pk);
    }
    let l = tagged_hash("KeyAgg list", &l_input);

    // Find second unique key
    let pk2 = pubkey_bytes
        .iter()
        .skip(1)
        .find(|pk| pk != &&pubkey_bytes[0]);

    // Aggregate the keys
    let mut q_option: Option<PublicKey> = None;

    for (i, pk_bytes) in pubkey_bytes.iter().enumerate() {
        // In xonly mode, pubkeys are 32 bytes, so reconstruct with even Y
        let p_i = if xonly {
            let xonly_pk = XOnlyPublicKey::from_slice(pk_bytes).map_err(|e| {
                BitGoMusigError::InvalidPubkey(format!(
                    "Invalid x-only pubkey at index {}: {}",
                    i, e
                ))
            })?;
            PublicKey::from_x_only_public_key(xonly_pk, Parity::Even)
        } else {
            // Parse as compressed (33-byte) pubkey
            PublicKey::from_slice(pk_bytes).map_err(|e| {
                BitGoMusigError::InvalidPubkey(format!(
                    "Invalid compressed pubkey at index {}: {}",
                    i, e
                ))
            })?
        };

        // Compute coefficient
        let a_i = if let Some(pk2_bytes) = pk2 {
            if pk_bytes == pk2_bytes {
                // Second unique key gets coefficient 1
                Scalar::ONE
            } else {
                // Compute coefficient for this key
                let mut coeff_input = Vec::new();
                coeff_input.extend_from_slice(&l);
                coeff_input.extend_from_slice(pk_bytes);
                let coeff_hash = tagged_hash("KeyAgg coefficient", &coeff_input);
                Scalar::from_be_bytes(coeff_hash).map_err(|e| {
                    BitGoMusigError::AggregationFailed(format!("Invalid coefficient: {}", e))
                })?
            }
        } else {
            // All keys are identical - this is cryptographically invalid
            return Err(BitGoMusigError::InvalidPubkeyCount(
                "All pubkeys are identical - MuSig requires at least two distinct keys".to_string(),
            ));
        };

        // Multiply point by coefficient
        let contribution = p_i.mul_tweak(&secp, &a_i).map_err(|e| {
            BitGoMusigError::AggregationFailed(format!("Point multiplication failed: {}", e))
        })?;

        // Add to aggregate
        q_option = match q_option {
            None => Some(contribution),
            Some(q) => {
                let combined = q.combine(&contribution).map_err(|e| {
                    BitGoMusigError::AggregationFailed(format!("Point addition failed: {}", e))
                })?;
                Some(combined)
            }
        };
    }

    let q = q_option.ok_or_else(|| {
        BitGoMusigError::AggregationFailed("Aggregation resulted in point at infinity".to_string())
    })?;

    // Return x-coordinate (x-only pubkey)
    let (xonly_result, _parity) = q.x_only_public_key();
    Ok(xonly_result.serialize())
}

/// BitGo legacy P2TR key aggregation.
///
/// This is the legacy algorithm used by the BitGo 'p2tr' output script type (chain 30, 31).
/// Here, we convert the pubkeys to xonly first and then sort.
/// This corresponds to an older variant of the musig2 scheme.
pub fn key_agg_bitgo_p2tr_legacy(
    pubkeys: &[CompressedPublicKey],
) -> Result<[u8; 32], BitGoMusigError> {
    // For xonly mode, normalize all pubkeys to use only x-coordinate in hashes
    // by converting them to 32-byte x-only format
    let mut xonly_keys: Vec<Vec<u8>> = pubkeys
        .iter()
        .map(|pk| {
            let bytes = pk.to_bytes();
            bytes[bytes.len() - 32..].to_vec()
        })
        .collect();

    // Sort the keys after xonly conversion, before aggregation
    xonly_keys.sort();

    key_agg(&xonly_keys)
}

/// P2TR MuSig2 key aggregation.
///
/// This is the standard BIP327 key aggregation without sorting or x-only mode.
/// Order of keys matters - different order produces different aggregate keys.
pub fn key_agg_p2tr_musig2(pubkeys: &[CompressedPublicKey]) -> Result<[u8; 32], BitGoMusigError> {
    let pubkey_bytes: Vec<Vec<u8>> = pubkeys.iter().map(|pk| pk.to_bytes().to_vec()).collect();
    key_agg(&pubkey_bytes)
}

/// P2TR MuSig2 key aggregation using external musig2 crate.
///
/// This function uses the external `musig2` crate to perform BIP327-compliant
/// key aggregation. It should produce identical results to `key_agg_p2tr_musig2`.
pub fn key_agg_p2tr_musig2_external_crate(
    pubkeys: &[CompressedPublicKey],
) -> Result<[u8; 32], BitGoMusigError> {
    if pubkeys.len() < 2 {
        return Err(BitGoMusigError::InvalidPubkeyCount(
            "At least two pubkeys are required for MuSig key aggregation".to_string(),
        ));
    }

    // Check for duplicate keys
    let first = &pubkeys[0];
    let has_distinct = pubkeys.iter().skip(1).any(|pk| pk != first);
    if !has_distinct {
        return Err(BitGoMusigError::InvalidPubkeyCount(
            "All pubkeys are identical - MuSig requires at least two distinct keys".to_string(),
        ));
    }

    // Convert CompressedPublicKey to musig2::secp256k1::PublicKey
    let secp_pubkeys: Result<Vec<musig2::secp256k1::PublicKey>, _> = pubkeys
        .iter()
        .enumerate()
        .map(|(i, cpk)| {
            musig2::secp256k1::PublicKey::from_slice(&cpk.to_bytes()).map_err(|e| {
                BitGoMusigError::InvalidPubkey(format!("Invalid pubkey at index {}: {}", i, e))
            })
        })
        .collect();
    let secp_pubkeys = secp_pubkeys?;

    // Use musig2 crate for key aggregation
    let key_agg_ctx = KeyAggContext::new(secp_pubkeys).map_err(|e| {
        BitGoMusigError::AggregationFailed(format!("KeyAggContext creation failed: {}", e))
    })?;

    // Get the aggregated x-only public key
    let agg_pk: musig2::secp256k1::XOnlyPublicKey = key_agg_ctx.aggregated_pubkey();
    Ok(agg_pk.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey_from_hex(hex: &str) -> CompressedPublicKey {
        CompressedPublicKey::from_slice(&hex::decode(hex).unwrap()).unwrap()
    }

    fn pubkey_from_hex_xonly(hex: &str) -> [u8; 32] {
        XOnlyPublicKey::from_slice(&hex::decode(hex).unwrap())
            .unwrap()
            .serialize()
    }

    /// Test keys used across multiple tests
    struct TestKeys {
        user: CompressedPublicKey,
        bitgo: CompressedPublicKey,
        backup: CompressedPublicKey,
    }

    fn get_test_keys() -> TestKeys {
        TestKeys {
            user: pubkey_from_hex(
                "02d20a62701c54f6eb3abb9f964b0e29ff90ffa3b4e3fcb73e7c67d4950fa6e3c7",
            ),
            bitgo: pubkey_from_hex(
                "03203ab799ce28e2cca044f594c69275050af4bb0854ad730a8f74622342300e64",
            ),
            backup: pubkey_from_hex(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
        }
    }

    /// Expected fixtures for key aggregation tests
    struct AggregationFixtures {
        p2tr_legacy: [u8; 32],
        p2tr_musig2_forward: [u8; 32],
        p2tr_musig2_reverse: [u8; 32],
    }

    fn get_aggregation_fixtures() -> AggregationFixtures {
        AggregationFixtures {
            p2tr_legacy: pubkey_from_hex_xonly(
                "cc899cac29f6243ef481be86f0d39e173c075cd57193d46332b1ec0b42c439aa",
            ),
            p2tr_musig2_forward: pubkey_from_hex_xonly(
                "c0e255b4510e041ab81151091d875687a618de314344dff4b73b1bcd366cdbd8",
            ),
            p2tr_musig2_reverse: pubkey_from_hex_xonly(
                "e48d309b535811eb0b148c4b0600a10e82e289899429e40aee05577504eca356",
            ),
        }
    }

    /// Assert that aggregation result matches expected fixture
    fn assert_aggregation(result: [u8; 32], expected: [u8; 32], msg: &str) {
        assert_eq!(result, expected, "{}", msg);
    }

    #[test]
    fn test_bitgo_p2tr_aggregation() {
        // Test matching the Python test_agg_bitgo function
        // This is the algorithm used by the bitgo 'p2tr' output script type (chain 30, 31)
        let keys = get_test_keys();
        let fixtures = get_aggregation_fixtures();

        // Test 1: bitgo_p2tr_legacy aggregation using xonly conversion + sort
        let result = key_agg_bitgo_p2tr_legacy(&[keys.user, keys.bitgo]).unwrap();
        assert_aggregation(
            result,
            fixtures.p2tr_legacy,
            "p2tr legacy aggregation mismatch",
        );

        // Test 2: bitgo_p2tr_legacy aggregation in reverse order should give same result (because sort=true)
        let result = key_agg_bitgo_p2tr_legacy(&[keys.bitgo, keys.user]).unwrap();
        assert_aggregation(
            result,
            fixtures.p2tr_legacy,
            "p2tr legacy aggregation (reverse) mismatch",
        );

        // Test 3: p2tr_musig2 aggregation using standard BIP327
        let result = key_agg_p2tr_musig2(&[keys.user, keys.bitgo]).unwrap();
        assert_aggregation(
            result,
            fixtures.p2tr_musig2_forward,
            "p2trMusig2 aggregation mismatch",
        );

        // Test 4: p2tr_musig2 aggregation in reverse order gives different result (because sort=false)
        let result = key_agg_p2tr_musig2(&[keys.bitgo, keys.user]).unwrap();
        assert_aggregation(
            result,
            fixtures.p2tr_musig2_reverse,
            "p2trMusig2 aggregation (reverse) mismatch",
        );
    }

    #[test]
    fn test_identical_keys_error() {
        // Test that aggregating identical keys returns an error
        let keys = get_test_keys();

        // All keys are identical - should error
        let result = key_agg_bitgo_p2tr_legacy(&[keys.user, keys.user]);
        assert!(
            result.is_err(),
            "Expected error when all keys are identical"
        );
        assert!(
            matches!(result, Err(BitGoMusigError::InvalidPubkeyCount(_))),
            "Expected InvalidPubkeyCount error"
        );

        // Same for p2tr_musig2
        let result = key_agg_p2tr_musig2(&[keys.user, keys.user]);
        assert!(
            result.is_err(),
            "Expected error when all keys are identical"
        );
        assert!(
            matches!(result, Err(BitGoMusigError::InvalidPubkeyCount(_))),
            "Expected InvalidPubkeyCount error"
        );
    }

    #[test]
    fn test_external_crate_matches_internal_implementation() {
        // Test that the external musig2 crate produces the same results as our internal implementation
        let keys = get_test_keys();
        let fixtures = get_aggregation_fixtures();

        // Test 1: Same order should produce same results
        let result_internal = key_agg_p2tr_musig2(&[keys.user, keys.bitgo]).unwrap();
        let result_external = key_agg_p2tr_musig2_external_crate(&[keys.user, keys.bitgo]).unwrap();
        assert_aggregation(
            result_internal,
            fixtures.p2tr_musig2_forward,
            "Internal implementation mismatch",
        );
        assert_aggregation(
            result_external,
            fixtures.p2tr_musig2_forward,
            "External crate mismatch",
        );

        // Test 2: Reverse order should produce same results (but different from test 1)
        let result_internal_reverse = key_agg_p2tr_musig2(&[keys.bitgo, keys.user]).unwrap();
        let result_external_reverse =
            key_agg_p2tr_musig2_external_crate(&[keys.bitgo, keys.user]).unwrap();
        assert_aggregation(
            result_internal_reverse,
            fixtures.p2tr_musig2_reverse,
            "Internal implementation (reverse) mismatch",
        );
        assert_aggregation(
            result_external_reverse,
            fixtures.p2tr_musig2_reverse,
            "External crate (reverse) mismatch",
        );

        // Test 3: Verify order matters for both implementations
        assert_ne!(
            result_internal, result_internal_reverse,
            "Different key order should produce different results"
        );
        assert_ne!(
            result_external, result_external_reverse,
            "Different key order should produce different results for external crate"
        );
    }

    #[test]
    fn test_external_crate_identical_keys_error() {
        // Test that the external crate also rejects identical keys
        let keys = get_test_keys();

        let result = key_agg_p2tr_musig2_external_crate(&[keys.user, keys.user]);
        assert!(
            result.is_err(),
            "External crate should error when all keys are identical"
        );
    }

    #[test]
    fn test_external_crate_with_three_keys() {
        // Test with three keys to ensure it works with more than 2 keys
        let keys = get_test_keys();

        let result_internal = key_agg_p2tr_musig2(&[keys.user, keys.bitgo, keys.backup]).unwrap();
        let result_external =
            key_agg_p2tr_musig2_external_crate(&[keys.user, keys.bitgo, keys.backup]).unwrap();

        assert_eq!(
            result_internal, result_external,
            "External crate should match internal implementation with 3 keys"
        );
    }
}
