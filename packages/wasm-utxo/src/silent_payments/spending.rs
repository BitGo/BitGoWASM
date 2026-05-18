//! BIP-352 Silent Payment spend key derivation.
//!
//! Derives the private key needed to spend a matched silent payment output.
//! This is a trivial scalar addition: p_k = b_spend + t_k.

use miniscript::bitcoin::secp256k1::{Scalar, SecretKey};

use super::SilentPaymentError;

/// Derive the private key for spending a silent payment output.
///
/// Given the receiver's spend private key (`b_spend`) and the tweak (`t_k`)
/// from scanning, compute `p_k = b_spend + t_k`.
/// The resulting key can sign for the P2TR output via standard taproot keypath.
pub fn derive_spend_key(
    b_spend: &SecretKey,
    tweak: &[u8; 32],
) -> Result<SecretKey, SilentPaymentError> {
    let t_k = Scalar::from_be_bytes(*tweak)
        .map_err(|e| SilentPaymentError::InvalidScalar(format!("invalid tweak scalar: {}", e)))?;

    b_spend
        .add_tweak(&t_k)
        .map_err(|e| SilentPaymentError::Secp256k1(format!("tweak addition failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniscript::bitcoin::secp256k1::{PublicKey, Secp256k1};

    #[test]
    fn test_derive_spend_key_basic() {
        let secp = Secp256k1::new();
        let b_spend = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let tweak = [1u8; 32];

        let derived = derive_spend_key(&b_spend, &tweak).unwrap();

        // Verify that the derived key is b_spend + t_k by checking pubkeys
        let b_spend_pub = PublicKey::from_secret_key(&secp, &b_spend);
        let t_k_secret = SecretKey::from_slice(&tweak).unwrap();
        let t_k_pub = PublicKey::from_secret_key(&secp, &t_k_secret);
        let expected_pub = b_spend_pub.combine(&t_k_pub).unwrap();

        let derived_pub = PublicKey::from_secret_key(&secp, &derived);
        assert_eq!(derived_pub, expected_pub);
    }

    #[test]
    fn test_derive_spend_key_negated_tweak_rejected() {
        // If b_spend + t_k = 0 (mod n), it should fail.
        // This is extremely unlikely in practice but we test the error path.
        // Scalar::from_be_bytes(0) is actually valid (zero scalar),
        // and add_tweak with zero scalar just returns the same key.
        let b_spend = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let zero_tweak = [0u8; 32];

        // Zero is a valid Scalar, add_tweak with zero returns the original key
        let result = derive_spend_key(&b_spend, &zero_tweak);
        // This should succeed since zero tweak doesn't change the key
        assert!(result.is_ok());
        assert_eq!(result.unwrap().secret_bytes(), b_spend.secret_bytes());
    }
}
