//! Bitcoin message signing and verification (BIP-137)

use crate::bitcoin::{
    consensus::Encodable,
    hashes::{sha256d, Hash},
    secp256k1::{self, PublicKey, Secp256k1, SecretKey},
    VarInt,
};
use crate::error::WasmUtxoError;

/// Bitcoin message signing prefix
const BITCOIN_SIGNED_MESSAGE_PREFIX: &[u8] = b"\x18Bitcoin Signed Message:\n";

/// Compute Bitcoin message hash (double SHA256 with magic prefix)
fn bitcoin_message_hash(message: &str) -> sha256d::Hash {
    let message_bytes = message.as_bytes();

    // Build the full message: magic + varint(len) + message
    let mut data = Vec::new();
    data.extend_from_slice(BITCOIN_SIGNED_MESSAGE_PREFIX);

    let varint = VarInt::from(message_bytes.len());
    let mut varint_bytes = Vec::new();
    // consensus_encode on VarInt to Vec<u8> is infallible
    varint.consensus_encode(&mut varint_bytes).unwrap();
    data.extend_from_slice(&varint_bytes);

    data.extend_from_slice(message_bytes);

    sha256d::Hash::hash(&data)
}

/// Sign a message using Bitcoin message signing (BIP-137)
///
/// Returns 65-byte recoverable signature (1-byte header + 64-byte signature).
/// Header = 31 + recovery_id (always compressed keys).
pub fn sign_bitcoin_message(
    secret_key: &SecretKey,
    message: &str,
) -> Result<Vec<u8>, WasmUtxoError> {
    let message_hash = bitcoin_message_hash(message);
    let msg = secp256k1::Message::from_digest(*message_hash.as_ref());

    let secp = Secp256k1::signing_only();
    let recoverable_sig = secp.sign_ecdsa_recoverable(&msg, secret_key);
    let (recovery_id, compact_sig) = recoverable_sig.serialize_compact();

    // BIP-137 format: 1-byte header + 64-byte signature
    // Header: 27 + recovery_id + (compressed ? 4 : 0)
    // We always use compressed keys, so header = 31 + recovery_id
    let header = 31 + recovery_id.to_i32() as u8;

    let mut sig_bytes = Vec::with_capacity(65);
    sig_bytes.push(header);
    sig_bytes.extend_from_slice(&compact_sig);

    Ok(sig_bytes)
}

/// Verify a Bitcoin message signature (BIP-137)
///
/// Recovers the public key from the 65-byte signature and compares it to the
/// provided public key. Returns `true` if they match.
pub fn verify_bitcoin_message(
    public_key: &PublicKey,
    message: &str,
    signature: &[u8],
) -> Result<bool, WasmUtxoError> {
    if signature.len() != 65 {
        return Err(WasmUtxoError::new("Signature must be 65 bytes"));
    }

    let recovery_flags = signature[0];
    let compact_sig = &signature[1..65];

    // Decode recovery ID from flags
    // Compressed keys: 31-34 (recid 0-3), Uncompressed: 27-30
    let recovery_id = if (31..=34).contains(&recovery_flags) {
        secp256k1::ecdsa::RecoveryId::from_i32((recovery_flags - 31) as i32)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid recovery ID: {}", e)))?
    } else if (27..=30).contains(&recovery_flags) {
        secp256k1::ecdsa::RecoveryId::from_i32((recovery_flags - 27) as i32)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid recovery ID: {}", e)))?
    } else {
        return Err(WasmUtxoError::new(&format!(
            "Invalid signature header: {}",
            recovery_flags
        )));
    };

    let recoverable_sig =
        secp256k1::ecdsa::RecoverableSignature::from_compact(compact_sig, recovery_id)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid signature format: {}", e)))?;

    let message_hash = bitcoin_message_hash(message);
    let msg = secp256k1::Message::from_digest(*message_hash.as_ref());

    let secp = Secp256k1::verification_only();
    let recovered_pubkey = secp
        .recover_ecdsa(&msg, &recoverable_sig)
        .map_err(|e| WasmUtxoError::new(&format!("Failed to recover public key: {}", e)))?;

    Ok(&recovered_pubkey == public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_slice(&[0x01; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let message = "Hello, Bitcoin!";
        let signature = sign_bitcoin_message(&secret_key, message).unwrap();

        assert_eq!(signature.len(), 65);
        assert!(verify_bitcoin_message(&public_key, message, &signature).unwrap());
    }

    #[test]
    fn test_verify_wrong_key() {
        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_slice(&[0x01; 32]).expect("32 bytes, within curve order");
        let wrong_secret_key =
            SecretKey::from_slice(&[0x02; 32]).expect("32 bytes, within curve order");
        let wrong_public_key = PublicKey::from_secret_key(&secp, &wrong_secret_key);

        let message = "Hello, Bitcoin!";
        let signature = sign_bitcoin_message(&secret_key, message).unwrap();

        assert!(!verify_bitcoin_message(&wrong_public_key, message, &signature).unwrap());
    }

    #[test]
    fn test_verify_wrong_message() {
        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_slice(&[0x01; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let signature = sign_bitcoin_message(&secret_key, "original message").unwrap();

        assert!(!verify_bitcoin_message(&public_key, "different message", &signature).unwrap());
    }

    #[test]
    fn test_verify_invalid_signature_length() {
        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_slice(&[0x01; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let result = verify_bitcoin_message(&public_key, "test", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_hash_deterministic() {
        let hash1 = bitcoin_message_hash("test message");
        let hash2 = bitcoin_message_hash("test message");
        assert_eq!(hash1, hash2);

        let hash3 = bitcoin_message_hash("different message");
        assert_ne!(hash1, hash3);
    }
}
