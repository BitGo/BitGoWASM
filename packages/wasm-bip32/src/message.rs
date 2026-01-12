use crate::error::WasmBip32Error;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Bitcoin message magic prefix
const BITCOIN_MESSAGE_MAGIC: &[u8] = b"\x18Bitcoin Signed Message:\n";

/// Compute Bitcoin message hash (double SHA256 with magic prefix)
fn bitcoin_message_hash(message: &str) -> [u8; 32] {
    let message_bytes = message.as_bytes();

    // Build the full message: magic + varint(len) + message
    let mut data = Vec::new();
    data.extend_from_slice(BITCOIN_MESSAGE_MAGIC);
    write_varint(&mut data, message_bytes.len());
    data.extend_from_slice(message_bytes);

    // Double SHA256
    let first_hash = Sha256::digest(&data);
    let second_hash = Sha256::digest(first_hash);

    let mut result = [0u8; 32];
    result.copy_from_slice(&second_hash);
    result
}

/// Write a variable-length integer
fn write_varint(data: &mut Vec<u8>, value: usize) {
    if value < 0xfd {
        data.push(value as u8);
    } else if value <= 0xffff {
        data.push(0xfd);
        data.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffffffff {
        data.push(0xfe);
        data.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        data.push(0xff);
        data.extend_from_slice(&(value as u64).to_le_bytes());
    }
}

/// Sign a raw 32-byte message hash with ECDSA
pub fn sign_raw(signing_key: &SigningKey, message_hash: &[u8]) -> Result<Vec<u8>, WasmBip32Error> {
    let (signature, _recovery_id): (Signature, RecoveryId) = signing_key
        .sign_prehash(message_hash)
        .map_err(|e| WasmBip32Error::new(&format!("Signing failed: {}", e)))?;

    Ok(signature.to_vec())
}

/// Verify a raw ECDSA signature
pub fn verify_raw(verifying_key: &VerifyingKey, message_hash: &[u8], signature: &[u8]) -> bool {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    verifying_key.verify_prehash(message_hash, &sig).is_ok()
}

/// Sign a message using Bitcoin message signing (BIP-137)
/// Returns 65-byte recoverable signature (1-byte header + 64-byte signature)
pub fn sign_bitcoin_message(
    signing_key: &SigningKey,
    message: &str,
) -> Result<Vec<u8>, WasmBip32Error> {
    let message_hash = bitcoin_message_hash(message);

    let (signature, recovery_id): (Signature, RecoveryId) = signing_key
        .sign_prehash(&message_hash)
        .map_err(|e| WasmBip32Error::new(&format!("Signing failed: {}", e)))?;

    // BIP-137 format: 1-byte header + 64-byte signature
    // Header: 27 + recovery_id + (4 if compressed)
    // We always use compressed keys, so header = 31 + recovery_id
    let header = 31 + recovery_id.to_byte();

    let mut sig_bytes = Vec::with_capacity(65);
    sig_bytes.push(header);
    sig_bytes.extend_from_slice(&signature.to_bytes());

    Ok(sig_bytes)
}

/// Verify a Bitcoin message signature (BIP-137)
/// Signature must be 65 bytes (1-byte header + 64-byte signature)
pub fn verify_bitcoin_message(
    verifying_key: &VerifyingKey,
    message: &str,
    signature: &[u8],
) -> Result<bool, WasmBip32Error> {
    if signature.len() != 65 {
        return Err(WasmBip32Error::new("Signature must be 65 bytes"));
    }

    let header = signature[0];
    let r_s = &signature[1..65];

    // Extract recovery id from header
    // Header values: 27-30 uncompressed, 31-34 compressed
    let recovery_id = if (31..=34).contains(&header) {
        header - 31
    } else if (27..=30).contains(&header) {
        header - 27
    } else {
        return Err(WasmBip32Error::new("Invalid signature header"));
    };

    let sig =
        Signature::from_slice(r_s).map_err(|_| WasmBip32Error::new("Invalid signature format"))?;

    let recid = RecoveryId::from_byte(recovery_id)
        .ok_or_else(|| WasmBip32Error::new("Invalid recovery id"))?;

    let message_hash = bitcoin_message_hash(message);

    // Recover the public key from the signature
    let recovered_key = VerifyingKey::recover_from_prehash(&message_hash, &sig, recid)
        .map_err(|_| WasmBip32Error::new("Failed to recover public key from signature"))?;

    // Compare recovered key with provided key
    Ok(recovered_key == *verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_message_hash() {
        // The hash should be deterministic
        let hash1 = bitcoin_message_hash("test message");
        let hash2 = bitcoin_message_hash("test message");
        assert_eq!(hash1, hash2);

        // Different messages should produce different hashes
        let hash3 = bitcoin_message_hash("different message");
        assert_ne!(hash1, hash3);
    }
}
