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
/// Returns base64-encoded recoverable signature
pub fn sign_bitcoin_message(
    signing_key: &SigningKey,
    message: &str,
) -> Result<String, WasmBip32Error> {
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

    Ok(base64_encode(&sig_bytes))
}

/// Verify a Bitcoin message signature (BIP-137)
pub fn verify_bitcoin_message(
    verifying_key: &VerifyingKey,
    message: &str,
    signature_base64: &str,
) -> Result<bool, WasmBip32Error> {
    let sig_bytes = base64_decode(signature_base64)
        .map_err(|_| WasmBip32Error::new("Invalid base64 signature"))?;

    if sig_bytes.len() != 65 {
        return Err(WasmBip32Error::new("Signature must be 65 bytes"));
    }

    let header = sig_bytes[0];
    let r_s = &sig_bytes[1..65];

    // Extract recovery id from header
    // Header values: 27-30 uncompressed, 31-34 compressed
    let recovery_id = if (31..=34).contains(&header) {
        header - 31
    } else if (27..=30).contains(&header) {
        header - 27
    } else {
        return Err(WasmBip32Error::new("Invalid signature header"));
    };

    let signature =
        Signature::from_slice(r_s).map_err(|_| WasmBip32Error::new("Invalid signature format"))?;

    let recid = RecoveryId::from_byte(recovery_id)
        .ok_or_else(|| WasmBip32Error::new("Invalid recovery id"))?;

    let message_hash = bitcoin_message_hash(message);

    // Recover the public key from the signature
    let recovered_key = VerifyingKey::recover_from_prehash(&message_hash, &signature, recid)
        .map_err(|_| WasmBip32Error::new("Failed to recover public key from signature"))?;

    // Compare recovered key with provided key
    Ok(recovered_key == *verifying_key)
}

/// Simple base64 encoding (no external dependency)
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = data.get(i + 1).copied().unwrap_or(0) as usize;
        let b2 = data.get(i + 2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

/// Simple base64 decoding
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    const DECODE_TABLE: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
        -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1,
        -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];

    let input = input.trim_end_matches('=');
    let mut result = Vec::with_capacity(input.len() * 3 / 4);

    let mut buf = 0u32;
    let mut buf_len = 0;

    for &byte in input.as_bytes() {
        if byte >= 128 {
            return Err(());
        }
        let val = DECODE_TABLE[byte as usize];
        if val < 0 {
            return Err(());
        }

        buf = (buf << 6) | (val as u32);
        buf_len += 6;

        if buf_len >= 8 {
            buf_len -= 8;
            result.push((buf >> buf_len) as u8);
            buf &= (1 << buf_len) - 1;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let test_cases = vec![
            vec![],
            vec![0],
            vec![0, 1],
            vec![0, 1, 2],
            vec![0, 1, 2, 3],
            (0..65).collect::<Vec<u8>>(),
        ];

        for data in test_cases {
            let encoded = base64_encode(&data);
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(data, decoded);
        }
    }

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
