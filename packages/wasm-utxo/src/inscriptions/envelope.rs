//! Inscription envelope script builder
//!
//! Creates the taproot script containing the inscription data following
//! the Ordinals protocol format.

use miniscript::bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF, OP_PUSHBYTES_0};
use miniscript::bitcoin::opcodes::OP_FALSE;
use miniscript::bitcoin::script::{Builder, PushBytesBuf};
use miniscript::bitcoin::secp256k1::XOnlyPublicKey;
use miniscript::bitcoin::ScriptBuf;

/// Maximum size of a single data push in tapscript (520 bytes)
const MAX_PUSH_SIZE: usize = 520;

/// Split data into chunks of at most MAX_PUSH_SIZE bytes
fn split_into_chunks(data: &[u8]) -> Vec<&[u8]> {
    data.chunks(MAX_PUSH_SIZE).collect()
}

/// Build an inscription envelope script
///
/// The script follows the Ordinals protocol format:
/// ```text
/// <pubkey> OP_CHECKSIG OP_FALSE OP_IF
///   "ord"
///   OP_1 OP_1 <content_type>
///   OP_0 <data_chunk_1> <data_chunk_2> ...
/// OP_ENDIF
/// ```
///
/// # Arguments
/// * `internal_key` - The x-only public key for the taproot output
/// * `content_type` - MIME type of the inscription (e.g., "text/plain", "image/png")
/// * `data` - The inscription data
///
/// # Returns
/// A compiled Bitcoin script containing the inscription
pub fn build_inscription_script(
    internal_key: &XOnlyPublicKey,
    content_type: &str,
    data: &[u8],
) -> ScriptBuf {
    let mut builder = Builder::new();

    // <pubkey> OP_CHECKSIG
    builder = builder.push_x_only_key(internal_key);
    builder = builder.push_opcode(OP_CHECKSIG);

    // OP_FALSE OP_IF (start inscription envelope)
    builder = builder.push_opcode(OP_FALSE);
    builder = builder.push_opcode(OP_IF);

    // "ord" - protocol identifier
    let ord_bytes = PushBytesBuf::try_from(b"ord".to_vec()).expect("ord is 3 bytes");
    builder = builder.push_slice(ord_bytes);

    // Content type tag: push byte 0x01 (tag number for content-type)
    // Encoded as PUSHBYTES_1 0x01 (two bytes: 01 01)
    let tag_content_type = PushBytesBuf::try_from(vec![0x01]).expect("single byte");
    builder = builder.push_slice(tag_content_type);

    // <content_type>
    let content_type_bytes =
        PushBytesBuf::try_from(content_type.as_bytes().to_vec()).expect("content type too long");
    builder = builder.push_slice(content_type_bytes);

    // OP_0 - body tag
    builder = builder.push_opcode(OP_PUSHBYTES_0);

    // Data chunks (split into MAX_PUSH_SIZE byte chunks)
    for chunk in split_into_chunks(data) {
        let chunk_bytes = PushBytesBuf::try_from(chunk.to_vec()).expect("chunk is <= 520 bytes");
        builder = builder.push_slice(chunk_bytes);
    }

    // OP_ENDIF (end inscription envelope)
    builder = builder.push_opcode(OP_ENDIF);

    builder.into_script()
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniscript::bitcoin::secp256k1::{Secp256k1, SecretKey};
    use miniscript::bitcoin::XOnlyPublicKey;

    fn test_pubkey() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1u8; 32]).expect("32 bytes, within curve order");
        let (xonly, _parity) = secret_key.x_only_public_key(&secp);
        xonly
    }

    #[test]
    fn test_build_inscription_script_simple() {
        let pubkey = test_pubkey();
        let script = build_inscription_script(&pubkey, "text/plain", b"Hello, World!");

        // Verify the script contains expected elements
        let script_bytes = script.as_bytes();
        assert!(script_bytes.len() > 50); // Should have reasonable length

        // Check for "ord" in the script
        let script_hex = hex::encode(script_bytes);
        assert!(script_hex.contains(&hex::encode(b"ord")));

        // Check for content type
        assert!(script_hex.contains(&hex::encode(b"text/plain")));

        // Check for data
        assert!(script_hex.contains(&hex::encode(b"Hello, World!")));
    }

    #[test]
    fn test_build_inscription_script_large_data() {
        let pubkey = test_pubkey();
        // Create data larger than MAX_PUSH_SIZE
        let large_data = vec![0xABu8; 1000];
        let script = build_inscription_script(&pubkey, "application/octet-stream", &large_data);

        // Script should be created successfully
        assert!(script.as_bytes().len() > 1000);
    }
}
