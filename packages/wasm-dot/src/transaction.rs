//! Core transaction types and operations for DOT

use crate::address::encode_ss58;
use crate::error::WasmDotError;
use crate::types::{Era, Material, ParseContext, Validity};
use blake2::{digest::consts::U32, Blake2b, Digest};

/// Represents a DOT transaction (extrinsic)
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Raw transaction bytes
    raw_bytes: Vec<u8>,
    /// Whether the transaction is signed
    is_signed: bool,
    /// Signer public key (if signed)
    signer: Option<[u8; 32]>,
    /// Signature (if signed)
    signature: Option<[u8; 64]>,
    /// Era
    era: Era,
    /// Nonce
    nonce: u32,
    /// Tip
    tip: u128,
    /// Call data (SCALE encoded)
    call_data: Vec<u8>,
    /// Context for operations
    context: Option<TransactionContext>,
}

/// Transaction context containing chain info
#[derive(Debug, Clone)]
pub struct TransactionContext {
    pub material: Material,
    pub validity: Validity,
    pub reference_block: [u8; 32],
}

impl Transaction {
    /// Create a transaction from raw bytes
    ///
    /// # Arguments
    /// * `bytes` - Raw extrinsic bytes
    /// * `context` - Optional parsing context with chain material
    pub fn from_bytes(bytes: &[u8], context: Option<ParseContext>) -> Result<Self, WasmDotError> {
        if bytes.is_empty() {
            return Err(WasmDotError::InvalidTransaction(
                "Empty transaction".to_string(),
            ));
        }

        // Parse the extrinsic
        let (is_signed, signer, signature, era, nonce, tip, call_data) = parse_extrinsic(bytes)?;

        let tx_context = context.map(|ctx| TransactionContext {
            material: ctx.material,
            validity: Validity::default(),
            reference_block: [0u8; 32], // Unknown from bytes alone
        });

        Ok(Transaction {
            raw_bytes: bytes.to_vec(),
            is_signed,
            signer,
            signature,
            era,
            nonce,
            tip,
            call_data,
            context: tx_context,
        })
    }

    /// Serialize transaction to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, WasmDotError> {
        if let (Some(signer), Some(signature)) = (self.signer, self.signature) {
            // Build signed extrinsic
            let mut result = Vec::new();

            // Version byte: 0x84 = signed, version 4
            let version_byte = 0x84u8;

            // Build the extrinsic body (without length prefix)
            let mut body = Vec::new();
            body.push(version_byte);

            // Signer (MultiAddress::Id)
            body.push(0x00); // Id variant
            body.extend_from_slice(&signer);

            // Signature (MultiSignature::Ed25519)
            body.push(0x00); // Ed25519 variant
            body.extend_from_slice(&signature);

            // Era
            let era_bytes = encode_era(&self.era);
            body.extend_from_slice(&era_bytes);

            // Nonce (compact)
            body.extend_from_slice(&encode_compact(self.nonce as u128));

            // Tip (compact)
            body.extend_from_slice(&encode_compact(self.tip));

            // Call data
            body.extend_from_slice(&self.call_data);

            // Length prefix (compact encoded)
            result.extend_from_slice(&encode_compact(body.len() as u128));
            result.extend_from_slice(&body);

            Ok(result)
        } else {
            // Return original bytes for unsigned
            Ok(self.raw_bytes.clone())
        }
    }

    /// Get transaction ID (Blake2-256 hash of signed transaction)
    pub fn id(&self) -> Option<String> {
        if self.is_signed && self.signature.is_some() {
            let bytes = self.to_bytes().ok()?;
            let hash = blake2_256(&bytes);
            Some(format!("0x{}", hex::encode(hash)))
        } else {
            None
        }
    }

    /// Get the signable payload for this transaction
    ///
    /// Note: For DOT, this requires the context (material, reference block)
    pub fn signable_payload(&self) -> Result<Vec<u8>, WasmDotError> {
        let context = self
            .context
            .as_ref()
            .ok_or_else(|| WasmDotError::MissingContext("No context set for transaction".into()))?;

        let mut payload = Vec::new();

        // Call data
        payload.extend_from_slice(&self.call_data);

        // Era
        let era_bytes = encode_era(&self.era);
        payload.extend_from_slice(&era_bytes);

        // Nonce (compact)
        payload.extend_from_slice(&encode_compact(self.nonce as u128));

        // Tip (compact)
        payload.extend_from_slice(&encode_compact(self.tip));

        // Spec version (u32 LE)
        payload.extend_from_slice(&context.material.spec_version.to_le_bytes());

        // Transaction version (u32 LE)
        payload.extend_from_slice(&context.material.tx_version.to_le_bytes());

        // Genesis hash
        let genesis_hash = parse_hex_hash(&context.material.genesis_hash)?;
        payload.extend_from_slice(&genesis_hash);

        // Block hash (reference block)
        payload.extend_from_slice(&context.reference_block);

        // If payload > 256 bytes, return Blake2-256 hash instead
        if payload.len() > 256 {
            Ok(blake2_256(&payload).to_vec())
        } else {
            Ok(payload)
        }
    }

    /// Add a signature to this transaction
    ///
    /// # Arguments
    /// * `pubkey` - 32-byte Ed25519 public key
    /// * `signature` - 64-byte Ed25519 signature
    pub fn add_signature(&mut self, pubkey: &[u8], signature: &[u8]) -> Result<(), WasmDotError> {
        if pubkey.len() != 32 {
            return Err(WasmDotError::InvalidSignature(format!(
                "Public key must be 32 bytes, got {}",
                pubkey.len()
            )));
        }
        if signature.len() != 64 {
            return Err(WasmDotError::InvalidSignature(format!(
                "Signature must be 64 bytes, got {}",
                signature.len()
            )));
        }

        let mut signer = [0u8; 32];
        signer.copy_from_slice(pubkey);
        self.signer = Some(signer);

        let mut sig = [0u8; 64];
        sig.copy_from_slice(signature);
        self.signature = Some(sig);

        self.is_signed = true;

        Ok(())
    }

    /// Get sender address (SS58 encoded)
    pub fn sender(&self, prefix: u16) -> Option<String> {
        self.signer.and_then(|pk| encode_ss58(&pk, prefix).ok())
    }

    /// Get the signature bytes
    pub fn signature_bytes(&self) -> Option<&[u8; 64]> {
        self.signature.as_ref()
    }

    /// Check if transaction is signed
    pub fn is_signed(&self) -> bool {
        self.is_signed
    }

    /// Get nonce
    pub fn nonce(&self) -> u32 {
        self.nonce
    }

    /// Get tip
    pub fn tip(&self) -> u128 {
        self.tip
    }

    /// Get era
    pub fn era(&self) -> &Era {
        &self.era
    }

    /// Get call data
    pub fn call_data(&self) -> &[u8] {
        &self.call_data
    }

    /// Set context for the transaction
    pub fn set_context(
        &mut self,
        material: Material,
        validity: Validity,
        reference_block: &str,
    ) -> Result<(), WasmDotError> {
        let block_hash = parse_hex_hash(reference_block)?;
        self.context = Some(TransactionContext {
            material,
            validity,
            reference_block: block_hash,
        });
        Ok(())
    }
}

/// Parse a raw extrinsic
fn parse_extrinsic(
    bytes: &[u8],
) -> Result<
    (
        bool,
        Option<[u8; 32]>,
        Option<[u8; 64]>,
        Era,
        u32,
        u128,
        Vec<u8>,
    ),
    WasmDotError,
> {
    let mut cursor = 0;

    // Decode length prefix (compact)
    let (length, len_size) = decode_compact(&bytes[cursor..])?;
    cursor += len_size;

    let _extrinsic_length = length as usize;

    // Version byte
    if cursor >= bytes.len() {
        return Err(WasmDotError::InvalidTransaction(
            "Missing version byte".to_string(),
        ));
    }
    let version = bytes[cursor];
    cursor += 1;

    let is_signed = (version & 0x80) != 0;
    let _extrinsic_version = version & 0x7f;

    if is_signed {
        // Parse signed extrinsic

        // Signer (MultiAddress)
        if cursor >= bytes.len() {
            return Err(WasmDotError::InvalidTransaction(
                "Missing signer".to_string(),
            ));
        }
        let address_type = bytes[cursor];
        cursor += 1;

        let signer = if address_type == 0x00 {
            // Id variant - 32 byte account id
            if cursor + 32 > bytes.len() {
                return Err(WasmDotError::InvalidTransaction(
                    "Truncated signer".to_string(),
                ));
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes[cursor..cursor + 32]);
            cursor += 32;
            Some(pk)
        } else {
            return Err(WasmDotError::InvalidTransaction(format!(
                "Unsupported address type: {}",
                address_type
            )));
        };

        // Signature (MultiSignature)
        if cursor >= bytes.len() {
            return Err(WasmDotError::InvalidTransaction(
                "Missing signature".to_string(),
            ));
        }
        let sig_type = bytes[cursor];
        cursor += 1;

        let signature = if sig_type == 0x00 {
            // Ed25519 - 64 bytes
            if cursor + 64 > bytes.len() {
                return Err(WasmDotError::InvalidTransaction(
                    "Truncated signature".to_string(),
                ));
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&bytes[cursor..cursor + 64]);
            cursor += 64;
            Some(sig)
        } else {
            return Err(WasmDotError::InvalidTransaction(format!(
                "Unsupported signature type: {}",
                sig_type
            )));
        };

        // Era
        let (era, era_size) = decode_era(&bytes[cursor..])?;
        cursor += era_size;

        // Nonce (compact)
        let (nonce, nonce_size) = decode_compact(&bytes[cursor..])?;
        cursor += nonce_size;

        // Tip (compact)
        let (tip, tip_size) = decode_compact(&bytes[cursor..])?;
        cursor += tip_size;

        // Remaining bytes are call data
        let call_data = bytes[cursor..].to_vec();

        Ok((true, signer, signature, era, nonce as u32, tip, call_data))
    } else {
        // Unsigned extrinsic - just call data
        let call_data = bytes[cursor..].to_vec();
        Ok((false, None, None, Era::Immortal, 0, 0, call_data))
    }
}

/// Decode compact encoding
fn decode_compact(bytes: &[u8]) -> Result<(u128, usize), WasmDotError> {
    if bytes.is_empty() {
        return Err(WasmDotError::ScaleDecodeError(
            "Empty compact encoding".to_string(),
        ));
    }

    let mode = bytes[0] & 0b11;
    match mode {
        0b00 => Ok(((bytes[0] >> 2) as u128, 1)),
        0b01 => {
            if bytes.len() < 2 {
                return Err(WasmDotError::ScaleDecodeError(
                    "Truncated compact".to_string(),
                ));
            }
            let value = u16::from_le_bytes([bytes[0], bytes[1]]) >> 2;
            Ok((value as u128, 2))
        }
        0b10 => {
            if bytes.len() < 4 {
                return Err(WasmDotError::ScaleDecodeError(
                    "Truncated compact".to_string(),
                ));
            }
            let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) >> 2;
            Ok((value as u128, 4))
        }
        0b11 => {
            let len = (bytes[0] >> 2) + 4;
            if bytes.len() < 1 + len as usize {
                return Err(WasmDotError::ScaleDecodeError(
                    "Truncated compact".to_string(),
                ));
            }
            let mut value = 0u128;
            for i in 0..len as usize {
                value |= (bytes[1 + i] as u128) << (8 * i);
            }
            Ok((value, 1 + len as usize))
        }
        _ => unreachable!(),
    }
}

/// Encode compact
fn encode_compact(value: u128) -> Vec<u8> {
    if value < 0x40 {
        vec![(value as u8) << 2]
    } else if value < 0x4000 {
        let v = ((value as u16) << 2) | 0b01;
        v.to_le_bytes().to_vec()
    } else if value < 0x4000_0000 {
        let v = ((value as u32) << 2) | 0b10;
        v.to_le_bytes().to_vec()
    } else {
        let bytes_needed = (128 - value.leading_zeros() + 7) / 8;
        let mut result = vec![((bytes_needed - 4) << 2 | 0b11) as u8];
        for i in 0..bytes_needed {
            result.push((value >> (8 * i)) as u8);
        }
        result
    }
}

/// Decode era
fn decode_era(bytes: &[u8]) -> Result<(Era, usize), WasmDotError> {
    if bytes.is_empty() {
        return Err(WasmDotError::ScaleDecodeError(
            "Empty era encoding".to_string(),
        ));
    }

    if bytes[0] == 0x00 {
        Ok((Era::Immortal, 1))
    } else {
        if bytes.len() < 2 {
            return Err(WasmDotError::ScaleDecodeError(
                "Truncated mortal era".to_string(),
            ));
        }
        let encoded = u16::from_le_bytes([bytes[0], bytes[1]]);
        let period = 2u32.pow((encoded.trailing_zeros() + 1).min(16));
        let quantize_factor = (period / 4).max(1);
        let phase = ((encoded >> 4) as u32) * quantize_factor;
        Ok((Era::Mortal { period, phase }, 2))
    }
}

/// Encode era
fn encode_era(era: &Era) -> Vec<u8> {
    match era {
        Era::Immortal => vec![0x00],
        Era::Mortal { period, phase } => {
            let period = (*period).next_power_of_two().max(4).min(65536);
            let period_log = period.trailing_zeros();
            let quantize_factor = (period / 4).max(1);
            let quantized_phase = phase / quantize_factor;
            let encoded = ((quantized_phase << 4) | (period_log - 1)) as u16;
            encoded.to_le_bytes().to_vec()
        }
    }
}

/// Parse hex string to 32-byte hash
fn parse_hex_hash(hex_str: &str) -> Result<[u8; 32], WasmDotError> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)
        .map_err(|e| WasmDotError::InvalidInput(format!("Invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(WasmDotError::InvalidInput(format!(
            "Hash must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

/// Blake2-256 hash
fn blake2_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_encoding_roundtrip() {
        for value in [0u128, 1, 63, 64, 16383, 16384, 1073741823, 1073741824] {
            let encoded = encode_compact(value);
            let (decoded, _) = decode_compact(&encoded).unwrap();
            assert_eq!(decoded, value, "Failed for value {}", value);
        }
    }

    #[test]
    fn test_era_encoding_roundtrip() {
        let immortal = Era::Immortal;
        let immortal_bytes = encode_era(&immortal);
        let (decoded, _) = decode_era(&immortal_bytes).unwrap();
        assert!(decoded.is_immortal());

        let mortal = Era::Mortal {
            period: 64,
            phase: 0,
        };
        let mortal_bytes = encode_era(&mortal);
        let (decoded, _) = decode_era(&mortal_bytes).unwrap();
        assert!(!decoded.is_immortal());
    }
}
