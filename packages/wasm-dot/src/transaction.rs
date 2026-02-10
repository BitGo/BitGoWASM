//! Core transaction types and operations for DOT
//!
//! Uses subxt-core for signable payload and signature handling.

use crate::address::encode_ss58;
use crate::error::WasmDotError;
use crate::types::{Era, Material, ParseContext, Validity};
use alloc::vec::Vec;
use subxt_core::{
    config::{
        polkadot::{PolkadotConfig, PolkadotExtrinsicParamsBuilder},
        Config, ExtrinsicParams,
    },
    error::Error as SubxtError,
    metadata::Metadata,
    tx::{self, payload::Payload, ClientState, RuntimeVersion},
    utils::{AccountId32, Era as SubxtEra, MultiAddress, MultiSignature, H256},
};

extern crate alloc;

// =============================================================================
// Pre-encoded call payload wrapper
// =============================================================================

/// A Payload implementation that wraps pre-encoded call data bytes.
///
/// This allows us to use subxt-core's transaction building infrastructure
/// with call data that was already SCALE encoded.
struct PreEncodedPayload(Vec<u8>);

impl Payload for PreEncodedPayload {
    fn encode_call_data_to(
        &self,
        _metadata: &Metadata,
        out: &mut Vec<u8>,
    ) -> Result<(), SubxtError> {
        // Just copy the pre-encoded bytes directly
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

/// Represents a DOT transaction (extrinsic)
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Raw transaction bytes (for parsing existing transactions)
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
    /// Context for operations (material, validity, reference block)
    context: Option<TransactionContext>,
}

/// Transaction context containing chain info
#[derive(Debug, Clone)]
pub struct TransactionContext {
    pub material: Material,
    pub validity: Validity,
    pub reference_block: [u8; 32],
    /// Decoded metadata (cached for performance)
    metadata: Option<Metadata>,
}

impl TransactionContext {
    /// Get or decode metadata
    fn get_metadata(&self) -> Result<Metadata, WasmDotError> {
        if let Some(ref m) = self.metadata {
            return Ok(m.clone());
        }
        decode_metadata(&self.material.metadata)
    }

    /// Create ClientState for subxt-core
    fn to_client_state(&self) -> Result<ClientState<PolkadotConfig>, WasmDotError> {
        let metadata = self.get_metadata()?;
        let genesis_hash = parse_hex_hash(&self.material.genesis_hash)?;

        Ok(ClientState {
            metadata,
            genesis_hash: H256::from(genesis_hash),
            runtime_version: RuntimeVersion {
                spec_version: self.material.spec_version,
                transaction_version: self.material.tx_version,
            },
        })
    }

    /// Create extrinsic params using subxt-core builder
    ///
    /// Returns the params type expected by `tx::create_partial_signed`.
    fn to_extrinsic_params(
        &self,
        nonce: u32,
        tip: u128,
    ) -> <<PolkadotConfig as Config>::ExtrinsicParams as ExtrinsicParams<PolkadotConfig>>::Params
    {
        let builder = PolkadotExtrinsicParamsBuilder::<PolkadotConfig>::new()
            .nonce(nonce as u64)
            .tip(tip);

        // Set mortality - default is immortal if max_duration is 0
        if self.validity.max_duration == 0 {
            // Immortal - just build with defaults (no mortal call)
            builder.build()
        } else {
            // Mortal transaction
            // mortal_unchecked(from_block_number, from_block_hash, for_n_blocks)
            builder
                .mortal_unchecked(
                    self.validity.first_valid as u64,
                    H256::from(self.reference_block),
                    self.validity.max_duration as u64,
                )
                .build()
        }
    }
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
            metadata: None,
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
    ///
    /// Uses subxt-core's `sign_with_address_and_signature` for signed transactions.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WasmDotError> {
        if let (Some(signer), Some(signature)) = (self.signer, self.signature) {
            // Use subxt-core to create signed extrinsic if we have context
            if let Some(ref ctx) = self.context {
                let client_state = ctx.to_client_state()?;
                let params = ctx.to_extrinsic_params(self.nonce, self.tip);

                // Create payload from pre-encoded call data
                let call = PreEncodedPayload(self.call_data.clone());

                // Create partial transaction using subxt-core
                let partial = tx::create_partial_signed(&call, &client_state, params)
                    .map_err(|e| WasmDotError::InvalidTransaction(e.to_string()))?;

                // Create account ID and signature
                let account_id = AccountId32::from(signer);
                let address = MultiAddress::<AccountId32, ()>::Id(account_id);

                // Wrap signature as Ed25519
                let multi_sig = MultiSignature::Ed25519(signature);

                // Use subxt-core to create the final signed extrinsic
                let signed_tx = partial.sign_with_address_and_signature(&address, &multi_sig);
                return Ok(signed_tx.into_encoded());
            }

            // Fall back to manual serialization if no context
            self.to_bytes_manual()
        } else {
            // Unsigned: rebuild from current fields (nonce/tip/era may have been mutated)
            self.rebuild_unsigned_bytes()
        }
    }

    /// Manual serialization (fallback when context unavailable)
    fn to_bytes_manual(&self) -> Result<Vec<u8>, WasmDotError> {
        use parity_scale_codec::{Compact, Encode};

        let (signer, signature) = match (self.signer, self.signature) {
            (Some(s), Some(sig)) => (s, sig),
            _ => return Ok(self.raw_bytes.clone()),
        };

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
        Compact(self.nonce).encode_to(&mut body);

        // Tip (compact)
        Compact(self.tip).encode_to(&mut body);

        // Call data
        body.extend_from_slice(&self.call_data);

        // Length prefix (compact encoded)
        Compact(body.len() as u32).encode_to(&mut result);
        result.extend_from_slice(&body);

        Ok(result)
    }

    /// Rebuild unsigned bytes from current field values
    fn rebuild_unsigned_bytes(&self) -> Result<Vec<u8>, WasmDotError> {
        use parity_scale_codec::{Compact, Encode};

        let mut body = Vec::new();
        body.push(0x04); // unsigned, version 4

        let era_bytes = encode_era(&self.era);
        body.extend_from_slice(&era_bytes);

        Compact(self.nonce).encode_to(&mut body);
        Compact(self.tip).encode_to(&mut body);
        body.extend_from_slice(&self.call_data);

        let mut result = Compact(body.len() as u32).encode();
        result.extend_from_slice(&body);
        Ok(result)
    }

    /// Get transaction ID (Blake2-256 hash of signed transaction)
    pub fn id(&self) -> Option<String> {
        use blake2::{digest::consts::U32, Blake2b, Digest};

        if self.is_signed && self.signature.is_some() {
            let bytes = self.to_bytes().ok()?;
            let mut hasher = Blake2b::<U32>::new();
            hasher.update(&bytes);
            let hash = hasher.finalize();
            Some(format!("0x{}", hex::encode(hash)))
        } else {
            None
        }
    }

    /// Get the signable payload for this transaction
    ///
    /// Uses subxt-core's `PartialTransaction::signer_payload()` for correct construction.
    /// This creates the bytes that must be signed to produce a valid signature.
    pub fn signable_payload(&self) -> Result<Vec<u8>, WasmDotError> {
        let context = self
            .context
            .as_ref()
            .ok_or_else(|| WasmDotError::MissingContext("No context set for transaction".into()))?;

        let client_state = context.to_client_state()?;
        let params = context.to_extrinsic_params(self.nonce, self.tip);

        // Create payload from pre-encoded call data
        let call = PreEncodedPayload(self.call_data.clone());

        // Create partial transaction using subxt-core
        let partial = tx::create_partial_signed(&call, &client_state, params)
            .map_err(|e| WasmDotError::InvalidTransaction(e.to_string()))?;

        // Get the signer payload - this is what needs to be signed
        // subxt-core handles the > 256 byte hashing automatically
        Ok(partial.signer_payload())
    }

    /// Add a signature to this transaction
    ///
    /// Uses subxt-core's sign_with_address_and_signature for correct construction.
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
            metadata: None,
        });
        Ok(())
    }

    /// Set nonce
    pub fn set_nonce(&mut self, nonce: u32) {
        self.nonce = nonce;
    }

    /// Set tip
    pub fn set_tip(&mut self, tip: u128) {
        self.tip = tip;
    }

    /// Set era
    pub fn set_era(&mut self, era: Era) {
        self.era = era;
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Decode metadata from hex string
fn decode_metadata(metadata_hex: &str) -> Result<Metadata, WasmDotError> {
    let bytes = hex::decode(metadata_hex.trim_start_matches("0x"))
        .map_err(|e| WasmDotError::InvalidInput(format!("Invalid metadata hex: {}", e)))?;

    subxt_core::metadata::decode_from(&bytes[..])
        .map_err(|e| WasmDotError::InvalidInput(format!("Failed to decode metadata: {}", e)))
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

/// Encode era using subxt-core's Era type
pub(crate) fn encode_era(era: &Era) -> Vec<u8> {
    use parity_scale_codec::Encode;

    match era {
        Era::Immortal => SubxtEra::Immortal.encode(),
        Era::Mortal { period, phase } => {
            let period = (*period).next_power_of_two().clamp(4, 65536) as u64;
            let phase = (*phase as u64) % period;
            SubxtEra::Mortal { period, phase }.encode()
        }
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
    use parity_scale_codec::{Compact, Decode};

    let mut cursor = 0;

    // Decode length prefix (compact)
    let mut input = &bytes[cursor..];
    let length = <Compact<u32>>::decode(&mut input)
        .map_err(|e| WasmDotError::InvalidTransaction(format!("Invalid length: {}", e)))?;
    cursor = bytes.len() - input.len();

    let _extrinsic_length = length.0 as usize;

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
        let (era, era_size) = decode_era_bytes(&bytes[cursor..])?;
        cursor += era_size;

        // Nonce (compact)
        let mut input = &bytes[cursor..];
        let nonce = <Compact<u32>>::decode(&mut input)
            .map_err(|e| WasmDotError::InvalidTransaction(format!("Invalid nonce: {}", e)))?;
        cursor = bytes.len() - input.len();

        // Tip (compact)
        let mut input = &bytes[cursor..];
        let tip = <Compact<u128>>::decode(&mut input)
            .map_err(|e| WasmDotError::InvalidTransaction(format!("Invalid tip: {}", e)))?;
        cursor = bytes.len() - input.len();

        // Remaining bytes are call data
        let call_data = bytes[cursor..].to_vec();

        Ok((true, signer, signature, era, nonce.0, tip.0, call_data))
    } else {
        // Unsigned extrinsic: [0x04, era, nonce_compact, tip_compact, call_data]
        // Era, nonce, and tip are included so the transaction can be fully reconstructed
        // from the serialized bytes (same layout as signed, minus signer/signature).

        // Era
        let (era, era_size) = decode_era_bytes(&bytes[cursor..])?;
        cursor += era_size;

        // Nonce (compact)
        let mut input = &bytes[cursor..];
        let nonce = <Compact<u32>>::decode(&mut input)
            .map_err(|e| WasmDotError::InvalidTransaction(format!("Invalid nonce: {}", e)))?;
        cursor = bytes.len() - input.len();

        // Tip (compact)
        let mut input = &bytes[cursor..];
        let tip = <Compact<u128>>::decode(&mut input)
            .map_err(|e| WasmDotError::InvalidTransaction(format!("Invalid tip: {}", e)))?;
        cursor = bytes.len() - input.len();

        // Remaining bytes are call data
        let call_data = bytes[cursor..].to_vec();
        Ok((false, None, None, era, nonce.0, tip.0, call_data))
    }
}

/// Decode era from bytes
fn decode_era_bytes(bytes: &[u8]) -> Result<(Era, usize), WasmDotError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_era_encoding_roundtrip() {
        let immortal = Era::Immortal;
        let immortal_bytes = encode_era(&immortal);
        let (decoded, _) = decode_era_bytes(&immortal_bytes).unwrap();
        assert!(decoded.is_immortal());

        let mortal = Era::Mortal {
            period: 64,
            phase: 0,
        };
        let mortal_bytes = encode_era(&mortal);
        let (decoded, _) = decode_era_bytes(&mortal_bytes).unwrap();
        assert!(!decoded.is_immortal());
    }
}
