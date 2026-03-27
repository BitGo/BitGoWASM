use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use tlb_ton::{
    message::{CommonMsgInfo, Message},
    ser::CellSerializeExt,
    BagOfCells, BagOfCellsArgs,
};
use ton_contracts::wallet::v4r2::{WalletV4R2ExternalBody, WalletV4R2SignBody};

use crate::error::WasmTonError;

/// A TON transaction (external message BOC).
#[derive(Debug, Clone)]
pub struct Transaction {
    /// The raw BOC bytes
    boc_bytes: Vec<u8>,
    /// The parsed external message
    pub message: Message<WalletV4R2ExternalBody>,
}

const BOC_ARGS: BagOfCellsArgs = BagOfCellsArgs {
    has_idx: false,
    has_crc32c: true,
};

impl Transaction {
    /// Deserialize a transaction from raw BOC bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WasmTonError> {
        let boc = BagOfCells::deserialize(bytes)
            .map_err(|e| WasmTonError::new(&format!("failed to parse BOC: {e}")))?;
        let root = boc
            .single_root()
            .ok_or_else(|| WasmTonError::new("BOC must have exactly one root cell"))?;
        let message: Message<WalletV4R2ExternalBody> = root
            .parse_fully(())
            .map_err(|e| WasmTonError::new(&format!("failed to parse message: {e}")))?;
        Ok(Transaction {
            boc_bytes: bytes.to_vec(),
            message,
        })
    }

    /// Deserialize a transaction from base64-encoded BOC.
    pub fn from_base64(b64: &str) -> Result<Self, WasmTonError> {
        let bytes = STANDARD
            .decode(b64)
            .map_err(|e| WasmTonError::new(&format!("invalid base64: {e}")))?;
        Self::from_bytes(&bytes)
    }

    /// Get the signable payload (SHA-256 hash of the SignBody cell).
    /// This is what gets signed by Ed25519.
    pub fn signable_payload(&self) -> Result<Vec<u8>, WasmTonError> {
        let sign_body = &self.message.body.body;
        let cell = sign_body
            .to_cell(())
            .map_err(|e| WasmTonError::new(&format!("failed to serialize sign body: {e}")))?;
        let hash = cell.hash();
        Ok(hash.to_vec())
    }

    /// Get the sign body for inspection.
    pub fn sign_body(&self) -> &WalletV4R2SignBody {
        &self.message.body.body
    }

    /// Get the current signature.
    pub fn signature(&self) -> &[u8; 64] {
        &self.message.body.signature
    }

    /// Get the destination address from the external message.
    pub fn destination(&self) -> Option<String> {
        match &self.message.info {
            CommonMsgInfo::ExternalIn(info) => {
                if info.dst.is_null() {
                    None
                } else {
                    Some(info.dst.to_base64_url())
                }
            }
            _ => None,
        }
    }

    /// Add a signature to this transaction, producing new BOC bytes.
    pub fn add_signature(&mut self, signature: &[u8]) -> Result<(), WasmTonError> {
        if signature.len() != 64 {
            return Err(WasmTonError::new("signature must be 64 bytes"));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(signature);
        self.message.body.signature = sig;
        // Re-serialize
        self.boc_bytes = self.serialize_boc()?;
        Ok(())
    }

    /// Serialize the transaction to BOC bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WasmTonError> {
        Ok(self.boc_bytes.clone())
    }

    /// Serialize to base64 for broadcast.
    pub fn to_broadcast_format(&self) -> Result<String, WasmTonError> {
        Ok(STANDARD.encode(&self.boc_bytes))
    }

    /// Get the transaction ID (SHA-256 hash of the BOC, base64url encoded).
    pub fn id(&self) -> String {
        let hash = Sha256::digest(&self.boc_bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
    }

    fn serialize_boc(&self) -> Result<Vec<u8>, WasmTonError> {
        let cell = self
            .message
            .to_cell(())
            .map_err(|e| WasmTonError::new(&format!("failed to serialize message: {e}")))?;
        let boc = BagOfCells::from_root(cell);
        boc.serialize(BOC_ARGS)
            .map_err(|e| WasmTonError::new(&format!("failed to serialize BOC: {e}")))
    }
}
