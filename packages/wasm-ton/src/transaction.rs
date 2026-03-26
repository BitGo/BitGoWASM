//! Core TON transaction operations.
//!
//! TON transactions are BOC (Bag of Cells) encoded external messages.
//! The V4R2 wallet contract sends external messages with this structure:
//!
//! ```text
//! ExternalMessage {
//!   info: ExternalInMsgInfo { src: NULL, dst: wallet_address, import_fee: 0 },
//!   init: Option<StateInit>,    // only on first tx (wallet deployment)
//!   body: ExternalBody {
//!     signature: [u8; 64],      // Ed25519 signature (or zeros if unsigned)
//!     signing_body: SignBody {
//!       wallet_id: u32,
//!       expire_at: u32,
//!       seqno: u32,
//!       op: u8,                 // 0 for simple send
//!       mode: u8,
//!       internal_msg: Message,  // the actual transfer
//!     }
//!   }
//! }
//! ```
//!
//! The signable payload = SHA-256 hash of the signing_body cell.

use std::sync::Arc;

use tlb_ton::{
    message::{CommonMsgInfo, ExternalInMsgInfo, Message},
    ser::CellSerializeExt,
    BagOfCells, BagOfCellsArgs, Cell, MsgAddress,
};
use ton_contracts::wallet::v4r2::WalletV4R2ExternalBody;

use crate::error::WasmTonError;

/// Default BOC serialization args (no index, with CRC32C checksum).
const BOC_ARGS: BagOfCellsArgs = BagOfCellsArgs {
    has_idx: false,
    has_crc32c: true,
};

/// Raw external body serialization: signature(512 bits) + sign body cell inline.
struct RawExternalBody {
    signature: [u8; 64],
    sign_body: Cell,
}

impl tlb_ton::ser::CellSerialize for RawExternalBody {
    type Args = ();

    fn store(
        &self,
        builder: &mut tlb_ton::ser::CellBuilder,
        _: Self::Args,
    ) -> Result<(), tlb_ton::ser::CellBuilderError> {
        use tlb_ton::bits::ser::BitWriterExt;
        builder.pack(self.signature, ())?;
        builder.store(&self.sign_body, ())?;
        Ok(())
    }
}

/// The body of an external message, supporting both V4R2 and raw cell formats.
#[derive(Debug, Clone)]
enum ExternalBodyKind {
    /// Standard V4R2 wallet external body (signature + V4R2 sign body)
    V4R2(WalletV4R2ExternalBody),
    /// Raw cell external body for non-V4R2 wallets (e.g., V3 vesting contracts).
    /// Stores (signature, sign_body_cell) separately so we can replace the signature.
    Raw {
        signature: [u8; 64],
        sign_body_cell: Cell,
    },
}

/// A TON transaction (external message in BOC format).
///
/// Wraps a wallet external message for signing and serialization.
/// Supports both V4R2 (standard) and raw cell (vesting V3) formats.
#[derive(Debug, Clone)]
pub struct Transaction {
    /// The wallet address (destination of the external message)
    wallet_address: MsgAddress,
    /// Optional StateInit cell (for wallet deployment)
    state_init_cell: Option<Arc<Cell>>,
    /// The external body (V4R2 or raw cell)
    body_kind: ExternalBodyKind,
    /// Cached root cell for ID computation and re-serialization
    cached_root: Option<Arc<Cell>>,
}

impl Transaction {
    /// Deserialize a transaction from BOC bytes.
    pub fn from_bytes(boc_bytes: &[u8]) -> Result<Self, WasmTonError> {
        let boc = BagOfCells::deserialize(boc_bytes)
            .map_err(|e| WasmTonError::CellError(format!("Failed to parse BOC: {}", e)))?;

        let root = boc
            .into_single_root()
            .ok_or_else(|| WasmTonError::CellError("BOC must have exactly one root".into()))?;

        Self::from_root_cell(root)
    }

    /// Deserialize a transaction from base64-encoded BOC.
    pub fn from_base64(b64: &str) -> Result<Self, WasmTonError> {
        let boc = BagOfCells::parse_base64(b64)
            .map_err(|e| WasmTonError::CellError(format!("Failed to parse base64 BOC: {}", e)))?;

        let root = boc
            .into_single_root()
            .ok_or_else(|| WasmTonError::CellError("BOC must have exactly one root".into()))?;

        Self::from_root_cell(root)
    }

    /// Parse from a root cell (the external message).
    fn from_root_cell(root: Arc<Cell>) -> Result<Self, WasmTonError> {
        // Parse the root cell as a Message with the V4R2 external body
        let msg: Message<WalletV4R2ExternalBody> = root.parse_fully(()).map_err(|e| {
            WasmTonError::CellError(format!("Failed to parse external message: {}", e))
        })?;

        // Extract wallet address from ExternalIn info
        let wallet_address = match &msg.info {
            CommonMsgInfo::ExternalIn(ext_in) => ext_in.dst,
            other => {
                return Err(WasmTonError::CellError(format!(
                    "Expected ExternalIn message, got {:?}",
                    std::mem::discriminant(other)
                )));
            }
        };

        // Extract state_init: serialize it back to a Cell for storage
        let state_init_cell = msg
            .init
            .map(|si| {
                si.to_cell(()).map(Arc::new).map_err(|e| {
                    WasmTonError::CellError(format!("Failed to serialize state_init: {}", e))
                })
            })
            .transpose()?;

        Ok(Transaction {
            wallet_address,
            state_init_cell,
            body_kind: ExternalBodyKind::V4R2(msg.body),
            cached_root: Some(root),
        })
    }

    /// Deserialize a transaction from hex-encoded BOC.
    pub fn from_hex(hex_str: &str) -> Result<Self, WasmTonError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| WasmTonError::CellError(format!("Failed to decode hex: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    /// Get the signable payload (SHA-256 hash of the signing body cell).
    ///
    /// This is the 32-byte hash that gets signed with Ed25519.
    pub fn signable_payload(&self) -> Result<[u8; 32], WasmTonError> {
        let sign_body_cell = match &self.body_kind {
            ExternalBodyKind::V4R2(ext) => ext.body.to_cell(()).map_err(|e| {
                WasmTonError::CellError(format!("Failed to build sign body cell: {}", e))
            })?,
            ExternalBodyKind::Raw { sign_body_cell, .. } => sign_body_cell.clone(),
        };

        Ok(sign_body_cell.hash())
    }

    /// Add an Ed25519 signature to the transaction.
    ///
    /// Places the 64-byte signature in the external body and rebuilds the message.
    pub fn add_signature(&mut self, signature: &[u8]) -> Result<(), WasmTonError> {
        let sig: [u8; 64] = signature.try_into().map_err(|_| {
            WasmTonError::StringError(format!(
                "Signature must be 64 bytes, got {}",
                signature.len()
            ))
        })?;

        match &mut self.body_kind {
            ExternalBodyKind::V4R2(ext) => ext.signature = sig,
            ExternalBodyKind::Raw { signature: s, .. } => *s = sig,
        }
        // Invalidate cached root since we changed the signature
        self.cached_root = None;
        Ok(())
    }

    /// Get the current signature bytes.
    fn signature(&self) -> &[u8; 64] {
        match &self.body_kind {
            ExternalBodyKind::V4R2(ext) => &ext.signature,
            ExternalBodyKind::Raw { signature, .. } => signature,
        }
    }

    /// Build the external body cell (signature + signing body).
    fn build_body_cell(&self) -> Result<Cell, WasmTonError> {
        match &self.body_kind {
            ExternalBodyKind::V4R2(ext) => ext
                .to_cell(())
                .map_err(|e| WasmTonError::CellError(format!("Failed to build body cell: {}", e))),
            ExternalBodyKind::Raw {
                signature,
                sign_body_cell,
            } => {
                // Build: signature(512 bits) + sign_body_cell contents
                let raw_body = RawExternalBody {
                    signature: *signature,
                    sign_body: sign_body_cell.clone(),
                };
                raw_body.to_cell(()).map_err(|e| {
                    WasmTonError::CellError(format!("Failed to build raw body cell: {}", e))
                })
            }
        }
    }

    /// Build the root cell (external message) from current state.
    fn build_root_cell(&self) -> Result<Cell, WasmTonError> {
        let ext_in_info = ExternalInMsgInfo {
            src: MsgAddress::NULL,
            dst: self.wallet_address,
            import_fee: num_bigint::BigUint::ZERO,
        };

        let info = CommonMsgInfo::ExternalIn(ext_in_info);

        let body_cell = self.build_body_cell()?;

        // Build state_init as a Cell (if present)
        // We rebuild the message using the Message type with Cell types
        let msg: Message<Cell, Cell, Cell> = Message {
            info,
            init: self.state_init_cell.as_ref().map(|si_cell| {
                // Parse the StateInit back from the cell
                si_cell
                    .parse_fully(())
                    .expect("state_init cell should be parseable")
            }),
            body: body_cell,
        };

        msg.to_cell(())
            .map_err(|e| WasmTonError::CellError(format!("Failed to build message cell: {}", e)))
    }

    /// Get or build the root cell.
    fn root_cell(&self) -> Result<Arc<Cell>, WasmTonError> {
        if let Some(ref cached) = self.cached_root {
            return Ok(cached.clone());
        }
        Ok(Arc::new(self.build_root_cell()?))
    }

    /// Serialize the transaction to BOC bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WasmTonError> {
        let root = self.root_cell()?;
        let boc = BagOfCells::from_root(root);
        boc.serialize(BOC_ARGS)
            .map_err(|e| WasmTonError::CellError(format!("Failed to serialize BOC: {}", e)))
    }

    /// Serialize to broadcast format (base64-encoded BOC).
    ///
    /// TON nodes accept base64-encoded BOC for broadcasting.
    pub fn to_broadcast_format(&self) -> Result<String, WasmTonError> {
        let bytes = self.to_bytes()?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &bytes,
        ))
    }

    /// Get the transaction ID (hash of the external message cell).
    ///
    /// Returns None if the transaction is unsigned (all-zero signature).
    pub fn id(&self) -> Result<Option<String>, WasmTonError> {
        if self.signature().iter().all(|&b| b == 0) {
            return Ok(None);
        }

        let root = self.root_cell()?;
        let hash = root.hash();
        Ok(Some(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            hash,
        )))
    }

    /// Get the wallet address.
    pub fn wallet_address(&self) -> MsgAddress {
        self.wallet_address
    }

    /// Get a reference to the V4R2 external body.
    ///
    /// Panics if the transaction uses raw cell format (vesting).
    pub fn external_body(&self) -> &WalletV4R2ExternalBody {
        match &self.body_kind {
            ExternalBodyKind::V4R2(ext) => ext,
            ExternalBodyKind::Raw { .. } => {
                panic!("external_body() not available for raw cell transactions")
            }
        }
    }

    /// Get a reference to the V4R2 signing body.
    ///
    /// Panics if the transaction uses raw cell format (vesting).
    pub fn sign_body(&self) -> &ton_contracts::wallet::v4r2::WalletV4R2SignBody {
        match &self.body_kind {
            ExternalBodyKind::V4R2(ext) => &ext.body,
            ExternalBodyKind::Raw { .. } => {
                panic!("sign_body() not available for raw cell transactions")
            }
        }
    }

    /// Check whether this transaction uses V4R2 format.
    pub fn is_v4r2(&self) -> bool {
        matches!(&self.body_kind, ExternalBodyKind::V4R2(_))
    }

    /// Create a new Transaction from pre-built V4R2 components (used by the builder).
    pub fn from_components(
        wallet_address: MsgAddress,
        state_init_cell: Option<Arc<Cell>>,
        external_body: WalletV4R2ExternalBody,
    ) -> Result<Self, WasmTonError> {
        Ok(Transaction {
            wallet_address,
            state_init_cell,
            body_kind: ExternalBodyKind::V4R2(external_body),
            cached_root: None,
        })
    }

    /// Create a new Transaction from a raw signing body cell (used for vesting V3 contracts).
    pub fn from_raw_sign_body(
        wallet_address: MsgAddress,
        sign_body_cell: Cell,
    ) -> Result<Self, WasmTonError> {
        Ok(Transaction {
            wallet_address,
            state_init_cell: None,
            body_kind: ExternalBodyKind::Raw {
                signature: [0u8; 64],
                sign_body_cell,
            },
            cached_root: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Signed send transaction from BitGoJS sdk-coin-ton test fixtures
    const SIGNED_SEND_TX: &str = "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==";

    #[test]
    fn test_from_base64_roundtrip() {
        let tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();

        // Verify we can extract the wallet address
        let addr = tx.wallet_address();
        assert_eq!(addr.workchain_id, 0);

        // Verify the signing body
        let sign_body = tx.sign_body();
        assert_eq!(sign_body.seqno, 6);

        // Verify signable payload is 32 bytes
        let payload = tx.signable_payload().unwrap();
        assert_eq!(payload.len(), 32);

        // Verify the signature is not all zeros (it's signed)
        assert!(!tx.external_body().signature.iter().all(|&b| b == 0));

        // Verify we can get the transaction ID
        let id = tx.id().unwrap();
        assert!(id.is_some());
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, SIGNED_SEND_TX)
                .unwrap();
        let tx = Transaction::from_bytes(&bytes).unwrap();

        let re_serialized = tx.to_bytes().unwrap();

        // Roundtrip: deserialize the re-serialized bytes
        let tx2 = Transaction::from_bytes(&re_serialized).unwrap();
        assert_eq!(tx.wallet_address(), tx2.wallet_address());
        assert_eq!(tx.sign_body().seqno, tx2.sign_body().seqno);
    }

    #[test]
    fn test_signable_payload_matches_fixture() {
        // From BitGoJS: signedSendTransaction.signable
        let expected_signable_b64 = "k4XUmjB65j3klMXCXdh5Vs3bJZzo3NSfnXK8NIYFayI=";
        let expected_signable = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            expected_signable_b64,
        )
        .unwrap();

        let tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();
        let payload = tx.signable_payload().unwrap();

        assert_eq!(payload.as_slice(), expected_signable.as_slice());
    }

    #[test]
    fn test_add_signature() {
        let mut tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();

        // Replace signature with zeros
        let zero_sig = [0u8; 64];
        tx.add_signature(&zero_sig).unwrap();
        assert!(tx.external_body().signature.iter().all(|&b| b == 0));

        // ID should be None for unsigned
        assert!(tx.id().unwrap().is_none());

        // Add a fake signature back
        let fake_sig = [0xABu8; 64];
        tx.add_signature(&fake_sig).unwrap();
        assert!(tx.id().unwrap().is_some());
    }

    #[test]
    fn test_to_broadcast_format() {
        let tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();
        let broadcast = tx.to_broadcast_format().unwrap();
        // Should be valid base64
        assert!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &broadcast,).is_ok()
        );
    }

    #[test]
    fn test_invalid_signature_length() {
        let mut tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();
        assert!(tx.add_signature(&[0u8; 32]).is_err());
        assert!(tx.add_signature(&[0u8; 128]).is_err());
    }

    #[test]
    fn test_from_hex() {
        // Convert base64 to hex and verify from_hex works
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, SIGNED_SEND_TX)
                .unwrap();
        let hex_str = hex::encode(&bytes);

        let tx = Transaction::from_hex(&hex_str).unwrap();
        let sign_body = tx.sign_body();
        assert_eq!(sign_body.seqno, 6);

        // Verify signable payload matches the base64 version
        let tx_b64 = Transaction::from_base64(SIGNED_SEND_TX).unwrap();
        assert_eq!(
            tx.signable_payload().unwrap(),
            tx_b64.signable_payload().unwrap()
        );
    }

    #[test]
    fn test_from_hex_invalid() {
        assert!(Transaction::from_hex("not_valid_hex!!!").is_err());
        assert!(Transaction::from_hex("deadbeef").is_err()); // valid hex but not valid BOC
    }
}
