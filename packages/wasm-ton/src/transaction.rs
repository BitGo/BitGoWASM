//! Core TON transaction deserialization and manipulation.
//!
//! Wraps tonlib-core types for parsing BOC-encoded TON external messages.
//!
//! # Wire Format
//!
//! TON transactions are encoded as BOC (Bag of Cells). The root cell is an
//! external message containing:
//! - Header (ext_in_msg_info with src=none, dest=wallet address)
//! - Optional state_init (for first transaction from a wallet)
//! - Body cell containing:
//!   - For V3/V4: [64-byte signature][wallet_id][expire_time][seqno][send_modes + internal messages]
//!   - For V5: [prefix 0x7369676e][wallet_id][expire_time][seqno][actions][64-byte signature]
//!
//! The signable payload is the cell_hash() of the unsigned body cell (without signature).

use crate::address::WalletVersion;
use crate::error::WasmTonError;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use num_bigint::BigUint;
use num_traits::Zero;
use tonlib_core::cell::{ArcCell, BagOfCells, Cell};
use tonlib_core::tlb_types::block::coins::Grams;
use tonlib_core::tlb_types::block::message::{CommonMsgInfo, ExtInMsgInfo, Message};
use tonlib_core::tlb_types::block::msg_address::{MsgAddrNone, MsgAddressExt, MsgAddressInt};
use tonlib_core::tlb_types::block::state_init::StateInit;
use tonlib_core::tlb_types::tlb::TLB;
use tonlib_core::types::TonAddress;
use tonlib_core::wallet::version_helper::VersionHelper;
use tonlib_core::wallet::versioned::v3::WalletExtMsgBodyV3;
use tonlib_core::wallet::versioned::v4::WalletExtMsgBodyV4;
use tonlib_core::wallet::versioned::v5::WalletExtMsgBodyV5;
use tonlib_core::TonHash;

/// Parsed wallet message body (version-independent representation).
#[derive(Debug, Clone)]
pub struct WalletBody {
    pub wallet_id: i32,
    pub expire_time: u32,
    pub seqno: u32,
    pub send_modes: Vec<u8>,
    pub internal_messages: Vec<ArcCell>,
}

/// Represents a TON external message transaction.
#[derive(Debug, Clone)]
pub struct TonTransaction {
    /// Detected wallet version
    pub wallet_version: WalletVersion,
    /// Sequence number
    pub seqno: u32,
    /// Expiration time (unix timestamp)
    pub expire_time: u32,
    /// Sub-wallet ID
    pub wallet_id: i32,
    /// Send modes for each internal message
    pub send_modes: Vec<u8>,
    /// Internal messages (as cell references)
    pub internal_messages: Vec<ArcCell>,
    /// 64-byte Ed25519 signature (if signed)
    pub signature: Option<Vec<u8>>,
    /// Whether this transaction includes state_init
    pub has_state_init: bool,
    /// The destination address from the external message
    pub destination: TonAddress,
    /// The original unsigned body cell (for signable_payload)
    unsigned_body_cell: Cell,
    /// State init data (preserved for re-serialization)
    state_init: Option<StateInit>,
    /// The original root cell (preserved for ID computation)
    original_root_cell: Option<Cell>,
}

impl TonTransaction {
    /// Deserialize a transaction from BOC bytes.
    pub fn from_boc(bytes: &[u8]) -> Result<Self, WasmTonError> {
        let boc = BagOfCells::parse(bytes)?;
        let root = boc.single_root()?;
        Self::from_cell(&root)
    }

    /// Deserialize a transaction from base64-encoded BOC.
    pub fn from_base64(b64: &str) -> Result<Self, WasmTonError> {
        let bytes = STANDARD
            .decode(b64)
            .map_err(|e| WasmTonError::StringError(format!("Invalid base64: {}", e)))?;
        Self::from_boc(&bytes)
    }

    /// Parse from a root cell (external message).
    fn from_cell(root: &ArcCell) -> Result<Self, WasmTonError> {
        // Preserve the original root cell for ID computation.
        // Re-serialization can produce different BOC bytes (e.g. EitherRef
        // encoding differences for state_init), so we keep the original.
        let original_root_cell = root.as_ref().clone();

        // Parse the external message using TLB
        let message = Message::from_cell(root)?;

        // Extract destination address from ext_in_msg_info
        let destination = match &message.info {
            CommonMsgInfo::ExtIn(ext_in) => msg_address_int_to_ton_address(&ext_in.dest)?,
            _ => {
                return Err(WasmTonError::StringError(
                    "Expected external incoming message".to_string(),
                ))
            }
        };

        // Check for state_init
        let has_state_init = message.init.is_some();
        let state_init = message.init.as_ref().map(|ei| ei.value.clone());

        // Get the body cell
        let body_cell = &message.body.value;

        // Try to detect wallet version and parse the body
        let mut tx = Self::parse_body(body_cell, destination, has_state_init, state_init)?;
        tx.original_root_cell = Some(original_root_cell);
        Ok(tx)
    }

    /// Parse the body cell, detecting wallet version.
    fn parse_body(
        body_cell: &ArcCell,
        destination: TonAddress,
        has_state_init: bool,
        state_init: Option<StateInit>,
    ) -> Result<Self, WasmTonError> {
        // The body cell contains [signature][body] for V3/V4, or [body][signature] for V5.
        // We need to detect the version. Strategy:
        // 1. Check if V5 (starts with 0x7369676e prefix after removing signature)
        // 2. Otherwise assume V3/V4 (signature first, then body)

        let bit_len = body_cell.bit_len();

        // Try V5 first: body starts with 0x7369676e prefix, signature at end
        if let Ok(result) = Self::try_parse_v5(body_cell, &destination, has_state_init, &state_init)
        {
            return Ok(result);
        }

        // V3/V4: [64-byte signature][body cell data]
        // Signature is 512 bits, so body must be > 512 bits
        if bit_len <= 512 {
            return Err(WasmTonError::StringError(
                "Body cell too short for wallet message".to_string(),
            ));
        }

        let mut parser = body_cell.parser();

        // Extract signature (first 512 bits = 64 bytes)
        let signature = parser.load_bytes(64)?;
        let has_signature = !signature.iter().all(|&b| b == 0);

        // Remaining data is the unsigned body cell
        let unsigned_body_cell = Cell::read(&mut parser)?;

        // Now distinguish V3 vs V4 by trying to parse both.
        // V4 has an opcode field (8 bits) after subwallet_id + valid_until + seqno.
        // V3 does not have opcode.
        // We try V4 first since it's the BitGo default.
        if let Ok(body) = WalletExtMsgBodyV4::from_cell(&unsigned_body_cell) {
            return Ok(TonTransaction {
                wallet_version: WalletVersion::V4R2,
                seqno: body.msg_seqno,
                expire_time: body.valid_until,
                wallet_id: body.subwallet_id,
                send_modes: body.msgs_modes,
                internal_messages: body.msgs,
                signature: if has_signature { Some(signature) } else { None },
                has_state_init,
                destination,
                unsigned_body_cell,
                state_init,
                original_root_cell: None,
            });
        }

        // Try V3
        if let Ok(body) = WalletExtMsgBodyV3::from_cell(&unsigned_body_cell) {
            return Ok(TonTransaction {
                wallet_version: WalletVersion::V3R2,
                seqno: body.msg_seqno,
                expire_time: body.valid_until,
                wallet_id: body.subwallet_id,
                send_modes: body.msgs_modes,
                internal_messages: body.msgs,
                signature: if has_signature { Some(signature) } else { None },
                has_state_init,
                destination,
                unsigned_body_cell,
                state_init,
                original_root_cell: None,
            });
        }

        Err(WasmTonError::StringError(
            "Failed to parse wallet message body (tried V3, V4, V5)".to_string(),
        ))
    }

    /// Try to parse as V5R1 wallet message.
    fn try_parse_v5(
        body_cell: &ArcCell,
        destination: &TonAddress,
        has_state_init: bool,
        state_init: &Option<StateInit>,
    ) -> Result<Self, WasmTonError> {
        let bit_len = body_cell.bit_len();
        if bit_len < 512 {
            return Err(WasmTonError::StringError("Too short for V5".to_string()));
        }

        // V5: [prefix 0x7369676e (32 bits)][wallet_id][expire_time][seqno][actions]...[64-byte signature]
        // The body and signature are stored as: body data + signature at end of bits
        let mut parser = body_cell.parser();

        // Read the WalletExtMsgBodyV5 which handles the prefix check
        let body = WalletExtMsgBodyV5::read(&mut parser)
            .map_err(|e| WasmTonError::StringError(e.to_string()))?;

        // Read remaining 64 bytes as signature
        let signature = parser
            .load_bytes(64)
            .map_err(|e| WasmTonError::StringError(e.to_string()))?;
        let has_signature = !signature.iter().all(|&b| b == 0);

        // Reconstruct the unsigned body cell
        let unsigned_body_cell = body.to_cell()?;

        Ok(TonTransaction {
            wallet_version: WalletVersion::V5R1,
            seqno: body.msg_seqno,
            expire_time: body.valid_until,
            wallet_id: body.wallet_id,
            send_modes: body.msgs_modes,
            internal_messages: body.msgs,
            signature: if has_signature { Some(signature) } else { None },
            has_state_init,
            destination: destination.clone(),
            unsigned_body_cell,
            state_init: state_init.clone(),
            original_root_cell: None,
        })
    }

    /// Get the signable payload (cell_hash of the unsigned body cell).
    /// This is what needs to be signed by Ed25519.
    pub fn signable_payload(&self) -> [u8; 32] {
        let hash: TonHash = self.unsigned_body_cell.cell_hash();
        let bytes: &[u8] = hash.as_slice();
        let mut result = [0u8; 32];
        result.copy_from_slice(bytes);
        result
    }

    /// Add a signature to the transaction.
    /// Uses VersionHelper::sign_msg() to place the signature correctly based on wallet version.
    pub fn add_signature(&mut self, signature: &[u8]) -> Result<(), WasmTonError> {
        if signature.len() != 64 {
            return Err(WasmTonError::StringError(format!(
                "Signature must be 64 bytes, got {}",
                signature.len()
            )));
        }
        self.signature = Some(signature.to_vec());
        Ok(())
    }

    /// Serialize the transaction back to BOC bytes.
    pub fn to_boc(&self) -> Result<Vec<u8>, WasmTonError> {
        let cell = self.to_cell()?;
        let boc = BagOfCells::from_root(cell);
        Ok(boc.serialize(true)?)
    }

    /// Serialize to base64-encoded BOC (TON's broadcast format).
    pub fn to_base64(&self) -> Result<String, WasmTonError> {
        let bytes = self.to_boc()?;
        Ok(STANDARD.encode(bytes))
    }

    /// Build the full external message cell.
    fn to_cell(&self) -> Result<Cell, WasmTonError> {
        let tonlib_version = self.wallet_version.as_tonlib();

        // Build the signed body cell
        let signed_body = if let Some(ref sig) = self.signature {
            VersionHelper::sign_msg(tonlib_version, &self.unsigned_body_cell, sig)?
        } else {
            // No signature: use zeros
            let zero_sig = vec![0u8; 64];
            VersionHelper::sign_msg(tonlib_version, &self.unsigned_body_cell, &zero_sig)?
        };

        // Wrap in external message
        let ext_in_info = ExtInMsgInfo {
            src: MsgAddressExt::None(MsgAddrNone {}),
            dest: self.destination.to_msg_address_int(),
            import_fee: Grams::new(BigUint::zero()),
        };

        let mut message = Message::new(CommonMsgInfo::ExtIn(ext_in_info), signed_body.to_arc());

        if let Some(ref si) = self.state_init {
            message.with_state_init(si.clone());
        }

        Ok(message.to_cell()?)
    }

    /// Get the transaction ID: base64url of the final message cell hash.
    ///
    /// Uses the original root cell when available (preserving the exact
    /// encoding from the input BOC). Falls back to re-serialization via
    /// `to_cell()` for transactions built programmatically.
    pub fn id(&self) -> Option<String> {
        let cell = if let Some(ref original) = self.original_root_cell {
            original.clone()
        } else {
            match self.to_cell() {
                Ok(c) => c,
                Err(_) => return None,
            }
        };
        let hash = cell.cell_hash();
        Some(URL_SAFE.encode(hash.as_slice()))
    }
}

/// Convert MsgAddressInt to TonAddress.
fn msg_address_int_to_ton_address(addr: &MsgAddressInt) -> Result<TonAddress, WasmTonError> {
    match addr {
        MsgAddressInt::Std(std_addr) => {
            if std_addr.address.len() != 32 {
                return Err(WasmTonError::AddressError(format!(
                    "Expected 32-byte address hash, got {}",
                    std_addr.address.len()
                )));
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&std_addr.address);
            let ton_hash = TonHash::from(hash);
            Ok(TonAddress::new(std_addr.workchain, ton_hash))
        }
        MsgAddressInt::Var(_) => Err(WasmTonError::AddressError(
            "Variable-length address not supported".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BitGoJS fixture: signed send transaction (V4R2)
    const SIGNED_SEND_TX: &str = "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==";

    #[test]
    fn test_from_base64_v4r2() {
        let tx = TonTransaction::from_base64(SIGNED_SEND_TX).unwrap();
        assert_eq!(tx.wallet_version, WalletVersion::V4R2);
        assert!(tx.signature.is_some());
        assert!(tx.seqno > 0);
        assert_eq!(tx.internal_messages.len(), 1);
    }

    #[test]
    fn test_signable_payload() {
        let tx = TonTransaction::from_base64(SIGNED_SEND_TX).unwrap();
        let payload = tx.signable_payload();
        // The signable should be the base64 value from the fixture
        let expected = STANDARD
            .decode("k4XUmjB65j3klMXCXdh5Vs3bJZzo3NSfnXK8NIYFayI=")
            .unwrap();
        assert_eq!(payload.to_vec(), expected);
    }

    #[test]
    fn test_round_trip() {
        let original_bytes = STANDARD.decode(SIGNED_SEND_TX).unwrap();
        let tx = TonTransaction::from_boc(&original_bytes).unwrap();
        let reserialized = tx.to_boc().unwrap();
        // Parse both to ensure they produce the same transaction
        let tx2 = TonTransaction::from_boc(&reserialized).unwrap();
        assert_eq!(tx.seqno, tx2.seqno);
        assert_eq!(tx.expire_time, tx2.expire_time);
        assert_eq!(tx.wallet_id, tx2.wallet_id);
        assert_eq!(tx.wallet_version, tx2.wallet_version);
        assert_eq!(tx.signable_payload(), tx2.signable_payload());
    }

    #[test]
    fn test_id() {
        let tx = TonTransaction::from_base64(SIGNED_SEND_TX).unwrap();
        let id = tx.id();
        assert!(id.is_some());
        // Should match fixture: "tuyOkyFUMv_neV_FeNBH24Nd4cML2jUgDP4zjGkuOFI="
        assert_eq!(id.unwrap(), "tuyOkyFUMv_neV_FeNBH24Nd4cML2jUgDP4zjGkuOFI=");
    }

    #[test]
    fn test_add_signature() {
        let unsigned_tx_b64 = SIGNED_SEND_TX;
        let mut tx = TonTransaction::from_base64(unsigned_tx_b64).unwrap();
        let original_sig = tx.signature.clone().unwrap();

        // Add a different signature
        let new_sig = vec![42u8; 64];
        tx.add_signature(&new_sig).unwrap();
        assert_eq!(tx.signature.as_ref().unwrap(), &new_sig);

        // Restore original
        tx.add_signature(&original_sig).unwrap();
        assert_eq!(tx.signature.as_ref().unwrap(), &original_sig);
    }

    // V3R2 compatible signed send transaction (from BitGoJS fixture)
    const V3_SIGNED_TX: &str = "te6cckEBAgEAqAAB34gB6PRRbBG9U/w5zruVAiyjjtuAoJQrbKx6iNEFbGT4q1oHBW0S6HI3Mqn+qZUL6E/GLQEBfdhXuswqDfR0WMiOFLIpITCTcMwZNRZL6yKqMb7Zfzi/A8YXdkVVgxgakEPAaU1NGLtH0CDAAAAAGBwBAGZiAGcJlmF0UvErDsi5Rs21SP70rP1K36wtjBImqtbV96EuHMS0AAAAAAAAAAAAAAAAAAAiW72E";

    #[test]
    fn test_from_base64_v3r2() {
        let tx = TonTransaction::from_base64(V3_SIGNED_TX).unwrap();
        assert_eq!(tx.wallet_version, WalletVersion::V3R2);
        assert!(tx.signature.is_some());
        assert_eq!(tx.internal_messages.len(), 1);
    }

    #[test]
    fn test_v3_signable_payload() {
        let tx = TonTransaction::from_base64(V3_SIGNED_TX).unwrap();
        let payload = tx.signable_payload();
        let expected = STANDARD
            .decode("lOEOTzPXnPotTTHi7xgivFNUHH+xUgq/nKpaP/bK+Xo=")
            .unwrap();
        assert_eq!(payload.to_vec(), expected);
    }
}
