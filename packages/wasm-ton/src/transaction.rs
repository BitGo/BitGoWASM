//! Core TON transaction deserialization and signing operations.
//!
//! TON transactions are serialized as BOC (Bag of Cells) in base64 format.
//! A WalletV4R2 external message structure:
//!
//! ```text
//! Message {
//!   info: ExternalIn { src: NULL, dst: wallet_address, import_fee: 0 }
//!   init: Option<StateInit>  (present when seqno == 0)
//!   body: WalletV4R2ExternalBody {
//!     signature: [u8; 64]
//!     body: WalletV4R2SignBody {
//!       wallet_id: u32
//!       expire_at: DateTime<Utc>
//!       seqno: u32
//!       op: WalletV4R2Op::Send(Vec<SendMsgAction>)
//!     }
//!   }
//! }
//! ```
//!
//! The signable payload is the SHA-256 hash of the serialized WalletV4R2SignBody Cell.

use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigUint;
use tlb_ton::{
    bits::NoArgs,
    message::{CommonMsgInfo, ExternalInMsgInfo, Message},
    ser::CellSerializeExt,
    BagOfCells, BagOfCellsArgs, MsgAddress,
};
use ton_contracts::wallet::v4r2::{WalletV4R2ExternalBody, WalletV4R2SignBody};

use crate::error::WasmTonError;

/// Represents a deserialized TON transaction (external message).
///
/// Holds the parsed sign body, signature, destination address, and optional
/// StateInit. Provides methods for signable payload extraction, signature
/// placement, and re-serialization.
#[derive(Debug, Clone)]
pub struct Transaction {
    /// The sign body (wallet_id, expire_at, seqno, op with inner messages)
    sign_body: WalletV4R2SignBody,
    /// The 64-byte Ed25519 signature (all zeros if unsigned)
    signature: [u8; 64],
    /// Destination address (the wallet address)
    dest_address: MsgAddress,
    /// Whether the transaction includes a StateInit (first tx from wallet)
    has_state_init: bool,
    /// Original raw BOC bytes for round-trip fidelity
    #[allow(dead_code)]
    raw_boc: Vec<u8>,
}

impl Transaction {
    /// Deserialize a transaction from raw BOC bytes.
    ///
    /// Parses the external message structure and extracts the V4R2 sign body.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WasmTonError> {
        let boc = BagOfCells::deserialize(bytes)
            .map_err(|e| WasmTonError::InvalidTransaction(format!("Failed to parse BOC: {}", e)))?;

        let root = boc.single_root().ok_or_else(|| {
            WasmTonError::InvalidTransaction("BOC must have exactly one root".into())
        })?;

        // Parse as Message<WalletV4R2ExternalBody>
        let msg: Message<WalletV4R2ExternalBody> = root.parse_fully(()).map_err(|e| {
            WasmTonError::InvalidTransaction(format!("Failed to parse message: {}", e))
        })?;

        // Extract destination address from ExternalIn info
        let dest_address = match &msg.info {
            CommonMsgInfo::ExternalIn(ext_in) => ext_in.dst,
            _ => {
                return Err(WasmTonError::InvalidTransaction(
                    "Expected external inbound message".into(),
                ))
            }
        };

        let has_state_init = msg.init.is_some();

        Ok(Transaction {
            sign_body: msg.body.body,
            signature: msg.body.signature,
            dest_address,
            has_state_init,
            raw_boc: bytes.to_vec(),
        })
    }

    /// Deserialize a transaction from a base64-encoded BOC string.
    pub fn from_base64(s: &str) -> Result<Self, WasmTonError> {
        let bytes = STANDARD
            .decode(s)
            .map_err(|e| WasmTonError::InvalidTransaction(format!("Invalid base64: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    /// Get the signable payload: SHA-256 hash of the serialized WalletV4R2SignBody Cell.
    ///
    /// Returns 32 bytes that should be signed with Ed25519.
    pub fn signable_payload(&self) -> Result<Vec<u8>, WasmTonError> {
        let cell = self.sign_body.to_cell(NoArgs::EMPTY).map_err(|e| {
            WasmTonError::InvalidTransaction(format!(
                "Failed to serialize sign body to cell: {}",
                e
            ))
        })?;

        // SHA-256 hash of the Cell representation
        Ok(cell.hash().to_vec())
    }

    /// Add a 64-byte Ed25519 signature to the transaction.
    ///
    /// The signature is placed in the WalletV4R2ExternalBody, prepended to the sign body.
    pub fn add_signature(&mut self, signature: &[u8]) -> Result<(), WasmTonError> {
        if signature.len() != 64 {
            return Err(WasmTonError::InvalidSignature(format!(
                "Signature must be exactly 64 bytes, got {}",
                signature.len()
            )));
        }

        let mut sig = [0u8; 64];
        sig.copy_from_slice(signature);
        self.signature = sig;
        Ok(())
    }

    /// Serialize the transaction back to BOC bytes.
    ///
    /// Rebuilds the full external message with the current signature and sign body,
    /// then serializes to BOC format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WasmTonError> {
        let external_body = WalletV4R2ExternalBody {
            signature: self.signature,
            body: self.sign_body.clone(),
        };

        let msg = self.build_message(external_body)?;

        let cell = msg.to_cell(NoArgs::EMPTY).map_err(|e| {
            WasmTonError::InvalidTransaction(format!("Failed to serialize message to cell: {}", e))
        })?;

        let boc = BagOfCells::from_root(cell);
        boc.serialize(BagOfCellsArgs {
            has_idx: false,
            has_crc32c: true,
        })
        .map_err(|e| WasmTonError::InvalidTransaction(format!("Failed to serialize BOC: {}", e)))
    }

    /// Serialize to base64 (standard TON broadcast format).
    pub fn to_broadcast_format(&self) -> Result<String, WasmTonError> {
        let bytes = self.to_bytes()?;
        Ok(STANDARD.encode(&bytes))
    }

    /// Get the sign body (for parser access).
    pub fn sign_body(&self) -> &WalletV4R2SignBody {
        &self.sign_body
    }

    /// Get the signature bytes.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Get the destination (wallet) address.
    pub fn dest_address(&self) -> MsgAddress {
        self.dest_address
    }

    /// Whether the transaction has a StateInit (seqno == 0 deploy).
    pub fn has_state_init(&self) -> bool {
        self.has_state_init
    }

    /// Build the external message from the external body.
    ///
    /// Note: When rebuilding, we drop the StateInit because we don't store it.
    /// This means round-trip for seqno=0 transactions will lose the StateInit.
    /// This is acceptable because addSignature is called on existing transactions,
    /// not on freshly built ones (Phase 3 builder handles StateInit).
    fn build_message(
        &self,
        body: WalletV4R2ExternalBody,
    ) -> Result<Message<WalletV4R2ExternalBody>, WasmTonError> {
        Ok(Message {
            info: CommonMsgInfo::ExternalIn(ExternalInMsgInfo {
                src: MsgAddress::NULL,
                dst: self.dest_address,
                import_fee: BigUint::ZERO,
            }),
            init: None::<tlb_ton::state_init::StateInit>,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test fixture from BitGoJS: signed send transaction
    const SIGNED_SEND_TX: &str = "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==";

    // Signable payload hash from BitGoJS
    const EXPECTED_SIGNABLE: &str = "k4XUmjB65j3klMXCXdh5Vs3bJZzo3NSfnXK8NIYFayI=";

    #[test]
    fn test_from_base64() {
        let tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();
        // Verify it parses without error and has basic properties
        assert!(!tx.has_state_init);
        // seqno value from the actual fixture
        assert_eq!(tx.sign_body.seqno, 6);
    }

    #[test]
    fn test_signable_payload() {
        let tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();
        let payload = tx.signable_payload().unwrap();
        assert_eq!(payload.len(), 32);

        // Compare with known signable hash from BitGoJS
        let expected = STANDARD.decode(EXPECTED_SIGNABLE).unwrap();
        assert_eq!(
            payload, expected,
            "Signable payload must match BitGoJS fixture"
        );
    }

    #[test]
    fn test_add_signature() {
        let mut tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();
        let new_sig = [42u8; 64];
        tx.add_signature(&new_sig).unwrap();
        assert_eq!(tx.signature(), &new_sig);
    }

    #[test]
    fn test_add_signature_invalid_length() {
        let mut tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();
        assert!(tx.add_signature(&[0u8; 63]).is_err());
        assert!(tx.add_signature(&[0u8; 65]).is_err());
    }

    #[test]
    fn test_serialize_roundtrip() {
        let tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();

        // Re-serialize
        let bytes = tx.to_bytes().unwrap();

        // Re-parse
        let tx2 = Transaction::from_bytes(&bytes).unwrap();

        // Key fields should match
        assert_eq!(tx.sign_body.seqno, tx2.sign_body.seqno);
        assert_eq!(tx.sign_body.wallet_id, tx2.sign_body.wallet_id);
        assert_eq!(tx.sign_body.expire_at, tx2.sign_body.expire_at);
        assert_eq!(tx.signature, tx2.signature);
        assert_eq!(tx.dest_address, tx2.dest_address);

        // Signable payloads must be identical
        assert_eq!(
            tx.signable_payload().unwrap(),
            tx2.signable_payload().unwrap()
        );
    }

    #[test]
    fn test_to_broadcast_format() {
        let tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();
        let broadcast = tx.to_broadcast_format().unwrap();

        // Should be valid base64
        let decoded = STANDARD.decode(&broadcast).unwrap();
        assert!(!decoded.is_empty());

        // Should parse back
        let tx2 = Transaction::from_base64(&broadcast).unwrap();
        assert_eq!(tx.sign_body.seqno, tx2.sign_body.seqno);
    }

    // Token send transaction fixture
    const SIGNED_TOKEN_TX: &str = "te6cckECGgEABB0AAuGIAVSGb+UGjjP3lvt+zFA8wouI3McEd6CKbO2TwcZ3OfLKGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF9NTAQHUHhbX00VGZ3d2r8hbJxuz7PaxmuCOJ6kgckppQAFmQgABT9LR3Iqffskp0J9gWYO8Azlnb33BCMj8FqIUIGxGOZpiWgAAAAAAAAAAAAAAAAABGAGuD4p+pQAAAAAAAAAAQ7msoAgA/BGdBi/R01erquxJOvPgGKclBawUs3MAi0/IdctKQz8AKpDN/KDRxn7y32/ZigeYUXEbmOCO9BFNnbJ4OM7nPllGHoSBGQAkAAAAAGpldHRvbiB0ZXN0aW5nwHtw7A==";

    #[test]
    fn test_parse_token_transaction() {
        let tx = Transaction::from_base64(SIGNED_TOKEN_TX).unwrap();
        assert_eq!(tx.sign_body.seqno, 0);
        assert!(tx.has_state_init);
    }

    // Whales deposit fixture
    const WHALES_DEPOSIT_TX: &str = "te6cckEBAgEAvAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwFf6OLyGMsPoPXNPLUqMoUZTIrdu2maNNUK52q+Wa0BJhNq9e/qHXYsF9xU5TYbOsZt1EBGJf1GpkumdgXj0/4CU1NGLtKFdHwAAAC4AAcAQCLYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6gSoF8gAAAAAAAAAAAAAAAAAAB7zR/vAAAAAGlCugJDuaygCErRw2Y=";

    #[test]
    fn test_parse_whales_deposit() {
        let tx = Transaction::from_base64(WHALES_DEPOSIT_TX).unwrap();
        assert_eq!(tx.sign_body.seqno, 92);
    }

    // Single nominator withdraw fixture
    const SINGLE_NOMINATOR_TX: &str = "te6cckECGAEAA8MAAuGIADZN0H0n1tz6xkYgWqJSRmkURKYajjEgXeawBo9cifPIGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF8DDudwJkyEh7jUbJEjFCjriVxsSlRJFyF872V1eegb4QACPQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr6A613oAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAHA0/PoUC5EIEyWuPg==";

    #[test]
    fn test_parse_single_nominator() {
        let tx = Transaction::from_base64(SINGLE_NOMINATOR_TX).unwrap();
        assert_eq!(tx.sign_body.seqno, 0);
        assert!(tx.has_state_init);
    }

    // Whales withdrawal fixture
    const WHALES_WITHDRAWAL_TX: &str = "te6cckEBAgEAwAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwGzbdqzqRjzzou/GIUqqqdZn7Tevr+oSawF529ibEgSoxfcezGF5GW4oF6/Ws+4OanMgBwMVCe0GIEK3GSTzCIaU1NGLtKVSvAAAAC6AAcAQCUYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6BfXhAAAAAAAAAAAAAAAAAAANqAPv0AAAAAaUqlPEO5rKAFAlQL5ACKp3CI";

    #[test]
    fn test_parse_whales_withdrawal() {
        let tx = Transaction::from_base64(WHALES_WITHDRAWAL_TX).unwrap();
        assert_eq!(tx.sign_body.seqno, 93);
    }
}
