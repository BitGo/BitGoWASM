//! Core TON transaction handling.
//!
//! Wraps the toner crate types to provide deserialization from BOC,
//! signable payload extraction, signature placement, and serialization.

use std::sync::Arc;

use num_bigint::BigUint;
use tlb::{
    bits::ser::BitWriterExt,
    ser::{CellSerialize, CellSerializeExt},
    BagOfCells, BagOfCellsArgs, Cell, Ref,
};
use tlb_ton::{
    message::{CommonMsgInfo, ExternalInMsgInfo, Message},
    state_init::StateInit,
    MsgAddress,
};
use ton_contracts::wallet::v4r2::{WalletV4R2Data, WalletV4R2ExternalBody, WalletV4R2SignBody};

use crate::error::WasmTonError;

/// A parsed TON transaction wrapping the external message structure.
///
/// Holds the deserialized external message (with signature, sign body,
/// and inner transfer data) and supports re-serialization with new signatures.
#[derive(Debug, Clone)]
pub struct TonTransaction {
    /// The full external message cell (for BOC serialization)
    ext_cell: Cell,
    /// Parsed external body (signature + sign body)
    ext_body: WalletV4R2ExternalBody,
    /// Destination address from external message
    sender_addr: MsgAddress,
    /// Optional StateInit (present when seqno=0 for wallet deploy)
    state_init: Option<StateInit<Arc<Cell>, Arc<Cell>>>,
}

impl TonTransaction {
    /// Parse a transaction from base64-encoded BOC.
    pub fn from_boc(boc_base64: &str) -> Result<Self, WasmTonError> {
        let boc = BagOfCells::parse_base64(boc_base64).map_err(|e| e.to_string())?;
        let root = boc
            .single_root()
            .ok_or_else(|| WasmTonError::new("BOC must have exactly one root cell"))?;

        // Parse the external message with generic Cell bodies
        let ext_msg: Message<Cell, Arc<Cell>, Arc<Cell>> = root
            .parse_fully(())
            .map_err(|e| format!("Failed to parse external message: {e}"))?;

        // Extract sender address from external message info
        let sender_addr = match &ext_msg.info {
            CommonMsgInfo::ExternalIn(info) => info.dst.clone(),
            _ => return Err(WasmTonError::new("Expected external-in message")),
        };

        // Parse the body as V4R2 external body (signature + sign body)
        let ext_body: WalletV4R2ExternalBody = ext_msg
            .body
            .parse_fully(())
            .map_err(|e| format!("Failed to parse V4R2 external body: {e}"))?;

        // Keep the original cell for serialization
        let ext_cell = root.as_ref().clone();

        Ok(Self {
            ext_cell,
            ext_body,
            sender_addr,
            state_init: ext_msg.init,
        })
    }

    /// Get the signable payload (SHA-256 hash of the sign body cell).
    ///
    /// This is the 32-byte hash that gets signed by Ed25519.
    pub fn signable_payload(&self) -> Result<[u8; 32], WasmTonError> {
        let sign_cell = self
            .ext_body
            .body
            .to_cell(())
            .map_err(|e| format!("Failed to serialize sign body to cell: {e}"))?;
        Ok(sign_cell.hash())
    }

    /// Add a pre-computed signature to the transaction.
    ///
    /// Reconstructs the external message with the new signature placed
    /// at the correct position (first 512 bits of body).
    pub fn add_signature(
        &mut self,
        pubkey: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), WasmTonError> {
        // Update the signature in the external body
        self.ext_body.signature = *signature;

        // Rebuild the external cell with the new signature
        self.ext_cell = self.build_external_cell(pubkey)?;

        Ok(())
    }

    /// Serialize the transaction to base64 BOC (broadcast format).
    pub fn to_broadcast_format(&self) -> Result<String, WasmTonError> {
        let boc = BagOfCells::from_root(self.ext_cell.clone());
        let boc_bytes = boc
            .serialize(BagOfCellsArgs {
                has_idx: false,
                has_crc32c: true,
            })
            .map_err(|e| format!("Failed to serialize BOC: {e}"))?;
        Ok(base64_encode(&boc_bytes))
    }

    /// Serialize the transaction to raw BOC bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WasmTonError> {
        let boc = BagOfCells::from_root(self.ext_cell.clone());
        boc.serialize(BagOfCellsArgs {
            has_idx: false,
            has_crc32c: true,
        })
        .map_err(|e| format!("Failed to serialize BOC: {e}").into())
    }

    /// Get the transaction ID (base64url of the external message cell hash).
    ///
    /// Uses the TON convention: base64 with `/` replaced by `_` and `+` by `-`.
    pub fn id(&self) -> String {
        let hash = self.ext_cell.hash();
        base64url_encode(&hash)
    }

    /// Access the sign body (wallet_id, expire_at, seqno, op).
    pub fn sign_body(&self) -> &WalletV4R2SignBody {
        &self.ext_body.body
    }

    /// Access the signature bytes.
    pub fn signature(&self) -> &[u8; 64] {
        &self.ext_body.signature
    }

    /// Access the sender address.
    pub fn sender_addr(&self) -> &MsgAddress {
        &self.sender_addr
    }

    /// Extract the public key from StateInit (only available when seqno=0).
    pub fn public_key_from_state_init(&self) -> Result<Option<[u8; 32]>, WasmTonError> {
        if let Some(ref init) = self.state_init {
            if let Some(ref data_cell) = init.data {
                let data: WalletV4R2Data = data_cell
                    .parse_fully(())
                    .map_err(|e| format!("Failed to parse wallet data: {e}"))?;
                return Ok(Some(data.pubkey));
            }
        }
        Ok(None)
    }

    /// Check if the transaction has a state init (wallet deploy).
    pub fn has_state_init(&self) -> bool {
        self.state_init.is_some()
    }

    /// Build the external message cell from current state.
    fn build_external_cell(&self, _pubkey: &[u8; 32]) -> Result<Cell, WasmTonError> {
        let ext_info = CommonMsgInfo::ExternalIn(ExternalInMsgInfo {
            src: MsgAddress::NULL,
            dst: self.sender_addr.clone(),
            import_fee: BigUint::ZERO,
        });

        let mut builder = Cell::builder();
        CellSerialize::store(&ext_info, &mut builder, ())
            .map_err(|e| format!("Failed to store ext info: {e}"))?;

        if let Some(ref init) = self.state_init {
            builder
                .pack(true, ())
                .map_err(|e| format!("Failed to pack state init flag: {e}"))?;
            builder
                .pack(true, ())
                .map_err(|e| format!("Failed to pack state init ref flag: {e}"))?;
            builder
                .store_as::<_, Ref>(init, ())
                .map_err(|e| format!("Failed to store state init: {e}"))?;
        } else {
            builder
                .pack(false, ())
                .map_err(|e| format!("Failed to pack state init flag: {e}"))?;
        }

        builder
            .pack(false, ())
            .map_err(|e| format!("Failed to pack body flag: {e}"))?;
        CellSerialize::store(&self.ext_body, &mut builder, ())
            .map_err(|e| format!("Failed to store ext body: {e}"))?;

        Ok(builder.into_cell())
    }
}

/// Standard base64 encoding.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(bytes)
}

/// Base64url encoding (TON convention for tx IDs, with padding).
fn base64url_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE, Engine};
    URL_SAFE.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // BitGoJS fixture: signed send transaction (non-bounceable)
    const SIGNED_SEND_TX: &str = "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==";

    // BitGoJS fixture: signed single nominator withdraw (with state init, seqno=0)
    const SIGNED_NOMINATOR_TX: &str = "te6cckECGAEAA8MAAuGIADZN0H0n1tz6xkYgWqJSRmkURKYajjEgXeawBo9cifPIGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF8DDudwJkyEh7jUbJEjFCjriVxsSlRJFyF872V1eegb4QACPQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr6A613oAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAHA0/PoUC5EIEyWuPg==";

    // Expected values from BitGoJS fixtures
    const EXPECTED_SIGNABLE: &str = "k4XUmjB65j3klMXCXdh5Vs3bJZzo3NSfnXK8NIYFayI=";
    const EXPECTED_TX_ID: &str = "tuyOkyFUMv_neV_FeNBH24Nd4cML2jUgDP4zjGkuOFI=";
    const EXPECTED_NOMINATOR_SIGNABLE: &str = "SA4LoRhKDTiba8MKm0ECBAaiWqh2YtejttmfMzvNw14=";
    const EXPECTED_NOMINATOR_TX_ID: &str = "n1rr-QL61WZ7UJN7ESH2iPQO7toTy9WLqXoSIG1JtXg=";

    #[test]
    fn test_from_boc_send_transaction() {
        let tx = TonTransaction::from_boc(SIGNED_SEND_TX).unwrap();
        assert_eq!(tx.sign_body().seqno, 6);
        assert_eq!(tx.sign_body().wallet_id, 698983191);
    }

    #[test]
    fn test_signable_payload_matches_bitgojs() {
        let tx = TonTransaction::from_boc(SIGNED_SEND_TX).unwrap();
        let payload = tx.signable_payload().unwrap();
        let payload_b64 = base64_encode(&payload);
        assert_eq!(payload_b64, EXPECTED_SIGNABLE);
    }

    #[test]
    fn test_transaction_id() {
        let tx = TonTransaction::from_boc(SIGNED_SEND_TX).unwrap();
        assert_eq!(tx.id(), EXPECTED_TX_ID);
    }

    #[test]
    fn test_nominator_from_boc() {
        let tx = TonTransaction::from_boc(SIGNED_NOMINATOR_TX).unwrap();
        assert_eq!(tx.sign_body().seqno, 0);
        assert!(tx.has_state_init());
    }

    #[test]
    fn test_nominator_signable_payload() {
        let tx = TonTransaction::from_boc(SIGNED_NOMINATOR_TX).unwrap();
        let payload = tx.signable_payload().unwrap();
        let payload_b64 = base64_encode(&payload);
        assert_eq!(payload_b64, EXPECTED_NOMINATOR_SIGNABLE);
    }

    #[test]
    fn test_nominator_tx_id() {
        let tx = TonTransaction::from_boc(SIGNED_NOMINATOR_TX).unwrap();
        assert_eq!(tx.id(), EXPECTED_NOMINATOR_TX_ID);
    }

    #[test]
    fn test_public_key_extraction() {
        let tx = TonTransaction::from_boc(SIGNED_NOMINATOR_TX).unwrap();
        let pubkey = tx.public_key_from_state_init().unwrap();
        assert!(pubkey.is_some());
        let pubkey_hex = hex::encode(pubkey.unwrap());
        assert_eq!(
            pubkey_hex,
            "c0c3b9dc09932121ee351b2448c50a3ae2571b12951245c85f3bd95d5e7a06f8"
        );
    }

    #[test]
    fn test_broadcast_roundtrip() {
        let tx = TonTransaction::from_boc(SIGNED_SEND_TX).unwrap();
        let broadcast = tx.to_broadcast_format().unwrap();
        // Re-parse the broadcast format
        let tx2 = TonTransaction::from_boc(&broadcast).unwrap();
        assert_eq!(tx2.sign_body().seqno, tx.sign_body().seqno);
        assert_eq!(tx2.sign_body().wallet_id, tx.sign_body().wallet_id);
        assert_eq!(tx2.id(), tx.id());
    }

    // Whales deposit fixture
    const WHALES_DEPOSIT_TX: &str = "te6cckEBAgEAvAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwFf6OLyGMsPoPXNPLUqMoUZTIrdu2maNNUK52q+Wa0BJhNq9e/qHXYsF9xU5TYbOsZt1EBGJf1GpkumdgXj0/4CU1NGLtKFdHwAAAC4AAcAQCLYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6gSoF8gAAAAAAAAAAAAAAAAAAB7zR/vAAAAAGlCugJDuaygCErRw2Y=";

    #[test]
    fn test_whales_deposit_from_boc() {
        let tx = TonTransaction::from_boc(WHALES_DEPOSIT_TX).unwrap();
        assert_eq!(tx.sign_body().seqno, 92);
    }

    // Whales withdrawal fixture
    const WHALES_WITHDRAWAL_TX: &str = "te6cckEBAgEAwAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwGzbdqzqRjzzou/GIUqqqdZn7Tevr+oSawF529ibEgSoxfcezGF5GW4oF6/Ws+4OanMgBwMVCe0GIEK3GSTzCIaU1NGLtKVSvAAAAC6AAcAQCUYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6BfXhAAAAAAAAAAAAAAAAAAANqAPv0AAAAAaUqlPEO5rKAFAlQL5ACKp3CI";

    #[test]
    fn test_whales_withdrawal_from_boc() {
        let tx = TonTransaction::from_boc(WHALES_WITHDRAWAL_TX).unwrap();
        assert_eq!(tx.sign_body().seqno, 93);
    }

    // Token send fixture
    const TOKEN_SEND_TX: &str = "te6cckECGgEABB0AAuGIAVSGb+UGjjP3lvt+zFA8wouI3McEd6CKbO2TwcZ3OfLKGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF9NTAQHUHhbX00VGZ3d2r8hbJxuz7PaxmuCOJ6kgckppQAFmQgABT9LR3Iqffskp0J9gWYO8Azlnb33BCMj8FqIUIGxGOZpiWgAAAAAAAAAAAAAAAAABGAGuD4p+pQAAAAAAAAAAQ7msoAgA/BGdBi/R01erquxJOvPgGKclBawUs3MAi0/IdctKQz8AKpDN/KDRxn7y32/ZigeYUXEbmOCO9BFNnbJ4OM7nPllGHoSBGQAkAAAAAGpldHRvbiB0ZXN0aW5nwHtw7A==";

    #[test]
    fn test_token_send_from_boc() {
        let tx = TonTransaction::from_boc(TOKEN_SEND_TX).unwrap();
        assert_eq!(tx.sign_body().seqno, 0);
        assert!(tx.has_state_init());
    }
}
