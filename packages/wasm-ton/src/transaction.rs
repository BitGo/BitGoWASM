use base64::{engine::general_purpose::STANDARD, Engine};
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
    /// The root cell hash, computed from the original parsed cell (not re-serialized).
    /// This matches the standard TON cell representation hash that TonWeb and explorers compute.
    root_cell_hash: [u8; 32],
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
        // Compute the cell hash from the original parsed cell BEFORE any re-serialization.
        // This preserves the exact bit layout of the original BOC, including inner message
        // bodies that may not round-trip perfectly through tlb-ton's typed serialization.
        let root_cell_hash = root.hash();
        let message: Message<WalletV4R2ExternalBody> = root
            .parse_fully(())
            .map_err(|e| WasmTonError::new(&format!("failed to parse message: {e}")))?;
        Ok(Transaction {
            boc_bytes: bytes.to_vec(),
            message,
            root_cell_hash,
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
        // Re-serialize and update the root cell hash from the new BOC
        self.boc_bytes = self.serialize_boc()?;
        self.root_cell_hash = self.compute_root_cell_hash()?;
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

    /// Get the transaction ID (cell hash of the root message cell, base64url encoded).
    ///
    /// Uses the standard TON cell representation hash, computed from the original parsed cell
    /// (not re-serialized). This matches what TonWeb and TON explorers compute.
    pub fn id(&self) -> String {
        base64::engine::general_purpose::URL_SAFE.encode(self.root_cell_hash)
    }

    /// Compute the root cell hash from the current BOC bytes.
    fn compute_root_cell_hash(&self) -> Result<[u8; 32], WasmTonError> {
        let boc = BagOfCells::deserialize(&self.boc_bytes)
            .map_err(|e| WasmTonError::new(&format!("failed to parse BOC for hash: {e}")))?;
        let root = boc
            .single_root()
            .ok_or_else(|| WasmTonError::new("BOC must have exactly one root cell"))?;
        Ok(root.hash())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple send BOC from BitGoJS test fixtures.
    const SIMPLE_SEND_BOC: &str = "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==";

    /// SingleNominator withdraw BOC from BitGoJS test fixtures.
    const SINGLE_NOMINATOR_WITHDRAW_BOC: &str = "te6cckECGAEAA8MAAuGIADZN0H0n1tz6xkYgWqJSRmkURKYajjEgXeawBo9cifPIGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF8DDudwJkyEh7jUbJEjFCjriVxsSlRJFyF872V1eegb4QACPQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr6A613oAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAHA0/PoUC5EIEyWuPg==";

    #[test]
    fn test_simple_send_id() {
        let tx = Transaction::from_base64(SIMPLE_SEND_BOC).unwrap();
        assert_eq!(tx.id(), "tuyOkyFUMv_neV_FeNBH24Nd4cML2jUgDP4zjGkuOFI=");
    }

    #[test]
    fn test_single_nominator_withdraw_id() {
        let tx = Transaction::from_base64(SINGLE_NOMINATOR_WITHDRAW_BOC).unwrap();
        assert_eq!(tx.id(), "n1rr-QL61WZ7UJN7ESH2iPQO7toTy9WLqXoSIG1JtXg=");
    }

    #[test]
    fn test_id_uses_original_cell_hash_not_reserialized() {
        // Verify that the ID comes from the original parsed cell, not from re-serialization.
        // The SingleNominator withdraw BOC has an inner message body that doesn't round-trip
        // through tlb-ton's typed serialization, so re-serialized hash would differ.
        let tx = Transaction::from_base64(SINGLE_NOMINATOR_WITHDRAW_BOC).unwrap();

        // Alternative implementation: cell hash of the re-serialized message struct.
        // This differs from the original cell hash because tlb-ton's typed serialization
        // does not perfectly reconstruct all inner message body bits for complex transactions.
        let reserialized_hash = tx
            .message
            .to_cell(())
            .map(|cell| base64::engine::general_purpose::URL_SAFE.encode(cell.hash()))
            .unwrap();

        // The original cell hash (what we now use)
        let original_hash = tx.id();

        // For the SingleNominator withdraw, these should differ, proving the fix matters
        assert_ne!(
            reserialized_hash, original_hash,
            "re-serialized hash should differ from original for SingleNominator withdraw"
        );

        // The original hash matches the expected legacy ID
        assert_eq!(
            original_hash,
            "n1rr-QL61WZ7UJN7ESH2iPQO7toTy9WLqXoSIG1JtXg="
        );
    }
}
