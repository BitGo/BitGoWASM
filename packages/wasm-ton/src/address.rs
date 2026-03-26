use std::sync::Arc;

use tlb_ton::{ser::CellBuilderError, state_init::StateInit, Cell, MsgAddress};
use ton_contracts::wallet::{v4r2::V4R2, WalletVersion};

use crate::error::WasmTonError;

/// Default wallet ID for v4r2 wallets
pub const DEFAULT_WALLET_ID: u32 = V4R2::DEFAULT_WALLET_ID; // 0x29a9a317 = 698983191

/// Address information returned from decoding
#[derive(Debug, Clone)]
pub struct AddressInfo {
    pub workchain: i32,
    pub hash: [u8; 32],
    pub bounceable: bool,
}

/// Encode a public key into a TON user-friendly address.
///
/// Derives the v4R2 wallet address from the public key using StateInit hash,
/// then encodes as base64url user-friendly format.
pub fn encode(pubkey: &[u8; 32], bounceable: bool, wallet_id: u32) -> Result<String, WasmTonError> {
    let state_init: StateInit<Arc<Cell>, _> = V4R2::state_init(wallet_id, *pubkey);
    let addr = MsgAddress::derive(0, state_init).map_err(|e: CellBuilderError| e.to_string())?;
    let non_bounceable = !bounceable;
    Ok(addr.to_base64_url_flags(non_bounceable, false))
}

/// Decode a TON user-friendly address into its components.
pub fn decode(address: &str) -> Result<AddressInfo, WasmTonError> {
    let (addr, non_bounceable, _non_production) =
        MsgAddress::from_base64_url_flags(address).map_err(|e| e.to_string())?;
    Ok(AddressInfo {
        workchain: addr.workchain_id,
        hash: addr.address,
        bounceable: !non_bounceable,
    })
}

/// Validate whether a string is a valid TON user-friendly address.
pub fn validate(address: &str) -> bool {
    // Accept both base64url and standard base64 formats
    if address.len() == 48 {
        if address.contains(['-', '_']) {
            MsgAddress::from_base64_url(address).is_ok()
        } else {
            MsgAddress::from_base64_std(address).is_ok()
        }
    } else {
        // Also accept raw hex format (workchain:hash)
        MsgAddress::from_hex(address).is_ok()
    }
}

/// Check if a user-friendly address is bounceable.
pub fn is_bounceable(address: &str) -> Result<bool, WasmTonError> {
    let info = decode(address)?;
    Ok(info.bounceable)
}

/// Re-encode an address with a different bounceable flag.
pub fn set_bounceable(address: &str, bounceable: bool) -> Result<String, WasmTonError> {
    let (addr, _non_bounceable, _non_production) =
        MsgAddress::from_base64_url_flags(address).map_err(|e| e.to_string())?;
    let non_bounceable = !bounceable;
    Ok(addr.to_base64_url_flags(non_bounceable, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let pubkey_hex = "c0c3b9dc09932121ee351b2448c50a3ae2571b12951245c85f3bd95d5e7a06f8";
        let pubkey: [u8; 32] = hex::decode(pubkey_hex).unwrap().try_into().unwrap();

        // Encode as non-bounceable
        let addr = encode(&pubkey, false, DEFAULT_WALLET_ID).unwrap();
        assert!(addr.starts_with("UQ"));

        // Decode and verify
        let info = decode(&addr).unwrap();
        assert_eq!(info.workchain, 0);
        assert!(!info.bounceable);

        // Encode as bounceable
        let addr_bounce = encode(&pubkey, true, DEFAULT_WALLET_ID).unwrap();
        assert!(addr_bounce.starts_with("EQ"));

        let info_bounce = decode(&addr_bounce).unwrap();
        assert!(info_bounce.bounceable);

        // Same hash regardless of bounceable flag
        assert_eq!(info.hash, info_bounce.hash);
    }

    #[test]
    fn test_validate() {
        let pubkey_hex = "c0c3b9dc09932121ee351b2448c50a3ae2571b12951245c85f3bd95d5e7a06f8";
        let pubkey: [u8; 32] = hex::decode(pubkey_hex).unwrap().try_into().unwrap();
        let addr = encode(&pubkey, false, DEFAULT_WALLET_ID).unwrap();

        assert!(validate(&addr));
        assert!(!validate("not-a-valid-address"));
        assert!(!validate(""));
    }

    #[test]
    fn test_set_bounceable() {
        let pubkey_hex = "c0c3b9dc09932121ee351b2448c50a3ae2571b12951245c85f3bd95d5e7a06f8";
        let pubkey: [u8; 32] = hex::decode(pubkey_hex).unwrap().try_into().unwrap();

        let non_bounce = encode(&pubkey, false, DEFAULT_WALLET_ID).unwrap();
        let converted = set_bounceable(&non_bounce, true).unwrap();
        let info = decode(&converted).unwrap();
        assert!(info.bounceable);

        let back = set_bounceable(&converted, false).unwrap();
        assert_eq!(back, non_bounce);
    }

    #[test]
    fn test_known_address() {
        // Known address from BitGoJS test fixtures
        let addr = "UQAbJug-k-tufWMjEC1RKSM0iiJTDUcYkC7zWANHrkT55Afg";
        assert!(validate(addr));
        let info = decode(addr).unwrap();
        assert_eq!(info.workchain, 0);
        assert!(!info.bounceable);
    }
}
