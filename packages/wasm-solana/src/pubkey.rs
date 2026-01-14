//! Solana public key (address) implementation.
//!
//! Wraps `solana_pubkey::Pubkey` for WASM compatibility.

use crate::error::WasmSolanaError;
use std::str::FromStr;

/// Re-export the underlying Solana Pubkey type.
pub use solana_pubkey::Pubkey;

/// Extension trait for Pubkey to add WASM-friendly error handling.
pub trait PubkeyExt {
    fn from_base58(address: &str) -> Result<Pubkey, WasmSolanaError>;
    fn from_bytes_checked(bytes: &[u8]) -> Result<Pubkey, WasmSolanaError>;
}

impl PubkeyExt for Pubkey {
    /// Create a Pubkey from a base58 string with WasmSolanaError.
    fn from_base58(address: &str) -> Result<Pubkey, WasmSolanaError> {
        Pubkey::from_str(address)
            .map_err(|e| WasmSolanaError::new(&format!("Invalid base58: {}", e)))
    }

    /// Create a Pubkey from a byte slice with length validation.
    fn from_bytes_checked(bytes: &[u8]) -> Result<Pubkey, WasmSolanaError> {
        if bytes.len() != 32 {
            return Err(WasmSolanaError::new(&format!(
                "Invalid public key length: expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| WasmSolanaError::new("Failed to convert to 32-byte array"))?;

        Ok(Pubkey::from(array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_base58() {
        let address = "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH";
        let pubkey = Pubkey::from_base58(address).unwrap();
        assert_eq!(pubkey.to_string(), address);
    }

    #[test]
    fn test_from_bytes() {
        let bytes = [0u8; 32];
        let pubkey = Pubkey::from_bytes_checked(&bytes).unwrap();
        assert_eq!(pubkey.to_bytes(), bytes);
    }

    #[test]
    fn test_roundtrip() {
        let address = "11111111111111111111111111111111";
        let pubkey = Pubkey::from_base58(address).unwrap();
        assert_eq!(pubkey.to_string(), address);
    }

    #[test]
    fn test_invalid_base58() {
        assert!(Pubkey::from_base58("invalid!@#$").is_err());
    }

    #[test]
    fn test_invalid_length() {
        assert!(Pubkey::from_bytes_checked(&[0u8; 31]).is_err());
        assert!(Pubkey::from_bytes_checked(&[0u8; 33]).is_err());
    }

    #[test]
    fn test_display() {
        let address = "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH";
        let pubkey = Pubkey::from_base58(address).unwrap();
        assert_eq!(format!("{}", pubkey), address);
    }

    #[test]
    fn test_equality() {
        let addr1 = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
        let addr2 = Pubkey::from_bytes_checked(&[0u8; 32]).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_is_on_curve_valid_keypair() {
        let pubkey = Pubkey::from_base58("FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH").unwrap();
        assert!(pubkey.is_on_curve());
    }

    #[test]
    fn test_is_on_curve_off_curve_bytes() {
        // Find bytes that are NOT on the Ed25519 curve
        for seed in 1u8..=255 {
            let mut bytes = [seed; 32];
            bytes[31] = 0x80 | seed;
            let pubkey = Pubkey::from_bytes_checked(&bytes).unwrap();
            if !pubkey.is_on_curve() {
                return;
            }
        }
        panic!("Could not find an off-curve point");
    }
}
