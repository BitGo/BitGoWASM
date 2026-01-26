//! Ed25519 keypair implementation for Solana.
//!
//! Wraps `solana_keypair::Keypair` for WASM compatibility.

use crate::error::WasmSolanaError;
use solana_signer::Signer;

/// Re-export the underlying Solana Keypair type.
pub use solana_keypair::Keypair;

/// Extension trait for Keypair to add WASM-friendly methods.
pub trait KeypairExt {
    fn from_secret_key_bytes(secret_key: &[u8]) -> Result<Keypair, WasmSolanaError>;
    fn from_solana_secret_key(secret_key: &[u8]) -> Result<Keypair, WasmSolanaError>;
    fn public_key_bytes(&self) -> [u8; 32];
    fn secret_key_bytes(&self) -> [u8; 32];
    fn address(&self) -> String;
}

impl KeypairExt for Keypair {
    /// Create a keypair from a 32-byte secret key (Ed25519 seed).
    fn from_secret_key_bytes(secret_key: &[u8]) -> Result<Keypair, WasmSolanaError> {
        let bytes: [u8; 32] = secret_key.try_into().map_err(|_| {
            WasmSolanaError::new(&format!(
                "Secret key must be 32 bytes, got {}",
                secret_key.len()
            ))
        })?;

        // Use official solana-keypair method that handles 32-byte seeds
        Ok(Keypair::new_from_array(bytes))
    }

    /// Create a keypair from a 64-byte Solana secret key (secret + public concatenated).
    fn from_solana_secret_key(secret_key: &[u8]) -> Result<Keypair, WasmSolanaError> {
        if secret_key.len() != 64 {
            return Err(WasmSolanaError::new(&format!(
                "Solana secret key must be 64 bytes, got {}",
                secret_key.len()
            )));
        }

        Keypair::try_from(secret_key)
            .map_err(|e| WasmSolanaError::new(&format!("Invalid keypair: {}", e)))
    }

    /// Get the public key bytes (32 bytes).
    fn public_key_bytes(&self) -> [u8; 32] {
        self.pubkey().to_bytes()
    }

    /// Get the secret key bytes (32 bytes, the seed only).
    fn secret_key_bytes(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes[..32]);
        secret
    }

    /// Get the Solana address (base58-encoded public key).
    fn address(&self) -> String {
        self.pubkey().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let keypair = Keypair::new();
        assert_eq!(keypair.public_key_bytes().len(), 32);
        assert_eq!(keypair.secret_key_bytes().len(), 32);
    }

    #[test]
    fn test_from_secret_key() {
        let secret = [1u8; 32];
        let keypair = Keypair::from_secret_key_bytes(&secret).unwrap();
        assert_eq!(keypair.secret_key_bytes(), secret);
    }

    #[test]
    fn test_deterministic_pubkey() {
        let secret = [1u8; 32];
        let keypair1 = Keypair::from_secret_key_bytes(&secret).unwrap();
        let keypair2 = Keypair::from_secret_key_bytes(&secret).unwrap();
        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
        assert_eq!(keypair1.address(), keypair2.address());
    }

    #[test]
    fn test_solana_secret_key_format() {
        let secret = [1u8; 32];
        let keypair = Keypair::from_secret_key_bytes(&secret).unwrap();
        let pubkey = keypair.public_key_bytes();

        // Create 64-byte Solana format
        let mut solana_secret = [0u8; 64];
        solana_secret[..32].copy_from_slice(&secret);
        solana_secret[32..].copy_from_slice(&pubkey);

        let keypair2 = Keypair::from_solana_secret_key(&solana_secret).unwrap();
        assert_eq!(keypair.address(), keypair2.address());
    }

    #[test]
    fn test_invalid_secret_key_length() {
        assert!(Keypair::from_secret_key_bytes(&[0u8; 31]).is_err());
        assert!(Keypair::from_secret_key_bytes(&[0u8; 33]).is_err());
        assert!(Keypair::from_solana_secret_key(&[0u8; 63]).is_err());
        assert!(Keypair::from_solana_secret_key(&[0u8; 65]).is_err());
    }

    /// Test vector from BitGoJS sdk-coin-sol
    #[test]
    fn test_bitgojs_compatibility() {
        let seed: [u8; 32] = [
            210, 49, 239, 175, 249, 91, 42, 66, 77, 70, 3, 144, 23, 0, 145, 152, 86, 35, 166, 11,
            129, 49, 201, 162, 255, 195, 94, 229, 98, 78, 76, 38,
        ];
        let expected_address = "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH";

        let keypair = Keypair::from_secret_key_bytes(&seed).unwrap();
        assert_eq!(keypair.address(), expected_address);
    }
}
