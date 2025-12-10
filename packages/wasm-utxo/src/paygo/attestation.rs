//! PayGo Attestation data structure and message reconstruction

use super::{ENTROPY_LENGTH, NIL_UUID};

/// A PayGo address attestation containing entropy, signature, and address
#[derive(Debug, Clone)]
pub struct PayGoAttestation {
    /// 64 bytes of cryptographically random entropy
    pub entropy: Vec<u8>,
    /// ECDSA signature (recoverable signature format, typically 65 bytes)
    pub signature: Vec<u8>,
    /// Bitcoin address that was attested to
    pub address: String,
}

impl PayGoAttestation {
    /// Create a new PayGo attestation
    ///
    /// # Arguments
    /// * `entropy` - 64 bytes of entropy
    /// * `signature` - ECDSA signature bytes
    /// * `address` - Bitcoin address string
    ///
    /// # Returns
    /// * `Ok(PayGoAttestation)` if entropy is exactly 64 bytes
    /// * `Err(String)` if entropy length is invalid
    pub fn new(entropy: Vec<u8>, signature: Vec<u8>, address: String) -> Result<Self, String> {
        if entropy.len() != ENTROPY_LENGTH {
            return Err(format!(
                "Invalid entropy length: expected {}, got {}",
                ENTROPY_LENGTH,
                entropy.len()
            ));
        }
        Ok(Self {
            entropy,
            signature,
            address,
        })
    }

    /// Convert the attestation to the message that was signed
    ///
    /// The message format is: [ENTROPY][ADDRESS][NIL_UUID]
    /// - ENTROPY: 64 bytes
    /// - ADDRESS: UTF-8 encoded address string
    /// - NIL_UUID: 36 bytes UTF-8 string "00000000-0000-0000-0000-000000000000"
    ///
    /// # Returns
    /// A Vec<u8> containing the concatenated message
    pub fn to_message(&self) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&self.entropy);
        message.extend_from_slice(self.address.as_bytes());
        message.extend_from_slice(NIL_UUID.as_bytes());
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_valid_entropy() {
        let entropy = vec![0u8; 64];
        let signature = vec![1u8; 65];
        let address = "1CdWUVacSQQJ617HuNWByGiisEGXGNx2c".to_string();

        let attestation =
            PayGoAttestation::new(entropy.clone(), signature.clone(), address.clone());
        assert!(attestation.is_ok());

        let attestation = attestation.unwrap();
        assert_eq!(attestation.entropy, entropy);
        assert_eq!(attestation.signature, signature);
        assert_eq!(attestation.address, address);
    }

    #[test]
    fn test_new_invalid_entropy_length() {
        let entropy = vec![0u8; 32]; // Wrong length
        let signature = vec![1u8; 65];
        let address = "1CdWUVacSQQJ617HuNWByGiisEGXGNx2c".to_string();

        let result = PayGoAttestation::new(entropy, signature, address);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid entropy length: expected 64, got 32"));
    }

    #[test]
    fn test_to_message() {
        // Test fixtures from TypeScript implementation
        let entropy = vec![0u8; 64];
        let signature = hex::decode(
            "1fd62abac20bb963f5150aa4b3f4753c5f2f53ced5183ab7761d0c95c2820f6b\
             b722b6d0d9adbab782d2d0d66402794b6bd6449dc26f634035ee388a2b5e7b53f6",
        )
        .unwrap();
        let address = "1CdWUVacSQQJ617HuNWByGiisEGXGNx2c".to_string();

        let attestation = PayGoAttestation::new(entropy, signature, address.clone()).unwrap();
        let message = attestation.to_message();

        // Message should be: 64 bytes entropy + 33 bytes address + 36 bytes UUID = 133 bytes
        assert_eq!(message.len(), 133);

        // Verify components
        let entropy_part = &message[0..64];
        let address_part = &message[64..97];
        let uuid_part = &message[97..133];

        assert_eq!(entropy_part, &vec![0u8; 64][..]);
        assert_eq!(
            std::str::from_utf8(address_part).unwrap(),
            "1CdWUVacSQQJ617HuNWByGiisEGXGNx2c"
        );
        assert_eq!(
            std::str::from_utf8(uuid_part).unwrap(),
            "00000000-0000-0000-0000-000000000000"
        );
    }
}
