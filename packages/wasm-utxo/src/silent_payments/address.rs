//! BIP-352 Silent Payment address encoding and decoding.
//!
//! SP addresses use bech32m encoding with HRP `sp` (mainnet) or `tsp` (testnet/signet).
//! The data part starts with a version Fe32 (0 for v0) followed by the 66-byte payload:
//! B_scan (33 bytes compressed) || B_spend (33 bytes compressed).

use bech32::primitives::decode::CheckedHrpstring;
use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
use bech32::{Bech32m, Fe32, Hrp};
use miniscript::bitcoin::secp256k1::PublicKey;

use super::SilentPaymentError;
use crate::networks::Network;

/// The HRP for mainnet SP addresses
const SP_HRP: &str = "sp";
/// The HRP for testnet/signet SP addresses
const TSP_HRP: &str = "tsp";
/// Reserved incompatible version (must be rejected)
const VERSION_RESERVED_INCOMPATIBLE: u8 = 31;
/// Payload size for v0 addresses: 33 (B_scan) + 33 (B_spend)
const V0_PAYLOAD_LEN: usize = 66;

/// A decoded BIP-352 Silent Payment address.
#[derive(Debug, Clone)]
pub struct SilentPaymentAddress {
    /// B_scan: the scan public key
    pub scan_key: PublicKey,
    /// B_spend: the spend public key (or B_m if labeled)
    pub spend_key: PublicKey,
    /// Address version (0 for v0)
    pub version: u8,
    /// Human-readable part ("sp" or "tsp")
    pub hrp: Hrp,
}

/// Return the appropriate HRP for the given network.
pub fn sp_hrp_for_network(network: Network) -> Hrp {
    if network.is_mainnet() {
        Hrp::parse(SP_HRP).expect("valid HRP")
    } else {
        Hrp::parse(TSP_HRP).expect("valid HRP")
    }
}

/// Decode a BIP-352 Silent Payment address string.
///
/// Validates the HRP (must be "sp" or "tsp"), version byte, and payload.
/// For v0, the payload must be exactly 66 bytes (B_scan || B_spend).
/// Versions 1-30 are forward-compatible (first 66 bytes read, rest ignored).
/// Version 31 is reserved and rejected.
pub fn decode(address: &str) -> Result<SilentPaymentAddress, SilentPaymentError> {
    let checked = CheckedHrpstring::new::<Bech32m>(address)
        .map_err(|e| SilentPaymentError::InvalidAddress(format!("bech32m decode failed: {}", e)))?;

    let hrp = checked.hrp();

    // Validate HRP
    let sp_hrp = Hrp::parse(SP_HRP).expect("valid HRP");
    let tsp_hrp = Hrp::parse(TSP_HRP).expect("valid HRP");
    if hrp != sp_hrp && hrp != tsp_hrp {
        return Err(SilentPaymentError::InvalidAddress(format!(
            "invalid HRP: expected 'sp' or 'tsp', got '{}'",
            hrp
        )));
    }

    // Get raw Fe32 data to extract version byte
    let fe32_data: Vec<Fe32> = checked.fe32_iter::<std::iter::Empty<u8>>().collect();

    if fe32_data.is_empty() {
        return Err(SilentPaymentError::InvalidAddress(
            "empty data part".to_string(),
        ));
    }

    // First Fe32 is the version
    let version = fe32_data[0].to_u8();

    if version == VERSION_RESERVED_INCOMPATIBLE {
        return Err(SilentPaymentError::InvalidAddress(
            "version 31 is reserved for incompatible changes".to_string(),
        ));
    }

    // Convert remaining Fe32s to bytes
    let payload: Vec<u8> = fe32_data[1..].iter().copied().fes_to_bytes().collect();

    if payload.len() < V0_PAYLOAD_LEN {
        return Err(SilentPaymentError::InvalidAddress(format!(
            "payload too short: {} bytes, need at least {}",
            payload.len(),
            V0_PAYLOAD_LEN
        )));
    }

    if version == 0 && payload.len() != V0_PAYLOAD_LEN {
        return Err(SilentPaymentError::InvalidAddress(format!(
            "v0 payload must be exactly {} bytes, got {}",
            V0_PAYLOAD_LEN,
            payload.len()
        )));
    }

    let scan_key = PublicKey::from_slice(&payload[..33])
        .map_err(|e| SilentPaymentError::InvalidKey(format!("invalid scan key: {}", e)))?;

    let spend_key = PublicKey::from_slice(&payload[33..66])
        .map_err(|e| SilentPaymentError::InvalidKey(format!("invalid spend key: {}", e)))?;

    Ok(SilentPaymentAddress {
        scan_key,
        spend_key,
        version,
        hrp,
    })
}

/// Encode a BIP-352 Silent Payment address from component keys.
///
/// Uses v0 encoding. HRP is determined by network: mainnet -> "sp", testnet/signet -> "tsp".
pub fn encode(
    scan_key: &PublicKey,
    spend_key: &PublicKey,
    network: Network,
) -> Result<String, SilentPaymentError> {
    let hrp = sp_hrp_for_network(network);
    encode_with_hrp(scan_key, spend_key, hrp)
}

/// Encode a BIP-352 Silent Payment address with a specific HRP.
pub fn encode_with_hrp(
    scan_key: &PublicKey,
    spend_key: &PublicKey,
    hrp: Hrp,
) -> Result<String, SilentPaymentError> {
    let mut payload = Vec::with_capacity(V0_PAYLOAD_LEN);
    payload.extend_from_slice(&scan_key.serialize());
    payload.extend_from_slice(&spend_key.serialize());

    // Build the Fe32 stream: version Fe32 (Q = 0) followed by byte-to-Fe32 payload
    let version_fe = std::iter::once(Fe32::Q);
    let payload_fes = payload.into_iter().bytes_to_fes();
    let fe32_iter = version_fe.chain(payload_fes);

    // Encode using the low-level Encoder API with bech32m checksum
    let chars: String = fe32_iter.with_checksum::<Bech32m>(&hrp).chars().collect();

    Ok(chars)
}

impl SilentPaymentAddress {
    /// Returns true if this is a mainnet address.
    pub fn is_mainnet(&self) -> bool {
        self.hrp == Hrp::parse(SP_HRP).expect("valid HRP")
    }
}

impl std::fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match encode_with_hrp(&self.scan_key, &self.spend_key, self.hrp) {
            Ok(s) => f.write_str(&s),
            Err(e) => write!(f, "<invalid SP address: {}>", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniscript::bitcoin::secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn test_encode_decode_roundtrip_mainnet() {
        let secp = Secp256k1::new();
        let scan_sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let spend_sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        let address = encode(&scan_pk, &spend_pk, Network::Bitcoin).unwrap();
        assert!(address.starts_with("sp1"));

        let decoded = decode(&address).unwrap();
        assert_eq!(decoded.scan_key, scan_pk);
        assert_eq!(decoded.spend_key, spend_pk);
        assert_eq!(decoded.version, 0);
        assert!(decoded.is_mainnet());
    }

    #[test]
    fn test_encode_decode_roundtrip_testnet() {
        let secp = Secp256k1::new();
        let scan_sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let spend_sk = SecretKey::from_slice(&[4u8; 32]).unwrap();
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        let address = encode(&scan_pk, &spend_pk, Network::BitcoinTestnet4).unwrap();
        assert!(address.starts_with("tsp1"));

        let decoded = decode(&address).unwrap();
        assert_eq!(decoded.scan_key, scan_pk);
        assert_eq!(decoded.spend_key, spend_pk);
        assert_eq!(decoded.version, 0);
        assert!(!decoded.is_mainnet());
    }

    #[test]
    fn test_invalid_hrp() {
        // A valid bech32m string with wrong HRP
        let result = decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(result.is_err());
        if let Err(SilentPaymentError::InvalidAddress(msg)) = result {
            assert!(msg.contains("HRP") || msg.contains("bech32m"));
        }
    }

    #[test]
    fn test_decode_rejects_version_31() {
        let secp = Secp256k1::new();
        let scan_sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let spend_sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        // Manually encode with version 31 (Fe32::L)
        let hrp = Hrp::parse("sp").unwrap();
        let mut payload = Vec::with_capacity(66);
        payload.extend_from_slice(&scan_pk.serialize());
        payload.extend_from_slice(&spend_pk.serialize());

        let version_fe = std::iter::once(Fe32::L); // version 31
        let payload_fes = payload.into_iter().bytes_to_fes();
        let fe32_iter = version_fe.chain(payload_fes);

        let encoded: String = fe32_iter.with_checksum::<Bech32m>(&hrp).chars().collect();

        let result = decode(&encoded);
        assert!(result.is_err());
        if let Err(SilentPaymentError::InvalidAddress(msg)) = result {
            assert!(msg.contains("version 31"));
        }
    }

    #[test]
    fn test_all_testnet_variants_use_tsp() {
        let secp = Secp256k1::new();
        let scan_sk = SecretKey::from_slice(&[5u8; 32]).unwrap();
        let spend_sk = SecretKey::from_slice(&[6u8; 32]).unwrap();
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        for network in &[
            Network::BitcoinTestnet3,
            Network::BitcoinTestnet4,
            Network::BitcoinPublicSignet,
            Network::BitcoinBitGoSignet,
        ] {
            let addr = encode(&scan_pk, &spend_pk, *network).unwrap();
            assert!(
                addr.starts_with("tsp1"),
                "Expected tsp1 prefix for {:?}, got: {}",
                network,
                addr
            );
        }
    }
}
