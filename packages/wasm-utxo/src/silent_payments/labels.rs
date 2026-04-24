//! BIP-352 Silent Payment label support.
//!
//! Labels allow a single SP address to generate multiple "sub-addresses" that
//! the receiver can distinguish during scanning. Each label index `m` produces
//! a unique tweak applied to B_spend, creating a labeled address.

use std::collections::HashMap;

use miniscript::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use super::address::{encode_with_hrp, sp_hrp_for_network, SilentPaymentAddress};
use super::SilentPaymentError;
use crate::bip322::bip340_tagged_hash;
use crate::networks::Network;

/// Compute the label tweak for label index `m`.
///
/// `label_m = tagged_hash("BIP0352/Label", ser_256(b_scan) || ser_32(m))`
pub fn compute_label_tweak(b_scan: &SecretKey, m: u32) -> [u8; 32] {
    let mut msg = Vec::with_capacity(36);
    msg.extend_from_slice(&b_scan.secret_bytes());
    msg.extend_from_slice(&m.to_be_bytes());
    bip340_tagged_hash("BIP0352/Label", &msg)
}

/// Create a labeled silent payment address.
///
/// The labeled spend key is `B_m = B_spend + label_m * G`, where
/// `label_m = tagged_hash("BIP0352/Label", ser_256(b_scan) || ser_32(m))`.
pub fn create_labeled_address(
    scan_key: &PublicKey,
    spend_key: &PublicKey,
    b_scan: &SecretKey,
    m: u32,
    network: Network,
) -> Result<SilentPaymentAddress, SilentPaymentError> {
    let secp = Secp256k1::new();
    let label_tweak = compute_label_tweak(b_scan, m);

    let label_secret = SecretKey::from_slice(&label_tweak).map_err(|e| {
        SilentPaymentError::InvalidScalar(format!("label tweak is invalid scalar: {}", e))
    })?;
    let label_point = PublicKey::from_secret_key(&secp, &label_secret);

    let labeled_spend = spend_key
        .combine(&label_point)
        .map_err(|e| SilentPaymentError::Secp256k1(format!("point addition failed: {}", e)))?;

    let hrp = sp_hrp_for_network(network);

    Ok(SilentPaymentAddress {
        scan_key: *scan_key,
        spend_key: labeled_spend,
        version: 0,
        hrp,
    })
}

/// Build a lookup table of label tweaks for scanning.
///
/// Maps `label_tweak_pubkey_x_only (32 bytes)` -> `label_index (m)`.
/// During scanning, if an output doesn't directly match P_k, the scanner
/// computes `output - P_k` and checks if the result's x-only key matches
/// any entry in this table.
pub fn build_label_lookup(b_scan: &SecretKey, labels: &[u32]) -> HashMap<[u8; 32], u32> {
    let secp = Secp256k1::new();
    let mut lookup = HashMap::with_capacity(labels.len());

    for &m in labels {
        let tweak = compute_label_tweak(b_scan, m);
        if let Ok(sk) = SecretKey::from_slice(&tweak) {
            let pk = PublicKey::from_secret_key(&secp, &sk);
            let (x_only, _parity) = pk.x_only_public_key();
            lookup.insert(x_only.serialize(), m);
        }
    }

    lookup
}

/// Encode a labeled SP address to string.
pub fn encode_labeled_address(
    scan_key: &PublicKey,
    spend_key: &PublicKey,
    b_scan: &SecretKey,
    m: u32,
    network: Network,
) -> Result<String, SilentPaymentError> {
    let addr = create_labeled_address(scan_key, spend_key, b_scan, m, network)?;
    encode_with_hrp(&addr.scan_key, &addr.spend_key, addr.hrp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_tweak_deterministic() {
        let b_scan = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let tweak1 = compute_label_tweak(&b_scan, 0);
        let tweak2 = compute_label_tweak(&b_scan, 0);
        assert_eq!(tweak1, tweak2);
    }

    #[test]
    fn test_label_tweak_different_for_different_m() {
        let b_scan = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let tweak0 = compute_label_tweak(&b_scan, 0);
        let tweak1 = compute_label_tweak(&b_scan, 1);
        let tweak2 = compute_label_tweak(&b_scan, 2);
        assert_ne!(tweak0, tweak1);
        assert_ne!(tweak1, tweak2);
        assert_ne!(tweak0, tweak2);
    }

    #[test]
    fn test_labeled_address_differs_from_base() {
        let secp = Secp256k1::new();
        let b_scan = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let b_spend = SecretKey::from_slice(&[11u8; 32]).unwrap();
        let scan_pk = PublicKey::from_secret_key(&secp, &b_scan);
        let spend_pk = PublicKey::from_secret_key(&secp, &b_spend);

        let labeled =
            create_labeled_address(&scan_pk, &spend_pk, &b_scan, 1, Network::Bitcoin).unwrap();

        // scan_key should be the same
        assert_eq!(labeled.scan_key, scan_pk);
        // spend_key should differ (it's been tweaked)
        assert_ne!(labeled.spend_key, spend_pk);
    }

    #[test]
    fn test_build_label_lookup() {
        let b_scan = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let labels = vec![0, 1, 5, 100];
        let lookup = build_label_lookup(&b_scan, &labels);

        assert_eq!(lookup.len(), labels.len());
        // Each label should produce a unique x-only key
        for &m in &labels {
            let tweak = compute_label_tweak(&b_scan, m);
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&tweak).unwrap();
            let pk = PublicKey::from_secret_key(&secp, &sk);
            let (x_only, _) = pk.x_only_public_key();
            assert_eq!(lookup.get(&x_only.serialize()), Some(&m));
        }
    }
}
