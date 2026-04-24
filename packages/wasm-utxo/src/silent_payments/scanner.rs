//! BIP-352 Silent Payment transaction scanning (receiving side).
//!
//! Given the receiver's scan private key, spend public key, and transaction data,
//! detect which taproot outputs are silent payment outputs destined for this receiver.

use std::collections::HashMap;

use miniscript::bitcoin::secp256k1::{
    Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};

use super::labels;
use super::sender::SenderOutpoint;
use super::{SilentPaymentError, K_MAX};
use crate::bip322::bip340_tagged_hash;

/// A taproot output to check against during scanning.
pub struct TaprootOutput {
    /// The x-only public key from the taproot output (32 bytes)
    pub x_only_pubkey: [u8; 32],
    /// Output index in the transaction
    pub index: u32,
}

/// Result of finding a matching silent payment output.
pub struct ScanResult {
    /// Which transaction output matched
    pub output_index: u32,
    /// The t_k tweak value from the shared secret derivation
    pub tweak: [u8; 32],
    /// The derivation counter k
    pub k: u32,
    /// Label index if matched via label (None for direct match)
    pub label: Option<u32>,
    /// Label tweak bytes if matched via label.
    /// To derive the spend key for a labeled output: p_k = b_spend + t_k + label_tweak
    pub label_tweak: Option<[u8; 32]>,
}

/// Scan a transaction for silent payment outputs addressed to this receiver.
///
/// Implements the BIP-352 scanning algorithm:
/// 1. Sum all input public keys -> A
/// 2. Compute input_hash = tagged_hash("BIP0352/Inputs", smallest_outpoint || ser_P(A))
/// 3. ECDH: ecdh = b_scan * input_hash * A
/// 4. For each k, derive P_k and check against taproot outputs
/// 5. If labels provided, check point subtraction against label lookup
pub fn scan_transaction(
    b_scan: &SecretKey,
    b_spend_pubkey: &PublicKey,
    input_pubkeys: &[PublicKey],
    outpoints: &[SenderOutpoint],
    taproot_outputs: &[TaprootOutput],
    labels: Option<&HashMap<[u8; 32], u32>>,
) -> Result<Vec<ScanResult>, SilentPaymentError> {
    if input_pubkeys.is_empty() {
        return Err(SilentPaymentError::NoEligibleInputs);
    }
    if taproot_outputs.is_empty() {
        return Ok(Vec::new());
    }

    let secp = Secp256k1::new();

    // Step 1: Sum all input public keys -> A
    let pubkey_refs: Vec<&PublicKey> = input_pubkeys.iter().collect();
    let big_a = PublicKey::combine_keys(&pubkey_refs).map_err(|e| {
        SilentPaymentError::Secp256k1(format!(
            "public key sum failed (possibly point at infinity): {}",
            e
        ))
    })?;

    // Step 2: Compute input_hash
    let smallest_op = super::sender::smallest_outpoint(outpoints)?;
    let mut input_hash_msg = Vec::with_capacity(36 + 33);
    input_hash_msg.extend_from_slice(&smallest_op);
    input_hash_msg.extend_from_slice(&big_a.serialize());
    let input_hash = bip340_tagged_hash("BIP0352/Inputs", &input_hash_msg);

    let input_hash_scalar = Scalar::from_be_bytes(input_hash).map_err(|e| {
        SilentPaymentError::InvalidScalar(format!("input_hash scalar invalid: {}", e))
    })?;

    // Step 3: ECDH = b_scan * input_hash * A
    // First: A' = A * input_hash
    let a_tweaked = big_a.mul_tweak(&secp, &input_hash_scalar).map_err(|e| {
        SilentPaymentError::Secp256k1(format!("input_hash tweak on A failed: {}", e))
    })?;

    // Then: ecdh = b_scan * A'
    let b_scan_scalar = Scalar::from_be_bytes(b_scan.secret_bytes()).map_err(|e| {
        SilentPaymentError::InvalidScalar(format!("b_scan to scalar failed: {}", e))
    })?;
    let ecdh_point = a_tweaked
        .mul_tweak(&secp, &b_scan_scalar)
        .map_err(|e| SilentPaymentError::Secp256k1(format!("ECDH computation failed: {}", e)))?;

    // Step 4: Iterate over k values, derive P_k and check against outputs
    let mut results = Vec::new();
    let mut remaining_outputs: Vec<(usize, &TaprootOutput)> =
        taproot_outputs.iter().enumerate().collect();

    for k in 0..K_MAX {
        if remaining_outputs.is_empty() {
            break;
        }

        // t_k = tagged_hash("BIP0352/SharedSecret", ser_P(ecdh) || ser_32(k))
        let mut shared_secret_msg = Vec::with_capacity(33 + 4);
        shared_secret_msg.extend_from_slice(&ecdh_point.serialize());
        shared_secret_msg.extend_from_slice(&k.to_be_bytes());
        let t_k = bip340_tagged_hash("BIP0352/SharedSecret", &shared_secret_msg);

        // Check if t_k is a valid scalar
        let t_k_secret = match SecretKey::from_slice(&t_k) {
            Ok(s) => s,
            Err(_) => continue, // Edge case: skip invalid scalar, try next k
        };

        // P_k = B_spend + t_k * G
        let t_k_point = PublicKey::from_secret_key(&secp, &t_k_secret);
        let p_k = match b_spend_pubkey.combine(&t_k_point) {
            Ok(pk) => pk,
            Err(_) => continue,
        };
        let (p_k_x_only, _) = p_k.x_only_public_key();
        let p_k_bytes = p_k_x_only.serialize();

        // Check for direct match
        let matched_idx = remaining_outputs
            .iter()
            .enumerate()
            .find(|(_, (_, output))| output.x_only_pubkey == p_k_bytes)
            .map(|(vec_idx, _)| vec_idx);

        if let Some(vec_idx) = matched_idx {
            let output = remaining_outputs.remove(vec_idx).1;
            results.push(ScanResult {
                output_index: output.index,
                tweak: t_k,
                k,
                label: None,
                label_tweak: None,
            });
            continue;
        }

        // Check with labels if provided
        if let Some(label_lookup) = labels {
            let mut label_match = None;

            for (vec_idx, (_, output)) in remaining_outputs.iter().enumerate() {
                // Reconstruct the output point from x-only (try both parities)
                let x_only = match XOnlyPublicKey::from_slice(&output.x_only_pubkey) {
                    Ok(xo) => xo,
                    Err(_) => continue,
                };

                // Try even parity
                let output_point_even = PublicKey::from_x_only_public_key(x_only, Parity::Even);
                // m_G = output_point - P_k
                let p_k_neg = p_k.negate(&secp);
                if let Ok(diff) = output_point_even.combine(&p_k_neg) {
                    let (diff_x_only, _) = diff.x_only_public_key();
                    if let Some(&m) = label_lookup.get(&diff_x_only.serialize()) {
                        label_match = Some((vec_idx, m));
                        break;
                    }
                }

                // Try odd parity
                let output_point_odd = PublicKey::from_x_only_public_key(x_only, Parity::Odd);
                if let Ok(diff) = output_point_odd.combine(&p_k_neg) {
                    let (diff_x_only, _) = diff.x_only_public_key();
                    if let Some(&m) = label_lookup.get(&diff_x_only.serialize()) {
                        label_match = Some((vec_idx, m));
                        break;
                    }
                }
            }

            if let Some((vec_idx, m)) = label_match {
                let output = remaining_outputs.remove(vec_idx).1;
                let label_tweak_bytes = labels::compute_label_tweak(b_scan, m);
                results.push(ScanResult {
                    output_index: output.index,
                    tweak: t_k,
                    k,
                    label: Some(m),
                    label_tweak: Some(label_tweak_bytes),
                });
                continue;
            }
        }

        // No match at this k (with or without labels) -> stop scanning
        break;
    }

    Ok(results)
}

/// Extract a public key from a transaction input for silent payment scanning.
///
/// Returns None if the input type is not eligible (P2WSH, P2SH multisig, etc.)
///
/// Supported input types:
/// - P2TR: x-only key from witness program, reconstructed with even Y parity
/// - P2WPKH: compressed pubkey from last witness item
/// - P2SH-P2WPKH: compressed pubkey from last witness item
/// - P2PKH: compressed pubkey from scriptSig
pub fn extract_input_pubkey(
    script_pubkey: &miniscript::bitcoin::Script,
    _script_sig: &[u8],
    witness: &[Vec<u8>],
) -> Option<PublicKey> {
    // P2TR: witness version 1, 32-byte program
    if script_pubkey.is_p2tr() {
        let program_bytes = &script_pubkey.as_bytes()[2..34];
        let x_only = XOnlyPublicKey::from_slice(program_bytes).ok()?;
        Some(PublicKey::from_x_only_public_key(x_only, Parity::Even))
    }
    // P2WPKH: witness version 0, 20-byte program
    else if script_pubkey.is_p2wpkh() {
        let last_witness = witness.last()?;
        PublicKey::from_slice(last_witness).ok()
    }
    // P2SH wrapping P2WPKH: check scriptSig pushes a P2WPKH redeemScript
    else if script_pubkey.is_p2sh() && !witness.is_empty() {
        // For P2SH-P2WPKH, the witness contains [signature, pubkey]
        let last_witness = witness.last()?;
        if last_witness.len() == 33 {
            PublicKey::from_slice(last_witness).ok()
        } else {
            None
        }
    }
    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    else if script_pubkey.is_p2pkh() {
        // Extract expected hash160 from scriptPubKey (bytes [3..23])
        let spk_bytes = script_pubkey.as_bytes();
        let expected_hash = if spk_bytes.len() >= 23 {
            Some(&spk_bytes[3..23])
        } else {
            None
        };
        parse_p2pkh_pubkey(_script_sig, expected_hash)
    } else {
        None // Not eligible (P2WSH, bare multisig, etc.)
    }
}

/// Parse a P2PKH scriptSig to extract the compressed public key.
///
/// Handles both standard and malleated scriptSigs by scanning all data pushes
/// for a valid 33-byte compressed public key whose hash160 matches the
/// expected hash from the scriptPubKey. If no expected_hash is provided,
/// returns the first valid compressed pubkey found.
fn parse_p2pkh_pubkey(script_sig: &[u8], expected_hash: Option<&[u8]>) -> Option<PublicKey> {
    use miniscript::bitcoin::hashes::{hash160, Hash};

    // Scan all pushes in the scriptSig looking for a 33-byte compressed pubkey.
    let mut pos = 0;

    while pos < script_sig.len() {
        let op = script_sig[pos];

        if op == 0 || (op >= 0x50 && op != 0x4c && op != 0x4d && op != 0x4e) {
            // OP_0, OP_1..OP_16, or other single-byte opcodes
            pos += 1;
            continue;
        }

        let (data_start, data_len) = if (1..=75).contains(&op) {
            (pos + 1, op as usize)
        } else if op == 0x4c {
            // OP_PUSHDATA1
            if pos + 1 >= script_sig.len() {
                break;
            }
            (pos + 2, script_sig[pos + 1] as usize)
        } else if op == 0x4d {
            // OP_PUSHDATA2
            if pos + 2 >= script_sig.len() {
                break;
            }
            let len = u16::from_le_bytes([script_sig[pos + 1], script_sig[pos + 2]]) as usize;
            (pos + 3, len)
        } else {
            // Other opcodes (OP_IF, OP_ELSE, OP_ENDIF, etc.)
            pos += 1;
            continue;
        };

        if data_start + data_len > script_sig.len() {
            break;
        }

        let data = &script_sig[data_start..data_start + data_len];

        // Check if this is a 33-byte compressed public key
        if data_len == 33 && (data[0] == 0x02 || data[0] == 0x03) {
            if let Ok(pk) = PublicKey::from_slice(data) {
                // If we have an expected hash, verify it matches
                if let Some(expected) = expected_hash {
                    let pk_hash = hash160::Hash::hash(&pk.serialize());
                    if pk_hash.as_byte_array() == expected {
                        return Some(pk);
                    }
                    // Hash doesn't match, keep scanning
                } else {
                    return Some(pk);
                }
            }
        }

        pos = data_start + data_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::silent_payments::sender::{derive_silent_payment_outputs, SenderInput};

    #[test]
    fn test_scan_finds_sent_output() {
        let secp = Secp256k1::new();

        // Sender's input key
        let input_sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let input_pk = PublicKey::from_secret_key(&secp, &input_sk);

        // Receiver's keys
        let b_scan = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let b_spend = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let b_scan_pub = PublicKey::from_secret_key(&secp, &b_scan);
        let b_spend_pub = PublicKey::from_secret_key(&secp, &b_spend);

        let outpoints = vec![SenderOutpoint {
            txid: [0xab; 32],
            vout: 0,
        }];

        // Sender derives outputs
        let recipient = super::super::address::SilentPaymentAddress {
            scan_key: b_scan_pub,
            spend_key: b_spend_pub,
            version: 0,
            hrp: bech32::Hrp::parse("sp").unwrap(),
        };

        let sender_inputs = vec![SenderInput {
            private_key: input_sk,
            is_taproot: false,
        }];

        let outputs =
            derive_silent_payment_outputs(&sender_inputs, &outpoints, &[recipient]).unwrap();
        assert_eq!(outputs.len(), 1);

        // Scanner scans the transaction
        let taproot_outputs = vec![TaprootOutput {
            x_only_pubkey: outputs[0].x_only_pubkey,
            index: 0,
        }];

        let scan_results = scan_transaction(
            &b_scan,
            &b_spend_pub,
            &[input_pk],
            &outpoints,
            &taproot_outputs,
            None,
        )
        .unwrap();

        assert_eq!(scan_results.len(), 1);
        assert_eq!(scan_results[0].output_index, 0);
        assert_eq!(scan_results[0].k, 0);
        assert!(scan_results[0].label.is_none());
        assert_eq!(scan_results[0].tweak, outputs[0].tweak);
    }

    #[test]
    fn test_scan_with_taproot_input() {
        let secp = Secp256k1::new();

        // Sender's taproot input key
        let input_sk = SecretKey::from_slice(&[5u8; 32]).unwrap();
        let input_pk = PublicKey::from_secret_key(&secp, &input_sk);

        // For scanning, we need the public key as it would appear in the scriptPubKey
        // For taproot, we use the x-only key with even Y
        let (x_only, _parity) = input_pk.x_only_public_key();
        let scan_input_pk = PublicKey::from_x_only_public_key(x_only, Parity::Even);

        // Receiver's keys
        let b_scan = SecretKey::from_slice(&[6u8; 32]).unwrap();
        let b_spend = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let b_scan_pub = PublicKey::from_secret_key(&secp, &b_scan);
        let b_spend_pub = PublicKey::from_secret_key(&secp, &b_spend);

        let outpoints = vec![SenderOutpoint {
            txid: [0xcd; 32],
            vout: 1,
        }];

        let recipient = super::super::address::SilentPaymentAddress {
            scan_key: b_scan_pub,
            spend_key: b_spend_pub,
            version: 0,
            hrp: bech32::Hrp::parse("sp").unwrap(),
        };

        let sender_inputs = vec![SenderInput {
            private_key: input_sk,
            is_taproot: true,
        }];

        let outputs =
            derive_silent_payment_outputs(&sender_inputs, &outpoints, &[recipient]).unwrap();
        assert_eq!(outputs.len(), 1);

        // Scanner: for taproot inputs, use x-only key with even parity
        let scan_results = scan_transaction(
            &b_scan,
            &b_spend_pub,
            &[scan_input_pk],
            &outpoints,
            &[TaprootOutput {
                x_only_pubkey: outputs[0].x_only_pubkey,
                index: 0,
            }],
            None,
        )
        .unwrap();

        assert_eq!(scan_results.len(), 1);
    }

    #[test]
    fn test_full_round_trip_with_spend_key() {
        let secp = Secp256k1::new();

        let input_sk = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let input_pk = PublicKey::from_secret_key(&secp, &input_sk);

        let b_scan = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let b_spend = SecretKey::from_slice(&[30u8; 32]).unwrap();
        let b_scan_pub = PublicKey::from_secret_key(&secp, &b_scan);
        let b_spend_pub = PublicKey::from_secret_key(&secp, &b_spend);

        let outpoints = vec![SenderOutpoint {
            txid: [0x42; 32],
            vout: 0,
        }];

        // 1. Encode SP address
        let addr_str =
            crate::silent_payments::address::encode(&b_scan_pub, &b_spend_pub, Network::Bitcoin)
                .unwrap();

        // 2. Decode it
        let addr = crate::silent_payments::address::decode(&addr_str).unwrap();

        // 3. Sender derives outputs
        let outputs = derive_silent_payment_outputs(
            &[SenderInput {
                private_key: input_sk,
                is_taproot: false,
            }],
            &outpoints,
            &[addr],
        )
        .unwrap();

        // 4. Scanner detects the output
        let scan_results = scan_transaction(
            &b_scan,
            &b_spend_pub,
            &[input_pk],
            &outpoints,
            &[TaprootOutput {
                x_only_pubkey: outputs[0].x_only_pubkey,
                index: 0,
            }],
            None,
        )
        .unwrap();

        assert_eq!(scan_results.len(), 1);

        // 5. Derive spend key
        let spend_key =
            crate::silent_payments::spending::derive_spend_key(&b_spend, &scan_results[0].tweak)
                .unwrap();

        // 6. Verify: PublicKey from spend_key should match the output's x-only key
        let derived_pub = PublicKey::from_secret_key(&secp, &spend_key);
        let (derived_x_only, _) = derived_pub.x_only_public_key();
        assert_eq!(derived_x_only.serialize(), outputs[0].x_only_pubkey);
    }

    use crate::networks::Network;
}
