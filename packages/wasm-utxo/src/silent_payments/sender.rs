//! BIP-352 Silent Payment sender-side ECDH output derivation.
//!
//! Given a set of input private keys, outpoints, and recipient SP addresses,
//! derive the output P2TR scripts for each recipient. This is the core sending logic.

use std::collections::HashMap;

use miniscript::bitcoin::secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey};
use miniscript::bitcoin::ScriptBuf;

use super::address::SilentPaymentAddress;
use super::{SilentPaymentError, K_MAX};
use crate::bip322::bip340_tagged_hash;

/// secp256k1 curve order N (big-endian).
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Add two 256-bit scalars modulo the secp256k1 curve order.
/// Inputs and output are big-endian 32-byte arrays.
/// This handles intermediate zero values that SecretKey::add_tweak cannot.
fn scalar_add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // Add a + b as a 33-byte big-endian number (to handle carry)
    let mut sum = [0u8; 33];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let s = a[i] as u16 + b[i] as u16 + carry;
        sum[i + 1] = (s & 0xFF) as u8;
        carry = s >> 8;
    }
    sum[0] = carry as u8;

    // Reduce modulo N: if sum >= N, subtract N
    // Compare sum (33 bytes) with N (32 bytes, padded to 33)
    let mut n_padded = [0u8; 33];
    n_padded[1..].copy_from_slice(&SECP256K1_ORDER);

    // Check if sum >= N
    let mut gte = true;
    for i in 0..33 {
        if sum[i] > n_padded[i] {
            break;
        } else if sum[i] < n_padded[i] {
            gte = false;
            break;
        }
    }

    if gte {
        // Subtract N from sum
        let mut borrow: i16 = 0;
        for i in (0..33).rev() {
            let diff = sum[i] as i16 - n_padded[i] as i16 - borrow;
            if diff < 0 {
                sum[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                sum[i] = diff as u8;
                borrow = 0;
            }
        }
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&sum[1..33]);
    result
}

/// An input contributing to the silent payment derivation.
pub struct SenderInput {
    /// The private key for this input (a_i)
    pub private_key: SecretKey,
    /// Whether this input spends a taproot output (if true, negate if odd Y)
    pub is_taproot: bool,
}

/// An outpoint from the transaction's inputs.
pub struct SenderOutpoint {
    /// Transaction ID in little-endian byte order
    pub txid: [u8; 32],
    /// Output index in little-endian byte order
    pub vout: u32,
}

/// A derived silent payment output.
pub struct SilentPaymentOutput {
    /// The P2TR output script
    pub script_pubkey: ScriptBuf,
    /// The x-only public key for the output (32 bytes)
    pub x_only_pubkey: [u8; 32],
    /// The tweak t_k (needed by the receiver to derive the spend key)
    pub tweak: [u8; 32],
    /// Index of the recipient in the original recipients list
    pub recipient_index: usize,
}

/// Compute the lexicographically smallest outpoint serialization.
///
/// Each outpoint is serialized as `txid (32 bytes LE) || vout (4 bytes LE)`.
/// Returns the smallest by byte comparison.
pub fn smallest_outpoint(outpoints: &[SenderOutpoint]) -> Result<Vec<u8>, SilentPaymentError> {
    outpoints
        .iter()
        .map(|op| {
            let mut bytes = Vec::with_capacity(36);
            bytes.extend_from_slice(&op.txid);
            bytes.extend_from_slice(&op.vout.to_le_bytes());
            bytes
        })
        .min()
        .ok_or(SilentPaymentError::NoEligibleInputs)
}

/// Derive silent payment output scripts for the given recipients.
///
/// Implements the BIP-352 sending algorithm:
/// 1. Negate taproot private keys with odd Y
/// 2. Sum all private keys -> a
/// 3. Compute input_hash = tagged_hash("BIP0352/Inputs", smallest_outpoint || ser_P(A))
/// 4. Group recipients by B_scan
/// 5. For each group: ECDH shared secret, then derive P2TR outputs
pub fn derive_silent_payment_outputs(
    inputs: &[SenderInput],
    outpoints: &[SenderOutpoint],
    recipients: &[SilentPaymentAddress],
) -> Result<Vec<SilentPaymentOutput>, SilentPaymentError> {
    if inputs.is_empty() {
        return Err(SilentPaymentError::NoEligibleInputs);
    }
    if recipients.is_empty() {
        return Ok(Vec::new());
    }

    let secp = Secp256k1::new();

    // Step 1: Negate taproot keys with odd Y, collect all keys
    let mut adjusted_keys: Vec<SecretKey> = Vec::with_capacity(inputs.len());
    for input in inputs {
        let mut key = input.private_key;
        if input.is_taproot {
            let pubkey = PublicKey::from_secret_key(&secp, &key);
            let (_x_only, parity) = pubkey.x_only_public_key();
            if parity == Parity::Odd {
                key = key.negate();
            }
        }
        adjusted_keys.push(key);
    }

    // Step 2: Sum all private keys as raw scalars (mod curve order).
    // This handles the case where intermediate sums pass through zero.
    let mut sum_bytes = adjusted_keys[0].secret_bytes();
    for key in &adjusted_keys[1..] {
        sum_bytes = scalar_add_mod_n(&sum_bytes, &key.secret_bytes());
    }

    // The final sum must be a valid (non-zero) secret key
    let a = SecretKey::from_slice(&sum_bytes).map_err(|e| {
        SilentPaymentError::Secp256k1(format!("key sum is zero (point at infinity): {}", e))
    })?;

    // Step 3: Compute A = a * G
    let big_a = PublicKey::from_secret_key(&secp, &a);

    // Step 4: Compute input_hash
    let smallest_op = smallest_outpoint(outpoints)?;
    let mut input_hash_msg = Vec::with_capacity(36 + 33);
    input_hash_msg.extend_from_slice(&smallest_op);
    input_hash_msg.extend_from_slice(&big_a.serialize());
    let input_hash = bip340_tagged_hash("BIP0352/Inputs", &input_hash_msg);

    let input_hash_scalar = Scalar::from_be_bytes(input_hash).map_err(|e| {
        SilentPaymentError::InvalidScalar(format!("input_hash scalar invalid: {}", e))
    })?;

    // Step 5: Group recipients by B_scan
    let mut groups: HashMap<PublicKey, Vec<(usize, &SilentPaymentAddress)>> = HashMap::new();
    for (idx, recipient) in recipients.iter().enumerate() {
        groups
            .entry(recipient.scan_key)
            .or_default()
            .push((idx, recipient));
    }

    let mut outputs = Vec::with_capacity(recipients.len());

    // Step 6: For each group, compute ECDH and derive outputs
    for (b_scan, group) in &groups {
        if group.len() > K_MAX as usize {
            return Err(SilentPaymentError::TooManyRecipients(group.len()));
        }

        // a' = a * input_hash
        let a_tweaked = a.mul_tweak(&input_hash_scalar).map_err(|e| {
            SilentPaymentError::Secp256k1(format!("input_hash tweak failed: {}", e))
        })?;

        // ecdh = a' * B_scan
        let a_tweaked_scalar = Scalar::from_be_bytes(a_tweaked.secret_bytes()).map_err(|e| {
            SilentPaymentError::InvalidScalar(format!(
                "tweaked key to scalar conversion failed: {}",
                e
            ))
        })?;
        let ecdh_point = b_scan.mul_tweak(&secp, &a_tweaked_scalar).map_err(|e| {
            SilentPaymentError::Secp256k1(format!("ECDH computation failed: {}", e))
        })?;

        // Step 7: For each recipient k in the group
        for (k, (recipient_idx, recipient)) in group.iter().enumerate() {
            let k_u32 = k as u32;

            // t_k = tagged_hash("BIP0352/SharedSecret", ser_P(ecdh) || ser_32(k))
            let mut shared_secret_msg = Vec::with_capacity(33 + 4);
            shared_secret_msg.extend_from_slice(&ecdh_point.serialize());
            shared_secret_msg.extend_from_slice(&k_u32.to_be_bytes());
            let t_k = bip340_tagged_hash("BIP0352/SharedSecret", &shared_secret_msg);

            // Check if t_k is a valid scalar (skip if not)
            if Scalar::from_be_bytes(t_k).is_err() {
                continue; // Edge case: skip invalid scalar
            }

            // P_k = B_spend + t_k * G
            let t_k_secret = match SecretKey::from_slice(&t_k) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let t_k_point = PublicKey::from_secret_key(&secp, &t_k_secret);

            let p_k = recipient.spend_key.combine(&t_k_point).map_err(|e| {
                SilentPaymentError::Secp256k1(format!("output key derivation failed: {}", e))
            })?;

            // Extract x-only key and build P2TR script
            let (x_only, _parity) = p_k.x_only_public_key();

            // Build P2TR output: OP_1 (0x51) || OP_PUSHBYTES_32 (0x20) || x_only_key
            let script_pubkey = ScriptBuf::new_p2tr_tweaked(
                miniscript::bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(x_only),
            );

            outputs.push(SilentPaymentOutput {
                script_pubkey,
                x_only_pubkey: x_only.serialize(),
                tweak: t_k,
                recipient_index: *recipient_idx,
            });
        }
    }

    // Sort by recipient_index to maintain deterministic ordering
    outputs.sort_by_key(|o| o.recipient_index);

    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_smallest_outpoint_single() {
        let outpoints = vec![SenderOutpoint {
            txid: [0xab; 32],
            vout: 1,
        }];
        let result = smallest_outpoint(&outpoints).unwrap();
        assert_eq!(result.len(), 36);
        assert_eq!(&result[..32], &[0xab; 32]);
        assert_eq!(&result[32..], &1u32.to_le_bytes());
    }

    #[test]
    fn test_smallest_outpoint_multiple() {
        let outpoints = vec![
            SenderOutpoint {
                txid: [0xff; 32],
                vout: 0,
            },
            SenderOutpoint {
                txid: [0x00; 32],
                vout: 0,
            },
            SenderOutpoint {
                txid: [0xab; 32],
                vout: 0,
            },
        ];
        let result = smallest_outpoint(&outpoints).unwrap();
        // Should select the one with txid [0x00; 32]
        assert_eq!(&result[..32], &[0x00; 32]);
    }

    #[test]
    fn test_smallest_outpoint_empty_rejects() {
        let outpoints: Vec<SenderOutpoint> = vec![];
        let result = smallest_outpoint(&outpoints);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_outputs_empty_inputs_rejected() {
        let secp = Secp256k1::new();
        let scan_sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let spend_sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        let addr = SilentPaymentAddress {
            scan_key: scan_pk,
            spend_key: spend_pk,
            version: 0,
            hrp: bech32::Hrp::parse("sp").unwrap(),
        };

        let result = derive_silent_payment_outputs(&[], &[], &[addr]);
        assert!(matches!(result, Err(SilentPaymentError::NoEligibleInputs)));
    }

    #[test]
    fn test_derive_outputs_empty_recipients_ok() {
        let inputs = vec![SenderInput {
            private_key: SecretKey::from_slice(&[1u8; 32]).unwrap(),
            is_taproot: false,
        }];
        let outpoints = vec![SenderOutpoint {
            txid: [0xab; 32],
            vout: 0,
        }];

        let result = derive_silent_payment_outputs(&inputs, &outpoints, &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_derive_outputs_basic() {
        let secp = Secp256k1::new();
        let input_sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let scan_sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let spend_sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        let inputs = vec![SenderInput {
            private_key: input_sk,
            is_taproot: false,
        }];
        let outpoints = vec![SenderOutpoint {
            txid: [0xab; 32],
            vout: 0,
        }];
        let recipients = vec![SilentPaymentAddress {
            scan_key: scan_pk,
            spend_key: spend_pk,
            version: 0,
            hrp: bech32::Hrp::parse("sp").unwrap(),
        }];

        let outputs = derive_silent_payment_outputs(&inputs, &outpoints, &recipients).unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].recipient_index, 0);
        // P2TR scripts are 34 bytes: OP_1 (1) + OP_PUSHBYTES_32 (1) + pubkey (32)
        assert_eq!(outputs[0].script_pubkey.len(), 34);
    }
}
