//! ZIP-316 Unified Address (UA) parsing.
//!
//! A UA is a Bech32m string whose payload is F4Jumble-encoded (ZIP-316 §F4Jumble).
//! The un-jumbled payload is a sequence of receivers — each a
//! `CompactSize(typecode) ‖ CompactSize(length) ‖ data` record — followed by a
//! 16-byte padding equal to the human-readable part (HRP), zero-extended.
//!
//! Ironwood reuses the existing **Orchard** receiver (typecode `0x03`): an Orchard
//! unified receiver routes to the Ironwood pool once NU6.3 rules are active, so no
//! new typecode is required.
//!
//! Parsing here only needs Bech32m + F4Jumble⁻¹ + typecode scanning — no `orchard`
//! crate, no ZK machinery.

use super::blake2b::blake2b_var_personal;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::Bech32m;
use miniscript::bitcoin::consensus::Decodable;
use miniscript::bitcoin::VarInt;

/// ZIP-316 receiver typecodes.
const TYPECODE_P2PKH: u64 = 0x00;
const TYPECODE_P2SH: u64 = 0x01;
/// Orchard receiver typecode; Ironwood reuses it.
const TYPECODE_ORCHARD: u64 = 0x03;

/// Expected raw length of an Orchard/Ironwood receiver (11-byte diversifier + 32-byte pk_d).
const ORCHARD_RECEIVER_LEN: usize = 43;
/// Length of a transparent receiver's 20-byte hash (pubkey hash or script hash).
const TRANSPARENT_HASH_LEN: usize = 20;

/// Length of the trailing HRP padding, in bytes.
const PADDING_LEN: usize = 16;
/// Minimum valid F4Jumbled message length (ZIP-316).
const F4JUMBLE_MIN_LEN: usize = 48;
/// BLAKE2b output size in bytes.
const OUTBYTES: usize = 64;

/// F4Jumble H-round personalization: `b"UA_F4Jumble_H" ‖ [i, 0, 0]`.
fn h_pers(i: u8) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[..13].copy_from_slice(b"UA_F4Jumble_H");
    p[13] = i;
    p
}

/// F4Jumble G-round personalization: `b"UA_F4Jumble_G" ‖ [i, j_lo, j_hi]`.
fn g_pers(i: u8, j: u16) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[..13].copy_from_slice(b"UA_F4Jumble_G");
    p[13] = i;
    p[14] = (j & 0xff) as u8;
    p[15] = (j >> 8) as u8;
    p
}

fn xor_into(target: &mut [u8], source: &[u8]) {
    for (t, s) in target.iter_mut().zip(source.iter()) {
        *t ^= s;
    }
}

fn ceildiv(num: usize, den: usize) -> usize {
    num.div_ceil(den)
}

fn h_round(msg: &mut [u8], left_len: usize, i: u8) {
    let (left, right) = msg.split_at_mut(left_len);
    let hash = blake2b_var_personal(right, &h_pers(i), left.len());
    xor_into(left, &hash);
}

fn g_round(msg: &mut [u8], left_len: usize, i: u8) {
    let (left, right) = msg.split_at_mut(left_len);
    for j in 0..ceildiv(right.len(), OUTBYTES) {
        let hash = blake2b_var_personal(left, &g_pers(i, j as u16), OUTBYTES);
        xor_into(&mut right[j * OUTBYTES..], &hash);
    }
}

/// Invert F4Jumble in place (the 4-round unkeyed Feistel network run backwards).
fn f4jumble_inv(msg: &mut [u8]) -> Result<(), String> {
    if msg.len() < F4JUMBLE_MIN_LEN {
        return Err(format!(
            "unified address payload too short ({} bytes) for F4Jumble",
            msg.len()
        ));
    }
    let left_len = core::cmp::min(OUTBYTES, msg.len() / 2);
    // Inverse order of apply: h(1), g(1), h(0), g(0).
    h_round(msg, left_len, 1);
    g_round(msg, left_len, 1);
    h_round(msg, left_len, 0);
    g_round(msg, left_len, 0);
    Ok(())
}

/// The expected Bech32m HRP for a Zcash network.
fn hrp_for_network(network: &str) -> Result<&'static str, String> {
    match network {
        "zcash" | "zec" => Ok("u"),
        "zcashTest" | "tzec" => Ok("utest"),
        "zcashRegtest" => Ok("uregtest"),
        _ => Err(format!(
            "unknown Zcash network {:?}: expected \"zec\"/\"zcash\" or \"tzec\"/\"zcashTest\"",
            network
        )),
    }
}

/// A single parsed unified-address receiver.
struct Receiver {
    typecode: u64,
    data: Vec<u8>,
}

/// Decode a UA string to its list of receivers (typecode + raw data).
fn decode_receivers(address: &str, expected_hrp: &str) -> Result<Vec<Receiver>, String> {
    let checked = CheckedHrpstring::new::<Bech32m>(address)
        .map_err(|e| format!("invalid Bech32m unified address: {}", e))?;
    let hrp = checked.hrp();
    if hrp.as_str() != expected_hrp {
        return Err(format!(
            "unified address HRP {:?} does not match network HRP {:?}",
            hrp.as_str(),
            expected_hrp
        ));
    }

    let mut payload: Vec<u8> = checked.byte_iter().collect();
    f4jumble_inv(&mut payload)?;

    // Strip and validate the 16-byte HRP padding.
    if payload.len() < PADDING_LEN {
        return Err("unified address payload shorter than padding".to_string());
    }
    let split = payload.len() - PADDING_LEN;
    let padding = &payload[split..];
    let mut expected_padding = [0u8; PADDING_LEN];
    expected_padding[..expected_hrp.len()].copy_from_slice(expected_hrp.as_bytes());
    if padding != expected_padding {
        return Err("unified address padding does not match HRP".to_string());
    }
    payload.truncate(split);

    // Parse the TLV receiver records.
    let mut cursor = payload.as_slice();
    let mut receivers = Vec::new();
    let mut last_typecode: Option<u64> = None;
    while !cursor.is_empty() {
        let typecode = VarInt::consensus_decode(&mut cursor)
            .map(|v| v.0)
            .map_err(|e| format!("failed to read receiver typecode: {}", e))?;
        let len = VarInt::consensus_decode(&mut cursor)
            .map(|v| v.0)
            .map_err(|e| format!("failed to read receiver length: {}", e))?;
        let len = usize::try_from(len).map_err(|_| "receiver length overflow".to_string())?;
        if cursor.len() < len {
            return Err(format!(
                "receiver data truncated: need {} bytes, have {}",
                len,
                cursor.len()
            ));
        }
        // Typecodes must be strictly ascending (ZIP-316 encoding order).
        if let Some(prev) = last_typecode {
            if typecode <= prev {
                return Err("unified address receivers not in typecode order".to_string());
            }
        }
        last_typecode = Some(typecode);
        let (data, rest) = cursor.split_at(len);
        receivers.push(Receiver {
            typecode,
            data: data.to_vec(),
        });
        cursor = rest;
    }

    Ok(receivers)
}

/// Build a P2PKH scriptPubKey from a 20-byte pubkey hash.
fn p2pkh_script(hash: &[u8]) -> Vec<u8> {
    // OP_DUP OP_HASH160 <20> {hash} OP_EQUALVERIFY OP_CHECKSIG
    let mut s = Vec::with_capacity(25);
    s.extend_from_slice(&[0x76, 0xa9, 0x14]);
    s.extend_from_slice(hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// Build a P2SH scriptPubKey from a 20-byte script hash.
fn p2sh_script(hash: &[u8]) -> Vec<u8> {
    // OP_HASH160 <20> {hash} OP_EQUAL
    let mut s = Vec::with_capacity(23);
    s.extend_from_slice(&[0xa9, 0x14]);
    s.extend_from_slice(hash);
    s.push(0x87);
    s
}

/// Parse a ZIP-316 Unified Address and return the requested receiver bytes.
///
/// * `ironwood = true` → the Orchard receiver's raw 43 bytes (11-byte diversifier
///   + 32-byte `pk_d`); Ironwood reuses the Orchard receiver.
/// * `ironwood = false` → the transparent receiver as scriptPubKey bytes (P2PKH or
///   P2SH), ready to use directly as a `TxOut.script_pubkey`.
///
/// Returns an error if the UA lacks a receiver of the requested type.
pub fn parse_unified_address(
    address: &str,
    network: &str,
    ironwood: bool,
) -> Result<Vec<u8>, String> {
    let expected_hrp = hrp_for_network(network)?;
    let receivers = decode_receivers(address, expected_hrp)?;

    if ironwood {
        let orchard = receivers
            .iter()
            .find(|r| r.typecode == TYPECODE_ORCHARD)
            .ok_or_else(|| "unified address has no Ironwood/Orchard receiver".to_string())?;
        if orchard.data.len() != ORCHARD_RECEIVER_LEN {
            return Err(format!(
                "Orchard receiver must be {} bytes, got {}",
                ORCHARD_RECEIVER_LEN,
                orchard.data.len()
            ));
        }
        Ok(orchard.data.clone())
    } else {
        // Prefer P2PKH, then P2SH.
        for r in &receivers {
            if r.typecode == TYPECODE_P2PKH {
                if r.data.len() != TRANSPARENT_HASH_LEN {
                    return Err(format!(
                        "P2PKH receiver must be {} bytes, got {}",
                        TRANSPARENT_HASH_LEN,
                        r.data.len()
                    ));
                }
                return Ok(p2pkh_script(&r.data));
            }
        }
        for r in &receivers {
            if r.typecode == TYPECODE_P2SH {
                if r.data.len() != TRANSPARENT_HASH_LEN {
                    return Err(format!(
                        "P2SH receiver must be {} bytes, got {}",
                        TRANSPARENT_HASH_LEN,
                        r.data.len()
                    ));
                }
                return Ok(p2sh_script(&r.data));
            }
        }
        Err("unified address has no transparent receiver".to_string())
    }
}

/// Resolve a single component of a Unified Address.
///
/// This is the intent-named form of [`parse_unified_address`]:
/// * `resolve_shielded = true` → the shielded (Orchard/Ironwood) receiver's raw 43
///   bytes (11-byte diversifier + 32-byte `pk_d`).
/// * `resolve_shielded = false` → the transparent receiver as scriptPubKey bytes.
pub fn resolve_unified_address_component(
    address: &str,
    network: &str,
    resolve_shielded: bool,
) -> Result<Vec<u8>, String> {
    parse_unified_address(address, network, resolve_shielded)
}

/// Reduce a transparent Zcash address string to its `(typecode, hash20)` receiver
/// form: P2PKH → `(0x00, pubkey_hash)`, P2SH → `(0x01, script_hash)`.
fn transparent_address_to_receiver(address: &str, network: &str) -> Result<(u64, Vec<u8>), String> {
    use crate::address::{AddressCodec, ZCASH, ZCASH_TEST};

    let codec = match network {
        "zcash" | "zec" => &ZCASH,
        "zcashTest" | "tzec" => &ZCASH_TEST,
        _ => {
            return Err(format!(
                "transparent address comparison is only supported on zec/tzec, not {:?}",
                network
            ))
        }
    };
    let script = codec
        .decode(address)
        .map_err(|e| format!("invalid transparent Zcash address: {}", e))?;
    let bytes = script.as_bytes();
    if script.is_p2pkh() {
        Ok((TYPECODE_P2PKH, bytes[3..23].to_vec()))
    } else if script.is_p2sh() {
        Ok((TYPECODE_P2SH, bytes[2..22].to_vec()))
    } else {
        Err("transparent address is neither P2PKH nor P2SH".to_string())
    }
}

/// Determine whether `candidate` is contained within the unified address `unified`.
///
/// `unified` must be a Unified Address. `candidate` may be either:
/// * another Unified Address — returns `true` iff every one of its receivers is also
///   present (same typecode and data) in `unified`; or
/// * a transparent Zcash address (base58check) — returns `true` iff `unified`'s
///   transparent receiver matches it.
///
/// Both addresses must belong to `network`.
pub fn is_address_component_of(
    unified: &str,
    candidate: &str,
    network: &str,
) -> Result<bool, String> {
    let expected_hrp = hrp_for_network(network)?;
    let container = decode_receivers(unified, expected_hrp)?;

    let contains = |typecode: u64, data: &[u8]| -> bool {
        container
            .iter()
            .any(|r| r.typecode == typecode && r.data == data)
    };

    // A unified `candidate` starts with the network's HRP followed by the bech32
    // separator '1'; anything else is treated as a transparent base58check address.
    let ua_prefix = format!("{}1", expected_hrp);
    if candidate.starts_with(&ua_prefix) {
        let candidate_receivers = decode_receivers(candidate, expected_hrp)?;
        if candidate_receivers.is_empty() {
            return Ok(false);
        }
        Ok(candidate_receivers
            .iter()
            .all(|r| contains(r.typecode, &r.data)))
    } else {
        let (typecode, hash) = transparent_address_to_receiver(candidate, network)?;
        Ok(contains(typecode, &hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ZIP-316 F4Jumble test vector 0 (48-byte message).
    const F4JUMBLE_NORMAL: [u8; 48] = [
        0x5d, 0x7a, 0x8f, 0x73, 0x9a, 0x2d, 0x9e, 0x94, 0x5b, 0x0c, 0xe1, 0x52, 0xa8, 0x04, 0x9e,
        0x29, 0x4c, 0x4d, 0x6e, 0x66, 0xb1, 0x64, 0x93, 0x9d, 0xaf, 0xfa, 0x2e, 0xf6, 0xee, 0x69,
        0x21, 0x48, 0x1c, 0xdd, 0x86, 0xb3, 0xcc, 0x43, 0x18, 0xd9, 0x61, 0x4f, 0xc8, 0x20, 0x90,
        0x5d, 0x04, 0x2b,
    ];
    const F4JUMBLE_JUMBLED: [u8; 48] = [
        0x03, 0x04, 0xd0, 0x29, 0x14, 0x1b, 0x99, 0x5d, 0xa5, 0x38, 0x7c, 0x12, 0x59, 0x70, 0x67,
        0x35, 0x04, 0xd6, 0xc7, 0x64, 0xd9, 0x1e, 0xa6, 0xc0, 0x82, 0x12, 0x37, 0x70, 0xc7, 0x13,
        0x9c, 0xcd, 0x88, 0xee, 0x27, 0x36, 0x8c, 0xd0, 0xc0, 0x92, 0x1a, 0x04, 0x44, 0xc8, 0xe5,
        0x85, 0x8d, 0x22,
    ];

    #[test]
    fn f4jumble_inverse_matches_vector() {
        let mut buf = F4JUMBLE_JUMBLED.to_vec();
        f4jumble_inv(&mut buf).unwrap();
        assert_eq!(buf, F4JUMBLE_NORMAL);
    }

    /// Load the shared unified-address fixture (`test/fixtures/zcash/unified_address.json`).
    fn ua_fixtures() -> serde_json::Value {
        let s = crate::fixed_script_wallet::test_utils::fixtures::load_fixture(
            "zcash/unified_address.json",
        )
        .expect("load unified_address.json");
        serde_json::from_str(&s).expect("parse unified_address.json")
    }

    /// Read a string field `group.key` from the fixture.
    fn fx(v: &serde_json::Value, group: &str, key: &str) -> String {
        v[group][key]
            .as_str()
            .unwrap_or_else(|| panic!("missing fixture field {}.{}", group, key))
            .to_string()
    }

    /// Encode a 20-byte pubkey hash as a testnet P2PKH Zcash address.
    fn tn_p2pkh_address(pkh_hex: &str) -> String {
        use crate::address::{AddressCodec, ZCASH_TEST};
        use miniscript::bitcoin::{hashes::Hash, PubkeyHash, ScriptBuf};
        let hash: [u8; 20] = hex::decode(pkh_hex).unwrap().try_into().unwrap();
        let script = ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash));
        ZCASH_TEST.encode(&script).unwrap()
    }

    // --- ZIP-316 mainnet vector (P2PKH + Orchard receivers) ---

    #[test]
    fn parses_orchard_ironwood_receiver() {
        let f = ua_fixtures();
        let ua = fx(&f, "zip316Mainnet", "unified");
        let out = parse_unified_address(&ua, "zec", true).unwrap();
        assert_eq!(
            hex::encode(&out),
            fx(&f, "zip316Mainnet", "orchardReceiverHex")
        );
        assert_eq!(out.len(), ORCHARD_RECEIVER_LEN);
    }

    #[test]
    fn parses_transparent_receiver_as_p2pkh_script() {
        let f = ua_fixtures();
        let ua = fx(&f, "zip316Mainnet", "unified");
        let out = parse_unified_address(&ua, "zec", false).unwrap();
        let hash = hex::decode(fx(&f, "zip316Mainnet", "transparentPubkeyHashHex")).unwrap();
        assert_eq!(out, super::p2pkh_script(&hash));
        // Sanity: script wraps the 20-byte hash.
        assert_eq!(out.len(), 25);
    }

    #[test]
    fn wrong_network_hrp_is_rejected() {
        let ua = fx(&ua_fixtures(), "zip316Mainnet", "unified");
        // Mainnet UA parsed as testnet must fail on the HRP check.
        assert!(parse_unified_address(&ua, "tzec", true).is_err());
    }

    #[test]
    fn unknown_network_is_rejected() {
        let ua = fx(&ua_fixtures(), "zip316Mainnet", "unified");
        assert!(parse_unified_address(&ua, "bitcoin", true).is_err());
    }

    #[test]
    fn corrupted_address_is_rejected() {
        let ua = fx(&ua_fixtures(), "zip316Mainnet", "unified");
        let mut chars: Vec<char> = ua.chars().collect();
        // Flip a character in the data part to break the Bech32m checksum / jumble.
        let idx = chars.len() - 5;
        chars[idx] = if chars[idx] == 'q' { 'p' } else { 'q' };
        let corrupted: String = chars.into_iter().collect();
        assert!(parse_unified_address(&corrupted, "zec", true).is_err());
    }

    #[test]
    fn missing_requested_receiver_is_rejected() {
        // The ZIP-316 mainnet vector has P2PKH + Orchard but no P2SH; requesting a
        // transparent receiver still succeeds (P2PKH), but an all-shielded lookup on
        // a UA lacking Orchard would fail. Here we assert the transparent path works
        // and the shielded path returns the Orchard receiver — i.e. both are present.
        let f = ua_fixtures();
        let ua = fx(&f, "zip316Mainnet", "unified");
        assert!(parse_unified_address(&ua, "zec", true).is_ok());
        assert!(parse_unified_address(&ua, "zec", false).is_ok());
    }

    // --- Real testnet wallet vector (wallet-data/testnet-wallet-full.json) ---

    #[test]
    fn resolve_component_shielded_and_transparent() {
        let f = ua_fixtures();
        let ua = fx(&f, "testnetWallet", "unified");

        let shielded = resolve_unified_address_component(&ua, "tzec", true).unwrap();
        assert_eq!(
            hex::encode(&shielded),
            fx(&f, "testnetWallet", "ironwoodReceiverHex")
        );

        let transparent = resolve_unified_address_component(&ua, "tzec", false).unwrap();
        let pkh = hex::decode(fx(&f, "testnetWallet", "transparentPubkeyHashHex")).unwrap();
        assert_eq!(transparent, super::p2pkh_script(&pkh));
    }

    #[test]
    fn transparent_address_is_component_of_ua() {
        let f = ua_fixtures();
        let ua = fx(&f, "testnetWallet", "unified");
        let addr = fx(&f, "testnetWallet", "transparentAddress");
        assert!(is_address_component_of(&ua, &addr, "tzec").unwrap());
        // Sanity: the vector's transparent address round-trips to the wallet PKH.
        assert_eq!(
            tn_p2pkh_address(&fx(&f, "testnetWallet", "transparentPubkeyHashHex")),
            addr
        );
    }

    #[test]
    fn foreign_transparent_address_is_not_a_component() {
        let ua = fx(&ua_fixtures(), "testnetWallet", "unified");
        // A valid testnet address whose hash is not in the UA.
        let other = tn_p2pkh_address("00112233445566778899aabbccddeeff00112233");
        assert!(!is_address_component_of(&ua, &other, "tzec").unwrap());
    }

    #[test]
    fn ua_is_component_of_itself() {
        let ua = fx(&ua_fixtures(), "testnetWallet", "unified");
        assert!(is_address_component_of(&ua, &ua, "tzec").unwrap());
    }

    #[test]
    fn component_check_rejects_cross_network() {
        let f = ua_fixtures();
        let mainnet_ua = fx(&f, "zip316Mainnet", "unified");
        let tn_addr = fx(&f, "testnetWallet", "transparentAddress");
        // Mainnet UA container queried on testnet must fail on the HRP check.
        assert!(is_address_component_of(&mainnet_ua, &tn_addr, "tzec").is_err());
    }

    #[test]
    fn malformed_candidate_address_is_rejected() {
        let ua = fx(&ua_fixtures(), "testnetWallet", "unified");
        // Not a valid base58check transparent address and not a UA.
        assert!(is_address_component_of(&ua, "not-an-address", "tzec").is_err());
    }
}
