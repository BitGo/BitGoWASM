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
//! Parsing needs only Bech32m + F4Jumble⁻¹ + typecode scanning — no `orchard`
//! crate, no ZK machinery. The exact wire format and F4Jumble algorithm this file
//! implements are vendored in `docs/zip-0316-unified-address.md`.
//!
//! # API
//!
//! [`UnifiedAddress::parse`] decodes a UA once; the individual components are then
//! read through named accessors ([`UnifiedAddress::transparent_script`],
//! [`UnifiedAddress::orchard_receiver`], …). [`UnifiedAddress::contains`] answers
//! whether another address (a UA or a transparent address) is a receiver of this UA.

use super::blake2b::blake2b_var_personal;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::Bech32m;
use core::fmt;
use miniscript::bitcoin::consensus::{Decodable, Encodable};
use miniscript::bitcoin::VarInt;

/// Errors produced while parsing or inspecting a ZIP-316 Unified Address.
///
/// The variant name is surfaced to JS as `err.code` (e.g.
/// `"UnifiedAddressError.WrongHrp"`) via [`crate::error::WasmUtxoError`], so callers
/// can branch on the error kind instead of matching message text.
#[derive(Debug, strum::IntoStaticStr)]
pub enum UnifiedAddressError {
    /// The string is not valid Bech32m.
    BadBech32(String),
    /// Unknown Zcash network name.
    UnknownNetwork(String),
    /// The address HRP does not match the requested network.
    WrongHrp,
    /// The F4Jumble payload length is outside ZIP-316 `VALID_LENGTH` (48..=4194368).
    InvalidLength,
    /// The un-jumbled payload is shorter than the 16-byte HRP padding.
    PayloadTooShort,
    /// The trailing padding does not equal the zero-extended HRP.
    BadPadding,
    /// A receiver typecode or length CompactSize could not be read (or is non-minimal).
    BadReceiverEncoding(String),
    /// A receiver length does not fit in `usize`.
    ReceiverLengthOverflow,
    /// A receiver's declared length runs past the end of the payload.
    TruncatedReceiver,
    /// Receivers are not in strictly ascending typecode order (ZIP-316).
    ReceiverOrder,
    /// A receiver has an unexpected byte length for its type.
    BadReceiverLength,
    /// The address has no shielded receiver; ZIP-316 forbids transparent-only UAs.
    NoShieldedReceiver,
    /// The candidate is not a valid transparent Zcash P2PKH/P2SH address.
    BadTransparentAddress(String),
}

impl fmt::Display for UnifiedAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadBech32(e) => write!(f, "invalid Bech32m unified address: {e}"),
            Self::UnknownNetwork(n) => write!(
                f,
                "unknown Zcash network {n:?}: expected \"zec\"/\"zcash\" or \"tzec\"/\"zcashTest\""
            ),
            Self::WrongHrp => write!(f, "unified address HRP does not match the network"),
            Self::InvalidLength => write!(f, "unified address payload length out of F4Jumble range"),
            Self::PayloadTooShort => write!(f, "unified address payload shorter than padding"),
            Self::BadPadding => write!(f, "unified address padding does not match HRP"),
            Self::BadReceiverEncoding(e) => write!(f, "failed to read receiver field: {e}"),
            Self::ReceiverLengthOverflow => write!(f, "receiver length overflow"),
            Self::TruncatedReceiver => write!(f, "receiver data truncated"),
            Self::ReceiverOrder => write!(f, "unified address receivers not in typecode order"),
            Self::BadReceiverLength => write!(f, "receiver has an unexpected byte length"),
            Self::NoShieldedReceiver => write!(
                f,
                "unified address has no shielded receiver (transparent-only UAs are invalid per ZIP-316)"
            ),
            Self::BadTransparentAddress(e) => write!(f, "invalid transparent Zcash address: {e}"),
        }
    }
}

crate::impl_wasm_error_code!(UnifiedAddressError);

/// ZIP-316 receiver typecodes.
const TYPECODE_P2PKH: u64 = 0x00;
const TYPECODE_P2SH: u64 = 0x01;
const TYPECODE_SAPLING: u64 = 0x02;
/// Orchard receiver typecode; Ironwood reuses it.
const TYPECODE_ORCHARD: u64 = 0x03;

/// Expected raw length of a Sapling or Orchard/Ironwood receiver (11-byte
/// diversifier + 32-byte pk_d).
const SHIELDED_RECEIVER_LEN: usize = 43;
/// Length of a transparent receiver's 20-byte hash (pubkey hash or script hash).
const TRANSPARENT_HASH_LEN: usize = 20;

/// Length of the trailing HRP padding, in bytes.
const PADDING_LEN: usize = 16;
/// Minimum valid F4Jumbled message length (ZIP-316 `VALID_LENGTH`).
const F4JUMBLE_MIN_LEN: usize = 48;
/// Maximum valid F4Jumbled message length (ZIP-316 `VALID_LENGTH`).
const F4JUMBLE_MAX_LEN: usize = 4_194_368;
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
fn f4jumble_inv(msg: &mut [u8]) -> Result<(), UnifiedAddressError> {
    if !(F4JUMBLE_MIN_LEN..=F4JUMBLE_MAX_LEN).contains(&msg.len()) {
        return Err(UnifiedAddressError::InvalidLength);
    }
    let left_len = core::cmp::min(OUTBYTES, msg.len() / 2);
    // Inverse order of apply: h(1), g(1), h(0), g(0).
    h_round(msg, left_len, 1);
    g_round(msg, left_len, 1);
    h_round(msg, left_len, 0);
    g_round(msg, left_len, 0);
    Ok(())
}

/// Apply F4Jumble in place (the 4-round unkeyed Feistel network forwards) — the exact inverse of
/// [`f4jumble_inv`]: a Feistel network inverts by running the same per-round updates in reverse
/// round order, so this applies `g(0), h(0), g(1), h(1)`.
fn f4jumble(msg: &mut [u8]) -> Result<(), UnifiedAddressError> {
    if !(F4JUMBLE_MIN_LEN..=F4JUMBLE_MAX_LEN).contains(&msg.len()) {
        return Err(UnifiedAddressError::InvalidLength);
    }
    let left_len = core::cmp::min(OUTBYTES, msg.len() / 2);
    g_round(msg, left_len, 0);
    h_round(msg, left_len, 0);
    g_round(msg, left_len, 1);
    h_round(msg, left_len, 1);
    Ok(())
}

/// The expected Bech32m HRP for a Zcash network.
///
/// Only mainnet (`zec`/`zcash`) and testnet (`tzec`/`zcashTest`) are supported —
/// consistently across parsing and transparent-address comparison. Regtest is not
/// supported (there is no corresponding transparent base58check codec here).
fn hrp_for_network(network: &str) -> Result<&'static str, UnifiedAddressError> {
    match network {
        "zcash" | "zec" => Ok("u"),
        "zcashTest" | "tzec" => Ok("utest"),
        _ => Err(UnifiedAddressError::UnknownNetwork(network.to_string())),
    }
}

/// A single parsed unified-address receiver.
struct Receiver {
    typecode: u64,
    data: Vec<u8>,
}

/// Decode a UA string to its list of receivers (typecode + raw data).
fn decode_receivers(
    address: &str,
    expected_hrp: &str,
) -> Result<Vec<Receiver>, UnifiedAddressError> {
    let checked = CheckedHrpstring::new::<Bech32m>(address)
        .map_err(|e| UnifiedAddressError::BadBech32(e.to_string()))?;
    let hrp = checked.hrp();
    if hrp.as_str() != expected_hrp {
        return Err(UnifiedAddressError::WrongHrp);
    }

    let mut payload: Vec<u8> = checked.byte_iter().collect();
    f4jumble_inv(&mut payload)?;

    // Strip and validate the 16-byte HRP padding.
    if payload.len() < PADDING_LEN {
        return Err(UnifiedAddressError::PayloadTooShort);
    }
    let split = payload.len() - PADDING_LEN;
    let padding = &payload[split..];
    let mut expected_padding = [0u8; PADDING_LEN];
    expected_padding[..expected_hrp.len()].copy_from_slice(expected_hrp.as_bytes());
    if padding != expected_padding {
        return Err(UnifiedAddressError::BadPadding);
    }
    payload.truncate(split);

    // Parse the TLV receiver records. `VarInt::consensus_decode` rejects
    // non-minimal CompactSize, so typecodes/lengths must be canonically encoded.
    let mut cursor = payload.as_slice();
    let mut receivers = Vec::new();
    let mut last_typecode: Option<u64> = None;
    while !cursor.is_empty() {
        let typecode = VarInt::consensus_decode(&mut cursor)
            .map(|v| v.0)
            .map_err(|e| UnifiedAddressError::BadReceiverEncoding(e.to_string()))?;
        let len = VarInt::consensus_decode(&mut cursor)
            .map(|v| v.0)
            .map_err(|e| UnifiedAddressError::BadReceiverEncoding(e.to_string()))?;
        let len = usize::try_from(len).map_err(|_| UnifiedAddressError::ReceiverLengthOverflow)?;
        if cursor.len() < len {
            return Err(UnifiedAddressError::TruncatedReceiver);
        }
        // Typecodes must be strictly ascending (ZIP-316 encoding order).
        if let Some(prev) = last_typecode {
            if typecode <= prev {
                return Err(UnifiedAddressError::ReceiverOrder);
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

/// Encode a single Orchard/Ironwood receiver as a ZIP-316 Unified Address for `network`.
///
/// Deliberately narrower than a general UA encoder: BitGo never needs to *build* a UA carrying
/// more than one receiver (a transparent + Sapling + Orchard combo, say) — only to hand back a
/// human-readable address for a shielded output whose raw receiver it already has. A single-
/// receiver UA is a valid ZIP-316 address in its own right (receivers ⩾ 1, and typecode ordering
/// is trivially satisfied with only one), so this covers that case exactly without the added
/// receiver-merging logic a general encoder would need.
pub fn encode_orchard_receiver(
    receiver: &[u8; SHIELDED_RECEIVER_LEN],
    network: &str,
) -> Result<String, UnifiedAddressError> {
    let expected_hrp = hrp_for_network(network)?;

    // TLV receiver record: CompactSize(typecode) ‖ CompactSize(length) ‖ data.
    let mut payload = Vec::with_capacity(2 + SHIELDED_RECEIVER_LEN + PADDING_LEN);
    VarInt(TYPECODE_ORCHARD)
        .consensus_encode(&mut payload)
        .expect("Vec<u8> writes are infallible");
    VarInt(SHIELDED_RECEIVER_LEN as u64)
        .consensus_encode(&mut payload)
        .expect("Vec<u8> writes are infallible");
    payload.extend_from_slice(receiver);

    // Trailing 16-byte padding: the HRP, zero-extended.
    let mut padding = [0u8; PADDING_LEN];
    padding[..expected_hrp.len()].copy_from_slice(expected_hrp.as_bytes());
    payload.extend_from_slice(&padding);

    f4jumble(&mut payload)?;

    let hrp = bech32::Hrp::parse(expected_hrp).expect("hrp_for_network returns a valid HRP");
    bech32::encode::<Bech32m>(hrp, &payload)
        .map_err(|e| UnifiedAddressError::BadBech32(e.to_string()))
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

/// Reduce a transparent Zcash address string to its `(typecode, hash20)` receiver
/// form: P2PKH → `(0x00, pubkey_hash)`, P2SH → `(0x01, script_hash)`.
fn transparent_address_to_receiver(
    address: &str,
    network: &str,
) -> Result<(u64, Vec<u8>), UnifiedAddressError> {
    use crate::address::{AddressCodec, ZCASH, ZCASH_TEST};

    let codec = match network {
        "zcash" | "zec" => &ZCASH,
        "zcashTest" | "tzec" => &ZCASH_TEST,
        _ => return Err(UnifiedAddressError::UnknownNetwork(network.to_string())),
    };
    let script = codec
        .decode(address)
        .map_err(|e| UnifiedAddressError::BadTransparentAddress(e.to_string()))?;
    let bytes = script.as_bytes();
    if script.is_p2pkh() {
        Ok((TYPECODE_P2PKH, bytes[3..23].to_vec()))
    } else if script.is_p2sh() {
        Ok((TYPECODE_P2SH, bytes[2..22].to_vec()))
    } else {
        Err(UnifiedAddressError::BadTransparentAddress(
            "address is neither P2PKH nor P2SH".to_string(),
        ))
    }
}

/// Does `candidate` decode as a Bech32m string whose HRP is `expected_hrp`?
///
/// Used to distinguish a unified-address candidate from a transparent one without
/// relying on a fragile string prefix.
fn looks_like_unified(candidate: &str, expected_hrp: &str) -> bool {
    CheckedHrpstring::new::<Bech32m>(candidate)
        .map(|c| c.hrp().as_str() == expected_hrp)
        .unwrap_or(false)
}

/// Does `candidate` look like a unified address for `network` (Bech32m with this network's
/// HRP)? `false` for an unknown network name, same as any other non-match.
///
/// For a caller that needs to route between "parse as a unified address" and "parse as a
/// transparent address" (e.g. [`crate::zcash::address::to_output_script_or_shielded_receiver_with_coin`]):
/// this only sniffs the HRP, so it can't itself distinguish a well-formed UA from a malformed
/// one — callers that get `true` should still handle [`UnifiedAddress::parse`] failing.
pub fn looks_like_unified_for_network(candidate: &str, network: &str) -> bool {
    match hrp_for_network(network) {
        Ok(expected_hrp) => looks_like_unified(candidate, expected_hrp),
        Err(_) => false,
    }
}

/// A parsed ZIP-316 Unified Address.
///
/// Decode once with [`UnifiedAddress::parse`], then read each component through its
/// named accessor. Absent receivers return `None`.
pub struct UnifiedAddress {
    network: String,
    receivers: Vec<Receiver>,
}

impl UnifiedAddress {
    /// Parse a Unified Address for the given network (`zec`/`zcash` or `tzec`/`zcashTest`).
    ///
    /// Rejects a spec-invalid UA that carries no shielded (Sapling or Orchard/Ironwood)
    /// receiver — ZIP-316 forbids transparent-only (and empty) Unified Addresses.
    pub fn parse(address: &str, network: &str) -> Result<Self, UnifiedAddressError> {
        let expected_hrp = hrp_for_network(network)?;
        let receivers = decode_receivers(address, expected_hrp)?;
        let has_shielded = receivers
            .iter()
            .any(|r| r.typecode == TYPECODE_SAPLING || r.typecode == TYPECODE_ORCHARD);
        if !has_shielded {
            return Err(UnifiedAddressError::NoShieldedReceiver);
        }
        Ok(UnifiedAddress {
            network: network.to_string(),
            receivers,
        })
    }

    fn receiver_data(&self, typecode: u64) -> Option<&[u8]> {
        self.receivers
            .iter()
            .find(|r| r.typecode == typecode)
            .map(|r| r.data.as_slice())
    }

    fn shielded_receiver(&self, typecode: u64) -> Result<Option<Vec<u8>>, UnifiedAddressError> {
        match self.receiver_data(typecode) {
            None => Ok(None),
            Some(data) if data.len() == SHIELDED_RECEIVER_LEN => Ok(Some(data.to_vec())),
            Some(_) => Err(UnifiedAddressError::BadReceiverLength),
        }
    }

    fn transparent_hash(&self, typecode: u64) -> Result<Option<&[u8]>, UnifiedAddressError> {
        match self.receiver_data(typecode) {
            None => Ok(None),
            Some(data) if data.len() == TRANSPARENT_HASH_LEN => Ok(Some(data)),
            Some(_) => Err(UnifiedAddressError::BadReceiverLength),
        }
    }

    /// The Orchard/Ironwood receiver's raw 43 bytes (diversifier + `pk_d`), if present.
    ///
    /// Ironwood reuses the Orchard receiver, so this is the shielded receiver used to
    /// construct an Ironwood output note.
    pub fn orchard_receiver(&self) -> Result<Option<Vec<u8>>, UnifiedAddressError> {
        self.shielded_receiver(TYPECODE_ORCHARD)
    }

    /// The Sapling receiver's raw 43 bytes (diversifier + `pk_d`), if present.
    pub fn sapling_receiver(&self) -> Result<Option<Vec<u8>>, UnifiedAddressError> {
        self.shielded_receiver(TYPECODE_SAPLING)
    }

    /// The transparent receiver as scriptPubKey bytes (P2PKH or P2SH), if present.
    ///
    /// Ready to use directly as a `TxOut.script_pubkey`. Prefers P2PKH over P2SH when
    /// both are present (a UA holds at most one of each in practice).
    pub fn transparent_script(&self) -> Result<Option<Vec<u8>>, UnifiedAddressError> {
        if let Some(hash) = self.transparent_hash(TYPECODE_P2PKH)? {
            return Ok(Some(p2pkh_script(hash)));
        }
        if let Some(hash) = self.transparent_hash(TYPECODE_P2SH)? {
            return Ok(Some(p2sh_script(hash)));
        }
        Ok(None)
    }

    /// Determine whether `candidate` is a receiver of this unified address.
    ///
    /// `candidate` may be either another Unified Address (true iff every one of its
    /// receivers is also present here) or a transparent Zcash address (true iff this
    /// UA's transparent receiver matches it). `candidate` must be on the same network.
    pub fn contains(&self, candidate: &str) -> Result<bool, UnifiedAddressError> {
        let expected_hrp = hrp_for_network(&self.network)?;
        let has = |typecode: u64, data: &[u8]| -> bool {
            self.receivers
                .iter()
                .any(|r| r.typecode == typecode && r.data == data)
        };

        if looks_like_unified(candidate, expected_hrp) {
            let candidate_receivers = decode_receivers(candidate, expected_hrp)?;
            if candidate_receivers.is_empty() {
                return Ok(false);
            }
            Ok(candidate_receivers.iter().all(|r| has(r.typecode, &r.data)))
        } else {
            let (typecode, hash) = transparent_address_to_receiver(candidate, &self.network)?;
            Ok(has(typecode, &hash))
        }
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

    #[test]
    fn f4jumble_forward_matches_vector() {
        let mut buf = F4JUMBLE_NORMAL.to_vec();
        f4jumble(&mut buf).unwrap();
        assert_eq!(buf, F4JUMBLE_JUMBLED);
    }

    #[test]
    fn f4jumble_and_inverse_round_trip() {
        let mut buf: Vec<u8> = (0..200u16).map(|i| (i % 256) as u8).collect();
        let original = buf.clone();
        f4jumble(&mut buf).unwrap();
        assert_ne!(buf, original, "jumbling actually changes the bytes");
        f4jumble_inv(&mut buf).unwrap();
        assert_eq!(buf, original);
    }

    #[test]
    fn f4jumble_rejects_out_of_range_length() {
        assert!(f4jumble_inv(&mut [0u8; 47]).is_err());
    }

    mod encode_orchard_receiver_tests {
        use super::*;

        fn ua_fixtures() -> serde_json::Value {
            let s = crate::fixed_script_wallet::test_utils::fixtures::load_fixture(
                "zcash/unified_address.json",
            )
            .expect("load unified_address.json");
            serde_json::from_str(&s).expect("parse unified_address.json")
        }

        #[test]
        fn round_trips_through_parse_for_both_networks() {
            for (group, network) in [("zip316Mainnet", "zec"), ("testnetWallet", "tzec")] {
                let f = ua_fixtures();
                let receiver_hex = f[group]["orchardReceiverHex"]
                    .as_str()
                    .or_else(|| f[group]["ironwoodReceiverHex"].as_str())
                    .unwrap_or_else(|| panic!("missing orchard/ironwood receiver for {group}"));
                let receiver: [u8; SHIELDED_RECEIVER_LEN] =
                    hex::decode(receiver_hex).unwrap().try_into().unwrap();

                let encoded = encode_orchard_receiver(&receiver, network).unwrap();
                let parsed = UnifiedAddress::parse(&encoded, network).unwrap();
                assert_eq!(
                    parsed.orchard_receiver().unwrap().expect("orchard present"),
                    receiver.to_vec(),
                    "{group}: round-tripped receiver must match the original"
                );
            }
        }

        #[test]
        fn produces_the_correct_hrp_for_each_network() {
            let receiver = [0u8; SHIELDED_RECEIVER_LEN];
            assert!(encode_orchard_receiver(&receiver, "zec")
                .unwrap()
                .starts_with("u1"));
            assert!(encode_orchard_receiver(&receiver, "tzec")
                .unwrap()
                .starts_with("utest1"));
            // Both coin-name spellings for a network must produce byte-identical addresses.
            assert_eq!(
                encode_orchard_receiver(&receiver, "zcash").unwrap(),
                encode_orchard_receiver(&receiver, "zec").unwrap(),
            );
            assert_eq!(
                encode_orchard_receiver(&receiver, "zcashTest").unwrap(),
                encode_orchard_receiver(&receiver, "tzec").unwrap(),
            );
        }

        #[test]
        fn is_deterministic() {
            let receiver = [0x42u8; SHIELDED_RECEIVER_LEN];
            assert_eq!(
                encode_orchard_receiver(&receiver, "zec").unwrap(),
                encode_orchard_receiver(&receiver, "zec").unwrap(),
            );
        }

        #[test]
        fn rejects_an_unknown_network() {
            let receiver = [0u8; SHIELDED_RECEIVER_LEN];
            assert!(encode_orchard_receiver(&receiver, "bitcoin").is_err());
        }
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
    fn parses_orchard_and_transparent_components() {
        let f = ua_fixtures();
        let ua = UnifiedAddress::parse(&fx(&f, "zip316Mainnet", "unified"), "zec").unwrap();

        let orchard = ua.orchard_receiver().unwrap().expect("orchard present");
        assert_eq!(
            hex::encode(&orchard),
            fx(&f, "zip316Mainnet", "orchardReceiverHex")
        );
        assert_eq!(orchard.len(), SHIELDED_RECEIVER_LEN);

        let script = ua
            .transparent_script()
            .unwrap()
            .expect("transparent present");
        let hash = hex::decode(fx(&f, "zip316Mainnet", "transparentPubkeyHashHex")).unwrap();
        assert_eq!(script, super::p2pkh_script(&hash));
    }

    #[test]
    fn wrong_network_hrp_is_rejected() {
        let ua = fx(&ua_fixtures(), "zip316Mainnet", "unified");
        // Mainnet UA parsed as testnet must fail on the HRP check.
        assert!(UnifiedAddress::parse(&ua, "tzec").is_err());
    }

    #[test]
    fn unknown_network_is_rejected() {
        let ua = fx(&ua_fixtures(), "zip316Mainnet", "unified");
        assert!(UnifiedAddress::parse(&ua, "bitcoin").is_err());
    }

    #[test]
    fn corrupted_address_is_rejected() {
        let ua = fx(&ua_fixtures(), "zip316Mainnet", "unified");
        let mut chars: Vec<char> = ua.chars().collect();
        // Flip a character in the data part to break the Bech32m checksum / jumble.
        let idx = chars.len() - 5;
        chars[idx] = if chars[idx] == 'q' { 'p' } else { 'q' };
        let corrupted: String = chars.into_iter().collect();
        assert!(UnifiedAddress::parse(&corrupted, "zec").is_err());
    }

    // --- Real testnet wallet vector (wallet-data/testnet-wallet-full.json) ---

    #[test]
    fn resolves_wallet_components() {
        let f = ua_fixtures();
        let ua = UnifiedAddress::parse(&fx(&f, "testnetWallet", "unified"), "tzec").unwrap();

        assert_eq!(
            hex::encode(ua.orchard_receiver().unwrap().unwrap()),
            fx(&f, "testnetWallet", "ironwoodReceiverHex")
        );
        let pkh = hex::decode(fx(&f, "testnetWallet", "transparentPubkeyHashHex")).unwrap();
        assert_eq!(
            ua.transparent_script().unwrap().unwrap(),
            super::p2pkh_script(&pkh)
        );
    }

    #[test]
    fn contains_transparent_and_self() {
        let f = ua_fixtures();
        let ua_str = fx(&f, "testnetWallet", "unified");
        let ua = UnifiedAddress::parse(&ua_str, "tzec").unwrap();
        let addr = fx(&f, "testnetWallet", "transparentAddress");

        assert!(ua.contains(&addr).unwrap());
        assert!(ua.contains(&ua_str).unwrap());
        // Sanity: the vector's transparent address round-trips to the wallet PKH.
        assert_eq!(
            tn_p2pkh_address(&fx(&f, "testnetWallet", "transparentPubkeyHashHex")),
            addr
        );
    }

    #[test]
    fn foreign_transparent_address_is_not_a_component() {
        let ua =
            UnifiedAddress::parse(&fx(&ua_fixtures(), "testnetWallet", "unified"), "tzec").unwrap();
        // A valid testnet address whose hash is not in the UA.
        let other = tn_p2pkh_address("00112233445566778899aabbccddeeff00112233");
        assert!(!ua.contains(&other).unwrap());
    }

    #[test]
    fn contains_rejects_cross_network_candidate() {
        let f = ua_fixtures();
        // testnet UA container, mainnet UA candidate → candidate is not a testnet UA
        // and not a valid tzec transparent address → error.
        let ua = UnifiedAddress::parse(&fx(&f, "testnetWallet", "unified"), "tzec").unwrap();
        let mainnet_ua = fx(&f, "zip316Mainnet", "unified");
        assert!(ua.contains(&mainnet_ua).is_err());
    }

    #[test]
    fn contains_rejects_malformed_candidate() {
        let ua =
            UnifiedAddress::parse(&fx(&ua_fixtures(), "testnetWallet", "unified"), "tzec").unwrap();
        assert!(ua.contains("not-an-address").is_err());
    }

    #[test]
    fn wrong_hrp_error_is_typed() {
        // Parsing a mainnet UA as testnet yields WrongHrp — a typed variant, not a
        // stringly error.
        let ua = fx(&ua_fixtures(), "zip316Mainnet", "unified");
        assert!(matches!(
            UnifiedAddress::parse(&ua, "tzec"),
            Err(UnifiedAddressError::WrongHrp)
        ));
    }

    #[test]
    fn errors_expose_wasm_error_codes() {
        // The variant name is surfaced to JS as `err.code` via WasmUtxoError.
        use crate::error::{WasmErrorCode, WasmUtxoError};
        let cases = [
            (
                UnifiedAddressError::WrongHrp,
                "UnifiedAddressError.WrongHrp",
            ),
            (
                UnifiedAddressError::NoShieldedReceiver,
                "UnifiedAddressError.NoShieldedReceiver",
            ),
            (
                UnifiedAddressError::UnknownNetwork("btc".into()),
                "UnifiedAddressError.UnknownNetwork",
            ),
        ];
        for (err, expected_code) in cases {
            assert_eq!(err.code(), expected_code);
            // And it maps through WasmUtxoError with the same code.
            assert_eq!(WasmUtxoError::from(err).code(), expected_code);
        }
    }
}
