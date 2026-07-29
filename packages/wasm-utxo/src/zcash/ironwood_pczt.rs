//! Serialization of an `orchard` **PCZT** (Partially Constructed Zcash Transaction) Ironwood
//! bundle — the witness payload exchanged with the external Ironwood proof service and carried
//! through the PSBT.
//!
//! `orchard::pczt::Bundle` is not itself serde-serializable, so this module bridges it to a
//! compact wire form: a 1-byte [`FORMAT_VERSION`] followed by a [`postcard`]-encoded *mirror*
//! struct whose fields are exactly what `orchard`'s `Bundle/Action/Spend/Output::parse(...)`
//! consume. Serialize reads the bundle's public getters; deserialize reconstructs it via
//! `parse(...)`. Both `wasm-utxo` (build/combine) and the proof service (prove) use this format;
//! see `docs/ironwood-proof-service-contract.md`.
//!
//! Fields orchard exposes only as `>32`-byte arrays are stored as `Vec<u8>` (serde derives arrays
//! only up to length 32) and length-checked on the way back in. `zip32_derivation` is not a
//! `parse()` input and is intentionally dropped — the prover does not need it.

use std::collections::BTreeMap;

use ff::PrimeField;
use serde::{Deserialize, Serialize};

use orchard::bundle::BundleVersion;
use orchard::note::{NoteVersion, Nullifier};
use orchard::pczt::{
    Action as PcztAction, Bundle as PcztBundle, Output as PcztOutput, Spend as PcztSpend,
};
use orchard::value::Sign;
use orchard::{ProtocolVersion, ValuePool};

/// Wire format version; bump on any layout change (deserialize rejects unknown versions).
pub const FORMAT_VERSION: u8 = 0x01;

/// Errors from Ironwood PCZT (de)serialization.
#[derive(Debug, strum::IntoStaticStr)]
pub enum IronwoodPcztError {
    /// The `postcard` payload could not be encoded/decoded.
    Codec(String),
    /// Unknown/unsupported [`FORMAT_VERSION`] byte.
    UnsupportedVersion(u8),
    /// Empty input (no version byte).
    Empty,
    /// A byte field had the wrong length: (field, expected, actual).
    BadLength(&'static str, usize, usize),
    /// An unrepresentable (value_pool, protocol_version) combination.
    BadBundleVersion(u8, u8),
    /// A field that must decode to a valid curve/commitment value did not.
    BadFieldEncoding(&'static str),
    /// orchard rejected the reconstructed bundle.
    Parse(String),
}

impl core::fmt::Display for IronwoodPcztError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec(e) => write!(f, "ironwood-pczt: postcard codec error: {e}"),
            Self::UnsupportedVersion(v) => {
                write!(f, "ironwood-pczt: unsupported format version {v}")
            }
            Self::Empty => write!(f, "ironwood-pczt: empty input"),
            Self::BadLength(field, exp, act) => {
                write!(
                    f,
                    "ironwood-pczt: field {field} must be {exp} bytes, got {act}"
                )
            }
            Self::BadBundleVersion(vp, pv) => {
                write!(
                    f,
                    "ironwood-pczt: unrepresentable bundle version (pool {vp}, protocol {pv})"
                )
            }
            Self::BadFieldEncoding(field) => {
                write!(f, "ironwood-pczt: invalid encoding for {field}")
            }
            Self::Parse(e) => write!(f, "ironwood-pczt: orchard rejected the bundle: {e}"),
        }
    }
}

crate::impl_wasm_error_code!(IronwoodPcztError);

// ---- Mirror structs (serde ⇄ postcard) ----

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
struct BundleWire {
    flags: u8,
    value_pool: u8,       // 0 = Orchard, 1 = Ironwood
    protocol_version: u8, // 0 = InsecureV1, 1 = V2, 2 = V3
    value_sum_magnitude: u64,
    value_sum_negative: bool,
    anchor: [u8; 32],
    zkproof: Option<Vec<u8>>,
    bsk: Option<[u8; 32]>,
    actions: Vec<ActionWire>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
struct ActionWire {
    cv_net: [u8; 32],
    rcv: Option<[u8; 32]>,
    spend: SpendWire,
    output: OutputWire,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
struct SpendWire {
    nullifier: [u8; 32],
    rk: [u8; 32],
    spend_auth_sig: Option<Vec<u8>>, // 64
    recipient: Option<Vec<u8>>,      // 43
    value: Option<u64>,
    rho: Option<[u8; 32]>,
    rseed: Option<[u8; 32]>,
    fvk: Option<Vec<u8>>, // 96
    witness: Option<WitnessWire>,
    alpha: Option<[u8; 32]>,
    dummy_sk: Option<[u8; 32]>,
    proprietary: BTreeMap<String, Vec<u8>>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
struct WitnessWire {
    position: u32,
    auth_path: Vec<[u8; 32]>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
struct OutputWire {
    cmx: [u8; 32],
    ephemeral_key: [u8; 32],
    enc_ciphertext: Vec<u8>, // 580
    out_ciphertext: Vec<u8>, // 80
    recipient: Option<Vec<u8>>,
    value: Option<u64>,
    rseed: Option<[u8; 32]>,
    ock: Option<[u8; 32]>,
    user_address: Option<String>,
    proprietary: BTreeMap<String, Vec<u8>>,
}

// ---- Public API ----

/// Serialize an `orchard` PCZT Ironwood bundle to its wire form.
pub fn serialize_pczt(bundle: &PcztBundle) -> Result<Vec<u8>, IronwoodPcztError> {
    let wire = bundle_to_wire(bundle);
    let mut out = Vec::with_capacity(1 + 4096);
    out.push(FORMAT_VERSION);
    let body = postcard::to_stdvec(&wire).map_err(|e| IronwoodPcztError::Codec(e.to_string()))?;
    out.extend_from_slice(&body);
    Ok(out)
}

/// Reconstruct an `orchard` PCZT Ironwood bundle from its wire form.
pub fn deserialize_pczt(bytes: &[u8]) -> Result<PcztBundle, IronwoodPcztError> {
    let (&version, body) = bytes.split_first().ok_or(IronwoodPcztError::Empty)?;
    if version != FORMAT_VERSION {
        return Err(IronwoodPcztError::UnsupportedVersion(version));
    }
    let wire: BundleWire =
        postcard::from_bytes(body).map_err(|e| IronwoodPcztError::Codec(e.to_string()))?;
    wire_to_bundle(wire)
}

// ---- orchard bundle -> wire ----

fn bundle_to_wire(bundle: &PcztBundle) -> BundleWire {
    let (magnitude, sign) = bundle.value_sum().magnitude_sign();
    BundleWire {
        flags: bundle.flag_byte(),
        value_pool: match bundle.bundle_version().value_pool() {
            ValuePool::Orchard => 0,
            ValuePool::Ironwood => 1,
        },
        protocol_version: match bundle.bundle_version().protocol_version() {
            ProtocolVersion::InsecureV1 => 0,
            ProtocolVersion::V2 => 1,
            ProtocolVersion::V3 => 2,
        },
        value_sum_magnitude: magnitude,
        value_sum_negative: matches!(sign, Sign::Negative),
        anchor: bundle.anchor().to_bytes(),
        zkproof: bundle.zkproof().as_ref().map(|p| p.as_ref().to_vec()),
        bsk: bundle.bsk().as_ref().map(<[u8; 32]>::from),
        actions: bundle.actions().iter().map(action_to_wire).collect(),
    }
}

fn action_to_wire(a: &PcztAction) -> ActionWire {
    ActionWire {
        cv_net: a.cv_net().to_bytes(),
        rcv: a.rcv().as_ref().map(|r| r.to_bytes()),
        spend: spend_to_wire(a.spend()),
        output: output_to_wire(a.output()),
    }
}

fn spend_to_wire(s: &PcztSpend) -> SpendWire {
    SpendWire {
        nullifier: s.nullifier().to_bytes(),
        rk: <[u8; 32]>::from(s.rk()),
        spend_auth_sig: s
            .spend_auth_sig()
            .as_ref()
            .map(|sig| <[u8; 64]>::from(sig).to_vec()),
        recipient: s
            .recipient()
            .as_ref()
            .map(|a| a.to_raw_address_bytes().to_vec()),
        value: s.value().as_ref().map(|v| v.inner()),
        rho: s.rho().as_ref().map(|r| r.to_bytes()),
        rseed: s.rseed().as_ref().map(|r| *r.as_bytes()),
        fvk: s.fvk().as_ref().map(|f| f.to_bytes().to_vec()),
        witness: s.witness().as_ref().map(|w| WitnessWire {
            position: w.position(),
            auth_path: w.auth_path().iter().map(|h| h.to_bytes()).collect(),
        }),
        alpha: s.alpha().as_ref().map(|a| a.to_repr()),
        dummy_sk: s.dummy_sk().as_ref().map(|k| *k.to_bytes()),
        proprietary: s.proprietary().clone(),
    }
}

fn output_to_wire(o: &PcztOutput) -> OutputWire {
    let enc = o.encrypted_note();
    OutputWire {
        cmx: o.cmx().to_bytes(),
        ephemeral_key: enc.epk_bytes,
        enc_ciphertext: enc.enc_ciphertext.to_vec(),
        out_ciphertext: enc.out_ciphertext.to_vec(),
        recipient: o
            .recipient()
            .as_ref()
            .map(|a| a.to_raw_address_bytes().to_vec()),
        value: o.value().as_ref().map(|v| v.inner()),
        rseed: o.rseed().as_ref().map(|r| *r.as_bytes()),
        ock: o.ock().as_ref().map(|k| k.0),
        user_address: o.user_address().clone(),
        proprietary: o.proprietary().clone(),
    }
}

// ---- wire -> orchard bundle ----

fn arr<const N: usize>(v: &[u8], field: &'static str) -> Result<[u8; N], IronwoodPcztError> {
    v.try_into()
        .map_err(|_| IronwoodPcztError::BadLength(field, N, v.len()))
}

fn wire_to_bundle(w: BundleWire) -> Result<PcztBundle, IronwoodPcztError> {
    let bundle_version = match (w.value_pool, w.protocol_version) {
        (0, 0) => BundleVersion::orchard_insecure_v1(),
        (0, 1) => BundleVersion::orchard_v2(),
        (0, 2) => BundleVersion::orchard_v3(),
        (1, 2) => BundleVersion::ironwood_v3(),
        (vp, pv) => return Err(IronwoodPcztError::BadBundleVersion(vp, pv)),
    };
    // The per-note version is fixed by the bundle version (Orchard→V2, Ironwood→V3); it is not
    // carried on the wire.
    let note_version = bundle_version.note_version();

    let actions = w
        .actions
        .into_iter()
        .map(|a| wire_to_action(a, note_version))
        .collect::<Result<Vec<_>, _>>()?;

    PcztBundle::parse(
        actions,
        w.flags,
        bundle_version,
        (w.value_sum_magnitude, w.value_sum_negative),
        w.anchor,
        w.zkproof,
        w.bsk,
    )
    .map_err(|e| IronwoodPcztError::Parse(format!("{e:?}")))
}

fn wire_to_action(
    a: ActionWire,
    note_version: NoteVersion,
) -> Result<PcztAction, IronwoodPcztError> {
    // The output note's rho is the paired spend's nullifier.
    let spend_nullifier = Option::<Nullifier>::from(Nullifier::from_bytes(&a.spend.nullifier))
        .ok_or(IronwoodPcztError::BadFieldEncoding("nullifier"))?;
    let spend = wire_to_spend(a.spend, note_version)?;
    let output = wire_to_output(a.output, spend_nullifier, note_version)?;
    PcztAction::parse(a.cv_net, spend, output, a.rcv)
        .map_err(|e| IronwoodPcztError::Parse(format!("{e:?}")))
}

fn wire_to_spend(s: SpendWire, note_version: NoteVersion) -> Result<PcztSpend, IronwoodPcztError> {
    let spend_auth_sig = s
        .spend_auth_sig
        .as_deref()
        .map(|v| arr::<64>(v, "spend_auth_sig"))
        .transpose()?;
    let recipient = s
        .recipient
        .as_deref()
        .map(|v| arr::<43>(v, "spend.recipient"))
        .transpose()?;
    let fvk = s.fvk.as_deref().map(|v| arr::<96>(v, "fvk")).transpose()?;
    let witness = s
        .witness
        .map(|w| -> Result<_, IronwoodPcztError> {
            let path: [[u8; 32]; 32] = w
                .auth_path
                .try_into()
                .map_err(|_| IronwoodPcztError::BadFieldEncoding("witness.auth_path"))?;
            Ok((w.position, path))
        })
        .transpose()?;

    PcztSpend::parse(
        s.nullifier,
        s.rk,
        spend_auth_sig,
        recipient,
        s.value,
        s.rho,
        s.rseed,
        fvk,
        witness,
        s.alpha,
        None, // zip32_derivation: wallet metadata, not needed by the prover
        s.dummy_sk,
        note_version,
        s.proprietary,
    )
    .map_err(|e| IronwoodPcztError::Parse(format!("{e:?}")))
}

fn wire_to_output(
    o: OutputWire,
    spend_nullifier: Nullifier,
    note_version: NoteVersion,
) -> Result<PcztOutput, IronwoodPcztError> {
    let recipient = o
        .recipient
        .as_deref()
        .map(|v| arr::<43>(v, "output.recipient"))
        .transpose()?;
    let enc_ciphertext = arr::<580>(&o.enc_ciphertext, "enc_ciphertext")?;
    let out_ciphertext = arr::<80>(&o.out_ciphertext, "out_ciphertext")?;

    PcztOutput::parse(
        spend_nullifier,
        o.cmx,
        o.ephemeral_key,
        enc_ciphertext.to_vec(),
        out_ciphertext.to_vec(),
        recipient,
        o.value,
        o.rseed,
        o.ock,
        None, // zip32_derivation
        o.user_address,
        note_version,
        o.proprietary,
    )
    .map_err(|e| IronwoodPcztError::Parse(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::builder::{Builder, BundleType};
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use orchard::tree::Anchor;
    use orchard::value::NoteValue;
    use rand::rngs::OsRng;

    /// Construct a shielding PCZT (one Ironwood output, dummy spend) via the orchard Constructor.
    fn sample_pczt() -> PcztBundle {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);
        let bundle_version = BundleVersion::ironwood_v3();
        let flags = bundle_version.default_flags();
        let mut builder = Builder::new(
            BundleType::UNPADDED,
            bundle_version,
            flags,
            Anchor::empty_tree(),
        )
        .unwrap();
        builder
            .add_output(
                None,
                recipient,
                NoteValue::from_raw(100_000_000),
                [0u8; 512],
            )
            .unwrap();
        builder.build_for_pczt(OsRng).unwrap().0
    }

    #[test]
    fn bundle_roundtrip_is_byte_stable() {
        let bundle = sample_pczt();
        let bytes = serialize_pczt(&bundle).unwrap();
        assert_eq!(bytes[0], FORMAT_VERSION);

        // Byte-stability alone can't catch a field that's dropped symmetrically by both
        // directions, so also assert against sample_pczt()'s known values.
        let wire: BundleWire = postcard::from_bytes(&bytes[1..]).unwrap();
        assert_eq!(wire.anchor, Anchor::empty_tree().to_bytes());
        let bundle_version = BundleVersion::ironwood_v3();
        assert_eq!(
            wire.flags,
            bundle_version
                .default_flags()
                .to_byte(bundle_version)
                .unwrap()
        );
        assert_eq!(wire.actions.len(), 1);
        assert_eq!(wire.value_sum_magnitude, 100_000_000);
        assert!(wire.value_sum_negative);
        assert_ne!(wire.actions[0].output.cmx, [0u8; 32]);

        // Reconstruct, re-serialize: the second encoding must be byte-identical, proving the
        // orchard <-> wire mapping round-trips losslessly.
        let bundle2 = deserialize_pczt(&bytes).unwrap();
        let bytes2 = serialize_pczt(&bundle2).unwrap();
        assert_eq!(bytes, bytes2, "serialize∘deserialize is byte-stable");

        // And a third pass, for good measure.
        let bundle3 = deserialize_pczt(&bytes2).unwrap();
        assert_eq!(serialize_pczt(&bundle3).unwrap(), bytes);
    }

    #[test]
    fn rejects_unknown_version() {
        let bundle = sample_pczt();
        let mut bytes = serialize_pczt(&bundle).unwrap();
        bytes[0] = 0xff;
        assert!(matches!(
            deserialize_pczt(&bytes),
            Err(IronwoodPcztError::UnsupportedVersion(0xff))
        ));
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            deserialize_pczt(&[]),
            Err(IronwoodPcztError::Empty)
        ));
    }

    #[test]
    fn rejects_malformed_body() {
        let bundle = sample_pczt();
        let bytes = serialize_pczt(&bundle).unwrap();
        let truncated = &bytes[..bytes.len() / 2];
        assert!(matches!(
            deserialize_pczt(truncated),
            Err(IronwoodPcztError::Codec(_))
        ));
    }
}
