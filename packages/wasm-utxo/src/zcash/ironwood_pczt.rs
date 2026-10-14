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
use orchard::primitives::redpallas;
use orchard::value::Sign;
use orchard::{ProtocolVersion, ValuePool};

/// Wire format version; bump on any layout change (deserialize rejects unknown versions).
pub const FORMAT_VERSION: u8 = 0x02;

/// Per-spend metadata key recording whether a real spend's placeholder `rk` was replaced.
pub(crate) const SPEND_RK_STATE_PROPRIETARY_KEY: &str = "bitgo.rk_state";

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
    /// Two spends in the bundle carry the same nullifier — orchard does not check this, and
    /// consensus rejects a transaction with a repeated nullifier. The deserialize-time guard
    /// covers PCZTs that arrive over the wire (a proof-service response, a stored PSBT), not
    /// just ones built here.
    DuplicateNullifier {
        /// The later action whose nullifier repeats an earlier spend's.
        action_index: usize,
    },
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
            Self::DuplicateNullifier { action_index } => write!(
                f,
                "ironwood-pczt: duplicate nullifier across spend actions (action {action_index} \
                 repeats an earlier spend's nullifier)"
            ),
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
    fvk: Option<Vec<u8>>, // 96 — None for real spends; dummy spends carry their fabricating fvk
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

/// Shared body of the wire patchers: validate the version byte, decode the wire form, apply one
/// field mutation, and re-encode with the version byte.
fn with_patched_wire<F>(bytes: &[u8], patch: F) -> Result<Vec<u8>, IronwoodPcztError>
where
    F: FnOnce(&mut BundleWire) -> Result<(), IronwoodPcztError>,
{
    let (&version, body) = bytes.split_first().ok_or(IronwoodPcztError::Empty)?;
    if version != FORMAT_VERSION {
        return Err(IronwoodPcztError::UnsupportedVersion(version));
    }
    let mut wire: BundleWire =
        postcard::from_bytes(body).map_err(|e| IronwoodPcztError::Codec(e.to_string()))?;
    patch(&mut wire)?;
    let reencoded =
        postcard::to_stdvec(&wire).map_err(|e| IronwoodPcztError::Codec(e.to_string()))?;
    let mut out = Vec::with_capacity(1 + reencoded.len());
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&reencoded);
    Ok(out)
}

/// Splice the prover's `zkproof` bytes into an already-serialized PCZT.
///
/// This is the proof-service response path: `wasm-utxo` sends the signed PCZT (no proof), the
/// service returns the opaque halo2 proof bytes, and this re-emits the wire form with `zkproof`
/// set — without needing to reconstruct the orchard bundle (whose `zkproof` field is not otherwise
/// publicly settable). The proof length is NOT validated here; the Transaction Extractor
/// ([`orchard::pczt::Bundle::extract`]) rejects non-canonical proof sizes when combining.
pub fn with_zkproof(bytes: &[u8], proof: Vec<u8>) -> Result<Vec<u8>, IronwoodPcztError> {
    with_patched_wire(bytes, |wire| {
        wire.zkproof = Some(proof);
        Ok(())
    })
}

/// Splice a client-encrypted `out_ciphertext` into one action's output of an already-serialized
/// PCZT.
///
/// Mirrors [`with_zkproof`]'s "re-emit the wire form with one field replaced" shape: the client
/// builds `out_ciphertext` under its own `ovk` (never sent to the server), then patches it into the
/// keyless bundle the server built. `out_ciphertext` is sighash-committed, so this must run before
/// the ZIP-244 sighash is computed; every other field of the bundle/action is untouched.
pub fn with_out_ciphertext(
    bytes: &[u8],
    action_index: usize,
    out_ciphertext: super::ironwood_build::OutCiphertextBytes,
) -> Result<Vec<u8>, IronwoodPcztError> {
    with_patched_wire(bytes, |wire| {
        wire.actions
            .get_mut(action_index)
            .ok_or(IronwoodPcztError::BadFieldEncoding("actions[action_index]"))?
            .output
            .out_ciphertext = out_ciphertext.to_vec();
        Ok(())
    })
}

/// Replace one action spend's `rk` (spend validating key) and mark it ready for sighashing.
/// Rejects an `rk` that is not a canonical RedPallas verification key.
pub fn with_spend_rk(
    bytes: &[u8],
    action_index: usize,
    rk: [u8; 32],
) -> Result<Vec<u8>, IronwoodPcztError> {
    patch_spend_rk(bytes, action_index, rk, false)
}

/// Set the constructor placeholder `rk` and mark it as requiring signer replacement.
pub(crate) fn with_placeholder_spend_rk(
    bytes: &[u8],
    action_index: usize,
    rk: [u8; 32],
) -> Result<Vec<u8>, IronwoodPcztError> {
    patch_spend_rk(bytes, action_index, rk, true)
}

fn patch_spend_rk(
    bytes: &[u8],
    action_index: usize,
    rk: [u8; 32],
    is_placeholder: bool,
) -> Result<Vec<u8>, IronwoodPcztError> {
    with_patched_wire(bytes, |wire| {
        let spend = &mut wire
            .actions
            .get_mut(action_index)
            .ok_or(IronwoodPcztError::BadFieldEncoding("actions[action_index]"))?
            .spend;
        if redpallas::VerificationKey::<redpallas::SpendAuth>::try_from(rk).is_err() {
            return Err(IronwoodPcztError::BadFieldEncoding("spend.rk"));
        }
        spend.rk = rk;
        spend.proprietary.insert(
            SPEND_RK_STATE_PROPRIETARY_KEY.to_string(),
            vec![u8::from(!is_placeholder)],
        );
        Ok(())
    })
}

/// Replace one action spend's plaintext `value` in an already-serialized PCZT.
///
/// Test/defense tooling for the plaintext-integrity cross-check: a spend's plaintext value is
/// NOT bound by the proofs (only `cv_net`/`cm` are), so a value that disagrees with the bundle's
/// committed `value_sum` must be caught by `ironwood_bundle_info`'s cross-check instead of
/// silently flowing into fee accounting. The committed `value_sum` field is untouched.
pub fn with_spend_value(
    bytes: &[u8],
    action_index: usize,
    value: u64,
) -> Result<Vec<u8>, IronwoodPcztError> {
    with_patched_wire(bytes, |wire| {
        wire.actions
            .get_mut(action_index)
            .ok_or(IronwoodPcztError::BadFieldEncoding("actions[action_index]"))?
            .spend
            .value = Some(value);
        Ok(())
    })
}

/// Install the spending FVK on every real spend (dummy spends keep their fabricating FVK —
/// the IO Finalizer signs them with it).
///
/// The local prover derives `ak`/`nk` for the circuit from the FVK (`ProverError::
/// MissingFullViewingKey` otherwise), and real spends had it scrubbed at construction ("the
/// FVK never leaves its holder" — here the holder is the caller, which owns the notes and is
/// proving locally). Transient: the result is consumed in-memory and never stored back.
pub fn with_spend_fvk_on_real_spends(
    bytes: &[u8],
    fvk: super::ironwood_build::FvkBytes,
) -> Result<Vec<u8>, IronwoodPcztError> {
    with_patched_wire(bytes, |wire| {
        for action in wire.actions.iter_mut() {
            if action.spend.dummy_sk.is_none() {
                action.spend.fvk = Some(fvk.to_vec());
            }
        }
        Ok(())
    })
}

/// Clear one action spend's `fvk` in an already-serialized PCZT.
///
/// The Constructor role's real spends are built with the full viewing key held
/// transiently (the caller supplied it), so `bundle_to_wire` serializes it —
/// but the serialized PCZT the Constructor hands on must be keyless: the FVK
/// never leaves its holder (the client in the keyless flow, KMS in the keyed
/// flow). `scrub_spend_randomizers` clears it for every real spend, next to
/// the `alpha`/`rk` scrub. Dummy spends (shielding builds) keep their wire
/// `fvk`: it is the fabricating builder's random key, and `create_proof`
/// requires an fvk on every spend.
pub fn with_spend_fvk_cleared(
    bytes: &[u8],
    action_index: usize,
) -> Result<Vec<u8>, IronwoodPcztError> {
    with_patched_wire(bytes, |wire| {
        wire.actions
            .get_mut(action_index)
            .ok_or(IronwoodPcztError::BadFieldEncoding("actions[action_index]"))?
            .spend
            .fvk = None;
        Ok(())
    })
}

/// Splice one action spend's 64-byte RedPallas `spend_auth_sig` into an already-serialized PCZT.
///
/// Only the shape is enforced here; every other field of the bundle/action is untouched.
pub fn with_spend_auth_sig(
    bytes: &[u8],
    action_index: usize,
    sig: [u8; 64],
) -> Result<Vec<u8>, IronwoodPcztError> {
    with_patched_wire(bytes, |wire| {
        wire.actions
            .get_mut(action_index)
            .ok_or(IronwoodPcztError::BadFieldEncoding("actions[action_index]"))?
            .spend
            .spend_auth_sig = Some(sig.to_vec());
        Ok(())
    })
}

/// Set or clear one action spend's `alpha` (spend authorizing randomizer) in an
/// already-serialized PCZT.
///
/// `None` clears it; every other field of the bundle/action is untouched.
pub fn with_spend_alpha(
    bytes: &[u8],
    action_index: usize,
    alpha: Option<[u8; 32]>,
) -> Result<Vec<u8>, IronwoodPcztError> {
    with_patched_wire(bytes, |wire| {
        wire.actions
            .get_mut(action_index)
            .ok_or(IronwoodPcztError::BadFieldEncoding("actions[action_index]"))?
            .spend
            .alpha = alpha;
        Ok(())
    })
}

/// Test-only: replace one action output's `rseed` in the wire form, producing a PCZT whose output
/// fields no longer reconstruct the note its `cmx` commits to. Exists to exercise
/// [`super::ironwood_build::IronwoodBuildError::NoteCommitmentMismatch`], which is otherwise
/// unreachable through the public API.
#[cfg(test)]
pub(crate) fn with_output_rseed_for_test(
    bytes: &[u8],
    action_index: usize,
    rseed: [u8; 32],
) -> Result<Vec<u8>, IronwoodPcztError> {
    with_patched_wire(bytes, |wire| {
        wire.actions
            .get_mut(action_index)
            .ok_or(IronwoodPcztError::BadFieldEncoding("actions[action_index]"))?
            .output
            .rseed = Some(rseed);
        Ok(())
    })
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

    let bundle = PcztBundle::parse(
        actions,
        w.flags,
        bundle_version,
        (w.value_sum_magnitude, w.value_sum_negative),
        w.anchor,
        w.zkproof,
        w.bsk,
    )
    .map_err(|e| IronwoodPcztError::Parse(format!("{e:?}")))?;

    // Ingestion guard: two spends deriving the same nullifier are consensus-invalid (orchard
    // does not check this), and PCZTs arrive over the wire from elsewhere, so this cannot live
    // only at construction.
    if let Some(action_index) = duplicate_nullifier_index(&bundle) {
        return Err(IronwoodPcztError::DuplicateNullifier { action_index });
    }
    Ok(bundle)
}

/// Index of the later action whose nullifier repeats an earlier spend's, if any.
///
/// Orchard does not check this, and consensus rejects a transaction with a repeated nullifier.
/// Both the construction-time verifier (which returns the build-layer error) and the
/// deserialize-time ingestion guard (the wire-layer error) share this scan.
pub(crate) fn duplicate_nullifier_index(bundle: &PcztBundle) -> Option<usize> {
    let mut seen = std::collections::HashSet::new();
    for (i, action) in bundle.actions().iter().enumerate() {
        if !seen.insert(action.spend().nullifier().to_bytes()) {
            return Some(i);
        }
    }
    None
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
    let fvk = s.fvk.as_deref().map(|v| arr::<96>(v, "fvk")).transpose()?;

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
    use ff::Field;
    use orchard::builder::{Builder, BundleType};
    use orchard::keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey};
    use orchard::note::{Note, Rho};
    use orchard::tree::Anchor;
    use orchard::value::NoteValue;
    use rand::rngs::OsRng;

    use crate::zcash::ironwood_build::test_field_bytes as field_bytes;

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
    fn with_zkproof_sets_the_proof() {
        // A freshly constructed PCZT has no proof.
        let bundle = sample_pczt();
        assert!(bundle.zkproof().is_none());

        let bytes = serialize_pczt(&bundle).unwrap();
        let proof = vec![0xabu8; 4992];
        let proven = deserialize_pczt(&with_zkproof(&bytes, proof.clone()).unwrap()).unwrap();
        assert_eq!(
            proven.zkproof().as_ref().map(|p| p.as_ref().to_vec()),
            Some(proof)
        );

        // Injection is idempotent under re-serialization for the rest of the bundle: only zkproof
        // changed, everything else round-trips byte-stable.
        assert_eq!(
            with_zkproof(&serialize_pczt(&proven).unwrap(), vec![0xabu8; 4992]).unwrap(),
            with_zkproof(&bytes, vec![0xabu8; 4992]).unwrap()
        );
    }

    #[test]
    fn with_zkproof_rejects_unknown_version() {
        let mut bytes = serialize_pczt(&sample_pczt()).unwrap();
        bytes[0] = 0xff;
        assert!(matches!(
            with_zkproof(&bytes, vec![0u8; 4992]),
            Err(IronwoodPcztError::UnsupportedVersion(0xff))
        ));
        assert!(matches!(
            with_zkproof(&[], vec![0u8; 4992]),
            Err(IronwoodPcztError::Empty)
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

    #[test]
    fn rk_patcher_tracks_placeholder_and_replaced_states() {
        let bytes = serialize_pczt(&sample_pczt()).unwrap();
        let old_rk = <[u8; 32]>::from(deserialize_pczt(&bytes).unwrap().actions()[0].spend().rk());

        let placeholder = with_placeholder_spend_rk(&bytes, 0, old_rk).unwrap();
        let placeholder_bundle = deserialize_pczt(&placeholder).unwrap();
        assert_eq!(
            placeholder_bundle.actions()[0]
                .spend()
                .proprietary()
                .get(SPEND_RK_STATE_PROPRIETARY_KEY)
                .map(|state| state.as_slice()),
            Some(&[0u8][..])
        );

        let sk2 = Option::<SpendingKey>::from(SpendingKey::from_bytes([9u8; 32])).unwrap();
        let new_rk = <[u8; 32]>::from(redpallas::VerificationKey::from(
            &SpendAuthorizingKey::from(&sk2).randomize(&pasta_curves::pallas::Scalar::ZERO),
        ));
        assert_ne!(old_rk, new_rk);

        let patched = with_spend_rk(&placeholder, 0, new_rk).unwrap();
        let bundle = deserialize_pczt(&patched).unwrap();
        assert_eq!(<[u8; 32]>::from(bundle.actions()[0].spend().rk()), new_rk);
        assert_eq!(
            bundle.actions()[0]
                .spend()
                .proprietary()
                .get(SPEND_RK_STATE_PROPRIETARY_KEY)
                .map(|state| state.as_slice()),
            Some(&[1u8][..])
        );
        assert_eq!(serialize_pczt(&bundle).unwrap(), patched);
        assert_eq!(with_spend_rk(&patched, 0, new_rk).unwrap(), patched);
    }

    #[test]
    fn with_spend_rk_rejects_non_canonical_point() {
        let bytes = serialize_pczt(&sample_pczt()).unwrap();
        assert!(matches!(
            with_spend_rk(&bytes, 0, [0xffu8; 32]),
            Err(IronwoodPcztError::BadFieldEncoding("spend.rk"))
        ));
    }

    #[test]
    fn with_spend_auth_sig_sets_the_signature() {
        let bytes = serialize_pczt(&sample_pczt()).unwrap();
        let sig = [0x42u8; 64];
        let patched = with_spend_auth_sig(&bytes, 0, sig).unwrap();
        let bundle = deserialize_pczt(&patched).unwrap();
        assert_eq!(
            bundle.actions()[0]
                .spend()
                .spend_auth_sig()
                .as_ref()
                .map(<[u8; 64]>::from),
            Some(sig)
        );
    }

    #[test]
    fn deserialize_rejects_duplicate_nullifiers() {
        // Ingestion guard: construction-time checking alone does not cover PCZTs that arrive
        // over the wire (a proof-service response, a stored PSBT), so the duplicate-nullifier
        // check runs at deserialize too. Two dummy-spend actions, nullifiers forced equal.
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let bundle_version = BundleVersion::ironwood_v3();
        let mut builder = Builder::new(
            BundleType::UNPADDED,
            bundle_version,
            bundle_version.default_flags(),
            Anchor::empty_tree(),
        )
        .unwrap();
        builder
            .add_output(
                None,
                fvk.address_at(0u32, Scope::External),
                NoteValue::from_raw(100_000_000),
                [0u8; 512],
            )
            .unwrap();
        builder
            .add_output(
                None,
                fvk.address_at(1u32, Scope::External),
                NoteValue::from_raw(90_000_000),
                [0u8; 512],
            )
            .unwrap();
        let bundle = builder.build_for_pczt(OsRng).unwrap().0;
        let bytes = serialize_pczt(&bundle).unwrap();
        deserialize_pczt(&bytes).expect("the honest bundle decodes");

        let patched = with_patched_wire(&bytes, |wire| {
            let nf = wire.actions[0].spend.nullifier;
            wire.actions[1].spend.nullifier = nf;
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            deserialize_pczt(&patched),
            Err(IronwoodPcztError::DuplicateNullifier { action_index: 1 })
        ));
    }

    #[test]
    fn with_spend_patchers_reject_bad_context() {
        let bytes = serialize_pczt(&sample_pczt()).unwrap();
        let mut bad_version = bytes.clone();
        bad_version[0] = 0xff;
        assert!(matches!(
            with_spend_rk(&bad_version, 0, [1u8; 32]),
            Err(IronwoodPcztError::UnsupportedVersion(0xff))
        ));
        assert!(matches!(
            with_spend_auth_sig(&bad_version, 0, [1u8; 64]),
            Err(IronwoodPcztError::UnsupportedVersion(0xff))
        ));
        assert!(matches!(
            with_spend_rk(&[], 0, [1u8; 32]),
            Err(IronwoodPcztError::Empty)
        ));

        assert!(matches!(
            with_spend_rk(&bytes, 1, [1u8; 32]),
            Err(IronwoodPcztError::BadFieldEncoding("actions[action_index]"))
        ));
        assert!(matches!(
            with_spend_auth_sig(&bytes, 1, [1u8; 64]),
            Err(IronwoodPcztError::BadFieldEncoding("actions[action_index]"))
        ));
    }

    #[test]
    fn with_spend_alpha_sets_and_clears_the_randomizer() {
        let bytes = serialize_pczt(&sample_pczt()).unwrap();
        assert!(deserialize_pczt(&bytes).unwrap().actions()[0]
            .spend()
            .alpha()
            .is_some());

        // Set an arbitrary canonical alpha, then clear it again.
        let alpha = field_bytes(7);
        let set = with_spend_alpha(&bytes, 0, Some(alpha)).unwrap();
        assert_eq!(
            deserialize_pczt(&set).unwrap().actions()[0]
                .spend()
                .alpha()
                .map(|a| a.to_repr()),
            Some(alpha)
        );

        let cleared = with_spend_alpha(&set, 0, None).unwrap();
        assert!(deserialize_pczt(&cleared).unwrap().actions()[0]
            .spend()
            .alpha()
            .is_none());
        // Clearing the original bundle reproduces the byte-stable state, and the rest of the
        // bundle round-trips byte-stable.
        assert_eq!(
            serialize_pczt(&deserialize_pczt(&cleared).unwrap()).unwrap(),
            cleared
        );
    }

    /// A PCZT whose spend is fully populated — every optional `SpendWire` field
    /// (`witness`, `fvk`, `alpha`, `rho`, `rseed`, `value`, `recipient`, `spend_auth_sig`) is
    /// set at once, which no single stage of the real flow produces (the Constructor omits the
    /// FVK and `alpha` from real spends), so the round-trip and negative tests below exercise
    /// every optional field's encoding.
    ///
    /// The orchard structs are hand-assembled via `parse` rather than built with
    /// `Builder::add_spend`, so every field can be set directly. Cryptographically valid encodings are harvested from [`sample_pczt`]'s
    /// Builder output: the dummy spend's `nullifier`/`rk`/`cv_net` are real curve values, and
    /// the real output note's fields (`recipient`/`value`/`rseed`/`cmx`) satisfy the
    /// nullifier-is-rho coupling that
    /// [`compute_out_ciphertext`](super::super::ironwood_build::compute_out_ciphertext)
    /// relies on.
    fn sample_spend_pczt() -> PcztBundle {
        let base = sample_pczt();
        let base_bytes = serialize_pczt(&base).unwrap();
        let base_wire: BundleWire = postcard::from_bytes(&base_bytes[1..]).unwrap();
        let a = &base_wire.actions[0];

        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);

        // Recipient/value/rseed from the real output note; the paired dummy spend's
        // nullifier serves both as the spent note's rho (rseed validates against it) and as
        // the output note's rho (the coupling pinned by the test below).
        let recipient: [u8; 43] = a.output.recipient.clone().unwrap().try_into().unwrap();
        let value = a.output.value.unwrap();
        let rseed = a.output.rseed.unwrap();
        let nullifier = a.spend.nullifier;
        let rho = nullifier;

        // 32 canonical Merkle-hash encodings. `Spend::parse` only validates that each auth
        // path entry decodes as a base-field element (`MerkleHashOrchard::from_bytes` is
        // `pallas::Base::from_repr`), not tree structure, so small integers are valid
        // stand-ins for sibling hashes (real witnesses are covered by the `ironwood_build` tests).
        let auth_path: [[u8; 32]; 32] = core::array::from_fn(|i| {
            let mut b = [0u8; 32];
            b[0] = i as u8;
            b
        });

        // `alpha` is any canonical Pallas scalar; `[1u8; 32]` is 0x0101..01 < p.
        let alpha = [1u8; 32];
        // `spend_auth_sig` is an opaque 64-byte redpallas signature at parse time.
        let spend_auth_sig = [0xabu8; 64];

        let spend = PcztSpend::parse(
            nullifier,
            a.spend.rk,
            Some(spend_auth_sig),
            Some(recipient),
            Some(value),
            Some(rho),
            Some(rseed),
            Some(fvk.to_bytes()),
            Some((0u32, auth_path)),
            Some(alpha),
            None, // zip32_derivation: stays dropped (flat per-wallet key)
            None, // dummy_sk: a real spend, not a dummy
            BundleVersion::ironwood_v3().note_version(),
            BTreeMap::new(),
        )
        .unwrap();

        let output = PcztOutput::parse(
            Option::<Nullifier>::from(Nullifier::from_bytes(&nullifier)).unwrap(),
            a.output.cmx,
            a.output.ephemeral_key,
            a.output.enc_ciphertext.clone(),
            a.output.out_ciphertext.clone(),
            Some(recipient),
            Some(value),
            Some(rseed),
            a.output.ock,
            None,
            None,
            BundleVersion::ironwood_v3().note_version(),
            BTreeMap::new(),
        )
        .unwrap();

        let action = PcztAction::parse(a.cv_net, spend, output, a.rcv).unwrap();

        PcztBundle::parse(
            vec![action],
            base_wire.flags,
            BundleVersion::ironwood_v3(),
            (base_wire.value_sum_magnitude, base_wire.value_sum_negative),
            base_wire.anchor,
            None,
            None,
        )
        .unwrap()
    }

    /// Round-trip a fully-populated real spend and assert byte-exact re-serialization.
    #[test]
    fn spend_fields_roundtrip_is_byte_stable() {
        let bundle = sample_spend_pczt();
        let bytes = serialize_pczt(&bundle).unwrap();
        assert_eq!(bytes[0], FORMAT_VERSION);

        let wire: BundleWire = postcard::from_bytes(&bytes[1..]).unwrap();
        let s = &wire.actions[0].spend;
        assert!(s.spend_auth_sig.is_some());
        assert!(s.recipient.is_some());
        assert!(s.value.is_some());
        assert!(s.rho.is_some());
        assert!(s.rseed.is_some());
        assert!(s.fvk.is_some());
        assert!(s.witness.is_some());
        assert!(s.alpha.is_some());
        assert!(s.dummy_sk.is_none(), "a real spend carries no dummy_sk");
        assert_eq!(s.witness.as_ref().unwrap().auth_path.len(), 32);

        let bundle2 = deserialize_pczt(&bytes).unwrap();
        let bytes2 = serialize_pczt(&bundle2).unwrap();
        assert_eq!(
            bytes, bytes2,
            "serialize∘deserialize is byte-stable for a populated spend"
        );

        // And a third pass, for good measure.
        let bundle3 = deserialize_pczt(&bytes2).unwrap();
        assert_eq!(serialize_pczt(&bundle3).unwrap(), bytes);
    }

    /// The spend-path negative tests: malformed field lengths in `wire_to_spend` must reject
    /// with the exact error variant.
    #[test]
    fn spend_path_rejects_malformed_field_lengths() {
        let mk_wire = || {
            let bytes = serialize_pczt(&sample_spend_pczt()).unwrap();
            postcard::from_bytes::<BundleWire>(&bytes[1..]).unwrap()
        };
        let reencode = |wire: &BundleWire| {
            let mut out = vec![FORMAT_VERSION];
            out.extend_from_slice(&postcard::to_stdvec(wire).unwrap());
            out
        };

        // `fvk` must be 96 bytes.
        let mut wire = mk_wire();
        wire.actions[0].spend.fvk = Some(vec![0u8; 95]);
        assert!(matches!(
            deserialize_pczt(&reencode(&wire)),
            Err(IronwoodPcztError::BadLength("fvk", 96, 95))
        ));

        // `spend_auth_sig` must be 64 bytes.
        let mut wire = mk_wire();
        wire.actions[0].spend.spend_auth_sig = Some(vec![0u8; 63]);
        assert!(matches!(
            deserialize_pczt(&reencode(&wire)),
            Err(IronwoodPcztError::BadLength("spend_auth_sig", 64, 63))
        ));

        // `spend.recipient` must be 43 bytes.
        let mut wire = mk_wire();
        wire.actions[0].spend.recipient = Some(vec![0u8; 42]);
        assert!(matches!(
            deserialize_pczt(&reencode(&wire)),
            Err(IronwoodPcztError::BadLength("spend.recipient", 43, 42))
        ));

        // `witness.auth_path` must have exactly 32 entries.
        let mut wire = mk_wire();
        wire.actions[0]
            .spend
            .witness
            .as_mut()
            .unwrap()
            .auth_path
            .truncate(31);
        assert!(matches!(
            deserialize_pczt(&reencode(&wire)),
            Err(IronwoodPcztError::BadFieldEncoding("witness.auth_path"))
        ));
    }

    /// Pins the nullifier-is-rho coupling: for a Builder-produced Ironwood
    /// bundle, the output note's rho is the paired spend's nullifier, so the note reconstructs
    /// from wire fields and re-derives the committed `cmx`. If this coupling ever broke,
    /// `compute_out_ciphertext` would fail as a confusing `NoteCommitmentMismatch`.
    #[test]
    fn output_note_rho_is_paired_spend_nullifier() {
        for bundle in [sample_pczt(), sample_spend_pczt()] {
            let bundle = deserialize_pczt(&serialize_pczt(&bundle).unwrap()).unwrap();
            let action = bundle.actions().first().unwrap();
            let spend = action.spend();
            let output = action.output();

            let nf = spend.nullifier().to_bytes();
            let rho = Option::<Rho>::from(Rho::from_bytes(&nf)).expect("nullifier decodes as rho");
            let note = Option::<Note>::from(Note::from_parts(
                *output.recipient().as_ref().unwrap(),
                *output.value().as_ref().unwrap(),
                rho,
                *output.rseed().as_ref().unwrap(),
                *output.note_version(),
            ))
            .unwrap();
            assert_eq!(
                orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
                output.cmx().to_bytes()
            );
        }
    }

    /// The spend fields are `Option`s in the wire layout, so populating them is not a layout
    /// change: a fully-populated spend serializes under the current `FORMAT_VERSION` and
    /// deserializes cleanly.
    #[test]
    fn populated_spend_fields_use_the_current_format_version() {
        let bytes = serialize_pczt(&sample_spend_pczt()).unwrap();
        assert_eq!(bytes[0], FORMAT_VERSION);
        assert!(deserialize_pczt(&bytes).is_ok());
    }
}
