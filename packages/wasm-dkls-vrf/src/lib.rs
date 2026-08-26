//! BitGo bindings for Silence Labs' DKLS23 VRF keygen and MPC hard derivation.
//!
//! Silence Labs gates VRF keygen and hard derivation behind the non-default `vrf`
//! cargo feature and does not enable it when building their npm packages, so none of
//! the published `@silencelaboratories/dkls-wasm-ll-*` builds contain them. This crate
//! wraps exactly those two protocols and nothing else - signing DKG and DSG stay on
//! Silence Labs' published package.
//!
//! Everything on the wire is CBOR (`ciborium`), matching the encoding Silence Labs'
//! own wasm wrapper uses for key shares. That matters for hard derivation, where the
//! DKLS key share is a bidirectional interface between their build and ours.

use ciborium::{from_reader, into_writer};
use dkls23_ll::{
    dkg::Keyshare as RootKeyshare,
    vrf::{
        dkg as vrf_dkg, hard_derivation, keyshare_after_hard_derive, HardDeriveError,
        HardDeriveMsg0, HardDeriveMsg1, MpcDeriveInit, VrfKeygenError, VrfKeygenMsg1,
        VrfKeygenMsg2, VrfKeyshare as InnerVrfKeyshare,
    },
};
use js_sys::Uint8Array;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;
use wasm_bindgen::prelude::*;

/// Domain separation tags for persisted session state. A round-1 state must never be
/// accepted where a round-2 state is expected, and a VRF DKG state must never be
/// accepted where a hard-derivation state is expected.
const VRF_DKG_R1: &str = "dkls-vrf-dkg-round1-state$";
const VRF_DKG_R2: &str = "dkls-vrf-dkg-round2-state$";
const HARD_DERIVE_R0: &str = "dkls-vrf-hard-derive-round0-state$";
const HARD_DERIVE_R1: &str = "dkls-vrf-hard-derive-round1-state$";

#[derive(Debug, Error)]
pub enum Error {
    #[error("seed must be exactly 32 bytes, got {0}")]
    InvalidSeedLength(usize),

    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    #[error("serialization failed: {0}")]
    Serialization(String),

    #[error("deserialization failed: {0}")]
    Deserialization(String),

    #[error("state bytes do not carry the expected domain prefix")]
    InvalidStatePrefix,

    #[error("session is in round {actual}, expected round {expected}")]
    InvalidRound { expected: u8, actual: u8 },

    #[error("expected {expected} {kind}, got {actual}")]
    MessageCount {
        kind: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("duplicate message from party {0}")]
    DuplicateSender(u8),

    #[error("message from party {0}, which is not a known party")]
    UnknownSender(u8),

    #[error("message set is missing our own party id {0}")]
    MissingOwnMessage(u8),

    #[error("message set does not match the round 0 participant set")]
    ParticipantSetMismatch,

    #[error("root and VRF key shares disagree on {0}")]
    KeyshareMismatch(&'static str),

    #[error(transparent)]
    VrfKeygen(#[from] VrfKeygenError),

    #[error(transparent)]
    HardDerive(#[from] HardDeriveError),
}

// `wasm_bindgen` provides a blanket `From<E: std::error::Error> for JsError`, so every
// wasm entry point can just `?` on an `Error` and JS sees `new Error(<message>)`.

type Result<T> = std::result::Result<T, Error>;

// ------------------------------------------------------------------ helpers

fn rng_from_seed(seed: &[u8]) -> Result<ChaCha20Rng> {
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| Error::InvalidSeedLength(seed.len()))?;
    Ok(ChaCha20Rng::from_seed(seed))
}

fn cbor_enc<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut out = vec![];
    into_writer(value, &mut out).map_err(|e| Error::Serialization(e.to_string()))?;
    Ok(out)
}

fn cbor_dec<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    from_reader(bytes).map_err(|e| Error::Deserialization(e.to_string()))
}

fn add_prefix(prefix: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + body.len());
    out.extend_from_slice(prefix.as_bytes());
    out.extend_from_slice(body);
    out
}

fn rem_prefix<'a>(prefix: &str, blob: &'a [u8]) -> Result<&'a [u8]> {
    blob.strip_prefix(prefix.as_bytes())
        .ok_or(Error::InvalidStatePrefix)
}

fn decode_all<T: DeserializeOwned>(messages: &[Vec<u8>]) -> Result<Vec<T>> {
    messages.iter().map(|m| cbor_dec(m)).collect()
}

fn to_vecs(messages: Vec<Uint8Array>) -> Vec<Vec<u8>> {
    messages.iter().map(|m| m.to_vec()).collect()
}

/// Reject duplicate senders and senders outside `0..total_parties`, and return the
/// sender set in ascending order.
fn sender_set(senders: impl IntoIterator<Item = u8>, total_parties: u8) -> Result<Vec<u8>> {
    let mut seen = BTreeSet::new();
    for from in senders {
        if from >= total_parties {
            return Err(Error::UnknownSender(from));
        }
        if !seen.insert(from) {
            return Err(Error::DuplicateSender(from));
        }
    }
    Ok(seen.into_iter().collect())
}

fn require_count(kind: &'static str, expected: usize, actual: usize) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(Error::MessageCount {
            kind,
            expected,
            actual,
        })
    }
}

fn require_round(expected: u8, actual: u8) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(Error::InvalidRound { expected, actual })
    }
}

// ------------------------------------------------------------------ VRF key share

/// A Ristretto VRF key share produced by [`VrfDkgSession`].
///
/// The serialized form carries the party's secret VRF share - treat it exactly like a
/// signing key share: never log it, never persist it in the clear.
#[wasm_bindgen]
pub struct VrfKeyshare {
    inner: InnerVrfKeyshare,
}

impl VrfKeyshare {
    fn from_bytes_inner(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: cbor_dec(bytes)?,
        })
    }

    fn to_bytes_inner(&self) -> Result<Vec<u8>> {
        cbor_enc(&self.inner)
    }
}

#[wasm_bindgen]
impl VrfKeyshare {
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<VrfKeyshare, JsError> {
        Ok(Self::from_bytes_inner(bytes)?)
    }

    /// Serialize the key share. Output is secret material.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> std::result::Result<Vec<u8>, JsError> {
        Ok(self.to_bytes_inner()?)
    }

    /// Compressed Ristretto VRF public key (32 bytes).
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().compress().to_bytes().to_vec()
    }

    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> Vec<u8> {
        self.inner.key_id.to_vec()
    }

    #[wasm_bindgen(getter, js_name = rootChainCode)]
    pub fn root_chain_code(&self) -> Vec<u8> {
        self.inner.root_chain_code.to_vec()
    }

    #[wasm_bindgen(getter, js_name = finalSessionId)]
    pub fn final_session_id(&self) -> Vec<u8> {
        self.inner.final_session_id.to_vec()
    }

    #[wasm_bindgen(getter, js_name = partyId)]
    pub fn party_id(&self) -> u8 {
        self.inner.party_id
    }

    #[wasm_bindgen(getter)]
    pub fn threshold(&self) -> u8 {
        self.inner.threshold
    }

    #[wasm_bindgen(getter)]
    pub fn participants(&self) -> u8 {
        self.inner.total_parties
    }
}

// ------------------------------------------------------------------ VRF DKG

/// What we persist between rounds: Silence Labs' state plus the metadata their type
/// does not carry (participant count, threshold, round number).
#[derive(Serialize, Deserialize)]
struct VrfDkgStateBytes {
    inner: vrf_dkg::State,
    participants: u8,
    threshold: u8,
    round: u8,
}

/// A VRF distributed key generation session (Protocol 12 on Ristretto).
///
/// Round order is `createFirstMessage` -> `handleRound1Messages` ->
/// `handleRound2Messages`. Every message is a broadcast and carries its own sender id,
/// so message batches may include our own message - it is filtered out internally where
/// the protocol requires peers only.
#[wasm_bindgen]
pub struct VrfDkgSession {
    st: VrfDkgStateBytes,
}

impl VrfDkgSession {
    fn new_inner(participants: u8, threshold: u8, party_id: u8, seed: &[u8]) -> Result<Self> {
        if threshold < 2 {
            return Err(Error::InvalidParams(format!(
                "threshold must be at least 2, got {threshold}"
            )));
        }
        if threshold > participants {
            return Err(Error::InvalidParams(format!(
                "threshold {threshold} exceeds participants {participants}"
            )));
        }
        if party_id >= participants {
            return Err(Error::InvalidParams(format!(
                "party id {party_id} is not in 0..{participants}"
            )));
        }
        let inner = vrf_dkg::State::new(
            vrf_dkg::Party::new(participants, threshold, party_id),
            &mut rng_from_seed(seed)?,
        )?;
        Ok(Self {
            st: VrfDkgStateBytes {
                inner,
                participants,
                threshold,
                round: 1,
            },
        })
    }

    fn from_bytes_inner(bytes: &[u8]) -> Result<Self> {
        let body = rem_prefix(VRF_DKG_R1, bytes).or_else(|_| rem_prefix(VRF_DKG_R2, bytes))?;
        let st: VrfDkgStateBytes = cbor_dec(body)?;
        // The prefix and the embedded round must agree, otherwise the blob was
        // hand-assembled and we have no idea what it is.
        let expected = match st.round {
            1 => VRF_DKG_R1,
            2 => VRF_DKG_R2,
            other => {
                return Err(Error::InvalidRound {
                    expected: 1,
                    actual: other,
                })
            }
        };
        rem_prefix(expected, bytes)?;
        Ok(Self { st })
    }

    fn to_bytes_inner(&self) -> Result<Vec<u8>> {
        let prefix = match self.st.round {
            1 => VRF_DKG_R1,
            _ => VRF_DKG_R2,
        };
        Ok(add_prefix(prefix, &cbor_enc(&self.st)?))
    }

    fn create_first_message_inner(&mut self, seed: &[u8]) -> Result<Vec<u8>> {
        require_round(1, self.st.round)?;
        let msg1 = self.st.inner.generate_msg1(&mut rng_from_seed(seed)?)?;
        cbor_enc(&msg1)
    }

    fn handle_round1_messages_inner(
        &mut self,
        messages: &[Vec<u8>],
        seed: &[u8],
    ) -> Result<Vec<u8>> {
        require_round(1, self.st.round)?;
        let own = self.st.inner.party_id();
        let msgs: Vec<VrfKeygenMsg1> = decode_all(messages)?;
        sender_set(msgs.iter().map(|m| m.from_party), self.st.participants)?;
        let peers: Vec<VrfKeygenMsg1> = msgs.into_iter().filter(|m| m.from_party != own).collect();
        require_count(
            "round 1 messages from peers",
            self.st.participants as usize - 1,
            peers.len(),
        )?;
        let msg2 = self
            .st
            .inner
            .handle_msg1(&mut rng_from_seed(seed)?, peers)?;
        self.st.round = 2;
        cbor_enc(&msg2)
    }

    fn handle_round2_messages_inner(&mut self, messages: &[Vec<u8>]) -> Result<VrfKeyshare> {
        require_round(2, self.st.round)?;
        let msgs: Vec<VrfKeygenMsg2> = decode_all(messages)?;
        sender_set(msgs.iter().map(|m| m.from_party), self.st.participants)?;
        require_count(
            "round 2 messages",
            self.st.participants as usize,
            msgs.len(),
        )?;
        Ok(VrfKeyshare {
            inner: self.st.inner.handle_msg2(msgs)?,
        })
    }
}

#[wasm_bindgen]
impl VrfDkgSession {
    /// `seed` must be exactly 32 bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(
        participants: u8,
        threshold: u8,
        party_id: u8,
        seed: &[u8],
    ) -> std::result::Result<VrfDkgSession, JsError> {
        Ok(Self::new_inner(participants, threshold, party_id, seed)?)
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<VrfDkgSession, JsError> {
        Ok(Self::from_bytes_inner(bytes)?)
    }

    /// Serialize the session so it can be restored in a later round.
    ///
    /// The output embeds this party's secret polynomial share - it is as sensitive as a
    /// key share. Never log it, never persist it in the clear.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> std::result::Result<Vec<u8>, JsError> {
        Ok(self.to_bytes_inner()?)
    }

    #[wasm_bindgen(getter, js_name = partyId)]
    pub fn party_id(&self) -> u8 {
        self.st.inner.party_id()
    }

    #[wasm_bindgen(getter)]
    pub fn participants(&self) -> u8 {
        self.st.participants
    }

    #[wasm_bindgen(getter)]
    pub fn threshold(&self) -> u8 {
        self.st.threshold
    }

    /// Round number this session is waiting on: 1 or 2.
    #[wasm_bindgen(getter)]
    pub fn round(&self) -> u8 {
        self.st.round
    }

    /// Round 1 outbound: one broadcast payload for every other party.
    #[wasm_bindgen(js_name = createFirstMessage)]
    pub fn create_first_message(&mut self, seed: &[u8]) -> std::result::Result<Vec<u8>, JsError> {
        Ok(self.create_first_message_inner(seed)?)
    }

    /// Round 1 inbound, round 2 outbound. Takes every round-1 message the caller has,
    /// including our own; requires one message per party.
    #[wasm_bindgen(js_name = handleRound1Messages)]
    pub fn handle_round1_messages(
        &mut self,
        messages: Vec<Uint8Array>,
        seed: &[u8],
    ) -> std::result::Result<Vec<u8>, JsError> {
        Ok(self.handle_round1_messages_inner(&to_vecs(messages), seed)?)
    }

    /// Round 2 inbound: requires one message per party, including our own, and yields
    /// the VRF key share.
    #[wasm_bindgen(js_name = handleRound2Messages)]
    pub fn handle_round2_messages(
        &mut self,
        messages: Vec<Uint8Array>,
    ) -> std::result::Result<VrfKeyshare, JsError> {
        Ok(self.handle_round2_messages_inner(&to_vecs(messages))?)
    }
}

// ------------------------------------------------------------------ hard derivation

/// Result of a hard-derivation run: a DKLS key share for the derived key.
#[wasm_bindgen]
pub struct DerivedKeyshare {
    keyshare: Vec<u8>,
    public_key: Vec<u8>,
    root_chain_code: Vec<u8>,
}

#[wasm_bindgen]
impl DerivedKeyshare {
    /// CBOR-encoded DKLS key share, ready for Silence Labs' `Keyshare.fromBytes()`.
    /// Secret material.
    #[wasm_bindgen(getter)]
    pub fn keyshare(&self) -> Vec<u8> {
        self.keyshare.clone()
    }

    /// Compressed secp256k1 public key of the derived key (33 bytes).
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter, js_name = rootChainCode)]
    pub fn root_chain_code(&self) -> Vec<u8> {
        self.root_chain_code.clone()
    }
}

/// Persisted hard-derivation state.
///
/// `init` is kept alongside Silence Labs' state because `keyshare_after_hard_derive`
/// needs it in the final round and their `State` does not expose it. Same for
/// `participating_party_ids`, which is fixed by the round-0 sender set but is not
/// carried by their state either.
#[derive(Serialize, Deserialize)]
struct HardDeriveStateBytes {
    inner: hard_derivation::State,
    init: MpcDeriveInit,
    participants: u8,
    threshold: u8,
    party_id: u8,
    participating_party_ids: Vec<u8>,
    round: u8,
}

/// An MPC hard-derivation session: threshold VRF evaluation over `path`, followed by a
/// local tweak of the DKLS root key share.
///
/// Hard derivation cannot be split across two wasm modules: the tweak combines the root
/// key share's secret scalar with the secret VRF evaluation output, so both have to live
/// in the same address space. TypeScript only drives the rounds.
#[wasm_bindgen]
pub struct HardDeriveSession {
    st: HardDeriveStateBytes,
}

impl HardDeriveSession {
    fn new_inner(
        root_keyshare: &[u8],
        vrf_keyshare: &[u8],
        path: &[u8],
        seed: &[u8],
    ) -> Result<Self> {
        let root: RootKeyshare = cbor_dec(root_keyshare)?;
        let vrf: InnerVrfKeyshare = cbor_dec(vrf_keyshare)?;

        if root.total_parties != vrf.total_parties {
            return Err(Error::KeyshareMismatch("participant count"));
        }
        if root.threshold != vrf.threshold {
            return Err(Error::KeyshareMismatch("threshold"));
        }
        if root.party_id != vrf.party_id {
            return Err(Error::KeyshareMismatch("party id"));
        }

        let participants = root.total_parties;
        let threshold = root.threshold;
        let party_id = root.party_id;

        let init = MpcDeriveInit::with_ristretto_vrf(root, vrf);
        let inner =
            hard_derivation::State::new(init.clone(), path.to_vec(), &mut rng_from_seed(seed)?)?;

        Ok(Self {
            st: HardDeriveStateBytes {
                inner,
                init,
                participants,
                threshold,
                party_id,
                participating_party_ids: vec![],
                round: 0,
            },
        })
    }

    fn from_bytes_inner(bytes: &[u8]) -> Result<Self> {
        let body =
            rem_prefix(HARD_DERIVE_R0, bytes).or_else(|_| rem_prefix(HARD_DERIVE_R1, bytes))?;
        let st: HardDeriveStateBytes = cbor_dec(body)?;
        let expected = match st.round {
            0 => HARD_DERIVE_R0,
            1 => HARD_DERIVE_R1,
            other => {
                return Err(Error::InvalidRound {
                    expected: 0,
                    actual: other,
                })
            }
        };
        rem_prefix(expected, bytes)?;
        Ok(Self { st })
    }

    fn to_bytes_inner(&self) -> Result<Vec<u8>> {
        let prefix = match self.st.round {
            0 => HARD_DERIVE_R0,
            _ => HARD_DERIVE_R1,
        };
        Ok(add_prefix(prefix, &cbor_enc(&self.st)?))
    }

    fn create_first_message_inner(&mut self) -> Result<Vec<u8>> {
        require_round(0, self.st.round)?;
        let msg0 = self.st.inner.generate_msg0()?;
        cbor_enc(&msg0)
    }

    fn handle_round1_messages_inner(
        &mut self,
        messages: &[Vec<u8>],
        seed: &[u8],
        quorum: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        require_round(0, self.st.round)?;
        let msgs: Vec<HardDeriveMsg0> = decode_all(messages)?;
        let senders = sender_set(msgs.iter().map(|m| m.from_party), self.st.participants)?;
        require_count(
            "round 0 messages",
            self.st.threshold as usize,
            senders.len(),
        )?;
        if !senders.contains(&self.st.party_id) {
            return Err(Error::MissingOwnMessage(self.st.party_id));
        }
        let own = self.st.party_id;
        let peers: Vec<HardDeriveMsg0> = msgs.into_iter().filter(|m| m.from_party != own).collect();
        let msg1 =
            self.st
                .inner
                .handle_msg0(&mut rng_from_seed(seed)?, peers, quorum.as_deref())?;
        self.st.participating_party_ids = senders;
        self.st.round = 1;
        cbor_enc(&msg1)
    }

    fn handle_round2_messages_inner(&mut self, messages: &[Vec<u8>]) -> Result<DerivedKeyshare> {
        require_round(1, self.st.round)?;
        let msgs: Vec<HardDeriveMsg1> = decode_all(messages)?;
        let senders = sender_set(msgs.iter().map(|m| m.from_party), self.st.participants)?;
        require_count(
            "round 1 messages",
            self.st.threshold as usize,
            senders.len(),
        )?;
        if senders != self.st.participating_party_ids {
            return Err(Error::ParticipantSetMismatch);
        }

        let output = self.st.inner.handle_msg1(msgs)?;
        let derived =
            keyshare_after_hard_derive(&self.st.init, &output, &self.st.participating_party_ids);

        Ok(DerivedKeyshare {
            public_key: derived
                .public_key
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            root_chain_code: derived.root_chain_code.to_vec(),
            keyshare: cbor_enc(&derived)?,
        })
    }
}

#[wasm_bindgen]
impl HardDeriveSession {
    /// `rootKeyshare` is a CBOR DKLS key share as produced by Silence Labs' wasm
    /// (`Keyshare.toBytes()`); `vrfKeyshare` comes from [`VrfDkgSession`].
    ///
    /// `path` is an opaque VRF input label passed through unparsed. Every party must
    /// pass byte-identical `path` values: differing paths derive different keys and no
    /// error is raised. BitGo's convention is the ASCII bytes of `m/<index>'`.
    ///
    /// `seed` must be exactly 32 bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(
        root_keyshare: &[u8],
        vrf_keyshare: &[u8],
        path: &[u8],
        seed: &[u8],
    ) -> std::result::Result<HardDeriveSession, JsError> {
        Ok(Self::new_inner(root_keyshare, vrf_keyshare, path, seed)?)
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<HardDeriveSession, JsError> {
        Ok(Self::from_bytes_inner(bytes)?)
    }

    /// Serialize the session so it can be restored in a later round.
    ///
    /// The output embeds the entire root key share and the VRF key share. It is the most
    /// sensitive blob this package produces - never log it, never persist it in the clear.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> std::result::Result<Vec<u8>, JsError> {
        Ok(self.to_bytes_inner()?)
    }

    #[wasm_bindgen(getter, js_name = partyId)]
    pub fn party_id(&self) -> u8 {
        self.st.party_id
    }

    #[wasm_bindgen(getter)]
    pub fn participants(&self) -> u8 {
        self.st.participants
    }

    #[wasm_bindgen(getter)]
    pub fn threshold(&self) -> u8 {
        self.st.threshold
    }

    /// Round number this session is waiting on: 0 or 1.
    #[wasm_bindgen(getter)]
    pub fn round(&self) -> u8 {
        self.st.round
    }

    /// Round 0 outbound: one broadcast payload.
    #[wasm_bindgen(js_name = createFirstMessage)]
    pub fn create_first_message(&mut self) -> std::result::Result<Vec<u8>, JsError> {
        Ok(self.create_first_message_inner()?)
    }

    /// Round 0 inbound, round 1 outbound. Takes exactly `threshold` round-0 messages,
    /// our own included; that sender set becomes the participant set for the run.
    ///
    /// `quorum`, when given, is the party-id set the senders must match exactly.
    #[wasm_bindgen(js_name = handleRound1Messages)]
    pub fn handle_round1_messages(
        &mut self,
        messages: Vec<Uint8Array>,
        seed: &[u8],
        quorum: Option<Vec<u8>>,
    ) -> std::result::Result<Vec<u8>, JsError> {
        Ok(self.handle_round1_messages_inner(&to_vecs(messages), seed, quorum)?)
    }

    /// Round 1 inbound: requires one message from each round-0 participant and yields
    /// the derived DKLS key share.
    #[wasm_bindgen(js_name = handleRound2Messages)]
    pub fn handle_round2_messages(
        &mut self,
        messages: Vec<Uint8Array>,
    ) -> std::result::Result<DerivedKeyshare, JsError> {
        Ok(self.handle_round2_messages_inner(&to_vecs(messages))?)
    }
}

#[cfg(test)]
mod tests;
