//! BitGo frontend to Silence Labs' Multi-Party-Schnorr

mod mps {

    use multi_party_schnorr::{
        common::{
            redpallas::{RedPallasPoint, RedPallasPointBytes},
            ser::Serializable,
            traits::{GroupElem, Round, ScalarReduce},
            Bip32Public,
        },
        curve25519_dalek::EdwardsPoint,
        keygen::{
            KeyRefreshData, KeygenMsg1, KeygenMsg2, KeygenParty, Keyshare, R0 as DkgR0,
            R1 as DkgR1, R2 as DkgR2,
        },
        sign::{
            messages::{SignMsg1, SignMsg2, SignMsg3},
            PartialSign, SignError, SignReady, SignerParty, R0 as DsgR0, R1 as DsgR1, R2 as DsgR2,
        },
    };
    use multi_party_schnorr::{
        derive::{with_ristretto_vrf_ed25519, HardDerivePartyEd25519, MpcDeriveInitEd25519},
        vrf::{
            dkg::Party as VrfParty, keyshare_after_hard_derive, HardDeriveMsg0, HardDeriveMsg1,
            HardDeriveR0, HardDeriveR1, HardDeriveR2, VrfDkgParty, VrfDkgR0, VrfDkgR1, VrfDkgR2,
            VrfKeygenMsg1, VrfKeygenMsg2, VrfPoint,
        },
    };
    use rand::Rng;
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use std::{
        io::{Cursor, Read},
        sync::Arc,
    };
    use thiserror::Error;
    use zcash::derivation_session::{
        DerivationStatus, Message as DrvMessage, Session as DerivationSession,
    };

    /// Errors that can be returned as results.
    #[derive(Debug, Error)]
    pub enum MpsError {
        #[error("Serialization Error")]
        SerializationError,

        #[error("Deserialization Error")]
        DeserializationError,

        #[error("Invalid Input")]
        InvalidInput,

        #[error("Protocol Error")]
        ProtocolError,
    }

    /// Internal DKG state used for round 1.
    #[derive(Serialize, Deserialize)]
    struct DkgStateR1<G>
    where
        G: GroupElem,
        G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    {
        pub party_id: u8,
        pub msg: KeygenMsg1,

        #[serde(bound(
            serialize = "KeygenParty<DkgR1<G>, G>: Serialize",
            deserialize = "KeygenParty<DkgR1<G>, G>: Deserialize<'de>"
        ))]
        pub party: KeygenParty<DkgR1<G>, G>,
    }

    /// Internal DKG state used for round 2.
    #[derive(Serialize, Deserialize)]
    #[serde(bound(
        serialize = "G::Scalar: Serializable",
        deserialize = "G::Scalar: Serializable"
    ))]
    struct DkgStateR2<G>
    where
        G: GroupElem,
        G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    {
        pub party_id: u8,
        pub msg: KeygenMsg2<G>,
        pub party: KeygenParty<DkgR2, G>,
    }

    #[derive(Serialize, Deserialize)]
    struct VrfDkgStateR1 {
        party_id: u8,
        msg: VrfKeygenMsg1,
        party: VrfDkgParty<VrfDkgR1>,
    }

    #[derive(Serialize, Deserialize)]
    struct VrfDkgStateR2 {
        party_id: u8,
        msg: VrfKeygenMsg2,
        party: VrfDkgParty<VrfDkgR2>,
    }

    pub const ROOT_DOCUMENT_VERSION: u8 = 1;

    /// Combined root document produced by Ed25519 DKG when `with_vrf` is true.
    /// Ordinary DKG (`with_vrf=false`) still encodes a bare `Keyshare<EdwardsPoint>`.
    #[derive(Serialize, Deserialize)]
    pub struct RootDocument {
        pub version: u8,
        pub signing: Keyshare<EdwardsPoint>,
        pub vrf: Keyshare<VrfPoint>,
    }

    /// Internal DSG state used for round 1.
    #[derive(Serialize, Deserialize)]
    #[serde(bound(
        serialize = "G::Scalar: Serializable",
        deserialize = "G::Scalar: Serializable"
    ))]
    struct DsgStateR1<G>
    where
        G: GroupElem,
        G::Scalar: Serializable,
    {
        pub msg: SignMsg1,
        pub party: SignerParty<DsgR1<G>, G>,
    }

    /// Internal DSG state used for round 2.
    #[derive(Serialize, Deserialize)]
    #[serde(bound(
        serialize = "G::Scalar: Serializable",
        deserialize = "G::Scalar: Serializable"
    ))]
    struct DsgStateR2<G>
    where
        G: GroupElem,
        G::Scalar: Serializable,
    {
        pub msg: SignMsg2<G>,
        pub party: SignerParty<DsgR2<G>, G>,
    }

    /// Internal DSG state used for round 3.
    #[derive(Serialize, Deserialize)]
    #[serde(bound(
        serialize = "G::Scalar: Serializable",
        deserialize = "G::Scalar: Serializable"
    ))]
    struct DsgStateR3<G>
    where
        G: GroupElem,
        G::Scalar: Serializable,
    {
        pub msg: SignMsg3<G>,
        pub party: PartialSign<G>,
        pub alpha: [u8; 32],
    }

    /// Result from processing that includes a public messages for other
    /// parties and a private state to be stored in memory.
    pub struct MsgState {
        pub msg: Vec<u8>,
        pub state: Vec<u8>,
    }

    /// Signing share returned from round 2.
    pub struct Share {
        pub share: Vec<u8>,
        pub pk: [u8; 32],
        pub chaincode: [u8; 32],
        pub vrf_pk: Option<[u8; 32]>,
        pub vrf_chaincode: Option<[u8; 32]>,
    }

    pub struct MsgDerivationInit {
        pub share: Vec<u8>,
        pub pk: [u8; 32],
        pub msg: Vec<u8>,
        pub state: Vec<u8>,
    }

    /// Result from round 3 of RedPallas DSG.
    pub struct RedPallasSignature {
        pub signature: Vec<u8>,
        pub rk: [u8; 32],
        pub alpha: [u8; 32],
    }

    pub struct MsgDerivation {
        pub msg: Vec<u8>,
        pub state: Vec<u8>,
        pub done: bool,
        pub ask: Option<[u8; 32]>,
        pub nk: Option<[u8; 32]>,
        pub rivk: Option<[u8; 32]>,
        pub internal_ivk: Option<[u8; 64]>,
        pub external_ivk: Option<[u8; 64]>,
    }

    /// Orchard incoming viewing keys derived from FVK components.
    pub struct RedPallasIvks {
        pub internal_ivk: [u8; 64],
        pub external_ivk: [u8; 64],
    }

    trait IntoSignReady<G: GroupElem> {
        fn into_sign_ready(self) -> Result<(SignReady<G>, [u8; 32]), MpsError>;
    }

    impl<G: GroupElem> IntoSignReady<G> for SignReady<G> {
        fn into_sign_ready(self) -> Result<(SignReady<G>, [u8; 32]), MpsError> {
            Ok((self, [0u8; 32]))
        }
    }

    impl<G: GroupElem, T: Serialize> IntoSignReady<G> for (SignReady<G>, T) {
        fn into_sign_ready(self) -> Result<(SignReady<G>, [u8; 32]), MpsError> {
            let alpha: [u8; 32] =
                bincode::serde::encode_to_vec(&self.1, bincode::config::standard())
                    .map_err(|_| MpsError::SerializationError)?
                    .try_into()
                    .map_err(|_| MpsError::SerializationError)?;
            Ok((self.0, alpha))
        }
    }

    fn rem_prefix(prefix: &str, data: &[u8]) -> Result<Vec<u8>, MpsError> {
        Ok(data
            .strip_prefix(prefix.as_bytes())
            .ok_or(MpsError::InvalidInput)?
            .to_vec())
    }

    fn add_prefix(prefix: &str, data: &Vec<u8>) -> Vec<u8> {
        let mut result = Vec::with_capacity(prefix.len() + data.len());
        result.extend_from_slice(prefix.as_bytes());
        result.extend_from_slice(data.as_slice());
        result
    }

    fn encode_head_tail<H: Serialize, T: Serialize>(
        head: &H,
        tail: Option<&T>,
    ) -> Result<Vec<u8>, MpsError> {
        let mut buf = bincode::serde::encode_to_vec(head, bincode::config::standard())
            .map_err(|_| MpsError::SerializationError)?;
        if let Some(t) = tail {
            buf.extend(
                bincode::serde::encode_to_vec(t, bincode::config::standard())
                    .map_err(|_| MpsError::SerializationError)?,
            );
        }
        Ok(buf)
    }

    fn decode_head_tail<H: DeserializeOwned, T: DeserializeOwned>(
        data: &[u8],
    ) -> Result<(H, Option<T>), MpsError> {
        let (head, n) = bincode::serde::decode_from_slice(data, bincode::config::standard())
            .map_err(|_| MpsError::DeserializationError)?;
        let rest = &data[n..];
        if rest.is_empty() {
            return Ok((head, None));
        }
        let (tail, n2) = bincode::serde::decode_from_slice(rest, bincode::config::standard())
            .map_err(|_| MpsError::DeserializationError)?;
        if n2 != rest.len() {
            return Err(MpsError::DeserializationError);
        }
        Ok((head, Some(tail)))
    }

    pub fn encode_root_document_from_bytes(
        signing_bytes: &[u8],
        vrf_bytes: &[u8],
    ) -> Result<Vec<u8>, MpsError> {
        let (signing, n): (Keyshare<EdwardsPoint>, usize) =
            bincode::serde::decode_from_slice(signing_bytes, bincode::config::standard())
                .map_err(|_| MpsError::DeserializationError)?;
        if n != signing_bytes.len() {
            return Err(MpsError::DeserializationError);
        }
        let (vrf, n): (Keyshare<VrfPoint>, usize) =
            bincode::serde::decode_from_slice(vrf_bytes, bincode::config::standard())
                .map_err(|_| MpsError::DeserializationError)?;
        if n != vrf_bytes.len() {
            return Err(MpsError::DeserializationError);
        }
        encode_root_document(&signing, &vrf)
    }

    pub fn encode_root_document(
        signing: &Keyshare<EdwardsPoint>,
        vrf: &Keyshare<VrfPoint>,
    ) -> Result<Vec<u8>, MpsError> {
        bincode::serde::encode_to_vec(
            &RootDocument {
                version: ROOT_DOCUMENT_VERSION,
                signing: signing.clone(),
                vrf: vrf.clone(),
            },
            bincode::config::standard(),
        )
        .map_err(|_| MpsError::SerializationError)
    }

    pub fn decode_root_document(data: &[u8]) -> Result<RootDocument, MpsError> {
        let (doc, n): (RootDocument, usize) =
            bincode::serde::decode_from_slice(data, bincode::config::standard())
                .map_err(|_| MpsError::DeserializationError)?;
        if n != data.len() {
            return Err(MpsError::DeserializationError);
        }
        if doc.version != ROOT_DOCUMENT_VERSION {
            return Err(MpsError::InvalidInput);
        }
        Ok(doc)
    }

    /// Serialize a message pool as a concatenation of individually-encoded messages.
    /// This format supports simple byte concatenation to merge pools.
    pub fn serialize_pool(prefix: &str, msgs: &[DrvMessage]) -> Result<Vec<u8>, MpsError> {
        let mut buf = Vec::new();
        for msg in msgs {
            buf.extend(add_prefix(
                prefix,
                &bincode::serde::encode_to_vec(msg, bincode::config::standard())
                    .map_err(|_| MpsError::SerializationError)?,
            ));
        }
        Ok(buf)
    }

    /// Deserialize a pool produced by `serialize_pool`.
    pub fn deserialize_pool(prefix: &str, data: &[u8]) -> Result<Vec<DrvMessage>, MpsError> {
        let mut cursor = Cursor::new(data);
        let mut msgs = Vec::new();
        while (cursor.position() as usize) < data.len() {
            let mut buf_prefix = vec![0u8; prefix.len()];
            cursor
                .read_exact(&mut buf_prefix)
                .map_err(|_| MpsError::DeserializationError)?;
            let _ = buf_prefix
                .strip_prefix(prefix.as_bytes())
                .ok_or(MpsError::InvalidInput)?;
            let msg: DrvMessage =
                bincode::serde::decode_from_std_read(&mut cursor, bincode::config::standard())
                    .map_err(|_| MpsError::DeserializationError)?;
            msgs.push(msg);
        }
        Ok(msgs)
    }

    fn internal_dkg_round0_process<G>(
        party_id: u8,
        decryption_key: &[u8; 32],
        encryption_keys: &[Vec<u8>; 2],
        seed: &[u8; 32],
        with_vrf: bool,
    ) -> Result<MsgState, MpsError>
    where
        G: GroupElem,
        G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    {
        if party_id >= 3 {
            return Err(MpsError::InvalidInput);
        }

        // Parse decryption key
        let secret_key = crypto_box::SecretKey::from(*decryption_key);

        // Parse all party encryption keys
        let i0_pk = crypto_box::PublicKey::from(
            <[u8; 32]>::try_from(encryption_keys[0].clone()).map_err(|_| MpsError::InvalidInput)?,
        );
        let i1_pk = crypto_box::PublicKey::from(
            <[u8; 32]>::try_from(encryption_keys[1].clone()).map_err(|_| MpsError::InvalidInput)?,
        );
        let mut public_keys = Vec::new();
        if party_id == 0 {
            public_keys.push((1u8, i0_pk));
            public_keys.push((2u8, i1_pk));
        } else if party_id == 1 {
            public_keys.push((0u8, i0_pk));
            public_keys.push((2u8, i1_pk));
        } else {
            public_keys.push((0u8, i0_pk));
            public_keys.push((1u8, i1_pk));
        }
        public_keys.push((party_id, secret_key.public_key()));

        // Create KeygenParty
        let p0 = KeygenParty::<DkgR0, G>::new(
            2, // threshold
            3, // total parties
            party_id,
            Arc::new(secret_key),
            public_keys,
            None, // refresh_data
            None, // key_id
            *seed,
            None, // extra_data
        )
        .map_err(|_| MpsError::ProtocolError)?;

        // Generate message
        let (p1, msg1) = p0.process(()).map_err(|_| MpsError::ProtocolError)?;

        // Create the state for storage between rounds
        let state = DkgStateR1 {
            party_id,
            msg: msg1,
            party: p1,
        };

        let vrf_state = if with_vrf {
            let mut rng = rand::thread_rng();
            let vrf_party = VrfParty::new(3, 2, party_id);
            let vp0 = VrfDkgParty::<VrfDkgR0>::new(vrf_party, *seed, &mut rng)
                .map_err(|_| MpsError::ProtocolError)?;
            let (vp1, vrf_msg1) = vp0.process(()).map_err(|_| MpsError::ProtocolError)?;
            Some(VrfDkgStateR1 {
                party_id,
                msg: vrf_msg1,
                party: vp1,
            })
        } else {
            None
        };

        Ok(MsgState {
            msg: encode_head_tail(&state.msg, vrf_state.as_ref().map(|s| &s.msg))?,
            state: encode_head_tail(&state, vrf_state.as_ref())?,
        })
    }

    fn internal_dkg_round1_process<G>(
        round1_messages: &[Vec<u8>; 2],
        state: &[u8],
    ) -> Result<MsgState, MpsError>
    where
        G: GroupElem,
        G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    {
        let (state, vrf_state): (DkgStateR1<G>, Option<VrfDkgStateR1>) = decode_head_tail(state)?;

        let (i0_msg1, i0_vrf): (KeygenMsg1, Option<VrfKeygenMsg1>) =
            decode_head_tail(round1_messages[0].as_slice())?;
        let (i1_msg1, i1_vrf): (KeygenMsg1, Option<VrfKeygenMsg1>) =
            decode_head_tail(round1_messages[1].as_slice())?;

        let with_vrf = vrf_state.is_some();
        if with_vrf != i0_vrf.is_some() || with_vrf != i1_vrf.is_some() {
            return Err(MpsError::InvalidInput);
        }

        let party_id = state.party_id;
        let msgs = vec![i0_msg1, i1_msg1, state.msg];
        let (p2, msg2) = state
            .party
            .process(msgs)
            .map_err(|_| MpsError::ProtocolError)?;

        let next_vrf = if let Some(vrf_state) = vrf_state {
            let (vp2, vrf_msg2) = vrf_state
                .party
                .process(vec![i0_vrf.unwrap(), i1_vrf.unwrap(), vrf_state.msg])
                .map_err(|_| MpsError::ProtocolError)?;
            Some(VrfDkgStateR2 {
                party_id,
                msg: vrf_msg2,
                party: vp2,
            })
        } else {
            None
        };

        let state = DkgStateR2 {
            party_id,
            msg: msg2.clone(),
            party: p2,
        };

        Ok(MsgState {
            msg: encode_head_tail(&msg2, next_vrf.as_ref().map(|s| &s.msg))?,
            state: encode_head_tail(&state, next_vrf.as_ref())?,
        })
    }

    type DkgRound2Result<G> = (Keyshare<G>, u8, Option<Keyshare<VrfPoint>>);

    fn internal_dkg_round2_process<G>(
        round2_messages: &[Vec<u8>; 2],
        state: &[u8],
    ) -> Result<DkgRound2Result<G>, MpsError>
    where
        G: GroupElem,
        G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    {
        let (i0_msg2, i0_vrf): (KeygenMsg2<G>, Option<VrfKeygenMsg2>) =
            decode_head_tail(round2_messages[0].as_slice())?;
        let (i1_msg2, i1_vrf): (KeygenMsg2<G>, Option<VrfKeygenMsg2>) =
            decode_head_tail(round2_messages[1].as_slice())?;

        let (state, vrf_state): (DkgStateR2<G>, Option<VrfDkgStateR2>) = decode_head_tail(state)?;

        let with_vrf = vrf_state.is_some();
        if with_vrf != i0_vrf.is_some() || with_vrf != i1_vrf.is_some() {
            return Err(MpsError::InvalidInput);
        }

        let party_id = state.party_id;
        let share = state
            .party
            .process(vec![i0_msg2, i1_msg2, state.msg])
            .map_err(|_| MpsError::ProtocolError)?;

        let vrf_share = if let Some(vrf_state) = vrf_state {
            Some(
                vrf_state
                    .party
                    .process(vec![i0_vrf.unwrap(), i1_vrf.unwrap(), vrf_state.msg])
                    .map_err(|_| MpsError::ProtocolError)?,
            )
        } else {
            None
        };

        Ok((share, party_id, vrf_share))
    }

    fn internal_dsg_round0_process<G>(p0: SignerParty<DsgR0, G>) -> Result<MsgState, MpsError>
    where
        G: GroupElem,
        G::Scalar: Serializable,
    {
        // Generate message
        let (p1, msg1) = p0.process(()).map_err(|_| MpsError::ProtocolError)?;

        // Create the state for storage between rounds
        let state = DsgStateR1 {
            msg: msg1.clone(),
            party: p1,
        };

        Ok(MsgState {
            msg: bincode::serde::encode_to_vec(&msg1, bincode::config::standard())
                .map_err(|_| MpsError::SerializationError)?,
            state: bincode::serde::encode_to_vec(&state, bincode::config::standard())
                .map_err(|_| MpsError::SerializationError)?,
        })
    }

    fn internal_dsg_round1_process<G>(
        round1_message: &[u8],
        state: &[u8],
    ) -> Result<MsgState, MpsError>
    where
        G: GroupElem,
        G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    {
        // Parse state
        let state: DsgStateR1<G> =
            bincode::serde::decode_from_slice(state, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|_| MpsError::DeserializationError)?;

        // Parse messages
        let i0_msg1: SignMsg1 =
            bincode::serde::decode_from_slice(round1_message, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|_| MpsError::DeserializationError)?;
        let msgs = vec![i0_msg1, state.msg];

        // Process all round1 messages together
        let (p2, msg2) = state
            .party
            .process(msgs)
            .map_err(|_| MpsError::ProtocolError)?;

        // Create the state for storage between rounds
        let state = DsgStateR2 {
            msg: msg2.clone(),
            party: p2,
        };

        Ok(MsgState {
            msg: bincode::serde::encode_to_vec(&msg2, bincode::config::standard())
                .map_err(|_| MpsError::SerializationError)?,
            state: bincode::serde::encode_to_vec(&state, bincode::config::standard())
                .map_err(|_| MpsError::SerializationError)?,
        })
    }

    fn internal_dsg_round2_process<G>(
        round2_message: &[u8],
        state: &[u8],
    ) -> Result<MsgState, MpsError>
    where
        G: GroupElem,
        G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
        SignerParty<DsgR2<G>, G>: Round<Input = Vec<SignMsg2<G>>, Error = SignError>,
        <SignerParty<DsgR2<G>, G> as Round>::Output: IntoSignReady<G>,
        SignReady<G>: Round<Input = (), Output = (PartialSign<G>, SignMsg3<G>), Error = SignError>,
    {
        let i0_msg2: SignMsg2<G> =
            bincode::serde::decode_from_slice(round2_message, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|_| MpsError::DeserializationError)?;
        let state: DsgStateR2<G> =
            bincode::serde::decode_from_slice(state, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|_| MpsError::DeserializationError)?;
        let msgs = vec![i0_msg2, state.msg];
        let (ready_signer, alpha) = state
            .party
            .process(msgs)
            .map_err(|_| MpsError::ProtocolError)?
            .into_sign_ready()?;
        let (p3, msg3) = ready_signer
            .process(())
            .map_err(|_| MpsError::ProtocolError)?;
        let new_state = DsgStateR3 {
            msg: msg3.clone(),
            party: p3,
            alpha,
        };
        Ok(MsgState {
            msg: bincode::serde::encode_to_vec(&msg3, bincode::config::standard())
                .map_err(|_| MpsError::SerializationError)?,
            state: bincode::serde::encode_to_vec(&new_state, bincode::config::standard())
                .map_err(|_| MpsError::SerializationError)?,
        })
    }

    fn internal_dsg_round3_process<G, S, SC>(
        round3_message: &[u8],
        state: &[u8],
    ) -> Result<(Vec<u8>, G, [u8; 32]), MpsError>
    where
        G: GroupElem,
        G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
        PartialSign<G>: Round<Input = Vec<SignMsg3<G>>, Output = (S, SC), Error = SignError>,
        S: Into<[u8; 64]>,
    {
        let state: DsgStateR3<G> =
            bincode::serde::decode_from_slice(state, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|_| MpsError::DeserializationError)?;
        let i0_msg3: SignMsg3<G> =
            bincode::serde::decode_from_slice(round3_message, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|_| MpsError::DeserializationError)?;
        let public_key = state.party.public_key;
        let alpha = state.alpha;
        let (sig, _) = state
            .party
            .process(vec![i0_msg3, state.msg])
            .map_err(|_| MpsError::ProtocolError)?;
        let sig_bytes: [u8; 64] = sig.into();
        Ok((sig_bytes.to_vec(), public_key, alpha))
    }

    /// Process round 0 of DKG protocol for Ed25519.
    /// party_id: Party identifier / index.
    /// decryption_key: Private Curve25519 key.
    /// encryption_keys: Public Curve25519 keys of other parties.
    /// seed: PRNG seed for entropy.
    pub fn ed25519_dkg_round0_process(
        party_id: u8,
        decryption_key: &[u8; 32],
        encryption_keys: &[Vec<u8>; 2],
        seed: &[u8; 32],
        with_vrf: bool,
    ) -> Result<MsgState, MpsError> {
        let result = internal_dkg_round0_process::<EdwardsPoint>(
            party_id,
            decryption_key,
            encryption_keys,
            seed,
            with_vrf,
        )?;
        Ok(MsgState {
            msg: add_prefix("mps-ed25519-dkg-round1-message$", &result.msg),
            state: add_prefix("mps-ed25519-dkg-round1-state$", &result.state),
        })
    }

    fn internal_dkg_round0_import<G>(
        party_id: u8,
        decryption_key: &[u8; 32],
        encryption_keys: &[Vec<u8>; 2],
        s_i_0: G::Scalar,
        expected_pk: G,
        chain_code: [u8; 32],
    ) -> Result<MsgState, MpsError>
    where
        G: GroupElem,
        G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    {
        if party_id >= 3 {
            return Err(MpsError::InvalidInput);
        }

        // Parse decryption key
        let secret_key = crypto_box::SecretKey::from(*decryption_key);

        // Parse all party encryption keys
        let i0_pk = crypto_box::PublicKey::from(
            <[u8; 32]>::try_from(encryption_keys[0].clone()).map_err(|_| MpsError::InvalidInput)?,
        );
        let i1_pk = crypto_box::PublicKey::from(
            <[u8; 32]>::try_from(encryption_keys[1].clone()).map_err(|_| MpsError::InvalidInput)?,
        );
        let mut public_keys = Vec::new();
        if party_id == 0 {
            public_keys.push((1u8, i0_pk));
            public_keys.push((2u8, i1_pk));
        } else if party_id == 1 {
            public_keys.push((0u8, i0_pk));
            public_keys.push((2u8, i1_pk));
        } else {
            public_keys.push((0u8, i0_pk));
            public_keys.push((1u8, i1_pk));
        }
        public_keys.push((party_id, secret_key.public_key()));

        // Build refresh data from the MPCv1 additive scalar and expected public key
        let refresh_data = KeyRefreshData::make_refresh_data_migrate(
            party_id,
            2,
            3,
            s_i_0,
            expected_pk,
            chain_code,
        );

        // Create KeygenParty with refresh_data so the protocol re-shares from the existing key
        let p0 = KeygenParty::<DkgR0, G>::new(
            2, // threshold
            3, // total parties
            party_id,
            Arc::new(secret_key),
            public_keys,
            Some(refresh_data), // refresh_data
            None,               // key_id
            rand::thread_rng().gen(),
            None, // extra_data
        )
        .map_err(|_| MpsError::ProtocolError)?;

        // Generate message
        let (p1, msg1) = p0.process(()).map_err(|_| MpsError::ProtocolError)?;

        // Create the state for storage between rounds
        let state = DkgStateR1 {
            party_id,
            msg: msg1,
            party: p1,
        };

        Ok(MsgState {
            msg: bincode::serde::encode_to_vec(msg1, bincode::config::standard())
                .map_err(|_| MpsError::SerializationError)?,
            state: bincode::serde::encode_to_vec(&state, bincode::config::standard())
                .map_err(|_| MpsError::SerializationError)?,
        })
    }

    /// MPCv1 → MPCv2 retrofit: round 0 of DKG import for Ed25519.
    /// party_id: Party identifier / index.
    /// decryption_key: Private Curve25519 key.
    /// encryption_keys: Public Curve25519 keys of other parties.
    /// s_i_0: 32 bytes LE — additive scalar (pShare.u, clamped).
    /// expected_pk: 32 bytes — aggregate Ed25519 public key (pShare.y).
    /// chain_code: 32 bytes — root chain code (pShare.chaincode).
    pub fn ed25519_dkg_round0_import(
        party_id: u8,
        decryption_key: &[u8; 32],
        encryption_keys: &[Vec<u8>; 2],
        s_i_0: &[u8; 32],
        expected_pk: &[u8; 32],
        chain_code: &[u8; 32],
    ) -> Result<MsgState, MpsError> {
        use multi_party_schnorr::curve25519_dalek::{edwards::CompressedEdwardsY, Scalar};

        let scalar = Scalar::from_bytes_mod_order(*s_i_0);
        let pub_key = CompressedEdwardsY(*expected_pk)
            .decompress()
            .ok_or(MpsError::InvalidInput)?;

        let result = internal_dkg_round0_import::<EdwardsPoint>(
            party_id,
            decryption_key,
            encryption_keys,
            scalar,
            pub_key,
            *chain_code,
        )?;

        Ok(MsgState {
            msg: add_prefix("mps-ed25519-dkg-round1-message$", &result.msg),
            state: add_prefix("mps-ed25519-dkg-round1-state$", &result.state),
        })
    }

    /// Process round 1 of DKG protocol.
    /// round1_messages: Public messages from other parties.
    /// state: Private state result from from round 0.
    pub fn ed25519_dkg_round1_process(
        round1_messages: &[Vec<u8>; 2],
        state: &[u8],
    ) -> Result<MsgState, MpsError> {
        let i0_msg1 = rem_prefix("mps-ed25519-dkg-round1-message$", &round1_messages[0])?;
        let i1_msg1 = rem_prefix("mps-ed25519-dkg-round1-message$", &round1_messages[1])?;
        let state = rem_prefix("mps-ed25519-dkg-round1-state$", state)?;
        let result = internal_dkg_round1_process::<EdwardsPoint>(&[i0_msg1, i1_msg1], &state)?;
        Ok(MsgState {
            msg: add_prefix("mps-ed25519-dkg-round2-message$", &result.msg),
            state: add_prefix("mps-ed25519-dkg-round2-state$", &result.state),
        })
    }

    /// Process round 2 of DKG protocol.
    /// round2_messages: Public messages from other parties.
    /// state: Private state result from round 1.
    pub fn ed25519_dkg_round2_process(
        round2_messages: &[Vec<u8>; 2],
        state: &[u8],
    ) -> Result<Share, MpsError> {
        let i0_msg2 = rem_prefix("mps-ed25519-dkg-round2-message$", &round2_messages[0])?;
        let i1_msg2 = rem_prefix("mps-ed25519-dkg-round2-message$", &round2_messages[1])?;
        let state = rem_prefix("mps-ed25519-dkg-round2-state$", state)?;
        let (share, _, vrf_share) =
            internal_dkg_round2_process::<EdwardsPoint>(&[i0_msg2, i1_msg2], &state)?;
        let (share_bytes, vrf_pk, vrf_chaincode) = if let Some(vrf) = vrf_share {
            (
                encode_root_document(&share, &vrf)?,
                Some(vrf.public_key.compress().to_bytes()),
                Some(vrf.root_chain_code),
            )
        } else {
            (
                bincode::serde::encode_to_vec(&share, bincode::config::standard())
                    .map_err(|_| MpsError::SerializationError)?,
                None,
                None,
            )
        };
        Ok(Share {
            share: share_bytes,
            pk: share.public_key.compress().to_bytes(),
            chaincode: share.root_chain_code,
            vrf_pk,
            vrf_chaincode,
        })
    }

    /// Process round 0 of DSG protocol.
    /// share: Signing share from DKG.
    /// derivation_path: Key derivation path.
    /// message: Message to sign.
    pub fn ed25519_dsg_round0_process(
        share: &[u8],
        derivation_path: String,
        message: &[u8],
    ) -> Result<MsgState, MpsError> {
        // Deserialize share
        let keyshare: Keyshare<EdwardsPoint> =
            bincode::serde::decode_from_slice(share, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|_| MpsError::DeserializationError)?;

        // Create signer party
        let p0 = SignerParty::<DsgR0, EdwardsPoint>::new_with_format::<_, Bip32Public>(
            Arc::new(keyshare),
            message.to_vec(),
            derivation_path
                .parse()
                .map_err(|_| MpsError::DeserializationError)?,
            &mut rand::thread_rng(),
        );

        let result = internal_dsg_round0_process(p0)?;

        Ok(MsgState {
            msg: add_prefix("mps-ed25519-dsg-round1-message$", &result.msg),
            state: add_prefix("mps-ed25519-dsg-round1-state$", &result.state),
        })
    }

    /// Process round 1 of DSG protocol.
    /// round1_messages: Public messages from other parties.
    /// state: Private state result from round 0.
    pub fn ed25519_dsg_round1_process(
        round1_message: &[u8],
        state: &[u8],
    ) -> Result<MsgState, MpsError> {
        let round1_message = rem_prefix("mps-ed25519-dsg-round1-message$", round1_message)?;
        let state = rem_prefix("mps-ed25519-dsg-round1-state$", state)?;
        let result = internal_dsg_round1_process::<EdwardsPoint>(
            round1_message.as_slice(),
            state.as_slice(),
        )?;
        Ok(MsgState {
            msg: add_prefix("mps-ed25519-dsg-round2-message$", &result.msg),
            state: add_prefix("mps-ed25519-dsg-round2-state$", &result.state),
        })
    }

    /// Process round 2 of DSG protocol.
    /// round2_messages: Public messages from other parties.
    /// state: Private state result from round 1.
    pub fn ed25519_dsg_round2_process(
        round2_message: &[u8],
        state: &[u8],
    ) -> Result<MsgState, MpsError> {
        // Strip prefix
        let round2_message = rem_prefix("mps-ed25519-dsg-round2-message$", round2_message)?;
        let state = rem_prefix("mps-ed25519-dsg-round2-state$", state)?;

        let result = internal_dsg_round2_process::<EdwardsPoint>(&round2_message, &state)?;

        Ok(MsgState {
            msg: add_prefix("mps-ed25519-dsg-round3-message$", &result.msg),
            state: add_prefix("mps-ed25519-dsg-round3-state$", &result.state),
        })
    }

    /// Process round 3 of DSG protocol; returns the 64-byte signature.
    pub fn ed25519_dsg_round3_process(
        round3_message: &[u8],
        state: &[u8],
    ) -> Result<Vec<u8>, MpsError> {
        // Strip prefix
        let round3_message = rem_prefix("mps-ed25519-dsg-round3-message$", round3_message)?;
        let state = rem_prefix("mps-ed25519-dsg-round3-state$", state)?;

        let (sig, _, _) =
            internal_dsg_round3_process::<EdwardsPoint, _, _>(&round3_message, &state)?;

        Ok(sig)
    }

    // Hard derive (ed25519) — consumes a combined RootDocument (signing + VRF
    // shares from with_vrf DKG). 2-of-3 threshold; round0 bootstraps alone,
    // round1/round2 take a single peer message each. `path` is opaque bytes.

    #[derive(Serialize, Deserialize)]
    struct HardDeriveStateR1Ed25519 {
        msg: HardDeriveMsg0,
        party: HardDerivePartyEd25519<HardDeriveR1>,
        init: MpcDeriveInitEd25519,
    }

    #[derive(Serialize, Deserialize)]
    struct HardDeriveStateR2Ed25519 {
        msg: HardDeriveMsg1,
        party: HardDerivePartyEd25519<HardDeriveR2>,
        init: MpcDeriveInitEd25519,
    }

    pub fn ed25519_hard_derive_round0_process(
        root_share: &[u8],
        path: &[u8],
        _seed: &[u8],
    ) -> Result<MsgState, MpsError> {
        let doc = decode_root_document(root_share)?;
        let init: MpcDeriveInitEd25519 = with_ristretto_vrf_ed25519(doc.signing, doc.vrf);
        let mut rng = rand::thread_rng();
        let p0 = HardDerivePartyEd25519::<HardDeriveR0>::new(init.clone(), path.to_vec(), &mut rng)
            .map_err(|_| MpsError::ProtocolError)?;
        let (p1, msg0) = p0.process(()).map_err(|_| MpsError::ProtocolError)?;
        let state = HardDeriveStateR1Ed25519 {
            msg: msg0.clone(),
            party: p1,
            init,
        };
        Ok(MsgState {
            msg: add_prefix(
                "mps-ed25519-hard-derive-round1-message$",
                &bincode::serde::encode_to_vec(&msg0, bincode::config::standard())
                    .map_err(|_| MpsError::SerializationError)?,
            ),
            state: add_prefix(
                "mps-ed25519-hard-derive-round1-state$",
                &bincode::serde::encode_to_vec(&state, bincode::config::standard())
                    .map_err(|_| MpsError::SerializationError)?,
            ),
        })
    }

    pub fn ed25519_hard_derive_round1_process(
        round1_message: &[u8],
        state: &[u8],
    ) -> Result<MsgState, MpsError> {
        let state = rem_prefix("mps-ed25519-hard-derive-round1-state$", state)?;
        let state: HardDeriveStateR1Ed25519 =
            bincode::serde::decode_from_slice(&state, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|_| MpsError::DeserializationError)?;
        let round1_message = rem_prefix("mps-ed25519-hard-derive-round1-message$", round1_message)?;
        let peer: HardDeriveMsg0 =
            bincode::serde::decode_from_slice(&round1_message, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|_| MpsError::DeserializationError)?;
        let (p2, msg1) = state
            .party
            .process(vec![peer, state.msg])
            .map_err(|_| MpsError::ProtocolError)?;
        let new_state = HardDeriveStateR2Ed25519 {
            msg: msg1.clone(),
            party: p2,
            init: state.init,
        };
        Ok(MsgState {
            msg: add_prefix(
                "mps-ed25519-hard-derive-round2-message$",
                &bincode::serde::encode_to_vec(&msg1, bincode::config::standard())
                    .map_err(|_| MpsError::SerializationError)?,
            ),
            state: add_prefix(
                "mps-ed25519-hard-derive-round2-state$",
                &bincode::serde::encode_to_vec(&new_state, bincode::config::standard())
                    .map_err(|_| MpsError::SerializationError)?,
            ),
        })
    }

    pub fn ed25519_hard_derive_round2_process(
        round2_message: &[u8],
        state: &[u8],
        participating_party_ids: &[u8; 2],
    ) -> Result<Share, MpsError> {
        let state = rem_prefix("mps-ed25519-hard-derive-round2-state$", state)?;
        let state: HardDeriveStateR2Ed25519 =
            bincode::serde::decode_from_slice(&state, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|_| MpsError::DeserializationError)?;
        let round2_message = rem_prefix("mps-ed25519-hard-derive-round2-message$", round2_message)?;
        let peer: HardDeriveMsg1 =
            bincode::serde::decode_from_slice(&round2_message, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|_| MpsError::DeserializationError)?;
        let output = state
            .party
            .process(vec![peer, state.msg])
            .map_err(|_| MpsError::ProtocolError)?;
        let derived: Keyshare<EdwardsPoint> =
            keyshare_after_hard_derive(&state.init, &output, participating_party_ids.as_slice());
        Ok(Share {
            share: bincode::serde::encode_to_vec(&derived, bincode::config::standard())
                .map_err(|_| MpsError::SerializationError)?,
            pk: derived.public_key.compress().to_bytes(),
            chaincode: derived.root_chain_code,
            vrf_pk: None,
            vrf_chaincode: None,
        })
    }

    /// Process round 0 of RedPallas DKG (same flow as ed25519).
    pub fn redpallas_dkg_round0_process(
        party_id: u8,
        decryption_key: &[u8; 32],
        encryption_keys: &[Vec<u8>; 2],
        seed: &[u8; 32],
    ) -> Result<MsgState, MpsError> {
        let result = internal_dkg_round0_process::<RedPallasPoint>(
            party_id,
            decryption_key,
            encryption_keys,
            seed,
            false,
        )?;
        Ok(MsgState {
            msg: add_prefix("mps-redpallas-dkg-round1-message$", &result.msg),
            state: add_prefix("mps-redpallas-dkg-round1-state$", &result.state),
        })
    }

    /// Process round 1 of RedPallas DKG (same flow as ed25519).
    pub fn redpallas_dkg_round1_process(
        round1_messages: &[Vec<u8>; 2],
        state: &[u8],
    ) -> Result<MsgState, MpsError> {
        let i0_msg1 = rem_prefix("mps-redpallas-dkg-round1-message$", &round1_messages[0])?;
        let i1_msg1 = rem_prefix("mps-redpallas-dkg-round1-message$", &round1_messages[1])?;
        let state = rem_prefix("mps-redpallas-dkg-round1-state$", state)?;
        let result = internal_dkg_round1_process::<RedPallasPoint>(&[i0_msg1, i1_msg1], &state)?;
        Ok(MsgState {
            msg: add_prefix("mps-redpallas-dkg-round2-message$", &result.msg),
            state: add_prefix("mps-redpallas-dkg-round2-state$", &result.state),
        })
    }

    /// Process round 2 of RedPallas DKG; finalizes keyshare and starts derivation session.
    pub fn redpallas_dkg_round2_process(
        round2_messages: &[Vec<u8>; 2],
        state: &[u8],
        derivation_seed: &[u8; 32],
    ) -> Result<MsgDerivationInit, MpsError> {
        let i0_msg2 = rem_prefix("mps-redpallas-dkg-round2-message$", &round2_messages[0])?;
        let i1_msg2 = rem_prefix("mps-redpallas-dkg-round2-message$", &round2_messages[1])?;
        let state = rem_prefix("mps-redpallas-dkg-round2-state$", state)?;
        let (share, party_id, _) =
            internal_dkg_round2_process::<RedPallasPoint>(&[i0_msg2, i1_msg2], &state)?;
        let pk = RedPallasPointBytes::from(share.public_key).0;
        let share_bytes = bincode::serde::encode_to_vec(&share, bincode::config::standard())
            .map_err(|_| MpsError::SerializationError)?;

        let (drv_session, initial_outgoing) =
            DerivationSession::new(party_id, *share.shamir_share(), *derivation_seed)
                .map_err(|_| MpsError::ProtocolError)?;

        let drv = serialize_pool("mps-redpallas-dkg-derivation-message$", &initial_outgoing)?;

        let state =
            bincode::serde::encode_to_vec((party_id, &drv_session), bincode::config::standard())
                .map_err(|_| MpsError::SerializationError)?;

        Ok(MsgDerivationInit {
            share: share_bytes,
            pk,
            msg: drv,
            state: add_prefix("mps-redpallas-dkg-derivation-state$", &state),
        })
    }

    /// Drive the Orchard derivation session forward by one message.
    /// `messages` is the global pool shared across all parties. One message
    /// addressed to this party (or broadcast with no receiver) is consumed; any generated messages are added.
    /// The updated pool is returned as `messages`. Completion is detectable on
    /// any subsequent call via `session.derived_keys()`.
    pub fn redpallas_derivation_process(
        messages: &[u8],
        state: &[u8],
    ) -> Result<MsgDerivation, MpsError> {
        let state = rem_prefix("mps-redpallas-dkg-derivation-state$", state)?;
        let (party_id, mut session): (u8, DerivationSession) =
            bincode::serde::decode_from_slice(&state, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|_| MpsError::DeserializationError)?;

        let mut pool = deserialize_pool("mps-redpallas-dkg-derivation-message$", messages)?;

        // Find and consume the first message in the pool addressed to this party.
        let pos = pool
            .iter()
            .position(|msg| msg.receiver().is_none_or(|to| to == party_id));
        if let Some(idx) = pos {
            let msg = pool.remove(idx);
            let mut outgoing: Vec<DrvMessage> = Vec::new();
            let status = session
                .handle_messages(vec![msg], &mut outgoing)
                .map_err(|_| MpsError::ProtocolError)?;
            if let DerivationStatus::Aborted(_) = status {
                return Err(MpsError::ProtocolError);
            }
            pool.extend(outgoing);
        }

        let new_messages = serialize_pool("mps-redpallas-dkg-derivation-message$", &pool)?;

        let (done, ask, nk, rivk, internal_ivk, external_ivk) =
            if let Some(keys) = session.derived_keys() {
                (
                    true,
                    keys.ask,
                    keys.nk,
                    keys.rivk,
                    keys.internal_ivk,
                    keys.external_ivk,
                )
            } else {
                (false, [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 64], [0u8; 64])
            };

        let new_state =
            bincode::serde::encode_to_vec((party_id, &session), bincode::config::standard())
                .map_err(|_| MpsError::SerializationError)?;

        Ok(MsgDerivation {
            msg: new_messages,
            state: add_prefix("mps-redpallas-dkg-derivation-state$", &new_state),
            done,
            ask: if done { Some(ask) } else { None },
            nk: if done { Some(nk) } else { None },
            rivk: if done { Some(rivk) } else { None },
            internal_ivk: if done { Some(internal_ivk) } else { None },
            external_ivk: if done { Some(external_ivk) } else { None },
        })
    }

    /// Process round 0 of RedPallas DSG.
    pub fn redpallas_dsg_round0_process(
        share: &[u8],
        message: &[u8],
    ) -> Result<MsgState, MpsError> {
        let keyshare: Keyshare<RedPallasPoint> =
            bincode::serde::decode_from_slice(share, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|_| MpsError::DeserializationError)?;
        let p0 = SignerParty::<DsgR0, RedPallasPoint>::new(
            Arc::new(keyshare),
            message.to_vec(),
            "m".parse().map_err(|_| MpsError::InvalidInput)?, // RedPallas does not support derivation.
            &mut rand::thread_rng(),
        );
        let result = internal_dsg_round0_process(p0)?;
        Ok(MsgState {
            msg: add_prefix("mps-redpallas-dsg-round1-message$", &result.msg),
            state: add_prefix("mps-redpallas-dsg-round1-state$", &result.state),
        })
    }

    /// Process round 1 of RedPallas DSG.
    pub fn redpallas_dsg_round1_process(
        round1_message: &[u8],
        state: &[u8],
    ) -> Result<MsgState, MpsError> {
        let round1_message = rem_prefix("mps-redpallas-dsg-round1-message$", round1_message)?;
        let state = rem_prefix("mps-redpallas-dsg-round1-state$", state)?;
        let result = internal_dsg_round1_process::<RedPallasPoint>(&round1_message, &state)?;
        Ok(MsgState {
            msg: add_prefix("mps-redpallas-dsg-round2-message$", &result.msg),
            state: add_prefix("mps-redpallas-dsg-round2-state$", &result.state),
        })
    }

    /// Process round 2 of RedPallas DSG.
    pub fn redpallas_dsg_round2_process(
        round2_message: &[u8],
        state: &[u8],
    ) -> Result<MsgState, MpsError> {
        let round2_message = rem_prefix("mps-redpallas-dsg-round2-message$", round2_message)?;
        let state = rem_prefix("mps-redpallas-dsg-round2-state$", state)?;
        let result = internal_dsg_round2_process::<RedPallasPoint>(&round2_message, &state)?;
        Ok(MsgState {
            msg: add_prefix("mps-redpallas-dsg-round3-message$", &result.msg),
            state: add_prefix("mps-redpallas-dsg-round3-state$", &result.state),
        })
    }

    /// Derive Orchard incoming viewing keys from FVK components (ask, nk, rivk).
    /// Applies sign correction to ask so the resulting ak has a positive x-coordinate
    /// (bit 255 of encoding == 0), matching the Orchard FVK convention.
    pub fn redpallas_fvk_to_ivks(
        ask: &[u8; 32],
        nk: &[u8; 32],
        rivk: &[u8; 32],
    ) -> Result<RedPallasIvks, MpsError> {
        use multi_party_schnorr::group::ff::PrimeField;
        use orchard::{
            keys::{FullViewingKey, Scope},
            primitives::redpallas::{SigningKey, SpendAuth, VerificationKey},
        };
        use pasta_curves::pallas;

        // Compute ak = ask * G_SpendAuth with sign correction (bit 255 must be 0).
        let mut ask_eff: pallas::Scalar =
            Option::from(pallas::Scalar::from_repr(*ask)).ok_or(MpsError::InvalidInput)?;
        let ak_bytes: [u8; 32] = loop {
            let sk: SigningKey<SpendAuth> = ask_eff
                .to_repr()
                .try_into()
                .map_err(|_| MpsError::InvalidInput)?;
            let vk: VerificationKey<SpendAuth> = (&sk).into();
            let ak_candidate: [u8; 32] = (&vk).into();
            if (ak_candidate[31] >> 7) == 1 {
                ask_eff = -ask_eff;
                continue;
            }
            break ak_candidate;
        };

        let mut fvk_bytes = [0u8; 96];
        fvk_bytes[0..32].copy_from_slice(&ak_bytes);
        fvk_bytes[32..64].copy_from_slice(nk);
        fvk_bytes[64..96].copy_from_slice(rivk);

        let fvk = FullViewingKey::from_bytes(&fvk_bytes).ok_or(MpsError::InvalidInput)?;

        Ok(RedPallasIvks {
            internal_ivk: fvk.to_ivk(Scope::Internal).to_bytes(),
            external_ivk: fvk.to_ivk(Scope::External).to_bytes(),
        })
    }

    /// Process round 3 of RedPallas DSG; returns the 64-byte signature and the
    /// per-session randomized verification key (rk) against which it verifies.
    pub fn redpallas_dsg_round3_process(
        round3_message: &[u8],
        state: &[u8],
    ) -> Result<RedPallasSignature, MpsError> {
        let round3_message = rem_prefix("mps-redpallas-dsg-round3-message$", round3_message)?;
        let state = rem_prefix("mps-redpallas-dsg-round3-state$", state)?;
        let (signature, pk, alpha) =
            internal_dsg_round3_process::<RedPallasPoint, _, _>(&round3_message, &state)?;
        let rk = RedPallasPointBytes::from(pk).0;
        Ok(RedPallasSignature {
            signature,
            rk,
            alpha,
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use rand::{self, Rng};

    /// Test full DGK protocol.
    #[test]
    fn test_ed25519_dkg() {
        // Generate key pairs and seeds for all parties
        let mut prv_keys = Vec::new();
        let mut pub_keys = Vec::new();
        let mut seeds = Vec::new();
        for i in 0..3 {
            let secret_key = crypto_box::SecretKey::generate(&mut rand::thread_rng());
            let public_key = secret_key.public_key();
            prv_keys.push(secret_key);
            pub_keys.push((i, public_key));
            let seed: [u8; 32] = rand::thread_rng().gen();
            seeds.push(seed);
        }

        // Parties generate their round 0 messages
        let p0_0 = mps::ed25519_dkg_round0_process(
            0,
            &prv_keys[0].to_bytes(),
            &[
                pub_keys[1].1.to_bytes().to_vec(),
                pub_keys[2].1.to_bytes().to_vec(),
            ],
            &seeds[0],
            false,
        )
        .unwrap();
        let p1_0 = mps::ed25519_dkg_round0_process(
            1,
            &prv_keys[1].to_bytes(),
            &[
                pub_keys[0].1.to_bytes().to_vec(),
                pub_keys[2].1.to_bytes().to_vec(),
            ],
            &seeds[1],
            false,
        )
        .unwrap();
        let p2_0 = mps::ed25519_dkg_round0_process(
            2,
            &prv_keys[2].to_bytes(),
            &[
                pub_keys[0].1.to_bytes().to_vec(),
                pub_keys[1].1.to_bytes().to_vec(),
            ],
            &seeds[2],
            false,
        )
        .unwrap();

        // Parties generate their round 1 messages
        let p0_1 = mps::ed25519_dkg_round1_process(
            &[p1_0.msg.clone(), p2_0.msg.clone()],
            p0_0.state.as_slice(),
        )
        .unwrap();
        let p1_1 = mps::ed25519_dkg_round1_process(
            &[p0_0.msg.clone(), p2_0.msg.clone()],
            p1_0.state.as_slice(),
        )
        .unwrap();
        let p2_1 = mps::ed25519_dkg_round1_process(
            &[p0_0.msg.clone(), p1_0.msg.clone()],
            p2_0.state.as_slice(),
        )
        .unwrap();

        // Parties generate their key shares
        let p0_share = mps::ed25519_dkg_round2_process(
            &[p1_1.msg.clone(), p2_1.msg.clone()],
            p0_1.state.as_slice(),
        )
        .unwrap();
        let p1_share = mps::ed25519_dkg_round2_process(
            &[p0_1.msg.clone(), p2_1.msg.clone()],
            p1_1.state.as_slice(),
        )
        .unwrap();
        let p2_share = mps::ed25519_dkg_round2_process(
            &[p0_1.msg.clone(), p1_1.msg.clone()],
            p2_1.state.as_slice(),
        )
        .unwrap();

        // Assert generated public keychains are equal
        assert_eq!(
            p2_share.pk, p0_share.pk,
            "Party 0 public key differs from party 2 public key"
        );
        assert_eq!(
            p2_share.pk, p1_share.pk,
            "Party 1 public key differs from party 2 public key"
        );
        assert_eq!(
            p2_share.chaincode, p0_share.chaincode,
            "Party 0 chaincode differs from party 2 chaincode"
        );
        assert_eq!(
            p2_share.chaincode, p1_share.chaincode,
            "Party 1 chaincode differs from party 2 chaincode"
        );
    }

    /// Test full DKG import protocol (MPCv1 → MPCv2 retrofit).
    #[test]
    fn test_ed25519_dkg_import() {
        use multi_party_schnorr::curve25519_dalek::{
            constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, Scalar,
        };

        let mut rng = rand::thread_rng();

        // Synthesize 3 additive scalar shares and derive the expected public key.
        let scalar_bytes: Vec<[u8; 32]> = (0..3).map(|_| rng.gen()).collect();
        let scalars: Vec<Scalar> = scalar_bytes
            .iter()
            .map(|b| Scalar::from_bytes_mod_order(*b))
            .collect();
        let sum = scalars[0] + scalars[1] + scalars[2];
        let expected_pk: [u8; 32] = (ED25519_BASEPOINT_POINT * sum).compress().to_bytes();
        let chain_code: [u8; 32] = rng.gen();

        let mut prv_keys = Vec::new();
        let mut pub_keys: Vec<crypto_box::PublicKey> = Vec::new();
        for _ in 0..3 {
            let sk = crypto_box::SecretKey::generate(&mut rng);
            pub_keys.push(sk.public_key());
            prv_keys.push(sk);
        }

        let other_indices = [[1usize, 2], [0, 2], [0, 1]];

        let r0: Vec<_> = (0..3)
            .map(|i| {
                mps::ed25519_dkg_round0_import(
                    i as u8,
                    &prv_keys[i].to_bytes(),
                    &[
                        pub_keys[other_indices[i][0]].to_bytes().to_vec(),
                        pub_keys[other_indices[i][1]].to_bytes().to_vec(),
                    ],
                    &scalars[i].to_bytes(),
                    &expected_pk,
                    &chain_code,
                )
                .unwrap()
            })
            .collect();

        let r1: Vec<_> = (0..3)
            .map(|i| {
                mps::ed25519_dkg_round1_process(
                    &[
                        r0[other_indices[i][0]].msg.clone(),
                        r0[other_indices[i][1]].msg.clone(),
                    ],
                    &r0[i].state,
                )
                .unwrap()
            })
            .collect();

        let shares: Vec<_> = (0..3)
            .map(|i| {
                mps::ed25519_dkg_round2_process(
                    &[
                        r1[other_indices[i][0]].msg.clone(),
                        r1[other_indices[i][1]].msg.clone(),
                    ],
                    &r1[i].state,
                )
                .unwrap()
            })
            .collect();

        // All 3 parties agree on pk and chaincode, both match the inputs.
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.pk, expected_pk, "party {i} pk mismatch");
            assert_eq!(share.chaincode, chain_code, "party {i} chaincode mismatch");
        }
        assert_eq!(shares[0].pk, shares[1].pk);
        assert_eq!(shares[0].pk, shares[2].pk);

        // Verify the public key is a valid Ed25519 point and matches expected.
        let _ = CompressedEdwardsY(shares[0].pk)
            .decompress()
            .expect("pk must be a valid Ed25519 point");
    }

    /// Test full DSG protocol.
    #[test]
    fn test_ed25519_dsg() {
        // Generate signing shares
        let mut prv_keys = Vec::new();
        let mut pub_keys = Vec::new();
        let mut seeds = Vec::new();
        for i in 0..3 {
            let secret_key = crypto_box::SecretKey::generate(&mut rand::thread_rng());
            let public_key = secret_key.public_key();
            prv_keys.push(secret_key);
            pub_keys.push((i, public_key));
            let seed: [u8; 32] = rand::thread_rng().gen();
            seeds.push(seed);
        }

        // Parties generate their round 0 messages
        let dkg_p0_0 = mps::ed25519_dkg_round0_process(
            0,
            &prv_keys[0].to_bytes(),
            &[
                pub_keys[1].1.to_bytes().to_vec(),
                pub_keys[2].1.to_bytes().to_vec(),
            ],
            &seeds[0],
            false,
        )
        .unwrap();
        let dkg_p1_0 = mps::ed25519_dkg_round0_process(
            1,
            &prv_keys[1].to_bytes(),
            &[
                pub_keys[0].1.to_bytes().to_vec(),
                pub_keys[2].1.to_bytes().to_vec(),
            ],
            &seeds[1],
            false,
        )
        .unwrap();
        let dkg_p2_0 = mps::ed25519_dkg_round0_process(
            2,
            &prv_keys[2].to_bytes(),
            &[
                pub_keys[0].1.to_bytes().to_vec(),
                pub_keys[1].1.to_bytes().to_vec(),
            ],
            &seeds[2],
            false,
        )
        .unwrap();

        // Parties generate their round 1 messages
        let dkg_p0_1 = mps::ed25519_dkg_round1_process(
            &[dkg_p1_0.msg.clone(), dkg_p2_0.msg.clone()],
            dkg_p0_0.state.as_slice(),
        )
        .unwrap();
        let dkg_p1_1 = mps::ed25519_dkg_round1_process(
            &[dkg_p0_0.msg.clone(), dkg_p2_0.msg.clone()],
            dkg_p1_0.state.as_slice(),
        )
        .unwrap();
        let dkg_p2_1 = mps::ed25519_dkg_round1_process(
            &[dkg_p0_0.msg.clone(), dkg_p1_0.msg.clone()],
            dkg_p2_0.state.as_slice(),
        )
        .unwrap();

        // Parties generate their key shares
        let dkg_p0_share = mps::ed25519_dkg_round2_process(
            &[dkg_p1_1.msg.clone(), dkg_p2_1.msg.clone()],
            dkg_p0_1.state.as_slice(),
        )
        .unwrap();
        let dkg_p2_share = mps::ed25519_dkg_round2_process(
            &[dkg_p0_1.msg.clone(), dkg_p1_1.msg.clone()],
            dkg_p2_1.state.as_slice(),
        )
        .unwrap();

        // Message to sign.
        let msg = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";

        // Process DSG round 0
        let dsg_p0_0 =
            mps::ed25519_dsg_round0_process(dkg_p0_share.share.as_slice(), "m".to_string(), msg)
                .unwrap();
        let dsg_p2_0 =
            mps::ed25519_dsg_round0_process(dkg_p2_share.share.as_slice(), "m".to_string(), msg)
                .unwrap();

        // Process DSG round 1
        let dsg_p0_1 =
            mps::ed25519_dsg_round1_process(dsg_p2_0.msg.as_slice(), dsg_p0_0.state.as_slice())
                .unwrap();
        let dsg_p2_1 =
            mps::ed25519_dsg_round1_process(dsg_p0_0.msg.as_slice(), dsg_p2_0.state.as_slice())
                .unwrap();

        // Process DSG round 2
        let dsg_p0_2 =
            mps::ed25519_dsg_round2_process(dsg_p2_1.msg.as_slice(), dsg_p0_1.state.as_slice())
                .unwrap();
        let dsg_p2_2 =
            mps::ed25519_dsg_round2_process(dsg_p0_1.msg.as_slice(), dsg_p2_1.state.as_slice())
                .unwrap();

        // Process DSG round 3
        let dsg_p0_sig =
            mps::ed25519_dsg_round3_process(dsg_p2_2.msg.as_slice(), dsg_p0_2.state.as_slice())
                .unwrap();
        let dsg_p2_sig =
            mps::ed25519_dsg_round3_process(dsg_p0_2.msg.as_slice(), dsg_p2_2.state.as_slice())
                .unwrap();

        assert_eq!(
            dsg_p2_sig, dsg_p0_sig,
            "Party 0 signature differs from party 2 signature"
        );

        // Verify signature
        VerifyingKey::from_bytes(&dkg_p0_share.pk)
            .unwrap()
            .verify(
                msg,
                &Signature::from_bytes(dsg_p0_sig.as_slice().try_into().unwrap()),
            )
            .unwrap();
        VerifyingKey::from_bytes(&dkg_p2_share.pk)
            .unwrap()
            .verify(
                msg,
                &Signature::from_bytes(dsg_p2_sig.as_slice().try_into().unwrap()),
            )
            .unwrap();
    }

    /// Test full RedPallas DSG protocol; verifies alpha is non-zero, consistent
    /// between parties, and that the signature verifies against rk.
    #[test]
    fn test_redpallas_dsg() {
        use orchard::primitives::redpallas::{Signature, SpendAuth, VerificationKey};

        let mut prv_keys = Vec::new();
        let mut pub_keys = Vec::new();
        let mut seeds = Vec::new();
        for i in 0..3 {
            let secret_key = crypto_box::SecretKey::generate(&mut rand::thread_rng());
            let public_key = secret_key.public_key();
            prv_keys.push(secret_key);
            pub_keys.push((i, public_key));
            let seed: [u8; 32] = rand::thread_rng().gen();
            seeds.push(seed);
        }
        let derivation_seed: [u8; 32] = rand::thread_rng().gen();

        // DKG round 0
        let dkg_p0_0 = mps::redpallas_dkg_round0_process(
            0,
            &prv_keys[0].to_bytes(),
            &[
                pub_keys[1].1.to_bytes().to_vec(),
                pub_keys[2].1.to_bytes().to_vec(),
            ],
            &seeds[0],
        )
        .unwrap();
        let dkg_p1_0 = mps::redpallas_dkg_round0_process(
            1,
            &prv_keys[1].to_bytes(),
            &[
                pub_keys[0].1.to_bytes().to_vec(),
                pub_keys[2].1.to_bytes().to_vec(),
            ],
            &seeds[1],
        )
        .unwrap();
        let dkg_p2_0 = mps::redpallas_dkg_round0_process(
            2,
            &prv_keys[2].to_bytes(),
            &[
                pub_keys[0].1.to_bytes().to_vec(),
                pub_keys[1].1.to_bytes().to_vec(),
            ],
            &seeds[2],
        )
        .unwrap();

        // DKG round 1
        let dkg_p0_1 = mps::redpallas_dkg_round1_process(
            &[dkg_p1_0.msg.clone(), dkg_p2_0.msg.clone()],
            dkg_p0_0.state.as_slice(),
        )
        .unwrap();
        let dkg_p1_1 = mps::redpallas_dkg_round1_process(
            &[dkg_p0_0.msg.clone(), dkg_p2_0.msg.clone()],
            dkg_p1_0.state.as_slice(),
        )
        .unwrap();
        let dkg_p2_1 = mps::redpallas_dkg_round1_process(
            &[dkg_p0_0.msg.clone(), dkg_p1_0.msg.clone()],
            dkg_p2_0.state.as_slice(),
        )
        .unwrap();

        // DKG round 2 - get shares for parties 0 and 2
        let dkg_p0_init = mps::redpallas_dkg_round2_process(
            &[dkg_p1_1.msg.clone(), dkg_p2_1.msg.clone()],
            dkg_p0_1.state.as_slice(),
            &derivation_seed,
        )
        .unwrap();
        let dkg_p2_init = mps::redpallas_dkg_round2_process(
            &[dkg_p0_1.msg.clone(), dkg_p1_1.msg.clone()],
            dkg_p2_1.state.as_slice(),
            &derivation_seed,
        )
        .unwrap();

        assert_eq!(dkg_p0_init.pk, dkg_p2_init.pk, "DKG public keys differ");

        let msg = b"Test message for RedPallas signing";

        // DSG round 0
        let dsg_p0_0 =
            mps::redpallas_dsg_round0_process(dkg_p0_init.share.as_slice(), msg).unwrap();
        let dsg_p2_0 =
            mps::redpallas_dsg_round0_process(dkg_p2_init.share.as_slice(), msg).unwrap();

        // DSG round 1
        let dsg_p0_1 =
            mps::redpallas_dsg_round1_process(dsg_p2_0.msg.as_slice(), dsg_p0_0.state.as_slice())
                .unwrap();
        let dsg_p2_1 =
            mps::redpallas_dsg_round1_process(dsg_p0_0.msg.as_slice(), dsg_p2_0.state.as_slice())
                .unwrap();

        // DSG round 2
        let dsg_p0_2 =
            mps::redpallas_dsg_round2_process(dsg_p2_1.msg.as_slice(), dsg_p0_1.state.as_slice())
                .unwrap();
        let dsg_p2_2 =
            mps::redpallas_dsg_round2_process(dsg_p0_1.msg.as_slice(), dsg_p2_1.state.as_slice())
                .unwrap();

        // DSG round 3
        let dsg_p0 =
            mps::redpallas_dsg_round3_process(dsg_p2_2.msg.as_slice(), dsg_p0_2.state.as_slice())
                .unwrap();
        let dsg_p2 =
            mps::redpallas_dsg_round3_process(dsg_p0_2.msg.as_slice(), dsg_p2_2.state.as_slice())
                .unwrap();

        // Both parties produce identical outputs
        assert_eq!(dsg_p0.signature, dsg_p2.signature, "Signatures differ");
        assert_eq!(dsg_p0.rk, dsg_p2.rk, "Randomized keys differ");
        assert_eq!(dsg_p0.alpha, dsg_p2.alpha, "Alpha values differ");

        // Alpha is a random field element and must not be zero
        assert_ne!(dsg_p0.alpha, [0u8; 32], "Alpha is zero");

        // Signature verifies against rk, not the original public key
        let rk = VerificationKey::<SpendAuth>::try_from(dsg_p0.rk)
            .expect("rk must be a valid verification key");
        let sig = Signature::<SpendAuth>::from(
            <[u8; 64]>::try_from(dsg_p0.signature.as_slice()).expect("signature must be 64 bytes"),
        );
        rk.verify(msg, &sig)
            .expect("signature must verify against rk");
    }

    #[test]
    fn test_root_document_roundtrip_and_bare_keyshare() {
        use multi_party_schnorr::{curve25519_dalek::EdwardsPoint, keygen::Keyshare};

        let mut prv_keys = Vec::new();
        let mut pub_keys = Vec::new();
        let mut seeds = Vec::new();
        for i in 0..3 {
            let secret_key = crypto_box::SecretKey::generate(&mut rand::thread_rng());
            let public_key = secret_key.public_key();
            prv_keys.push(secret_key);
            pub_keys.push((i, public_key));
            let seed: [u8; 32] = rand::thread_rng().gen();
            seeds.push(seed);
        }
        let other = [[1usize, 2], [0, 2], [0, 1]];

        let r0: Vec<_> = (0..3)
            .map(|i| {
                mps::ed25519_dkg_round0_process(
                    i as u8,
                    &prv_keys[i].to_bytes(),
                    &[
                        pub_keys[other[i][0]].1.to_bytes().to_vec(),
                        pub_keys[other[i][1]].1.to_bytes().to_vec(),
                    ],
                    &seeds[i],
                    false,
                )
                .unwrap()
            })
            .collect();
        let r1: Vec<_> = (0..3)
            .map(|i| {
                mps::ed25519_dkg_round1_process(
                    &[r0[other[i][0]].msg.clone(), r0[other[i][1]].msg.clone()],
                    r0[i].state.as_slice(),
                )
                .unwrap()
            })
            .collect();
        let bare = mps::ed25519_dkg_round2_process(
            &[r1[other[0][0]].msg.clone(), r1[other[0][1]].msg.clone()],
            r1[0].state.as_slice(),
        )
        .unwrap();

        assert!(bare.vrf_pk.is_none());
        let (keyshare, n): (Keyshare<EdwardsPoint>, usize) =
            bincode::serde::decode_from_slice(&bare.share, bincode::config::standard()).unwrap();
        assert_eq!(n, bare.share.len());
        assert!(mps::decode_root_document(&bare.share).is_err());
        assert_eq!(keyshare.public_key.compress().to_bytes(), bare.pk);

        let r0v: Vec<_> = (0..3)
            .map(|i| {
                mps::ed25519_dkg_round0_process(
                    i as u8,
                    &prv_keys[i].to_bytes(),
                    &[
                        pub_keys[other[i][0]].1.to_bytes().to_vec(),
                        pub_keys[other[i][1]].1.to_bytes().to_vec(),
                    ],
                    &seeds[i],
                    true,
                )
                .unwrap()
            })
            .collect();
        let r1v: Vec<_> = (0..3)
            .map(|i| {
                mps::ed25519_dkg_round1_process(
                    &[r0v[other[i][0]].msg.clone(), r0v[other[i][1]].msg.clone()],
                    r0v[i].state.as_slice(),
                )
                .unwrap()
            })
            .collect();
        let shares: Vec<_> = (0..3)
            .map(|i| {
                mps::ed25519_dkg_round2_process(
                    &[r1v[other[i][0]].msg.clone(), r1v[other[i][1]].msg.clone()],
                    r1v[i].state.as_slice(),
                )
                .unwrap()
            })
            .collect();

        assert_eq!(shares[0].pk, shares[1].pk);
        assert_eq!(shares[1].pk, shares[2].pk);
        assert_eq!(shares[0].chaincode, shares[2].chaincode);
        assert_eq!(shares[0].vrf_pk, shares[1].vrf_pk);
        assert_eq!(shares[1].vrf_pk, shares[2].vrf_pk);
        assert!(shares[0].vrf_pk.is_some());

        let doc = mps::decode_root_document(&shares[0].share).unwrap();
        assert_eq!(doc.version, mps::ROOT_DOCUMENT_VERSION);
        let encoded = mps::encode_root_document(&doc.signing, &doc.vrf).unwrap();
        assert_eq!(encoded, shares[0].share);

        assert!(mps::ed25519_dkg_round1_process(
            &[r0v[1].msg.clone(), r0[2].msg.clone()],
            r0v[0].state.as_slice(),
        )
        .is_err());
    }
}

use js_sys::Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct MsgState {
    msg: Vec<u8>,
    state: Vec<u8>,
}

#[wasm_bindgen]
impl MsgState {
    #[wasm_bindgen(getter)]
    pub fn msg(&self) -> Vec<u8> {
        self.msg.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn state(&self) -> Vec<u8> {
        self.state.clone()
    }
}

#[wasm_bindgen]
pub struct Share {
    share: Vec<u8>,
    pk: Vec<u8>,
    chaincode: Vec<u8>,
    vrf_pk: Vec<u8>,
    vrf_chaincode: Vec<u8>,
}

#[wasm_bindgen]
impl Share {
    #[wasm_bindgen(getter)]
    pub fn share(&self) -> Vec<u8> {
        self.share.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pk(&self) -> Vec<u8> {
        self.pk.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn chaincode(&self) -> Vec<u8> {
        self.chaincode.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn vrf_pk(&self) -> Vec<u8> {
        self.vrf_pk.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn vrf_chaincode(&self) -> Vec<u8> {
        self.vrf_chaincode.clone()
    }
}

fn share_from_mps(result: mps::Share) -> Share {
    Share {
        share: result.share,
        pk: result.pk.to_vec(),
        chaincode: result.chaincode.to_vec(),
        vrf_pk: result.vrf_pk.map(|p| p.to_vec()).unwrap_or_default(),
        vrf_chaincode: result.vrf_chaincode.map(|p| p.to_vec()).unwrap_or_default(),
    }
}

#[wasm_bindgen]
pub struct MsgDerivationInit {
    share: Vec<u8>,
    pk: Vec<u8>,
    msg: Vec<u8>,
    state: Vec<u8>,
}

#[wasm_bindgen]
impl MsgDerivationInit {
    #[wasm_bindgen(getter)]
    pub fn share(&self) -> Vec<u8> {
        self.share.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pk(&self) -> Vec<u8> {
        self.pk.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn msg(&self) -> Vec<u8> {
        self.msg.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn state(&self) -> Vec<u8> {
        self.state.clone()
    }
}

#[wasm_bindgen]
pub struct MsgDerivation {
    msg: Vec<u8>,
    state: Vec<u8>,
    done: bool,
    ask: Option<Vec<u8>>,
    nk: Option<Vec<u8>>,
    rivk: Option<Vec<u8>>,
    internal_ivk: Option<Vec<u8>>,
    external_ivk: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl MsgDerivation {
    #[wasm_bindgen(getter)]
    pub fn msg(&self) -> Vec<u8> {
        self.msg.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn state(&self) -> Vec<u8> {
        self.state.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn done(&self) -> bool {
        self.done
    }

    #[wasm_bindgen(getter)]
    pub fn ask(&self) -> Option<Vec<u8>> {
        self.ask.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn nk(&self) -> Option<Vec<u8>> {
        self.nk.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn rivk(&self) -> Option<Vec<u8>> {
        self.rivk.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn internal_ivk(&self) -> Option<Vec<u8>> {
        self.internal_ivk.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn external_ivk(&self) -> Option<Vec<u8>> {
        self.external_ivk.clone()
    }
}

/// Extract exactly two `Vec<u8>` from a JS `Uint8Array[]`.
fn js_array_to_2_bufs(arr: &Array) -> Result<[Vec<u8>; 2], String> {
    use wasm_bindgen::JsCast;
    if arr.length() != 2 {
        return Err(mps::MpsError::InvalidInput.to_string());
    }
    let b0 = arr
        .get(0)
        .dyn_into::<js_sys::Uint8Array>()
        .map_err(|_| mps::MpsError::InvalidInput.to_string())?
        .to_vec();
    let b1 = arr
        .get(1)
        .dyn_into::<js_sys::Uint8Array>()
        .map_err(|_| mps::MpsError::InvalidInput.to_string())?
        .to_vec();
    Ok([b0, b1])
}

#[wasm_bindgen]
pub fn ed25519_dkg_round0_process(
    party_id: u8,
    decryption_key: &[u8],
    encryption_keys: Array,
    seed: &[u8],
    with_vrf: bool,
) -> Result<MsgState, String> {
    let decryption_key_32: [u8; 32] = decryption_key.try_into().map_err(|_| "Invalid input")?;
    let seed_32: [u8; 32] = seed.try_into().map_err(|_| "Invalid input")?;
    let [ek0, ek1] = js_array_to_2_bufs(&encryption_keys)?;
    let result = mps::ed25519_dkg_round0_process(
        party_id,
        &decryption_key_32,
        &[ek0, ek1],
        &seed_32,
        with_vrf,
    )
    .map_err(|e| e.to_string())?;

    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn ed25519_dkg_round0_import(
    party_id: u8,
    decryption_key: &[u8],
    encryption_keys: Array,
    s_i_0: &[u8],
    expected_pk: &[u8],
    chain_code: &[u8],
) -> Result<MsgState, String> {
    let decryption_key_32: [u8; 32] = decryption_key.try_into().map_err(|_| "Invalid input")?;
    let s_i_0_32: [u8; 32] = s_i_0.try_into().map_err(|_| "s_i_0 must be 32 bytes")?;
    let expected_pk_32: [u8; 32] = expected_pk
        .try_into()
        .map_err(|_| "expected_pk must be 32 bytes")?;
    let chain_code_32: [u8; 32] = chain_code
        .try_into()
        .map_err(|_| "chain_code must be 32 bytes")?;
    let [ek0, ek1] = js_array_to_2_bufs(&encryption_keys)?;
    let result = mps::ed25519_dkg_round0_import(
        party_id,
        &decryption_key_32,
        &[ek0, ek1],
        &s_i_0_32,
        &expected_pk_32,
        &chain_code_32,
    )
    .map_err(|e| e.to_string())?;

    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn ed25519_dkg_round1_process(
    round1_messages: Array,
    state: &[u8],
) -> Result<MsgState, String> {
    let [m0, m1] = js_array_to_2_bufs(&round1_messages)?;
    let result = mps::ed25519_dkg_round1_process(&[m0, m1], state).map_err(|e| e.to_string())?;

    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn ed25519_dkg_round2_process(round2_messages: Array, state: &[u8]) -> Result<Share, String> {
    let [m0, m1] = js_array_to_2_bufs(&round2_messages)?;
    let result = mps::ed25519_dkg_round2_process(&[m0, m1], state).map_err(|e| e.to_string())?;
    Ok(share_from_mps(result))
}

#[wasm_bindgen]
pub fn ed25519_dsg_round0_process(
    share: &[u8],
    derivation_path: String,
    message: &[u8],
) -> Result<MsgState, String> {
    let result = mps::ed25519_dsg_round0_process(share, derivation_path, message)
        .map_err(|e| e.to_string())?;

    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn ed25519_dsg_round1_process(round1_message: &[u8], state: &[u8]) -> Result<MsgState, String> {
    let result =
        mps::ed25519_dsg_round1_process(round1_message, state).map_err(|e| e.to_string())?;

    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn ed25519_dsg_round2_process(round2_message: &[u8], state: &[u8]) -> Result<MsgState, String> {
    let result =
        mps::ed25519_dsg_round2_process(round2_message, state).map_err(|e| e.to_string())?;

    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn ed25519_dsg_round3_process(round3_message: &[u8], state: &[u8]) -> Result<Vec<u8>, String> {
    let result =
        mps::ed25519_dsg_round3_process(round3_message, state).map_err(|e| e.to_string())?;

    Ok(result.to_vec())
}

#[wasm_bindgen]
pub fn ed25519_encode_root_document(signing: &[u8], vrf: &[u8]) -> Result<Vec<u8>, String> {
    mps::encode_root_document_from_bytes(signing, vrf).map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub fn ed25519_hard_derive_round0_process(
    root_share: &[u8],
    path: &[u8],
    seed: &[u8],
) -> Result<MsgState, String> {
    let result = mps::ed25519_hard_derive_round0_process(root_share, path, seed)
        .map_err(|e| e.to_string())?;
    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn ed25519_hard_derive_round1_process(
    round1_message: &[u8],
    state: &[u8],
) -> Result<MsgState, String> {
    let result = mps::ed25519_hard_derive_round1_process(round1_message, state)
        .map_err(|e| e.to_string())?;
    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn ed25519_hard_derive_round2_process(
    round2_message: &[u8],
    state: &[u8],
    participating_party_ids: &[u8],
) -> Result<Share, String> {
    let ids: [u8; 2] = participating_party_ids
        .try_into()
        .map_err(|_| "participating_party_ids must be exactly 2 ids")?;
    let result = mps::ed25519_hard_derive_round2_process(round2_message, state, &ids)
        .map_err(|e| e.to_string())?;
    Ok(share_from_mps(result))
}

#[wasm_bindgen]
pub fn redpallas_dkg_round0_process(
    party_id: u8,
    decryption_key: &[u8],
    encryption_keys: Array,
    seed: &[u8],
) -> Result<MsgState, String> {
    let decryption_key_32: [u8; 32] = decryption_key.try_into().map_err(|_| "Invalid input")?;
    let seed_32: [u8; 32] = seed.try_into().map_err(|_| "Invalid input")?;
    let [ek0, ek1] = js_array_to_2_bufs(&encryption_keys)?;
    let result =
        mps::redpallas_dkg_round0_process(party_id, &decryption_key_32, &[ek0, ek1], &seed_32)
            .map_err(|e| e.to_string())?;

    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn redpallas_dkg_round1_process(
    round1_messages: Array,
    state: &[u8],
) -> Result<MsgState, String> {
    let [m0, m1] = js_array_to_2_bufs(&round1_messages)?;
    let result = mps::redpallas_dkg_round1_process(&[m0, m1], state).map_err(|e| e.to_string())?;

    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn redpallas_dkg_round2_process(
    round2_messages: Array,
    state: &[u8],
    derivation_seed: &[u8],
) -> Result<MsgDerivationInit, String> {
    let derivation_seed_32: [u8; 32] = derivation_seed.try_into().map_err(|_| "Invalid input")?;
    let [m0, m1] = js_array_to_2_bufs(&round2_messages)?;
    let result = mps::redpallas_dkg_round2_process(&[m0, m1], state, &derivation_seed_32)
        .map_err(|e| e.to_string())?;

    Ok(MsgDerivationInit {
        share: result.share,
        pk: result.pk.to_vec(),
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn redpallas_derivation_process(
    messages: &[u8],
    state: &[u8],
) -> Result<MsgDerivation, String> {
    let result = mps::redpallas_derivation_process(messages, state).map_err(|e| e.to_string())?;

    Ok(MsgDerivation {
        msg: result.msg,
        state: result.state,
        done: result.done,
        ask: result.ask.map(|ask| ask.to_vec()),
        nk: result.nk.map(|nk| nk.to_vec()),
        rivk: result.rivk.map(|rivk| rivk.to_vec()),
        internal_ivk: result
            .internal_ivk
            .map(|internal_ivk| internal_ivk.to_vec()),
        external_ivk: result
            .external_ivk
            .map(|external_ivk| external_ivk.to_vec()),
    })
}

#[wasm_bindgen]
pub fn redpallas_dsg_round0_process(share: &[u8], message: &[u8]) -> Result<MsgState, String> {
    let result = mps::redpallas_dsg_round0_process(share, message).map_err(|e| e.to_string())?;

    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn redpallas_dsg_round1_process(
    round1_message: &[u8],
    state: &[u8],
) -> Result<MsgState, String> {
    let result =
        mps::redpallas_dsg_round1_process(round1_message, state).map_err(|e| e.to_string())?;

    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn redpallas_dsg_round2_process(
    round2_message: &[u8],
    state: &[u8],
) -> Result<MsgState, String> {
    let result =
        mps::redpallas_dsg_round2_process(round2_message, state).map_err(|e| e.to_string())?;

    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub struct RedPallasSignature {
    signature: Vec<u8>,
    rk: Vec<u8>,
    alpha: Vec<u8>,
}

#[wasm_bindgen]
impl RedPallasSignature {
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn rk(&self) -> Vec<u8> {
        self.rk.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn alpha(&self) -> Vec<u8> {
        self.alpha.clone()
    }
}

#[wasm_bindgen]
pub fn redpallas_dsg_round3_process(
    round3_message: &[u8],
    state: &[u8],
) -> Result<RedPallasSignature, String> {
    let result =
        mps::redpallas_dsg_round3_process(round3_message, state).map_err(|e| e.to_string())?;
    Ok(RedPallasSignature {
        signature: result.signature,
        rk: result.rk.to_vec(),
        alpha: result.alpha.to_vec(),
    })
}

#[wasm_bindgen]
pub struct RedPallasIvks {
    internal_ivk: Vec<u8>,
    external_ivk: Vec<u8>,
}

#[wasm_bindgen]
impl RedPallasIvks {
    #[wasm_bindgen(getter)]
    pub fn internal_ivk(&self) -> Vec<u8> {
        self.internal_ivk.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn external_ivk(&self) -> Vec<u8> {
        self.external_ivk.clone()
    }
}

#[wasm_bindgen]
pub fn redpallas_fvk_to_ivks(ask: &[u8], nk: &[u8], rivk: &[u8]) -> Result<RedPallasIvks, String> {
    let ask_32: [u8; 32] = ask.try_into().map_err(|_| "ask must be 32 bytes")?;
    let nk_32: [u8; 32] = nk.try_into().map_err(|_| "nk must be 32 bytes")?;
    let rivk_32: [u8; 32] = rivk.try_into().map_err(|_| "rivk must be 32 bytes")?;
    let result =
        mps::redpallas_fvk_to_ivks(&ask_32, &nk_32, &rivk_32).map_err(|e| e.to_string())?;
    Ok(RedPallasIvks {
        internal_ivk: result.internal_ivk.to_vec(),
        external_ivk: result.external_ivk.to_vec(),
    })
}

#[wasm_bindgen]
pub fn redpallas_verify(pk: &[u8], sig: &[u8], msg: &[u8]) -> Result<bool, String> {
    use orchard::primitives::redpallas::{Signature, SpendAuth, VerificationKey};

    let pk_bytes: [u8; 32] = pk.try_into().map_err(|_| "pk must be 32 bytes")?;
    let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| "sig must be 64 bytes")?;

    let vk = VerificationKey::<SpendAuth>::try_from(pk_bytes).map_err(|e| e.to_string())?;
    let signature = Signature::<SpendAuth>::from(sig_bytes);

    Ok(vk.verify(msg, &signature).is_ok())
}
