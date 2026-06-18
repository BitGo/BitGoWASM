//! BitGo frontend to Silence Labs' Multi-Party-Schnorr

mod mps {

    use multi_party_schnorr::{
        common::{
            ser::Serializable,
            traits::{GroupElem, Round, ScalarReduce},
            Bip32Public,
        },
        curve25519_dalek::EdwardsPoint,
        keygen::{
            KeygenMsg1, KeygenMsg2, KeygenParty, Keyshare, R0 as DkgR0, R1 as DkgR1, R2 as DkgR2,
        },
        sign::{
            messages::{SignMsg1, SignMsg2, SignMsg3},
            PartialSign, SignerParty, R0 as DsgR0, R1 as DsgR1, R2 as DsgR2,
        },
    };
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use thiserror::Error;

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
        pub msg: KeygenMsg1,

        #[serde(bound(
            serialize = "KeygenParty<DkgR1<G>, G>: Serialize",
            deserialize = "KeygenParty<DkgR1<G>, G>: Deserialize<'de>"
        ))]
        pub party: KeygenParty<DkgR1<G>, G>,
    }

    /// Internal DKG state used for round 2.
    #[derive(Serialize, Deserialize)]
    struct DkgStateR2<G>
    where
        G: GroupElem,
        G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    {
        pub msg: KeygenMsg2<G>,

        #[serde(bound(
            serialize = "KeygenParty<DkgR2, G>: Serialize",
            deserialize = "KeygenParty<DkgR2, G>: Deserialize<'de>"
        ))]
        pub party: KeygenParty<DkgR2, G>,
    }

    /// Internal DSG state used for round 1.
    #[derive(Serialize, Deserialize)]
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
    struct DsgStateR3<G>
    where
        G: GroupElem,
        G::Scalar: Serializable,
    {
        pub msg: SignMsg3<G>,
        pub party: PartialSign<G>,
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
    }

    fn rem_prefix(prefix: &str, data: &Vec<u8>) -> Result<Vec<u8>, MpsError> {
        Ok(data
            .as_slice()
            .strip_prefix(prefix.as_bytes())
            .ok_or(MpsError::InvalidInput)?
            .to_vec())
    }

    fn add_prefix(prefix: &str, data: &Vec<u8>) -> Vec<u8> {
        [prefix.as_bytes(), data.as_slice()].concat()
    }

    fn internal_dkg_round0_process<G>(
        party_id: u8,
        decryption_key: &[u8; 32],
        encryption_keys: &[Vec<u8>; 2],
        seed: &[u8; 32],
    ) -> Result<MsgState, MpsError>
    where
        G: GroupElem + Serialize,
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
            msg: msg1,
            party: p1,
        };

        Ok(MsgState {
            msg: bincode::serialize(&msg1).map_err(|_| MpsError::SerializationError)?,
            state: bincode::serialize(&state).map_err(|_| MpsError::SerializationError)?,
        })
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
    ) -> Result<MsgState, MpsError> {
        let result = internal_dkg_round0_process::<EdwardsPoint>(
            party_id,
            decryption_key,
            encryption_keys,
            seed,
        )?;
        Ok(MsgState {
            msg: add_prefix("mps-ed25519-dkg-round1-message$", &result.msg),
            state: add_prefix("mps-ed25519-dkg-round1-state$", &result.state),
        })
    }

    fn internal_dkg_round1_process<G>(
        round1_messages: &[Vec<u8>; 2],
        state: &[u8],
    ) -> Result<MsgState, MpsError>
    where
        G: GroupElem + Serialize,
        G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    {
        // Parse state
        let state: DkgStateR1<G> =
            bincode::deserialize(state).map_err(|_| MpsError::DeserializationError)?;

        // Parse messages
        let i0_msg1: KeygenMsg1 = bincode::deserialize(round1_messages[0].as_slice())
            .map_err(|_| MpsError::DeserializationError)?;
        let i1_msg1: KeygenMsg1 = bincode::deserialize(round1_messages[1].as_slice())
            .map_err(|_| MpsError::DeserializationError)?;
        let msgs = vec![i0_msg1, i1_msg1, state.msg];

        // Process all round0 messages together
        let (p2, msg2) = state
            .party
            .process(msgs)
            .map_err(|_| MpsError::ProtocolError)?;

        // Create the state for storage between rounds
        let state = DkgStateR2 {
            msg: msg2.clone(),
            party: p2,
        };

        Ok(MsgState {
            msg: bincode::serialize(&msg2).map_err(|_| MpsError::SerializationError)?,
            state: bincode::serialize(&state).map_err(|_| MpsError::SerializationError)?,
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
        let state = rem_prefix("mps-ed25519-dkg-round1-state$", &state.to_vec())?;
        let result = internal_dkg_round1_process::<EdwardsPoint>(&[i0_msg1, i1_msg1], &state)?;
        Ok(MsgState {
            msg: add_prefix("mps-ed25519-dkg-round2-message$", &result.msg),
            state: add_prefix("mps-ed25519-dkg-round2-state$", &result.state),
        })
    }

    fn internal_dkg_round2_process<G>(
        round2_messages: &[Vec<u8>; 2],
        state: &[u8],
    ) -> Result<Keyshare<G>, MpsError>
    where
        G: GroupElem + Serialize + for<'de> Deserialize<'de>,
        G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    {
        // Deserialize round2 messages from other parties
        let i0_msg2: KeygenMsg2<G> = bincode::deserialize(round2_messages[0].as_slice())
            .map_err(|_| MpsError::DeserializationError)?;
        let i1_msg2: KeygenMsg2<G> = bincode::deserialize(round2_messages[1].as_slice())
            .map_err(|_| MpsError::DeserializationError)?;

        // Deserialize state
        let state: DkgStateR2<G> =
            bincode::deserialize(state).map_err(|_| MpsError::DeserializationError)?;

        // Generate share
        let share = state
            .party
            .process(vec![i0_msg2, i1_msg2, state.msg.clone()])
            .map_err(|_| MpsError::ProtocolError)?;

        Ok(share)
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
        let state = rem_prefix("mps-ed25519-dkg-round2-state$", &state.to_vec())?;
        let share = internal_dkg_round2_process::<EdwardsPoint>(&[i0_msg2, i1_msg2], &state)?;
        Ok(Share {
            share: bincode::serialize(&share).map_err(|_| MpsError::SerializationError)?,
            pk: share.public_key.compress().to_bytes(),
            chaincode: share.root_chain_code,
        })
    }

    fn internal_dsg_round0_process<G>(p0: SignerParty<DsgR0, G>) -> Result<MsgState, MpsError>
    where
        G: GroupElem + Serialize,
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
            msg: bincode::serialize(&msg1).map_err(|_| MpsError::SerializationError)?,
            state: bincode::serialize(&state).map_err(|_| MpsError::SerializationError)?,
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
            bincode::deserialize(share).map_err(|_| MpsError::DeserializationError)?;

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

    fn internal_dsg_round1_process<G>(
        round1_message: &[u8],
        state: &[u8],
    ) -> Result<MsgState, MpsError>
    where
        G: GroupElem + Serialize + for<'de> Deserialize<'de>,
        G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    {
        // Parse state
        let state: DsgStateR1<G> =
            bincode::deserialize(state).map_err(|_| MpsError::DeserializationError)?;

        // Parse messages
        let i0_msg1: SignMsg1 =
            bincode::deserialize(round1_message).map_err(|_| MpsError::DeserializationError)?;
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
            msg: bincode::serialize(&msg2).map_err(|_| MpsError::SerializationError)?,
            state: bincode::serialize(&state).map_err(|_| MpsError::SerializationError)?,
        })
    }

    /// Process round 1 of DSG protocol.
    /// round1_messages: Public messages from other parties.
    /// state: Private state result from round 0.
    pub fn ed25519_dsg_round1_process(
        round1_message: &[u8],
        state: &[u8],
    ) -> Result<MsgState, MpsError> {
        let round1_message =
            rem_prefix("mps-ed25519-dsg-round1-message$", &round1_message.to_vec())?;
        let state = rem_prefix("mps-ed25519-dsg-round1-state$", &state.to_vec())?;
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
        let round2_message =
            rem_prefix("mps-ed25519-dsg-round2-message$", &round2_message.to_vec())?;
        let state = rem_prefix("mps-ed25519-dsg-round2-state$", &state.to_vec())?;

        // Parse state
        let state: DsgStateR2<EdwardsPoint> =
            bincode::deserialize(&state).map_err(|_| MpsError::DeserializationError)?;

        // Parse messages
        let i0_msg2: SignMsg2<EdwardsPoint> =
            bincode::deserialize(&round2_message).map_err(|_| MpsError::DeserializationError)?;
        let msgs = vec![i0_msg2, state.msg];

        // Process all round2 messages together
        let party = state
            .party
            .process(msgs)
            .map_err(|_| MpsError::ProtocolError)?;

        // Process partial signature
        let (p3, msg3) = party.process(()).map_err(|_| MpsError::ProtocolError)?;

        // Create the state for storage between rounds
        let state = DsgStateR3 {
            msg: msg3.clone(),
            party: p3,
        };

        Ok(MsgState {
            msg: add_prefix(
                "mps-ed25519-dsg-round3-message$",
                &bincode::serialize(&msg3).map_err(|_| MpsError::SerializationError)?,
            ),
            state: add_prefix(
                "mps-ed25519-dsg-round3-state$",
                &bincode::serialize(&state).map_err(|_| MpsError::SerializationError)?,
            ),
        })
    }

    /// Process round 3 of DSG protocol.
    /// round3_messages: Public messages from other parties.
    /// state: Private state result from round 2.
    pub fn ed25519_dsg_round3_process(
        round3_message: &[u8],
        state: &[u8],
    ) -> Result<Vec<u8>, MpsError> {
        // Strip prefix
        let round3_message =
            rem_prefix("mps-ed25519-dsg-round3-message$", &round3_message.to_vec())?;
        let state = rem_prefix("mps-ed25519-dsg-round3-state$", &state.to_vec())?;

        // Parse state
        let state: DsgStateR3<EdwardsPoint> =
            bincode::deserialize(&state).map_err(|_| MpsError::DeserializationError)?;

        // Parse messages
        let i0_msg3: SignMsg3<EdwardsPoint> =
            bincode::deserialize(&round3_message).map_err(|_| MpsError::DeserializationError)?;
        let msgs = vec![i0_msg3, state.msg];

        // Process all round2 messages together
        let (signature, _) = state
            .party
            .process(msgs)
            .map_err(|_| MpsError::ProtocolError)?;

        Ok(signature.to_vec())
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
}

#[wasm_bindgen]
pub struct MsgShare {
    msg: Vec<u8>,
    share: Share,
}

#[wasm_bindgen]
impl MsgShare {
    #[wasm_bindgen(getter)]
    pub fn msg(&self) -> Vec<u8> {
        self.msg.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn share(&self) -> Share {
        Share {
            share: self.share.share.clone(),
            pk: self.share.pk.clone(),
            chaincode: self.share.chaincode.clone(),
        }
    }
}

#[wasm_bindgen]
pub fn ed25519_dkg_round0_process(
    party_id: u8,
    decryption_key: &[u8],
    encryption_keys: Array,
    seed: &[u8],
) -> Result<MsgState, String> {
    let decryption_key_32: [u8; 32] = decryption_key[..32]
        .try_into()
        .map_err(|_| "Deserialization Error")?;
    let seed_32: [u8; 32] = seed[..32].try_into().map_err(|_| "Deserialization Error")?;
    let result = mps::ed25519_dkg_round0_process(
        party_id,
        &decryption_key_32,
        &[
            js_sys::Uint8Array::from(encryption_keys.get(0)).to_vec(),
            js_sys::Uint8Array::from(encryption_keys.get(1)).to_vec(),
        ],
        &seed_32,
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
    let result = mps::ed25519_dkg_round1_process(
        &[
            js_sys::Uint8Array::from(round1_messages.get(0)).to_vec(),
            js_sys::Uint8Array::from(round1_messages.get(1)).to_vec(),
        ],
        state,
    )
    .map_err(|e| e.to_string())?;

    Ok(MsgState {
        msg: result.msg,
        state: result.state,
    })
}

#[wasm_bindgen]
pub fn ed25519_dkg_round2_process(round2_messages: Array, state: &[u8]) -> Result<Share, String> {
    let result = mps::ed25519_dkg_round2_process(
        &[
            js_sys::Uint8Array::from(round2_messages.get(0)).to_vec(),
            js_sys::Uint8Array::from(round2_messages.get(1)).to_vec(),
        ],
        state,
    )
    .map_err(|e| e.to_string())?;

    Ok(Share {
        share: result.share,
        pk: result.pk.to_vec(),
        chaincode: result.chaincode.to_vec(),
    })
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
pub fn ed25519_dsg_round3_process(round2_message: &[u8], state: &[u8]) -> Result<Vec<u8>, String> {
    let result =
        mps::ed25519_dsg_round3_process(round2_message, state).map_err(|e| e.to_string())?;

    Ok(result.to_vec())
}
