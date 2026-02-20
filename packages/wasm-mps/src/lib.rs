//! Session-based Multi-Party Schnorr frontend

mod mps {

    use multi_party_schnorr::common::traits::Round;
    use multi_party_schnorr::curve25519_dalek::EdwardsPoint;
    use multi_party_schnorr::keygen::{KeygenMsg1, KeygenMsg2, KeygenParty, R0, R1, R2};
    use std::sync::Arc;
    use thiserror::Error;

    /// Errors that can be returned as results.
    #[derive(Debug, Error)]
    pub enum DkgError {
        #[error("Serialization Error")]
        SerializationError,

        #[error("Deserialization Error")]
        DeserializationError,

        #[error("Invalid Input")]
        InvalidInput,

        #[error("Protocol Error")]
        ProtocolError,
    }

    /// Internal state used for round 1.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct StateR1 {
        pub msg: KeygenMsg1,
        pub party: KeygenParty<R1<EdwardsPoint>, EdwardsPoint>,
    }

    /// Internal state used for round 2.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct StateR2 {
        pub msg: KeygenMsg2<EdwardsPoint>,
        pub party: KeygenParty<R2, EdwardsPoint>,
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
    }

    /// Process round 0 of protocol.
    /// party_id: Party indentifier / index.
    /// decryption_key: Private Curve25519 key.
    /// encryption_keys: Public Curve25519 keys of other parties.
    /// seed: PRNG seed for entropy.
    pub fn round0_process(
        party_id: u8,
        decryption_key: &[u8; 32],
        encryption_keys: &[Vec<u8>; 2],
        seed: &[u8; 32],
    ) -> Result<MsgState, DkgError> {
        if party_id >= 3 {
            return Err(DkgError::InvalidInput);
        }

        // Parse decryption key
        let secret_key = crypto_box::SecretKey::from(*decryption_key);

        // Parse all party encryption keys
        let i0_pk = crypto_box::PublicKey::from(
            <[u8; 32]>::try_from(encryption_keys[0].clone()).map_err(|_| DkgError::InvalidInput)?,
        );
        let i1_pk = crypto_box::PublicKey::from(
            <[u8; 32]>::try_from(encryption_keys[1].clone()).map_err(|_| DkgError::InvalidInput)?,
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
        let p0 = KeygenParty::<R0, EdwardsPoint>::new(
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
        .map_err(|_| DkgError::ProtocolError)?;

        // Generate message
        let (p1, msg1) = p0.process(()).map_err(|_| DkgError::ProtocolError)?;

        // Create the state for storage between rounds
        let state = StateR1 {
            msg: msg1,
            party: p1,
        };

        Ok(MsgState {
            msg: bincode::serialize(&msg1).map_err(|_| DkgError::SerializationError)?,
            state: bincode::serialize(&state).map_err(|_| DkgError::SerializationError)?,
        })
    }

    /// Process round 1 of protocol.
    /// round1_messages: Public messages from other parties.
    /// state: Private state result from from round 0.
    pub fn round1_process(
        round1_messages: &[Vec<u8>; 2],
        state: &[u8],
    ) -> Result<MsgState, DkgError> {
        // Parse state
        let state: StateR1 =
            bincode::deserialize(state).map_err(|_| DkgError::DeserializationError)?;

        // Parse messages
        let i0_msg1: KeygenMsg1 = bincode::deserialize(round1_messages[0].as_slice())
            .map_err(|_| DkgError::DeserializationError)?;
        let i1_msg1: KeygenMsg1 = bincode::deserialize(round1_messages[1].as_slice())
            .map_err(|_| DkgError::DeserializationError)?;
        let msgs = vec![i0_msg1, i1_msg1, state.msg];

        // Process all round0 messages together
        let (p2, msg2) = state
            .party
            .process(msgs)
            .map_err(|_| DkgError::ProtocolError)?;

        // Create the state for storage between rounds
        let state = StateR2 {
            msg: msg2.clone(),
            party: p2,
        };

        Ok(MsgState {
            msg: bincode::serialize(&msg2).map_err(|_| DkgError::SerializationError)?,
            state: bincode::serialize(&state).map_err(|_| DkgError::SerializationError)?,
        })
    }

    /// Process round 2 of protocol.
    /// round2_messages: Public messages from other parties.
    /// state: Private state result from round 1.
    pub fn round2_process(round2_messages: &[Vec<u8>; 2], state: &[u8]) -> Result<Share, DkgError> {
        // Deserialize round2 messages from other parties
        let i0_msg2: KeygenMsg2<EdwardsPoint> = bincode::deserialize(round2_messages[0].as_slice())
            .map_err(|_| DkgError::DeserializationError)?;
        let i1_msg2: KeygenMsg2<EdwardsPoint> = bincode::deserialize(round2_messages[1].as_slice())
            .map_err(|_| DkgError::DeserializationError)?;

        // Deserialize state
        let state: StateR2 =
            bincode::deserialize(state).map_err(|_| DkgError::DeserializationError)?;

        // Generate share
        let share = state
            .party
            .process(vec![i0_msg2, i1_msg2, state.msg.clone()])
            .map_err(|_| DkgError::ProtocolError)?;

        Ok(Share {
            share: bincode::serialize(&share).map_err(|_| DkgError::SerializationError)?,
            pk: share.public_key.compress().to_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::{self, Rng};

    #[test]
    fn test_dkg() {
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
        let p0_0 = mps::round0_process(
            0,
            &prv_keys[0].to_bytes(),
            &[
                pub_keys[1].1.to_bytes().to_vec(),
                pub_keys[2].1.to_bytes().to_vec(),
            ],
            &seeds[0],
        )
        .unwrap();
        let p1_0 = mps::round0_process(
            1,
            &prv_keys[1].to_bytes(),
            &[
                pub_keys[0].1.to_bytes().to_vec(),
                pub_keys[2].1.to_bytes().to_vec(),
            ],
            &seeds[1],
        )
        .unwrap();
        let p2_0 = mps::round0_process(
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
        let p0_1 =
            mps::round1_process(&[p1_0.msg.clone(), p2_0.msg.clone()], p0_0.state.as_slice())
                .unwrap();
        let p1_1 =
            mps::round1_process(&[p0_0.msg.clone(), p2_0.msg.clone()], p1_0.state.as_slice())
                .unwrap();
        let p2_1 =
            mps::round1_process(&[p0_0.msg.clone(), p1_0.msg.clone()], p2_0.state.as_slice())
                .unwrap();

        // Parties generate their key shares
        let p0_share =
            mps::round2_process(&[p1_1.msg.clone(), p2_1.msg.clone()], p0_1.state.as_slice())
                .unwrap();
        let p1_share =
            mps::round2_process(&[p0_1.msg.clone(), p2_1.msg.clone()], p1_1.state.as_slice())
                .unwrap();
        let p2_share =
            mps::round2_process(&[p0_1.msg.clone(), p1_1.msg.clone()], p2_1.state.as_slice())
                .unwrap();

        // Assert generated public keys are equal
        assert_eq!(
            p2_share.pk, p0_share.pk,
            "Party 0 share differs from party 2 share"
        );
        assert_eq!(
            p2_share.pk, p1_share.pk,
            "Party 1 share differs from party 2 share"
        );
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
        }
    }
}

#[wasm_bindgen]
pub fn round0_process(
    party_id: u8,
    decryption_key: &[u8],
    encryption_keys: Array,
    seed: &[u8],
) -> Result<MsgState, String> {
    let decryption_key_32: [u8; 32] = decryption_key[..32]
        .try_into()
        .map_err(|_| "Deserialization Error")?;
    let seed_32: [u8; 32] = seed[..32].try_into().map_err(|_| "Deserialization Error")?;
    let result = mps::round0_process(
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
pub fn round1_process(round1_messages: Array, state: &[u8]) -> Result<MsgState, String> {
    let result = mps::round1_process(
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
pub fn round2_process(round2_messages: Array, state: &[u8]) -> Result<Share, String> {
    let result = mps::round2_process(
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
    })
}
