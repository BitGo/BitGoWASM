use super::*;
use dkls23_ll::dkg::{
    KeygenMsg1, KeygenMsg2, KeygenMsg3, KeygenMsg4, Party as RootParty, State as RootState,
};

fn seed(party_id: u8, round: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = party_id;
    s[1] = round;
    s
}

// --------------------------------------------------------------- VRF DKG helpers

/// Run a full VRF DKG over `participants` parties and return the resulting key shares.
/// `serialize_between_rounds` exercises `toBytes`/`fromBytes` after every round.
fn run_vrf_dkg(
    participants: u8,
    threshold: u8,
    serialize_between_rounds: bool,
) -> Vec<VrfKeyshare> {
    let roundtrip = |s: VrfDkgSession| -> VrfDkgSession {
        if serialize_between_rounds {
            VrfDkgSession::from_bytes_inner(&s.to_bytes_inner().unwrap()).unwrap()
        } else {
            s
        }
    };

    let mut sessions: Vec<VrfDkgSession> = (0..participants)
        .map(|i| {
            roundtrip(VrfDkgSession::new_inner(participants, threshold, i, &seed(i, 0)).unwrap())
        })
        .collect();

    let msg1: Vec<Vec<u8>> = sessions
        .iter_mut()
        .enumerate()
        .map(|(i, s)| s.create_first_message_inner(&seed(i as u8, 1)).unwrap())
        .collect();
    let mut sessions: Vec<VrfDkgSession> = sessions.into_iter().map(roundtrip).collect();

    let msg2: Vec<Vec<u8>> = sessions
        .iter_mut()
        .enumerate()
        .map(|(i, s)| {
            s.handle_round1_messages_inner(&msg1, &seed(i as u8, 2))
                .unwrap()
        })
        .collect();
    let mut sessions: Vec<VrfDkgSession> = sessions.into_iter().map(roundtrip).collect();

    sessions
        .iter_mut()
        .map(|s| s.handle_round2_messages_inner(&msg2).unwrap())
        .collect()
}

fn assert_shared_vrf_state(shares: &[VrfKeyshare]) {
    let first = &shares[0];
    for share in &shares[1..] {
        assert_eq!(share.public_key(), first.public_key());
        assert_eq!(share.key_id(), first.key_id());
        assert_eq!(share.root_chain_code(), first.root_chain_code());
        assert_eq!(share.final_session_id(), first.final_session_id());
    }
    assert_eq!(first.public_key().len(), 32);
    assert_eq!(first.key_id().len(), 32);
    assert_eq!(first.root_chain_code().len(), 32);
}

// --------------------------------------------------------------- VRF DKG tests

#[test]
fn vrf_dkg_3_of_3() {
    let shares = run_vrf_dkg(3, 3, false);
    assert_eq!(shares.len(), 3);
    assert_shared_vrf_state(&shares);
    for (i, share) in shares.iter().enumerate() {
        assert_eq!(share.party_id(), i as u8);
        assert_eq!(share.threshold(), 3);
        assert_eq!(share.participants(), 3);
    }
}

#[test]
fn vrf_dkg_2_of_3() {
    let shares = run_vrf_dkg(3, 2, false);
    assert_eq!(shares.len(), 3);
    assert_shared_vrf_state(&shares);
}

#[test]
fn vrf_dkg_session_roundtrips_between_rounds() {
    let shares = run_vrf_dkg(3, 2, true);
    assert_shared_vrf_state(&shares);
}

#[test]
fn vrf_dkg_is_deterministic_for_fixed_seeds() {
    let a = run_vrf_dkg(3, 2, false);
    let b = run_vrf_dkg(3, 2, false);
    assert_eq!(a[0].public_key(), b[0].public_key());
    assert_eq!(
        a[0].to_bytes_inner().unwrap(),
        b[0].to_bytes_inner().unwrap()
    );
}

#[test]
fn vrf_keyshare_roundtrips() {
    let shares = run_vrf_dkg(3, 2, false);
    let bytes = shares[1].to_bytes_inner().unwrap();
    let restored = VrfKeyshare::from_bytes_inner(&bytes).unwrap();
    assert_eq!(restored.party_id(), 1);
    assert_eq!(restored.public_key(), shares[1].public_key());
    assert_eq!(restored.to_bytes_inner().unwrap(), bytes);
}

#[test]
fn vrf_dkg_rejects_bad_parameters() {
    assert!(matches!(
        VrfDkgSession::new_inner(3, 1, 0, &seed(0, 0)),
        Err(Error::InvalidParams(_))
    ));
    assert!(matches!(
        VrfDkgSession::new_inner(3, 4, 0, &seed(0, 0)),
        Err(Error::InvalidParams(_))
    ));
    assert!(matches!(
        VrfDkgSession::new_inner(3, 2, 3, &seed(0, 0)),
        Err(Error::InvalidParams(_))
    ));
    assert!(matches!(
        VrfDkgSession::new_inner(3, 2, 0, &[0u8; 16]),
        Err(Error::InvalidSeedLength(16))
    ));
}

#[test]
fn vrf_dkg_rejects_wrong_message_counts_and_duplicates() {
    let mut sessions: Vec<VrfDkgSession> = (0..3)
        .map(|i| VrfDkgSession::new_inner(3, 2, i, &seed(i, 0)).unwrap())
        .collect();
    let msg1: Vec<Vec<u8>> = sessions
        .iter_mut()
        .enumerate()
        .map(|(i, s)| s.create_first_message_inner(&seed(i as u8, 1)).unwrap())
        .collect();

    // one peer message missing
    assert!(matches!(
        sessions[0].handle_round1_messages_inner(&msg1[..2], &seed(0, 2)),
        Err(Error::MessageCount { .. })
    ));
    // duplicate sender
    let dup = vec![msg1[0].clone(), msg1[1].clone(), msg1[1].clone()];
    assert!(matches!(
        sessions[0].handle_round1_messages_inner(&dup, &seed(0, 2)),
        Err(Error::DuplicateSender(1))
    ));

    let msg2: Vec<Vec<u8>> = sessions
        .iter_mut()
        .enumerate()
        .map(|(i, s)| {
            s.handle_round1_messages_inner(&msg1, &seed(i as u8, 2))
                .unwrap()
        })
        .collect();

    // round 2 wants every party's message, our own included
    assert!(matches!(
        sessions[0].handle_round2_messages_inner(&msg2[..2]),
        Err(Error::MessageCount { .. })
    ));
    assert!(sessions[0].handle_round2_messages_inner(&msg2).is_ok());
}

#[test]
fn vrf_dkg_rejects_round_skipping_and_foreign_state() {
    let mut session = VrfDkgSession::new_inner(3, 2, 0, &seed(0, 0)).unwrap();
    assert_eq!(session.round(), 1);
    assert!(matches!(
        session.handle_round2_messages_inner(&[]),
        Err(Error::InvalidRound {
            expected: 2,
            actual: 1
        })
    ));

    let r1_state = session.to_bytes_inner().unwrap();
    session.create_first_message_inner(&seed(0, 1)).unwrap();

    // a round-1 state must not deserialize as a hard-derivation state, and vice versa
    assert!(matches!(
        HardDeriveSession::from_bytes_inner(&r1_state),
        Err(Error::InvalidStatePrefix)
    ));
    assert!(matches!(
        VrfDkgSession::from_bytes_inner(&r1_state[1..]),
        Err(Error::InvalidStatePrefix)
    ));
}

// --------------------------------------------------------- hard derivation helpers

/// Run the (unwrapped) DKLS23 signing DKG to get root key shares to derive from.
/// Only used by tests - the signing DKG is never exposed by this crate.
fn root_keyshares(n: u8, t: u8) -> Vec<RootKeyshare> {
    let mut rng = rand::thread_rng();
    let mut parties: Vec<RootState> = (0..n)
        .map(|party_id| {
            RootState::new(
                RootParty::new(n as usize, t as usize, party_id as usize),
                &mut rng,
            )
        })
        .collect();

    let msg1: Vec<KeygenMsg1> = parties.iter().map(|p| p.generate_msg1()).collect();

    let mut msg2: Vec<KeygenMsg2> = vec![];
    for (i, party) in parties.iter_mut().enumerate() {
        let batch: Vec<KeygenMsg1> = msg1
            .iter()
            .filter(|m| m.from_id != i as u8)
            .cloned()
            .collect();
        msg2.extend(party.handle_msg1(&mut rng, batch).unwrap());
    }

    let mut msg3: Vec<KeygenMsg3> = vec![];
    for (i, party) in parties.iter_mut().enumerate() {
        let batch: Vec<KeygenMsg2> = msg2
            .iter()
            .filter(|m| m.to_id == i as u8)
            .cloned()
            .collect();
        msg3.extend(party.handle_msg2(&mut rng, batch).unwrap());
    }

    let commitments: Vec<[u8; 32]> = parties.iter().map(|p| p.calculate_commitment_2()).collect();

    let mut msg4: Vec<KeygenMsg4> = vec![];
    for (i, party) in parties.iter_mut().enumerate() {
        let batch: Vec<KeygenMsg3> = msg3
            .iter()
            .filter(|m| m.to_id == i as u8)
            .cloned()
            .collect();
        msg4.push(party.handle_msg3(&mut rng, batch, &commitments).unwrap());
    }

    parties
        .into_iter()
        .enumerate()
        .map(|(i, mut party)| {
            let batch: Vec<KeygenMsg4> = msg4
                .iter()
                .filter(|m| m.from_id != i as u8)
                .cloned()
                .collect();
            party.handle_msg4(batch).unwrap()
        })
        .collect()
}

struct DeriveFixture {
    root: Vec<Vec<u8>>,
    vrf: Vec<Vec<u8>>,
}

fn derive_fixture(n: u8, t: u8) -> DeriveFixture {
    DeriveFixture {
        root: root_keyshares(n, t)
            .iter()
            .map(|ks| cbor_enc(ks).unwrap())
            .collect(),
        vrf: run_vrf_dkg(n, t, false)
            .iter()
            .map(|ks| ks.to_bytes_inner().unwrap())
            .collect(),
    }
}

const PATH: &[u8] = b"m/0'";

fn hard_derive_sessions(fixture: &DeriveFixture, quorum: &[u8]) -> Vec<HardDeriveSession> {
    quorum
        .iter()
        .map(|&i| {
            HardDeriveSession::new_inner(
                &fixture.root[i as usize],
                &fixture.vrf[i as usize],
                PATH,
                &seed(i, 3),
            )
            .unwrap()
        })
        .collect()
}

/// Run hard derivation for the parties in `quorum`.
fn run_hard_derive(
    fixture: &DeriveFixture,
    quorum: &[u8],
    serialize_between_rounds: bool,
) -> Vec<DerivedKeyshare> {
    let roundtrip = |s: HardDeriveSession| -> HardDeriveSession {
        if serialize_between_rounds {
            HardDeriveSession::from_bytes_inner(&s.to_bytes_inner().unwrap()).unwrap()
        } else {
            s
        }
    };

    let mut sessions: Vec<HardDeriveSession> = hard_derive_sessions(fixture, quorum)
        .into_iter()
        .map(roundtrip)
        .collect();

    let msg0: Vec<Vec<u8>> = sessions
        .iter_mut()
        .map(|s| s.create_first_message_inner().unwrap())
        .collect();
    let mut sessions: Vec<HardDeriveSession> = sessions.into_iter().map(roundtrip).collect();

    let msg1: Vec<Vec<u8>> = sessions
        .iter_mut()
        .zip(quorum)
        .map(|(s, &i)| {
            s.handle_round1_messages_inner(&msg0, &seed(i, 4), None)
                .unwrap()
        })
        .collect();
    let mut sessions: Vec<HardDeriveSession> = sessions.into_iter().map(roundtrip).collect();

    sessions
        .iter_mut()
        .map(|s| s.handle_round2_messages_inner(&msg1).unwrap())
        .collect()
}

fn assert_shared_derived_state(derived: &[DerivedKeyshare], fixture: &DeriveFixture) {
    let first = &derived[0];
    assert_eq!(first.public_key().len(), 33);
    assert_eq!(first.root_chain_code().len(), 32);
    for d in &derived[1..] {
        assert_eq!(d.public_key(), first.public_key());
        assert_eq!(d.root_chain_code(), first.root_chain_code());
    }

    // hard derivation must actually move the key
    let root: RootKeyshare = cbor_dec(&fixture.root[0]).unwrap();
    let root_pk = root.public_key.to_encoded_point(true).as_bytes().to_vec();
    assert_ne!(first.public_key(), root_pk);

    // and the emitted bytes must still be a DKLS key share
    for (i, d) in derived.iter().enumerate() {
        let ks: RootKeyshare = cbor_dec(&d.keyshare()).unwrap();
        assert_eq!(ks.total_parties, root.total_parties);
        assert_eq!(ks.threshold, root.threshold);
        assert_eq!(
            ks.public_key.to_encoded_point(true).as_bytes().to_vec(),
            first.public_key()
        );
        assert_eq!(ks.root_chain_code.to_vec(), first.root_chain_code());
        let _ = i;
    }
}

// ------------------------------------------------------------ hard derivation tests

#[test]
fn hard_derive_2_of_3() {
    let fixture = derive_fixture(3, 2);
    let derived = run_hard_derive(&fixture, &[0, 1], false);
    assert_eq!(derived.len(), 2);
    assert_shared_derived_state(&derived, &fixture);
}

#[test]
fn hard_derive_session_roundtrips_between_rounds() {
    let fixture = derive_fixture(3, 2);
    let derived = run_hard_derive(&fixture, &[1, 2], true);
    assert_eq!(derived.len(), 2);
    assert_shared_derived_state(&derived, &fixture);
}

#[test]
fn hard_derive_path_changes_the_derived_key() {
    let fixture = derive_fixture(2, 2);
    let derived = run_hard_derive(&fixture, &[0, 1], false);

    let mut sessions: Vec<HardDeriveSession> = (0..2u8)
        .map(|i| {
            HardDeriveSession::new_inner(
                &fixture.root[i as usize],
                &fixture.vrf[i as usize],
                b"m/1'",
                &seed(i, 3),
            )
            .unwrap()
        })
        .collect();
    let msg0: Vec<Vec<u8>> = sessions
        .iter_mut()
        .map(|s| s.create_first_message_inner().unwrap())
        .collect();
    let msg1: Vec<Vec<u8>> = sessions
        .iter_mut()
        .enumerate()
        .map(|(i, s)| {
            s.handle_round1_messages_inner(&msg0, &seed(i as u8, 4), None)
                .unwrap()
        })
        .collect();
    let other: Vec<DerivedKeyshare> = sessions
        .iter_mut()
        .map(|s| s.handle_round2_messages_inner(&msg1).unwrap())
        .collect();

    assert_ne!(derived[0].public_key(), other[0].public_key());
}

#[test]
fn hard_derive_rejects_mismatched_keyshares() {
    let a = derive_fixture(3, 2);
    let b = derive_fixture(3, 3);

    // threshold mismatch between root and VRF key share
    assert!(matches!(
        HardDeriveSession::new_inner(&a.root[0], &b.vrf[0], PATH, &seed(0, 3)),
        Err(Error::KeyshareMismatch("threshold"))
    ));
    // party id mismatch
    assert!(matches!(
        HardDeriveSession::new_inner(&a.root[0], &a.vrf[1], PATH, &seed(0, 3)),
        Err(Error::KeyshareMismatch("party id"))
    ));
    // garbage in
    assert!(matches!(
        HardDeriveSession::new_inner(&[1, 2, 3], &a.vrf[0], PATH, &seed(0, 3)),
        Err(Error::Deserialization(_))
    ));
}

#[test]
fn hard_derive_rejects_bad_round0_message_sets() {
    let fixture = derive_fixture(3, 2);
    let mut sessions = hard_derive_sessions(&fixture, &[0, 1, 2]);
    let msg0: Vec<Vec<u8>> = sessions
        .iter_mut()
        .map(|s| s.create_first_message_inner().unwrap())
        .collect();

    // more than `threshold` senders
    assert!(matches!(
        sessions[0].handle_round1_messages_inner(&msg0, &seed(0, 4), None),
        Err(Error::MessageCount { .. })
    ));
    // `threshold` senders, but ours is not among them
    assert!(matches!(
        sessions[0].handle_round1_messages_inner(&msg0[1..], &seed(0, 4), None),
        Err(Error::MissingOwnMessage(0))
    ));
    // duplicate sender
    let dup = vec![msg0[1].clone(), msg0[1].clone()];
    assert!(matches!(
        sessions[0].handle_round1_messages_inner(&dup, &seed(0, 4), None),
        Err(Error::DuplicateSender(1))
    ));
    // and the happy path still works afterwards
    assert!(sessions[0]
        .handle_round1_messages_inner(&msg0[..2], &seed(0, 4), None)
        .is_ok());
    assert_eq!(sessions[0].round(), 1);
}

#[test]
fn hard_derive_rejects_round1_participant_set_change() {
    let fixture = derive_fixture(3, 2);
    let mut sessions = hard_derive_sessions(&fixture, &[0, 1, 2]);
    let msg0: Vec<Vec<u8>> = sessions
        .iter_mut()
        .map(|s| s.create_first_message_inner().unwrap())
        .collect();

    // parties 0 and 1 run the quorum, party 2 also produces a round-1 message
    let msg1: Vec<Vec<u8>> = sessions
        .iter_mut()
        .enumerate()
        .map(|(i, s)| {
            let batch = match i {
                2 => vec![msg0[1].clone(), msg0[2].clone()],
                _ => msg0[..2].to_vec(),
            };
            s.handle_round1_messages_inner(&batch, &seed(i as u8, 4), None)
                .unwrap()
        })
        .collect();

    // party 0 committed to {0,1} in round 0; a {0,2} message set must be rejected
    assert!(matches!(
        sessions[0].handle_round2_messages_inner(&[msg1[0].clone(), msg1[2].clone()]),
        Err(Error::ParticipantSetMismatch)
    ));
    assert!(matches!(
        sessions[0].handle_round2_messages_inner(&msg1),
        Err(Error::MessageCount { .. })
    ));
    assert!(sessions[0].handle_round2_messages_inner(&msg1[..2]).is_ok());
}

#[test]
fn hard_derive_honours_an_explicit_quorum() {
    let fixture = derive_fixture(3, 2);
    let mut sessions = hard_derive_sessions(&fixture, &[0, 1, 2]);
    let msg0: Vec<Vec<u8>> = sessions
        .iter_mut()
        .map(|s| s.create_first_message_inner().unwrap())
        .collect();

    // senders {0,1} do not match the declared quorum {0,2}
    assert!(sessions[0]
        .handle_round1_messages_inner(&msg0[..2], &seed(0, 4), Some(vec![0, 2]))
        .is_err());
    assert!(sessions[0]
        .handle_round1_messages_inner(&msg0[..2], &seed(0, 4), Some(vec![0, 1]))
        .is_ok());
}
