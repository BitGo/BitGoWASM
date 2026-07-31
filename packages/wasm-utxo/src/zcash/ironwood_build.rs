//! Bridge between the `orchard` PCZT roles and the v6 [`IronwoodBundle`] wire type.
//!
//! For a transparent → Ironwood shielding transaction, `wasm-utxo` plays three of the four
//! `orchard` PCZT roles; the fourth (Prover) runs in an external service:
//!
//! - **Constructor** ([`construct_shield_pczt`]): builds the shielded bundle — one output note to
//!   the recipient, padded with a dummy spend — as an `orchard::pczt::Bundle` with no proof or
//!   signatures yet. All action data (value commitments, note commitments, ciphertexts) is fixed
//!   here, and it is exactly what the ZIP-244 shielded sighash commits to.
//! - **IO Finalizer / Signer** ([`finalize_shield_io`]): derives the binding signing key (`bsk`)
//!   and signs the dummy spends over the now-fixed shielded sighash.
//! - **Transaction Extractor** ([`combine`]): given the signed PCZT with the prover's `zkproof`
//!   spliced in ([`super::ironwood_pczt::with_zkproof`]), verifies the spend-auth signatures,
//!   applies the binding signature, and maps the authorized orchard bundle to an [`IronwoodBundle`]
//!   ready for [`encode_v6_transaction`](super::v6::encode_v6_transaction).
//!
//! The **Prover** role (halo2) is intentionally absent — proving is delegated to an external
//! service so the shipped WASM never links the circuit.
//!
//! ## Why the proof can be filled in after signing
//!
//! A v6 transparent signature commits (via the ZIP-244 sighash) to the shielded *action data*
//! (`ironwood_digest`), but not to the `proof`, `anchor`, or `binding_sig` (those live in the
//! authorizing digest, which the sighash excludes). So the order is: fix action data at build,
//! compute the sighash, sign (transparent inputs + dummy spends), then prove, then combine. The
//! binding signature — applied during [`combine`] — signs the same build-time sighash and has no
//! dependency on the transparent signatures.

use rand::{CryptoRng, RngCore};

use orchard::builder::{Builder, BundleType};
use orchard::bundle::BundleVersion;
use orchard::keys::OutgoingViewingKey;
use orchard::pczt::Bundle as PcztBundle;
use orchard::tree::Anchor;
use orchard::value::NoteValue;
use orchard::{Action as OrchardAction, Address};

use super::v6::{IronwoodAction, IronwoodBundle};

/// Length of a raw Orchard/Ironwood receiver (`Address`) in bytes.
pub const ORCHARD_ADDRESS_SIZE: usize = 43;
/// Length of an Ironwood note-commitment-tree root (`Anchor`) in bytes.
pub const ANCHOR_SIZE: usize = 32;
/// Length of an outgoing viewing key in bytes.
pub const OVK_SIZE: usize = 32;
/// Length of the ZIP-302 memo field in bytes.
pub const MEMO_SIZE: usize = 512;

/// A raw Orchard/Ironwood receiver.
pub type OrchardAddressBytes = [u8; ORCHARD_ADDRESS_SIZE];
/// An Ironwood note-commitment-tree root.
pub type AnchorBytes = [u8; ANCHOR_SIZE];
/// A raw outgoing viewing key.
pub type OvkBytes = [u8; OVK_SIZE];
/// A ZIP-302 memo field.
pub type MemoBytes = [u8; MEMO_SIZE];

/// Errors produced while constructing or combining an Ironwood shielded bundle.
///
/// The variant name is surfaced to JS as `err.code` (e.g. `"IronwoodBuildError.BadRecipient"`)
/// via [`crate::error::WasmUtxoError`].
#[derive(Debug, strum::IntoStaticStr)]
pub enum IronwoodBuildError {
    /// The recipient bytes are not a valid Orchard/Ironwood raw address.
    BadRecipient,
    /// The anchor bytes are not a valid Ironwood note-commitment-tree root.
    BadAnchor,
    /// The orchard builder rejected the bundle parameters.
    Builder(String),
    /// The orchard builder rejected the output.
    Output(String),
    /// IO finalization (bsk derivation / dummy-spend signing) failed.
    Finalize(String),
    /// The Transaction Extractor rejected the PCZT (missing proof/sig/bsk, or a non-canonical proof).
    Extract(String),
    /// The bundle had no actions (nothing to shield).
    EmptyBundle,
    /// Binding the bundle failed: either the spend-auth signatures didn't verify against the
    /// sighash, or `bsk` (set by [`finalize_shield_io`]) is missing or does not match the bundle's
    /// value commitments.
    BindingSignatureFailed,
}

impl core::fmt::Display for IronwoodBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadRecipient => write!(f, "ironwood-build: invalid recipient address bytes"),
            Self::BadAnchor => write!(f, "ironwood-build: invalid anchor bytes"),
            Self::Builder(e) => write!(f, "ironwood-build: builder error: {e}"),
            Self::Output(e) => write!(f, "ironwood-build: output error: {e}"),
            Self::Finalize(e) => write!(f, "ironwood-build: IO finalization failed: {e}"),
            Self::Extract(e) => write!(f, "ironwood-build: extractor error: {e}"),
            Self::EmptyBundle => write!(f, "ironwood-build: bundle has no actions"),
            Self::BindingSignatureFailed => {
                write!(
                    f,
                    "ironwood-build: failed to bind the bundle (invalid spend-auth signatures, \
                     or a missing/invalid binding signing key)"
                )
            }
        }
    }
}

crate::impl_wasm_error_code!(IronwoodBuildError);

/// Constructor: build a transparent → Ironwood shielding bundle as an orchard PCZT.
///
/// Produces a single output note of `amount` zatoshi to `recipient` (a 43-byte raw Orchard/Ironwood
/// address), paired with a dummy spend (`BundleType::UNPADDED` ⇒ exactly one action). `anchor` is
/// the current Ironwood note-commitment-tree root. `ovk`, if given, is the raw outgoing viewing key
/// used to make the output recoverable by the sender; pass `None` for a keyless build. `rng` must be
/// a CSPRNG — it seeds the note randomness (`rseed`, `rcv`) that fixes the action data.
///
/// The returned PCZT carries no signatures or proof yet; run [`finalize_shield_io`] once the sighash
/// is known, then hand it to the prover and [`combine`].
pub fn construct_shield_pczt<R: RngCore + CryptoRng>(
    recipient: &OrchardAddressBytes,
    amount: u64,
    ovk: Option<OvkBytes>,
    anchor: &AnchorBytes,
    memo: &MemoBytes,
    rng: R,
) -> Result<PcztBundle, IronwoodBuildError> {
    let recipient = Option::from(Address::from_raw_address_bytes(recipient))
        .ok_or(IronwoodBuildError::BadRecipient)?;
    let anchor = Option::from(Anchor::from_bytes(*anchor)).ok_or(IronwoodBuildError::BadAnchor)?;
    let ovk = ovk.map(OutgoingViewingKey::from);

    let bundle_version = BundleVersion::ironwood_v3();
    let flags = bundle_version.default_flags();
    let mut builder = Builder::new(BundleType::UNPADDED, bundle_version, flags, anchor)
        .map_err(|e| IronwoodBuildError::Builder(e.to_string()))?;
    builder
        .add_output(ovk, recipient, NoteValue::from_raw(amount), *memo)
        .map_err(|e| IronwoodBuildError::Output(e.to_string()))?;
    let (bundle, _meta) = builder
        .build_for_pczt(rng)
        .map_err(|e| IronwoodBuildError::Builder(e.to_string()))?;
    Ok(bundle)
}

/// IO Finalizer / Signer: derive the binding signing key and sign the dummy spends.
///
/// `sighash` is the ZIP-244 shielded sig digest computed over the *complete* v6 transaction
/// (transparent inputs/outputs plus this bundle's action data); it must not change afterwards, since
/// the binding signature applied in [`combine`] signs the same value.
pub fn finalize_shield_io<R: RngCore + CryptoRng>(
    bundle: &mut PcztBundle,
    sighash: [u8; 32],
    rng: R,
) -> Result<(), IronwoodBuildError> {
    bundle
        .finalize_io(sighash, rng)
        .map_err(|e| IronwoodBuildError::Finalize(e.to_string()))
}

/// Map an orchard action (in any authorization state) to the v6 wire action.
///
/// The action-data fields are authorization-independent, so this serves both the effects-only
/// (action-data) view and the fully-authorized combine output.
fn action_to_ironwood<A>(a: &OrchardAction<A>) -> IronwoodAction {
    let enc = a.encrypted_note();
    IronwoodAction {
        cv: a.cv_net().to_bytes(),
        // The action's on-wire `nullifier` field doubles as the paired output note's `rho`.
        nullifier: a.nullifier().to_bytes(),
        rk: <[u8; 32]>::from(a.rk()),
        cmx: a.cmx().to_bytes(),
        ephemeral_key: enc.epk_bytes,
        enc_ciphertext: enc.enc_ciphertext,
        out_ciphertext: enc.out_ciphertext,
    }
}

/// Action-data view of the PCZT: the [`IronwoodBundle`] fields the ZIP-244 sighash and txid commit
/// to (commitments, ciphertexts, flags, value balance, anchor).
///
/// `proof`, `spend_auth_sigs`, and `binding_sig` are left empty — the result is meant for computing
/// digests, NOT for [`encode_v6_transaction`](super::v6::encode_v6_transaction) (which requires one
/// spend-auth signature per action). Use [`combine`] to produce an encodable bundle.
pub fn pczt_action_data(bundle: &PcztBundle) -> Result<IronwoodBundle, IronwoodBuildError> {
    let effects = bundle
        .extract_effects::<i64>()
        .map_err(|e| IronwoodBuildError::Extract(e.to_string()))?
        .ok_or(IronwoodBuildError::EmptyBundle)?;
    Ok(IronwoodBundle {
        actions: effects.actions().iter().map(action_to_ironwood).collect(),
        flags: effects.flag_byte(),
        value_balance: *effects.value_balance(),
        anchor: effects.anchor().to_bytes(),
        proof: Vec::new(),
        spend_auth_sigs: Vec::new(),
        binding_sig: [0u8; 64],
    })
}

/// Transaction Extractor: turn a signed + proven PCZT into a fully-authorized [`IronwoodBundle`].
///
/// `bundle` must already carry every `spend_auth_sig` (from [`finalize_shield_io`]), the binding
/// signing key `bsk` (also set by [`finalize_shield_io`]), and a canonical `zkproof` (from the proof
/// service, spliced in via [`super::ironwood_pczt::with_zkproof`]). `sighash` must equal the shielded
/// sig digest used when finalizing IO: it is what the binding signature signs and what every
/// spend-auth signature is verified against. `rng` seeds the (randomized) binding signature.
pub fn combine<R: RngCore + CryptoRng>(
    bundle: &PcztBundle,
    sighash: [u8; 32],
    rng: R,
) -> Result<IronwoodBundle, IronwoodBuildError> {
    let unbound = bundle
        .extract::<i64>()
        .map_err(|e| IronwoodBuildError::Extract(e.to_string()))?
        .ok_or(IronwoodBuildError::EmptyBundle)?;
    let authorized = unbound
        .apply_binding_signature(sighash, rng)
        .ok_or(IronwoodBuildError::BindingSignatureFailed)?;

    let spend_auth_sigs = authorized
        .actions()
        .iter()
        .map(|a| <[u8; 64]>::from(a.authorization()))
        .collect();
    Ok(IronwoodBundle {
        actions: authorized
            .actions()
            .iter()
            .map(action_to_ironwood)
            .collect(),
        flags: authorized.flag_byte(),
        value_balance: *authorized.value_balance(),
        anchor: authorized.anchor().to_bytes(),
        proof: authorized.authorization().proof().as_ref().to_vec(),
        spend_auth_sigs,
        binding_sig: <[u8; 64]>::from(authorized.authorization().binding_signature()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zcash::ironwood_pczt::{deserialize_pczt, serialize_pczt, with_zkproof};
    use crate::zcash::transaction::ZCASH_IRONWOOD_VERSION_GROUP_ID;
    use crate::zcash::v6::{
        compute_v6_sig_digest, compute_v6_txid, decode_v6_transaction, encode_v6_transaction,
        ZcashV6Transaction,
    };
    use miniscript::bitcoin::hashes::Hash;
    use miniscript::bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use orchard::Proof;
    use rand::rngs::OsRng;

    const NU6_3_BRANCH_ID: u32 = 0x37a5165b;

    /// A deterministic Ironwood receiver derived from a fixed spending key, for building test PCZTs.
    fn test_recipient() -> [u8; ORCHARD_ADDRESS_SIZE] {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        fvk.address_at(0u32, Scope::External).to_raw_address_bytes()
    }

    /// A single-P2PKH-input, no-output transparent skeleton to hang the Ironwood bundle on.
    fn transparent_skeleton() -> Transaction {
        Transaction {
            version: miniscript::bitcoin::transaction::Version::non_standard(6),
            input: vec![TxIn {
                // A non-zero prevout: an all-zeros hash would be read as a coinbase input.
                previous_output: OutPoint::new(Txid::from_byte_array([0x11u8; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from(vec![0x76u8, 0xa9, 0x14]),
            }],
            lock_time: miniscript::bitcoin::locktime::absolute::LockTime::from_consensus(0),
        }
    }

    fn v6_tx(transparent: Transaction, bundle: Option<IronwoodBundle>) -> ZcashV6Transaction {
        ZcashV6Transaction {
            version_group_id: ZCASH_IRONWOOD_VERSION_GROUP_ID,
            consensus_branch_id: NU6_3_BRANCH_ID,
            transparent,
            expiry_height: 0,
            sapling_value_balance: 0,
            ironwood_bundle: bundle,
        }
    }

    #[test]
    fn construct_yields_single_action_shielding_amount() {
        let amount = 100_000_000u64;
        let pczt = construct_shield_pczt(
            &test_recipient(),
            amount,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        let data = pczt_action_data(&pczt).unwrap();
        assert_eq!(data.actions.len(), 1, "UNPADDED single output ⇒ one action");
        // ironwood_v3 default flags = spends | outputs | cross-address.
        assert_eq!(data.flags, 0x07);
        // A pure output bundle (dummy spend has value 0): value_balance = 0 - amount.
        assert_eq!(data.value_balance, -(amount as i64));
    }

    /// End-to-end (build → sighash → sign dummy spend → inject proof → combine), no circuit:
    /// the resulting v6 tx round-trips through the codec and its txid is stable. A canonical-length
    /// placeholder proof stands in for the external prover (the codec/txid never inspect proof
    /// bytes, and the Extractor only length-checks them).
    #[test]
    fn build_finalize_combine_produces_encodable_tx() {
        let amount = 100_000_000u64;
        let mut pczt = construct_shield_pczt(
            &test_recipient(),
            amount,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();

        // Fix the transaction structure, then compute the shielded sighash it commits to.
        let transparent = transparent_skeleton();
        let input_amounts = [200_000_000i64];
        let input_scripts = [ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac])];
        let tx_for_sighash = v6_tx(transparent.clone(), Some(pczt_action_data(&pczt).unwrap()));
        let sighash = compute_v6_sig_digest(&tx_for_sighash, &input_amounts, &input_scripts);

        // Signer + IO finalizer (dummy spend-auth signature + bsk).
        finalize_shield_io(&mut pczt, sighash, OsRng).unwrap();

        // Round-trip through the proof-service wire path: serialize, splice a canonical-length
        // placeholder proof, deserialize.
        let signed_bytes = serialize_pczt(&pczt).unwrap();
        let proof = vec![0u8; Proof::expected_proof_size(1)];
        let proven = deserialize_pczt(&with_zkproof(&signed_bytes, proof).unwrap()).unwrap();

        // Combine → fully-authorized bundle.
        let bundle = combine(&proven, sighash, OsRng).unwrap();
        assert_eq!(bundle.actions.len(), 1);
        assert_eq!(bundle.spend_auth_sigs.len(), 1);
        assert_eq!(bundle.proof.len(), Proof::expected_proof_size(1));
        assert_eq!(bundle.flags, 0x07);

        // The action data survived unchanged from build → combine (digests are stable).
        assert_eq!(
            bundle.actions,
            tx_for_sighash.ironwood_bundle.unwrap().actions
        );

        // The assembled tx encodes and round-trips, with a stable txid.
        let tx = v6_tx(transparent, Some(bundle));
        let bytes = encode_v6_transaction(&tx).unwrap();
        let decoded = decode_v6_transaction(&bytes).unwrap();
        assert_eq!(decoded, tx);
        assert_eq!(compute_v6_txid(&decoded), compute_v6_txid(&tx));
    }

    /// Cross-check the combined transaction against `zebra-chain` (an independent NU6.3
    /// implementation): zebra must decode our bytes, see a v6 tx, and agree on the ZIP-244 txid
    /// and structure. This proves our Constructor → [`IronwoodBundle`] → wire mapping is canonical.
    /// (zebra parses but does not verify the proof on deserialize, so the placeholder proof is fine.)
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn combined_tx_matches_zebra() {
        use zebra_chain::serialization::ZcashDeserialize;
        use zebra_chain::transaction::Transaction as ZebraTx;

        let amount = 100_000_000u64;
        let mut pczt = construct_shield_pczt(
            &test_recipient(),
            amount,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        let transparent = transparent_skeleton();
        let input_amounts = [200_000_000i64];
        let input_scripts = [ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac])];
        let sighash = compute_v6_sig_digest(
            &v6_tx(transparent.clone(), Some(pczt_action_data(&pczt).unwrap())),
            &input_amounts,
            &input_scripts,
        );
        finalize_shield_io(&mut pczt, sighash, OsRng).unwrap();
        let signed_bytes = serialize_pczt(&pczt).unwrap();
        let proven = deserialize_pczt(
            &with_zkproof(&signed_bytes, vec![0u8; Proof::expected_proof_size(1)]).unwrap(),
        )
        .unwrap();
        let bundle = combine(&proven, sighash, OsRng).unwrap();

        let tx = v6_tx(transparent, Some(bundle));
        let bytes = encode_v6_transaction(&tx).unwrap();

        let zebra = ZebraTx::zcash_deserialize(&bytes[..]).expect("zebra decodes our v6 tx");
        assert_eq!(zebra.version(), 6);
        assert_eq!(zebra.ironwood_actions().count(), 1);
        assert_eq!(zebra.inputs().len(), tx.transparent.input.len());
        assert_eq!(zebra.outputs().len(), tx.transparent.output.len());

        let mut our_txid = compute_v6_txid(&tx);
        our_txid.reverse();
        assert_eq!(
            zebra.hash().to_string(),
            hex::encode(our_txid),
            "zebra txid == ours"
        );
    }

    /// Load a Zcash test fixture's contents from `test/fixtures/zcash/`.
    #[cfg(not(target_arch = "wasm32"))]
    fn load_zcash_fixture(name: &str) -> String {
        crate::fixed_script_wallet::test_utils::fixtures::load_fixture(&format!("zcash/{}", name))
            .unwrap_or_else(|e| panic!("failed to load fixture {}: {}", name, e))
    }

    /// Golden shielded-sighash oracle, using the real on-chain `shield1zec` transaction.
    ///
    /// The transaction's Ironwood bundle carries a real RedPallas dummy spend-auth signature and a
    /// real binding signature, both produced by an external Ironwood signer over the ZIP-244
    /// *shielded* sig digest. We reconstruct the orchard bundle from the on-wire action data and
    /// verify **both** real signatures against the digest [`compute_v6_sig_digest`] computes. If
    /// they verify, our shielded sig digest is byte-correct — the shielded twin of the transparent
    /// golden test in `v6.rs`, and an independent check since neither signature was produced by this
    /// code.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn golden_shield1zec_shielded_signatures_verify() {
        use nonempty::NonEmpty;
        use orchard::bundle::{Bundle as OrchardBundle, EffectsOnly};
        use orchard::note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext};
        use orchard::primitives::redpallas::{Binding, Signature, SpendAuth, VerificationKey};
        use orchard::value::ValueCommitment;

        let raw = hex::decode(load_zcash_fixture("v6_shield1zec_rawtx.hex").trim()).unwrap();
        let tx = decode_v6_transaction(&raw).unwrap();
        let bundle = tx.ironwood_bundle.clone().expect("ironwood bundle present");

        // Spent output committed by ZIP-244 (from the reference that built this tx; see the
        // transparent golden test in v6.rs).
        let prevout_value: i64 = 313_990_000;
        let prevout_script = ScriptBuf::from(
            hex::decode("76a9147c6b843a25873c036aff575516e3802bcc47f63488ac").unwrap(),
        );
        assert_eq!(tx.transparent.input.len(), 1);
        let sighash =
            compute_v6_sig_digest(&tx, &[prevout_value], std::slice::from_ref(&prevout_script));

        // Reconstruct the orchard EffectsOnly bundle from the on-wire action data, so we can derive
        // the binding validating key and verify the real signatures.
        let actions = bundle
            .actions
            .iter()
            .map(|a| {
                let cv_net =
                    Option::from(ValueCommitment::from_bytes(&a.cv)).expect("valid cv_net");
                let rk = VerificationKey::<SpendAuth>::try_from(a.rk).expect("valid rk");
                let cmx =
                    Option::from(ExtractedNoteCommitment::from_bytes(&a.cmx)).expect("valid cmx");
                let nf = Option::from(Nullifier::from_bytes(&a.nullifier)).expect("valid nf");
                let encrypted_note = TransmittedNoteCiphertext {
                    epk_bytes: a.ephemeral_key,
                    enc_ciphertext: a.enc_ciphertext,
                    out_ciphertext: a.out_ciphertext,
                };
                OrchardAction::from_parts(nf, rk, cmx, encrypted_note, cv_net, ())
                    .expect("valid action")
            })
            .collect::<Vec<_>>();
        let actions = NonEmpty::from_vec(actions).expect("at least one action");

        let orchard_bundle = OrchardBundle::<EffectsOnly, i64>::from_parts(
            actions,
            BundleVersion::ironwood_v3().default_flags(),
            bundle.value_balance,
            Option::from(Anchor::from_bytes(bundle.anchor)).expect("valid anchor"),
            EffectsOnly,
            BundleVersion::ironwood_v3(),
        )
        .expect("valid bundle");
        assert_eq!(orchard_bundle.flag_byte(), bundle.flags);

        // The real dummy spend-auth signature verifies against our shielded sig digest.
        let spend_auth_sig = Signature::<SpendAuth>::from(bundle.spend_auth_sigs[0]);
        orchard_bundle.actions()[0]
            .rk()
            .verify(&sighash, &spend_auth_sig)
            .expect("real spend-auth signature verifies against compute_v6_sig_digest");

        // The real binding signature verifies against our shielded sig digest.
        let binding_sig = Signature::<Binding>::from(bundle.binding_sig);
        orchard_bundle
            .binding_validating_key()
            .verify(&sighash, &binding_sig)
            .expect("real binding signature verifies against compute_v6_sig_digest");
    }
}
