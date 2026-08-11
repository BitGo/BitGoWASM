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
    /// The requested action index does not exist in the bundle.
    ActionIndexOutOfRange,
    /// The PCZT output is missing a field ([`recipient`](orchard::pczt::Output::recipient),
    /// [`value`](orchard::pczt::Output::value), or [`rseed`](orchard::pczt::Output::rseed)) needed
    /// to reconstruct the note and recompute `out_ciphertext`.
    MissingOutputFields,
    /// The reconstructed note is not internally valid (e.g. a corrupted `rseed`/`rho` pair).
    InvalidNote,
    /// The note reconstructed from the PCZT output's fields does not commit to the `cmx` the action
    /// already carries, so recomputing `out_ciphertext` from it would encrypt an `esk` inconsistent
    /// with the action's fixed `ephemeral_key`.
    NoteCommitmentMismatch,
    /// The bitgo/user key bytes are not a valid secp256k1 public/private key.
    BadKey(String),
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
            Self::ActionIndexOutOfRange => write!(f, "ironwood-build: action index out of range"),
            Self::MissingOutputFields => write!(
                f,
                "ironwood-build: output is missing recipient/value/rseed; cannot recompute \
                 out_ciphertext"
            ),
            Self::InvalidNote => write!(
                f,
                "ironwood-build: reconstructed note is not internally valid"
            ),
            Self::NoteCommitmentMismatch => write!(
                f,
                "ironwood-build: the note reconstructed from the output's recipient/value/rseed does \
                 not commit to the action's cmx; refusing to recompute out_ciphertext from it"
            ),
            Self::BadKey(e) => write!(f, "ironwood-build: invalid key: {e}"),
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

/// Length of the Ironwood/orchard `out_ciphertext` field in bytes (`OUT_PLAINTEXT_SIZE` + AEAD tag).
pub const OUT_CIPHERTEXT_SIZE: usize = zcash_note_encryption::OUT_CIPHERTEXT_SIZE;
/// An Ironwood/orchard `out_ciphertext`.
pub type OutCiphertextBytes = [u8; OUT_CIPHERTEXT_SIZE];

/// Client-managed `ovk`: derive a 32-byte outgoing viewing key as the ECDH shared secret
/// between the BitGo cosigner's secp256k1 public key and the user's secp256k1 private key.
///
/// This never touches the server: the server-side (keyless) build in [`construct_shield_pczt`]
/// passes `ovk = None`, and the client calls this — with a key pair it alone can complete an ECDH
/// with — to derive an `ovk` the server never sees, then splices the resulting `out_ciphertext` in
/// via [`compute_out_ciphertext`] and [`super::ironwood_pczt::with_out_ciphertext`].
///
/// **The canonical key pair is the two *root* wallet keys**: `bitgo_pubkey` is
/// `RootWalletKeys::bitgo_key()`'s raw pubkey and `user_privkey` is the user root `Xpriv`'s secret
/// key — never a `(chain, index)`-derived leaf key. Both sides of the agreement are therefore
/// transaction-independent, so the `ovk` does not depend on which inputs a transaction happens to
/// spend or the order they appear in, and the server can re-derive it from
/// `ECDH(bitgo_root_privkey, user_root_pubkey)` — the same shared secret from the other side —
/// knowing only the wallet's keys. Callers should go through
/// [`ZcashBitGoPsbt::set_ironwood_out_ciphertext_for_user`], which enforces this pairing;
/// see also the `server_can_independently_derive_ovk_and_validate_out_ciphertext_before_signing`
/// test for the validation the server runs before countersigning.
///
/// Because both inputs are long-term keys, the resulting `ovk` is a long-term *wallet* key — the
/// same value for every transaction of a given wallet — exactly as an `ovk` is treated in Zcash
/// generally. It is not, and is not intended to be, per-transaction.
///
/// `secp256k1`'s ECDH (SHA-256 of the compressed shared point, its default hashing) already yields a
/// uniformly random 32-byte value suitable as a raw `ovk` directly — no separate KDF step is needed.
///
/// [`ZcashBitGoPsbt::set_ironwood_out_ciphertext_for_user`]: crate::fixed_script_wallet::bitgo_psbt::zcash_psbt::ZcashBitGoPsbt::set_ironwood_out_ciphertext_for_user
pub fn derive_client_ovk(
    bitgo_pubkey: &[u8],
    user_privkey: &[u8],
) -> Result<OvkBytes, IronwoodBuildError> {
    let pk = secp256k1::PublicKey::from_slice(bitgo_pubkey)
        .map_err(|e| IronwoodBuildError::BadKey(format!("bitgo pubkey: {e}")))?;
    let sk = secp256k1::SecretKey::from_slice(user_privkey)
        .map_err(|e| IronwoodBuildError::BadKey(format!("user private key: {e}")))?;
    let shared = secp256k1::ecdh::SharedSecret::new(&pk, &sk);
    Ok(shared.secret_bytes())
}

/// Recompute `out_ciphertext` for one action of a PCZT under a client-supplied `ovk`, reconstructing
/// the output note from the Constructor-set PCZT fields (`recipient`, `value`, `rseed`, and `rho`
/// derived from the paired spend's `nullifier`). Reuses the note's ZIP-212-derived `esk`/`epk`, so
/// the result is consistent with the action's already-fixed `cv`/`cmx`/`ephemeral_key`/
/// `enc_ciphertext` — only `out_ciphertext` changes.
///
/// The reconstructed note is checked against the action's already-committed `cmx` before it is
/// used: `out_ciphertext` carries `pk_d || esk`, so a note reconstructed from stale or corrupted
/// fields would produce a ciphertext whose `esk` does not match the action's fixed `ephemeral_key`
/// — ciphertext that encrypts and splices in cleanly, and only reveals itself as garbage when
/// someone later tries to recover the note. Failing here turns that into
/// [`IronwoodBuildError::NoteCommitmentMismatch`].
///
/// The caller (see [`super::ironwood_pczt::with_out_ciphertext`]) is responsible for splicing the
/// returned bytes into the PCZT wire form; this function only computes them.
pub fn compute_out_ciphertext<R: RngCore + CryptoRng>(
    pczt: &PcztBundle,
    action_index: usize,
    ovk: OvkBytes,
    rng: &mut R,
) -> Result<OutCiphertextBytes, IronwoodBuildError> {
    use orchard::note::Rho;
    use orchard::note_encryption::IronwoodDomain;
    use orchard::Note;
    use zcash_note_encryption::NoteEncryption;

    let action = pczt
        .actions()
        .get(action_index)
        .ok_or(IronwoodBuildError::ActionIndexOutOfRange)?;
    let output = action.output();
    let recipient = output
        .recipient()
        .as_ref()
        .ok_or(IronwoodBuildError::MissingOutputFields)?;
    let value = output
        .value()
        .as_ref()
        .ok_or(IronwoodBuildError::MissingOutputFields)?;
    let rseed = output
        .rseed()
        .as_ref()
        .ok_or(IronwoodBuildError::MissingOutputFields)?;
    let rho = Option::<Rho>::from(Rho::from_bytes(&action.spend().nullifier().to_bytes()))
        .ok_or(IronwoodBuildError::InvalidNote)?;
    let note: Note = Option::from(Note::from_parts(
        *recipient,
        *value,
        rho,
        *rseed,
        *output.note_version(),
    ))
    .ok_or(IronwoodBuildError::InvalidNote)?;

    // The note we just rebuilt must be the note this action already commits to — otherwise the
    // `esk` we are about to encrypt belongs to a different note than the action's `ephemeral_key`,
    // and the resulting `out_ciphertext` is unrecoverable garbage that nothing downstream checks.
    let committed_cmx = output.cmx();
    if orchard::note::ExtractedNoteCommitment::from(note.commitment()) != *committed_cmx {
        return Err(IronwoodBuildError::NoteCommitmentMismatch);
    }

    // The memo only affects `enc_ciphertext` (already fixed at build time), not
    // `outgoing_plaintext_bytes` (pk_d || esk) — unused here, so a placeholder is fine.
    let placeholder_memo = [0u8; 512];
    let enc = NoteEncryption::<IronwoodDomain>::new(
        Some(orchard::keys::OutgoingViewingKey::from(ovk)),
        note,
        placeholder_memo,
    );
    Ok(enc.encrypt_outgoing_plaintext(action.cv_net(), committed_cmx, rng))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zcash::ironwood_pczt::{
        deserialize_pczt, serialize_pczt, with_out_ciphertext, with_zkproof,
    };
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

    /// Golden `out_ciphertext` oracle, using the real on-chain `shield1zec` transaction's note
    /// (`cv`, `cmx`, `epk`, and the confidential `rseed`/`recipient`/`value` build inputs — not
    /// on-chain, but known out-of-band for this reference transaction) together with the real `ovk`
    /// derived from that note's own spending key.
    ///
    /// The on-chain `out_ciphertext` for this particular reference transaction was itself built
    /// **keyless** (`ovk = None`, the random-placeholder path every other build/test in this crate
    /// also exercises) — confirmed here by demonstrating that `try_output_recovery_with_ovk` cannot
    /// decrypt it under *any* real `ovk` derived from the note's own key material (neither
    /// `Scope::External` nor `Scope::Internal`), even though every other field of the note
    /// (`recipient`, `value`, `rseed`, hence `cmx`, hence `enc_ciphertext`) is independently
    /// confirmed correct against the chain. So there is no real on-chain `out_ciphertext` for this
    /// fixture to byte-match against — instead, this pins that our own [`compute_out_ciphertext`]
    /// (fed the real `cv`/`cmx`/rho from the chain and the real `ovk` from the note's key material)
    /// produces ciphertext that is itself correctly recoverable, end to end, on genuine on-chain
    /// note data rather than a self-built one.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn golden_shield1zec_out_ciphertext_round_trips_on_real_on_chain_note_data() {
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};
        use orchard::note::{
            ExtractedNoteCommitment, NoteVersion, Nullifier, RandomSeed, Rho,
            TransmittedNoteCiphertext,
        };
        use orchard::note_encryption::IronwoodDomain;
        use orchard::primitives::redpallas::{SpendAuth, VerificationKey};
        use orchard::value::ValueCommitment;
        use orchard::{Address, Note};
        use zcash_note_encryption::{try_output_recovery_with_ovk, NoteEncryption};

        // Confidential build inputs for this reference transaction (not on-chain; known out-of-band
        // for this fixture only).
        let recipient_hex =
            "d632c28aa0831d671be17709a42c9627e2eb687a1b2a55768ea470c9bae7499cd0bd3d0eb0484e307236b5";
        let rseed_hex = "ecbb65cca04f6701f4a96c3d7b9edc5ecf421451fef4350978e84066c841d2d3";
        let spending_key_hex = "9d451e17e1c0874374dcdb64d3d8e151b26f346a1a227d7b7b7f18bbc6c9cb40";
        let value_zat: u64 = 100_000_000;

        let raw = hex::decode(load_zcash_fixture("v6_shield1zec_rawtx.hex").trim()).unwrap();
        let tx = decode_v6_transaction(&raw).unwrap();
        let bundle = tx.ironwood_bundle.expect("ironwood bundle present");
        let action = &bundle.actions[0];

        // Reconstruct the real output note and confirm it commits to the real on-chain cmx.
        let recipient_bytes: [u8; ORCHARD_ADDRESS_SIZE] =
            hex::decode(recipient_hex).unwrap().try_into().unwrap();
        let recipient =
            Option::<Address>::from(Address::from_raw_address_bytes(&recipient_bytes)).unwrap();
        let rseed_bytes: [u8; 32] = hex::decode(rseed_hex).unwrap().try_into().unwrap();
        // The action's on-wire `nullifier` field doubles as the paired output note's `rho` (see
        // `action_to_ironwood`).
        let rho = Option::<Rho>::from(Rho::from_bytes(&action.nullifier)).unwrap();
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed_bytes, &rho)).unwrap();
        let note = Option::<Note>::from(Note::from_parts(
            recipient,
            orchard::value::NoteValue::from_raw(value_zat),
            rho,
            rseed,
            NoteVersion::V3,
        ))
        .unwrap();
        let cmx_bytes: [u8; 32] = (&ExtractedNoteCommitment::from(note.commitment())).into();
        assert_eq!(
            cmx_bytes, action.cmx,
            "reconstructed note commits to the real on-chain cmx"
        );

        let cv_net =
            Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&action.cv)).unwrap();
        let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
            &action.cmx,
        ))
        .unwrap();

        // The encrypted note plaintext (independent of ovk) matches the real on-chain bytes,
        // confirming esk/epk — and hence the whole note reconstruction — is correct.
        let placeholder_memo = [0u8; 512];
        let enc = NoteEncryption::<IronwoodDomain>::new(None, note, placeholder_memo);
        assert_eq!(
            enc.encrypt_note_plaintext().to_vec(),
            action.enc_ciphertext.to_vec(),
            "reconstructed note encrypts to the real on-chain enc_ciphertext"
        );

        // Real `ovk`s derived from the note's own spending key do not decrypt the real on-chain
        // out_ciphertext — it was built keyless (ovk = None), so there is nothing for a real ovk to
        // recover there.
        let sk_bytes: [u8; 32] = hex::decode(spending_key_hex).unwrap().try_into().unwrap();
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(sk_bytes)).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let rk = VerificationKey::<SpendAuth>::try_from(action.rk).expect("valid rk");
        let nf = Option::from(Nullifier::from_bytes(&action.nullifier)).expect("valid nf");
        let on_chain_encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: action.ephemeral_key,
            enc_ciphertext: action.enc_ciphertext,
            out_ciphertext: action.out_ciphertext,
        };
        let on_chain_action = OrchardAction::from_parts(
            nf,
            rk.clone(),
            cmx,
            on_chain_encrypted_note,
            cv_net.clone(),
            (),
        )
        .expect("valid action");
        let domain = IronwoodDomain::for_action(&on_chain_action);
        for scope in [Scope::External, Scope::Internal] {
            assert!(
                try_output_recovery_with_ovk(
                    &domain,
                    &fvk.to_ovk(scope),
                    &on_chain_action,
                    &cv_net,
                    &action.out_ciphertext,
                )
                .is_none(),
                "the real on-chain out_ciphertext is not recoverable under any real ovk \
                 ({scope:?}) — it was built keyless"
            );
        }

        // Feeding this note's real cv/cmx (from the chain) and a real ovk (from the note's own key
        // material) into the same `NoteEncryption::encrypt_outgoing_plaintext` primitive
        // [`compute_out_ciphertext`] wraps produces ciphertext that *is* correctly recoverable end
        // to end — unlike the on-chain placeholder just shown above.
        let real_ovk = fvk.to_ovk(Scope::External);
        let enc_with_real_ovk =
            NoteEncryption::<IronwoodDomain>::new(Some(real_ovk.clone()), note, placeholder_memo);
        let recomputed = enc_with_real_ovk.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut OsRng);
        let recomputed_encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: action.ephemeral_key,
            enc_ciphertext: action.enc_ciphertext,
            out_ciphertext: recomputed,
        };
        let recomputed_action =
            OrchardAction::from_parts(nf, rk, cmx, recomputed_encrypted_note, cv_net.clone(), ())
                .expect("valid action");
        let (recovered_note, recovered_recipient, _memo) = try_output_recovery_with_ovk(
            &domain,
            &real_ovk,
            &recomputed_action,
            &cv_net,
            &recomputed,
        )
        .expect("our own out_ciphertext, built from real on-chain cv/cmx, is recoverable");
        assert_eq!(recovered_recipient, recipient);
        assert_eq!(
            recovered_note.value(),
            orchard::value::NoteValue::from_raw(value_zat)
        );
    }

    // ---- Client-managed `ovk` ----

    /// A fixed secp256k1 key pair standing in for "the BitGo cosigner pubkey" and "the user's
    /// private key" — the two ECDH counterparties [`derive_client_ovk`] combines.
    fn test_key_pair(seed: u8) -> (secp256k1::PublicKey, secp256k1::SecretKey) {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        (pk, sk)
    }

    #[test]
    fn derive_client_ovk_is_a_deterministic_ecdh_agreement() {
        let (bitgo_pk, _) = test_key_pair(0x11);
        let (_, user_sk) = test_key_pair(0x22);

        let ovk1 = derive_client_ovk(&bitgo_pk.serialize(), &user_sk.secret_bytes()).unwrap();
        let ovk2 = derive_client_ovk(&bitgo_pk.serialize(), &user_sk.secret_bytes()).unwrap();
        assert_eq!(ovk1, ovk2, "deterministic in its two key inputs");

        // ECDH agreement: the same shared secret is reachable from either side of the key pair —
        // BitGo's privkey + the user's pubkey agrees with BitGo's pubkey + the user's privkey.
        let secp = secp256k1::Secp256k1::new();
        let (_, bitgo_sk) = test_key_pair(0x11);
        let (user_pk, _) = test_key_pair(0x22);
        assert_eq!(
            bitgo_pk,
            secp256k1::PublicKey::from_secret_key(&secp, &bitgo_sk)
        );
        let ovk_from_other_side =
            derive_client_ovk(&user_pk.serialize(), &bitgo_sk.secret_bytes()).unwrap();
        assert_eq!(ovk1, ovk_from_other_side, "ECDH agreement is symmetric");

        // A different user key yields a different ovk.
        let (_, other_user_sk) = test_key_pair(0x33);
        let ovk3 = derive_client_ovk(&bitgo_pk.serialize(), &other_user_sk.secret_bytes()).unwrap();
        assert_ne!(ovk1, ovk3);
    }

    #[test]
    fn derive_client_ovk_rejects_malformed_keys() {
        let (bitgo_pk, _) = test_key_pair(0x11);
        let (_, user_sk) = test_key_pair(0x22);
        assert!(matches!(
            derive_client_ovk(&[0u8; 33], &user_sk.secret_bytes()),
            Err(IronwoodBuildError::BadKey(_))
        ));
        assert!(matches!(
            derive_client_ovk(&bitgo_pk.serialize(), &[0u8; 32]),
            Err(IronwoodBuildError::BadKey(_))
        ));
    }

    #[test]
    fn compute_out_ciphertext_is_recoverable_only_with_the_matching_ovk() {
        use orchard::note_encryption::IronwoodDomain;
        use zcash_note_encryption::try_output_recovery_with_ovk;

        let pczt = construct_shield_pczt(
            &test_recipient(),
            100_000_000,
            None, // keyless server build
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        let action = &pczt.actions()[0];

        let (bitgo_pk, _) = test_key_pair(0xaa);
        let (_, user_sk) = test_key_pair(0xbb);
        let ovk = derive_client_ovk(&bitgo_pk.serialize(), &user_sk.secret_bytes()).unwrap();
        let out_ct = compute_out_ciphertext(&pczt, 0, ovk, &mut OsRng.clone()).unwrap();

        let domain = IronwoodDomain::for_pczt_action(action);
        let recovered = try_output_recovery_with_ovk(
            &domain,
            &orchard::keys::OutgoingViewingKey::from(ovk),
            action,
            action.cv_net(),
            &out_ct,
        );
        let (note, recipient, _memo) = recovered.expect("recoverable with the matching ovk");
        assert_eq!(recipient, *action.output().recipient().as_ref().unwrap());
        assert_eq!(note.value(), *action.output().value().as_ref().unwrap());

        // A different (wrong) ovk does not recover the note.
        let (_, wrong_user_sk) = test_key_pair(0xcc);
        let wrong_ovk =
            derive_client_ovk(&bitgo_pk.serialize(), &wrong_user_sk.secret_bytes()).unwrap();
        assert!(try_output_recovery_with_ovk(
            &domain,
            &orchard::keys::OutgoingViewingKey::from(wrong_ovk),
            action,
            action.cv_net(),
            &out_ct,
        )
        .is_none());

        // Rejects an out-of-range action index.
        assert!(matches!(
            compute_out_ciphertext(&pczt, 1, ovk, &mut OsRng.clone()),
            Err(IronwoodBuildError::ActionIndexOutOfRange)
        ));
    }

    /// A PCZT whose output fields no longer reconstruct the note its `cmx` commits to is rejected
    /// rather than producing an `out_ciphertext` whose `esk` disagrees with the action's fixed
    /// `ephemeral_key` — ciphertext that would splice in cleanly and only reveal itself as garbage
    /// when someone later tried to recover the note.
    #[test]
    fn compute_out_ciphertext_rejects_a_note_that_does_not_match_the_committed_cmx() {
        use crate::zcash::ironwood_pczt::with_output_rseed_for_test;

        let pczt = construct_shield_pczt(
            &test_recipient(),
            100_000_000,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        let bytes = serialize_pczt(&pczt).unwrap();
        let tampered =
            deserialize_pczt(&with_output_rseed_for_test(&bytes, 0, [0x5au8; 32]).unwrap())
                .unwrap();

        let (bitgo_pk, _) = test_key_pair(0xa1);
        let (_, user_sk) = test_key_pair(0xa2);
        let ovk = derive_client_ovk(&bitgo_pk.serialize(), &user_sk.secret_bytes()).unwrap();
        assert!(matches!(
            compute_out_ciphertext(&tampered, 0, ovk, &mut OsRng.clone()),
            Err(IronwoodBuildError::NoteCommitmentMismatch)
        ));
    }

    /// Server-side (HSM) validation: ECDH agreement is symmetric, so the server — holding
    /// `bitgo_privkey` — can derive the *same* `ovk` from the other side of the key pair
    /// (`ECDH(bitgo_privkey, user_pubkey)`, vs. the client's `ECDH(bitgo_pubkey, user_privkey)`)
    /// without ever learning `user_privkey` or the `ovk` itself over the wire. It then uses that
    /// independently-derived `ovk` to decrypt `out_ciphertext` and check it actually describes the
    /// action's committed note (`recipient`/`value`) before it would be willing to countersign —
    /// rather than trusting the client-supplied ciphertext blindly.
    #[test]
    fn server_can_independently_derive_ovk_and_validate_out_ciphertext_before_signing() {
        use orchard::note_encryption::IronwoodDomain;
        use zcash_note_encryption::try_output_recovery_with_ovk;

        // Keyless server build, exactly as it would happen for real.
        let pczt = construct_shield_pczt(
            &test_recipient(),
            100_000_000,
            None,
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();
        let action = &pczt.actions()[0];

        let (bitgo_pk, bitgo_sk) = test_key_pair(0xd1);
        let (user_pk, user_sk) = test_key_pair(0xd2);

        // Client side: derive ovk from (bitgo pubkey, user privkey) and produce out_ciphertext.
        let client_ovk = derive_client_ovk(&bitgo_pk.serialize(), &user_sk.secret_bytes()).unwrap();
        let out_ct = compute_out_ciphertext(&pczt, 0, client_ovk, &mut OsRng.clone()).unwrap();

        // Server side: never sees `user_sk` or `client_ovk`. It only has its own `bitgo_sk` and the
        // user's public key (e.g. from wallet metadata), and derives the ovk from the other side of
        // the same ECDH pair.
        let server_ovk = derive_client_ovk(&user_pk.serialize(), &bitgo_sk.secret_bytes()).unwrap();
        assert_eq!(
            server_ovk, client_ovk,
            "ECDH agreement: the server derives the identical ovk from its own privkey + the \
             user's pubkey"
        );

        // The server decrypts out_ciphertext with its independently-derived ovk and checks it
        // actually matches the action's committed note — the check it would run before countersigning.
        let domain = IronwoodDomain::for_pczt_action(action);
        let (note, recipient, _memo) = try_output_recovery_with_ovk(
            &domain,
            &orchard::keys::OutgoingViewingKey::from(server_ovk),
            action,
            action.cv_net(),
            &out_ct,
        )
        .expect("server validates out_ciphertext with its own ECDH-derived ovk");
        assert_eq!(recipient, *action.output().recipient().as_ref().unwrap());
        assert_eq!(note.value(), *action.output().value().as_ref().unwrap());

        // If the client used a *different* user pubkey than the one the server has on file for that
        // user, the server's derived ovk no longer agrees, and validation correctly fails — this is
        // the check that would block signing.
        let (wrong_user_pk, _) = test_key_pair(0xd3);
        let mismatched_server_ovk =
            derive_client_ovk(&wrong_user_pk.serialize(), &bitgo_sk.secret_bytes()).unwrap();
        assert_ne!(mismatched_server_ovk, client_ovk);
        assert!(
            try_output_recovery_with_ovk(
                &domain,
                &orchard::keys::OutgoingViewingKey::from(mismatched_server_ovk),
                action,
                action.cv_net(),
                &out_ct,
            )
            .is_none(),
            "server rejects out_ciphertext when the on-file user pubkey doesn't match"
        );
    }

    /// End-to-end test: the server builds a **keyless** shielding PCZT (single
    /// transparent input, single Ironwood output — the same shape `ZcashBitGoPsbt::add_ironwood_output`
    /// produces) and hands its serialized bytes to "the client". The client deserializes, derives its
    /// `ovk` on the fly as the ECDH agreement of the BitGo cosigner pubkey and its own private key,
    /// recomputes `out_ciphertext` under that `ovk`, and splices it back in — all *before* the ZIP-244
    /// sighash (which commits to `out_ciphertext`) is computed and the transparent input is signed.
    #[test]
    fn keyless_build_then_client_sets_out_ciphertext_via_ecdh_ovk_then_signs_and_combines() {
        let amount = 100_000_000u64;
        let pczt = construct_shield_pczt(
            &test_recipient(),
            amount,
            None, // keyless: server never sees an ovk
            &Anchor::empty_tree().to_bytes(),
            &[0u8; 512],
            OsRng,
        )
        .unwrap();

        let transparent = transparent_skeleton();
        let data_before = pczt_action_data(&pczt).unwrap();
        assert_eq!(transparent.input.len(), 1, "single transparent input");
        assert_eq!(
            data_before.actions.len(),
            1,
            "single Ironwood output/action"
        );

        // Server: serialize the keyless PCZT for handoff (this is what `ZcashBitGoPsbt::serialize_v6`
        // carries in the PSBT's proprietary map).
        let server_bytes = serialize_pczt(&pczt).unwrap();

        // Client: deserialize, derive its ovk on the fly (ECDH of the BitGo cosigner pubkey and its
        // own signing private key — the server never sees either the ovk or the user privkey).
        let client_pczt = deserialize_pczt(&server_bytes).unwrap();
        let (bitgo_pubkey, _) = test_key_pair(0x42);
        let (_, user_privkey) = test_key_pair(0x99);
        let ovk =
            derive_client_ovk(&bitgo_pubkey.serialize(), &user_privkey.secret_bytes()).unwrap();
        let new_out_ciphertext =
            compute_out_ciphertext(&client_pczt, 0, ovk, &mut OsRng.clone()).unwrap();
        assert_ne!(
            new_out_ciphertext.to_vec(),
            data_before.actions[0].out_ciphertext.to_vec(),
            "client's ovk-encrypted ciphertext differs from the keyless placeholder"
        );

        let patched_bytes = with_out_ciphertext(&server_bytes, 0, new_out_ciphertext).unwrap();
        let mut patched = deserialize_pczt(&patched_bytes).unwrap();

        let data_after = pczt_action_data(&patched).unwrap();
        assert_eq!(
            data_after.actions[0].out_ciphertext.to_vec(),
            new_out_ciphertext.to_vec()
        );
        // Every other action-data field is untouched by the splice.
        assert_eq!(data_after.actions[0].cv, data_before.actions[0].cv);
        assert_eq!(data_after.actions[0].cmx, data_before.actions[0].cmx);
        assert_eq!(
            data_after.actions[0].enc_ciphertext,
            data_before.actions[0].enc_ciphertext
        );
        assert_eq!(data_after.value_balance, data_before.value_balance);

        // Now — and only now — the ZIP-244 sighash is computed (it commits to `out_ciphertext`) and
        // the transparent input is "signed" (finalize_shield_io signs the dummy spend over it).
        let input_amounts = [200_000_000i64];
        let input_scripts = [ScriptBuf::from(vec![0x76u8, 0xa9, 0x14, 0x88, 0xac])];
        let tx_for_sighash = v6_tx(transparent.clone(), Some(data_after.clone()));
        let sighash = compute_v6_sig_digest(&tx_for_sighash, &input_amounts, &input_scripts);

        // The sighash differs from what it would have been over the keyless placeholder — pinning
        // the ordering constraint: signing before setting out_ciphertext would sign the wrong digest.
        let placeholder_tx = v6_tx(transparent.clone(), Some(data_before.clone()));
        let placeholder_sighash =
            compute_v6_sig_digest(&placeholder_tx, &input_amounts, &input_scripts);
        assert_ne!(
            sighash, placeholder_sighash,
            "out_ciphertext is sighash-committed"
        );

        finalize_shield_io(&mut patched, sighash, OsRng).unwrap();
        let signed_bytes = serialize_pczt(&patched).unwrap();
        let proof = vec![0u8; Proof::expected_proof_size(1)];
        let proven = deserialize_pczt(&with_zkproof(&signed_bytes, proof).unwrap()).unwrap();

        let bundle = combine(&proven, sighash, OsRng).unwrap();
        assert_eq!(
            bundle.actions[0].out_ciphertext.to_vec(),
            new_out_ciphertext.to_vec(),
            "the client-set out_ciphertext survives to the combined bundle"
        );

        // The resulting v6 transaction encodes/decodes round-trip cleanly.
        let tx = v6_tx(transparent, Some(bundle));
        let encoded = encode_v6_transaction(&tx).unwrap();
        let decoded = decode_v6_transaction(&encoded).unwrap();
        assert_eq!(decoded, tx);
    }
}
