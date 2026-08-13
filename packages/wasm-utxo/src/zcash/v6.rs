//! Zcash v6 (Ironwood / NU6.3) transaction wire format.
//!
//! A v6 transaction restructures the header relative to v4: `consensusBranchId`,
//! `lockTime`, and `expiryHeight` all move to the front (before the transparent
//! inputs/outputs), and two shielded-bundle slots are appended after Sapling — a
//! v6-personalized Orchard slot (empty for our flows, `nActionsOrchard = 0`) and a
//! new Ironwood slot.
//!
//! Wire layout (all integers little-endian, `varint` = CompactSize):
//!
//! ```text
//! Header:      version(4) versionGroupId(4) consensusBranchId(4) lockTime(4) expiryHeight(4)
//! Transparent: tx_in_count(varint) tx_in[]  tx_out_count(varint) tx_out[]
//! Sapling:     nSpendsSapling(varint=0) nOutputsSapling(varint=0)
//! Orchard v6:  nActionsOrchard(varint=0)          // bundle body present only if > 0
//! Ironwood:    nActionsIronwood(varint) actions[820×n] flags(1) valueBalance(8)
//!              anchor(32) proofsSize(varint) proofs[] spendAuthSigs[64×n] bindingSig(64)
//!              // whole block present only if nActionsIronwood > 0
//! ```
//!
//! This codec supports the shapes the Ironwood flows actually produce: empty
//! Sapling and empty Orchard slots plus a populated Ironwood bundle. Non-empty
//! Sapling or Orchard bundles are rejected with a clear error rather than
//! mis-parsed, since no BitGo flow emits them.

use super::blake2b::blake2b_256_personal;
use super::transaction::{ZCASH_IRONWOOD_VERSION_GROUP_ID, ZCASH_V6_VERSION_HEADER};
use core::fmt;
use miniscript::bitcoin::consensus::{Decodable, Encodable};
use miniscript::bitcoin::{Transaction, TxIn, TxOut, VarInt};

/// Errors produced while decoding or encoding a Zcash v6 (Ironwood) transaction.
///
/// The variant name is surfaced to JS as `err.code` (e.g. `"ZcashV6Error.TruncatedActions"`)
/// via [`crate::error::WasmUtxoError`], so callers can branch on the error kind.
#[derive(Debug, strum::IntoStaticStr)]
pub enum ZcashV6Error {
    /// A consensus field could not be decoded.
    Decode(String),
    /// A field could not be encoded.
    Encode(String),
    /// The version header is not the v6 header.
    UnexpectedVersion(u32),
    /// The version group id is not the Ironwood version group id.
    UnexpectedVersionGroupId(u32),
    /// A non-empty Sapling bundle was encountered (unsupported).
    UnsupportedSaplingBundle,
    /// A non-empty Orchard v6 bundle was encountered (unsupported).
    UnsupportedOrchardBundle,
    /// The encoder was asked to write a non-zero Sapling value balance (unsupported).
    NonZeroSaplingValueBalance,
    /// The declared action or proof count/size overflows `usize`.
    CountOverflow,
    /// Fewer bytes remain than the declared actions require.
    TruncatedActions,
    /// The reader reached end of input before a fixed-size field was complete.
    UnexpectedEof,
    /// A single Ironwood action was not exactly [`IRONWOOD_ACTION_SIZE`] bytes.
    BadActionLength,
    /// Trailing bytes remain after the Ironwood bundle.
    TrailingBytes,
    /// The spend-auth signature count does not match the action count.
    SpendAuthSigCountMismatch,
}

impl fmt::Display for ZcashV6Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "v6: failed to decode: {e}"),
            Self::Encode(e) => write!(f, "v6: failed to encode: {e}"),
            Self::UnexpectedVersion(v) => write!(
                f,
                "v6: unexpected version header 0x{v:08x} (expected 0x{ZCASH_V6_VERSION_HEADER:08x})"
            ),
            Self::UnexpectedVersionGroupId(v) => write!(
                f,
                "v6: unexpected version group id 0x{v:08x} (expected 0x{ZCASH_IRONWOOD_VERSION_GROUP_ID:08x})"
            ),
            Self::UnsupportedSaplingBundle => {
                write!(f, "v6: non-empty Sapling bundle is not supported")
            }
            Self::UnsupportedOrchardBundle => {
                write!(f, "v6: non-empty Orchard v6 bundle is not supported")
            }
            Self::NonZeroSaplingValueBalance => {
                write!(f, "v6: non-zero Sapling value balance is not supported")
            }
            Self::CountOverflow => write!(f, "v6: action/proof count overflow"),
            Self::TruncatedActions => write!(f, "v6: declared actions exceed remaining bytes"),
            Self::UnexpectedEof => write!(f, "v6: unexpected end of input"),
            Self::BadActionLength => {
                write!(f, "v6: Ironwood action must be {IRONWOOD_ACTION_SIZE} bytes")
            }
            Self::TrailingBytes => write!(f, "v6: trailing bytes after Ironwood bundle"),
            Self::SpendAuthSigCountMismatch => {
                write!(f, "v6: spend-auth signature count does not match action count")
            }
        }
    }
}

crate::impl_wasm_error_code!(ZcashV6Error);

/// ZIP-244 personalization for the Ironwood bundle digest.
pub const ZTXID_IRONWOOD_HASH_PERSONAL: &[u8; 16] = b"ZTxIdIronwd_H_v6";
/// ZIP-244 personalization for the Ironwood compact-actions sub-digest.
pub const ZTXID_IRONWOOD_COMPACT_PERSONAL: &[u8; 16] = b"ZTxIdIrnActCH_v6";
/// ZIP-244 personalization for the Ironwood memos sub-digest.
pub const ZTXID_IRONWOOD_MEMOS_PERSONAL: &[u8; 16] = b"ZTxIdIrnActMH_v6";
/// ZIP-244 personalization for the Ironwood non-compact actions sub-digest.
pub const ZTXID_IRONWOOD_NONCOMPACT_PERSONAL: &[u8; 16] = b"ZTxIdIrnActNH_v6";
/// ZIP-244 personalization for the (v6-personalized) Orchard slot digest.
pub const ZTXID_ORCHARD_V6_HASH_PERSONAL: &[u8; 16] = b"ZTxIdOrchardH_v6";
/// ZIP-244 personalization for the header digest.
pub const ZTXID_HEADERS_PERSONAL: &[u8; 16] = b"ZTxIdHeadersHash";
/// ZIP-244 personalization for the transparent digest.
pub const ZTXID_TRANSPARENT_PERSONAL: &[u8; 16] = b"ZTxIdTranspaHash";
/// ZIP-244 personalization for the prevouts sub-digest.
pub const ZTXID_PREVOUTS_PERSONAL: &[u8; 16] = b"ZTxIdPrevoutHash";
/// ZIP-244 personalization for the sequences sub-digest.
pub const ZTXID_SEQUENCE_PERSONAL: &[u8; 16] = b"ZTxIdSequencHash";
/// ZIP-244 personalization for the outputs sub-digest.
pub const ZTXID_OUTPUTS_PERSONAL: &[u8; 16] = b"ZTxIdOutputsHash";
/// ZIP-244 personalization for the sapling digest.
pub const ZTXID_SAPLING_PERSONAL: &[u8; 16] = b"ZTxIdSaplingHash";
/// ZIP-244 outer txid personalization prefix; the 4-byte consensus branch id
/// (little-endian) is appended to form the full 16-byte personalization. Shared by the
/// txid digest and the signature (SIGHASH) digest.
pub const ZCASH_TXID_PERSONAL_PREFIX: &[u8; 12] = b"ZcashTxHash_";
/// ZIP-244 §S.2b personalization for the transparent input-amounts sig sub-digest.
pub const ZTXID_AMOUNTS_SIG_PERSONAL: &[u8; 16] = b"ZTxTrAmountsHash";
/// ZIP-244 §S.2c personalization for the transparent scriptPubKeys sig sub-digest.
pub const ZTXID_SCRIPTS_SIG_PERSONAL: &[u8; 16] = b"ZTxTrScriptsHash";
/// ZIP-244 §S.2g personalization for the per-input (txin) sig sub-digest. Hashed over the
/// empty string for a shielded signature; over the signed input's fields for a transparent one.
pub const ZTXID_TXIN_SIG_PERSONAL: &[u8; 16] = b"Zcash___TxInHash";
/// The `SIGHASH_ALL` hash type byte. Shielded signatures always use `SIGHASH_ALL`, and the
/// BitGo transparent flows sign with `SIGHASH_ALL` as well.
const SIGHASH_ALL: u8 = 0x01;

/// Boundary between the compact note plaintext and the memo inside `encCiphertext`.
const ENC_COMPACT_END: usize = 52;
/// Boundary between the memo and the Poly1305 tag inside `encCiphertext`.
const ENC_MEMO_END: usize = 564;

/// Serialized size of a single Ironwood action on the wire.
pub const IRONWOOD_ACTION_SIZE: usize = 820;

/// Length of the encrypted note ciphertext in an Ironwood action.
pub const ENC_CIPHERTEXT_SIZE: usize = 580;

/// Length of the outgoing ciphertext in an Ironwood action.
pub const OUT_CIPHERTEXT_SIZE: usize = 80;

/// A single Ironwood action (820 bytes on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IronwoodAction {
    /// Value commitment.
    pub cv: [u8; 32],
    /// Spend nullifier; also serves as the `rho` input to the paired output note commitment.
    pub nullifier: [u8; 32],
    /// Randomized spend-auth verification key (RedPallas).
    pub rk: [u8; 32],
    /// Output note commitment x-coordinate (appended as a leaf to the Ironwood tree).
    pub cmx: [u8; 32],
    /// Ephemeral key for note encryption.
    pub ephemeral_key: [u8; 32],
    /// Encrypted note ciphertext: 52 (V3 note plaintext) + 512 (memo) + 16 (Poly1305 tag).
    pub enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    /// Outgoing ciphertext: 64 (out plaintext) + 16 (tag).
    pub out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
}

impl IronwoodAction {
    /// Parse an action from exactly [`IRONWOOD_ACTION_SIZE`] bytes.
    fn from_bytes(b: &[u8]) -> Result<Self, ZcashV6Error> {
        if b.len() != IRONWOOD_ACTION_SIZE {
            return Err(ZcashV6Error::BadActionLength);
        }
        let mut off = 0;
        let mut take32 = || {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b[off..off + 32]);
            off += 32;
            a
        };
        let cv = take32();
        let nullifier = take32();
        let rk = take32();
        let cmx = take32();
        let ephemeral_key = take32();
        let mut enc_ciphertext = [0u8; ENC_CIPHERTEXT_SIZE];
        enc_ciphertext.copy_from_slice(&b[off..off + ENC_CIPHERTEXT_SIZE]);
        off += ENC_CIPHERTEXT_SIZE;
        let mut out_ciphertext = [0u8; OUT_CIPHERTEXT_SIZE];
        out_ciphertext.copy_from_slice(&b[off..off + OUT_CIPHERTEXT_SIZE]);
        Ok(IronwoodAction {
            cv,
            nullifier,
            rk,
            cmx,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
        })
    }

    /// Serialize the action to its [`IRONWOOD_ACTION_SIZE`]-byte wire form.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(IRONWOOD_ACTION_SIZE);
        out.extend_from_slice(&self.cv);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.rk);
        out.extend_from_slice(&self.cmx);
        out.extend_from_slice(&self.ephemeral_key);
        out.extend_from_slice(&self.enc_ciphertext);
        out.extend_from_slice(&self.out_ciphertext);
        out
    }
}

/// A parsed Ironwood bundle (present only when there is at least one action).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IronwoodBundle {
    /// Action array (each 820 bytes on the wire).
    pub actions: Vec<IronwoodAction>,
    /// Flag byte: `0x07` = spends | outputs | cross-address.
    pub flags: u8,
    /// Net value crossing the Ironwood pool boundary.
    pub value_balance: i64,
    /// Ironwood note-commitment tree root (separate from Orchard's).
    pub anchor: [u8; 32],
    /// Opaque `PostNu6_3` Halo2 proof bytes (server-provided).
    pub proof: Vec<u8>,
    /// One RedPallas spend-auth signature per action.
    pub spend_auth_sigs: Vec<[u8; 64]>,
    /// RedPallas binding signature (server-provided).
    pub binding_sig: [u8; 64],
}

impl IronwoodBundle {
    /// Compute the ZIP-244 `ironwood_digest` over this bundle.
    ///
    /// Per ZIP-244 the digest is a three-way split over the per-action byte ranges,
    /// combined with the flag byte and (little-endian) value balance:
    ///
    /// ```text
    /// compactHash    = BLAKE2b("ZTxIdIrnActCH_v6", per-action: nullifier ‖ cmx ‖ epk ‖ enc[0..52])
    /// memosHash      = BLAKE2b("ZTxIdIrnActMH_v6", per-action: enc[52..564])
    /// noncompactHash = BLAKE2b("ZTxIdIrnActNH_v6", per-action: cv ‖ rk ‖ enc[564..580] ‖ outCiphertext)
    /// ironwood_digest = BLAKE2b("ZTxIdIronwd_H_v6",
    ///     compactHash ‖ memosHash ‖ noncompactHash ‖ flags ‖ valueBalance)
    /// ```
    ///
    /// The anchor, proof, and signatures are intentionally excluded — the digest
    /// covers action data only (see ZIP-244 §"Ironwood bundle digest").
    pub fn digest(&self) -> [u8; 32] {
        let mut compact = Vec::new();
        let mut memos = Vec::new();
        let mut noncompact = Vec::new();

        for a in &self.actions {
            compact.extend_from_slice(&a.nullifier);
            compact.extend_from_slice(&a.cmx);
            compact.extend_from_slice(&a.ephemeral_key);
            compact.extend_from_slice(&a.enc_ciphertext[..ENC_COMPACT_END]);

            memos.extend_from_slice(&a.enc_ciphertext[ENC_COMPACT_END..ENC_MEMO_END]);

            noncompact.extend_from_slice(&a.cv);
            noncompact.extend_from_slice(&a.rk);
            noncompact.extend_from_slice(&a.enc_ciphertext[ENC_MEMO_END..]);
            noncompact.extend_from_slice(&a.out_ciphertext);
        }

        let compact_hash = blake2b_256_personal(&compact, ZTXID_IRONWOOD_COMPACT_PERSONAL);
        let memos_hash = blake2b_256_personal(&memos, ZTXID_IRONWOOD_MEMOS_PERSONAL);
        let noncompact_hash = blake2b_256_personal(&noncompact, ZTXID_IRONWOOD_NONCOMPACT_PERSONAL);

        let mut body = Vec::with_capacity(32 * 3 + 1 + 8);
        body.extend_from_slice(&compact_hash);
        body.extend_from_slice(&memos_hash);
        body.extend_from_slice(&noncompact_hash);
        body.push(self.flags);
        body.extend_from_slice(&self.value_balance.to_le_bytes());

        blake2b_256_personal(&body, ZTXID_IRONWOOD_HASH_PERSONAL)
    }
}

/// ZIP-244 `ironwood_digest` for a v6 transaction's Ironwood slot.
///
/// An absent bundle (`nActionsIronwood = 0`) hashes to the empty personalized digest.
pub fn ironwood_digest(bundle: Option<&IronwoodBundle>) -> [u8; 32] {
    match bundle {
        Some(b) => b.digest(),
        None => blake2b_256_personal(&[], ZTXID_IRONWOOD_HASH_PERSONAL),
    }
}

/// ZIP-244 digest for the (empty) v6 Orchard slot.
///
/// BitGo Ironwood flows never populate the Orchard v6 slot, so this is always the
/// empty personalized digest.
pub fn orchard_v6_empty_digest() -> [u8; 32] {
    blake2b_256_personal(&[], ZTXID_ORCHARD_V6_HASH_PERSONAL)
}

/// ZIP-244 header digest: version, versionGroupId, consensusBranchId, lockTime, expiryHeight.
fn header_digest(tx: &ZcashV6Transaction) -> [u8; 32] {
    let mut data = Vec::with_capacity(20);
    data.extend_from_slice(&ZCASH_V6_VERSION_HEADER.to_le_bytes());
    data.extend_from_slice(&tx.version_group_id.to_le_bytes());
    data.extend_from_slice(&tx.consensus_branch_id.to_le_bytes());
    data.extend_from_slice(&tx.transparent.lock_time.to_consensus_u32().to_le_bytes());
    data.extend_from_slice(&tx.expiry_height.to_le_bytes());
    blake2b_256_personal(&data, ZTXID_HEADERS_PERSONAL)
}

/// ZIP-244 transparent (txid) digest.
///
/// When the transaction has neither transparent inputs nor outputs, this is the
/// empty personalized hash. Otherwise it combines the prevouts, sequences, and
/// outputs sub-digests (each computed over an empty input list when the
/// corresponding component is absent, e.g. the unshield case).
fn transparent_txid_digest(tx: &ZcashV6Transaction) -> [u8; 32] {
    use miniscript::bitcoin::consensus::Encodable;

    let inputs = &tx.transparent.input;
    let outputs = &tx.transparent.output;

    if inputs.is_empty() && outputs.is_empty() {
        return blake2b_256_personal(&[], ZTXID_TRANSPARENT_PERSONAL);
    }

    let mut prevouts = Vec::new();
    let mut sequences = Vec::new();
    for txin in inputs {
        txin.previous_output
            .consensus_encode(&mut prevouts)
            .expect("vec write is infallible");
        txin.sequence
            .consensus_encode(&mut sequences)
            .expect("vec write is infallible");
    }
    let mut outputs_data = Vec::new();
    for txout in outputs {
        txout
            .consensus_encode(&mut outputs_data)
            .expect("vec write is infallible");
    }

    let prevouts_hash = blake2b_256_personal(&prevouts, ZTXID_PREVOUTS_PERSONAL);
    let sequence_hash = blake2b_256_personal(&sequences, ZTXID_SEQUENCE_PERSONAL);
    let outputs_hash = blake2b_256_personal(&outputs_data, ZTXID_OUTPUTS_PERSONAL);

    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(&prevouts_hash);
    data.extend_from_slice(&sequence_hash);
    data.extend_from_slice(&outputs_hash);
    blake2b_256_personal(&data, ZTXID_TRANSPARENT_PERSONAL)
}

/// Compute the ZIP-244 v6 txid: the five-component BLAKE2b hash tree.
///
/// ```text
/// txid = BLAKE2b-256("ZcashTxHash_" ‖ consensusBranchId(LE),
///          header_digest ‖ transparent_digest ‖ sapling_digest
///          ‖ orchard_v6_digest ‖ ironwood_digest)
/// ```
///
/// The result is in internal byte order (as with the v4 sha256d txid); reverse it
/// for display.
pub fn compute_v6_txid(tx: &ZcashV6Transaction) -> [u8; 32] {
    let header = header_digest(tx);
    let transparent = transparent_txid_digest(tx);
    // Sapling bundle is empty for all BitGo flows.
    let sapling = blake2b_256_personal(&[], ZTXID_SAPLING_PERSONAL);
    let orchard = orchard_v6_empty_digest();
    let ironwood = ironwood_digest(tx.ironwood_bundle.as_ref());

    let mut data = Vec::with_capacity(32 * 5);
    data.extend_from_slice(&header);
    data.extend_from_slice(&transparent);
    data.extend_from_slice(&sapling);
    data.extend_from_slice(&orchard);
    data.extend_from_slice(&ironwood);

    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(ZCASH_TXID_PERSONAL_PREFIX);
    personal[12..].copy_from_slice(&tx.consensus_branch_id.to_le_bytes());

    blake2b_256_personal(&data, &personal)
}

/// Decode raw v6 transaction bytes and compute their ZIP-244 txid.
pub fn compute_v6_txid_from_bytes(bytes: &[u8]) -> Result<[u8; 32], ZcashV6Error> {
    let tx = decode_v6_transaction(bytes)?;
    Ok(compute_v6_txid(&tx))
}

/// ZIP-244 §S.2 `transparent_sig_digest`, parameterized by the per-input (`txin`) sub-digest.
///
/// The shielded and per-input transparent signature digests differ *only* in the `txin`
/// component: empty for a shielded signature, populated for the transparent input being signed.
/// Every other sub-digest (prevouts / amounts / scriptPubKeys / sequences / outputs) is identical
/// under `SIGHASH_ALL`, so both callers share this builder. `input_amounts` and
/// `input_script_pubkeys` are the spent outputs' values and scriptPubKeys, one per transparent
/// input in input order.
fn transparent_sig_digest_with_txin(
    tx: &ZcashV6Transaction,
    input_amounts: &[i64],
    input_script_pubkeys: &[miniscript::bitcoin::ScriptBuf],
    txin_sig_hash: [u8; 32],
) -> [u8; 32] {
    let inputs = &tx.transparent.input;
    // Per ZIP-244, the sig transparent digest collapses to the txid one only when there are
    // neither transparent inputs nor outputs (e.g. a fully-shielded tx). With outputs but no
    // inputs (unshield: shielded spend -> transparent output), the full S.2 structure still
    // applies, since hash_type/amounts/scripts/txin differ from the txid digest whenever
    // outputs is non-empty.
    if inputs.is_empty() && tx.transparent.output.is_empty() {
        return transparent_txid_digest(tx);
    }

    debug_assert_eq!(
        input_amounts.len(),
        inputs.len(),
        "input_amounts must have one entry per transparent input"
    );
    debug_assert_eq!(
        input_script_pubkeys.len(),
        inputs.len(),
        "input_script_pubkeys must have one entry per transparent input"
    );

    // S.2a prevouts / S.2d sequences / S.2e outputs: identical to the txid sub-digests under
    // SIGHASH_ALL (plain concatenation, no CompactSize count).
    let mut prevouts = Vec::new();
    let mut sequences = Vec::new();
    for txin in inputs {
        txin.previous_output
            .consensus_encode(&mut prevouts)
            .expect("vec write is infallible");
        txin.sequence
            .consensus_encode(&mut sequences)
            .expect("vec write is infallible");
    }
    let mut outputs_data = Vec::new();
    for txout in &tx.transparent.output {
        txout
            .consensus_encode(&mut outputs_data)
            .expect("vec write is infallible");
    }
    let prevouts_hash = blake2b_256_personal(&prevouts, ZTXID_PREVOUTS_PERSONAL);
    let sequence_hash = blake2b_256_personal(&sequences, ZTXID_SEQUENCE_PERSONAL);
    let outputs_hash = blake2b_256_personal(&outputs_data, ZTXID_OUTPUTS_PERSONAL);

    // S.2b amounts / S.2c scriptPubKeys: `zcash_encoding::Array` encoding — each element written
    // back-to-back with NO outer count. Amounts are 8-byte signed LE; scriptPubKeys use their
    // standard (individually length-prefixed) consensus encoding.
    let mut amounts_data = Vec::with_capacity(input_amounts.len() * 8);
    for amount in input_amounts {
        amounts_data.extend_from_slice(&amount.to_le_bytes());
    }
    let mut scripts_data = Vec::new();
    for script in input_script_pubkeys {
        script
            .consensus_encode(&mut scripts_data)
            .expect("vec write is infallible");
    }
    let amounts_hash = blake2b_256_personal(&amounts_data, ZTXID_AMOUNTS_SIG_PERSONAL);
    let scripts_hash = blake2b_256_personal(&scripts_data, ZTXID_SCRIPTS_SIG_PERSONAL);

    let mut data = Vec::with_capacity(1 + 32 * 6);
    data.push(SIGHASH_ALL);
    data.extend_from_slice(&prevouts_hash);
    data.extend_from_slice(&amounts_hash);
    data.extend_from_slice(&scripts_hash);
    data.extend_from_slice(&sequence_hash);
    data.extend_from_slice(&outputs_hash);
    data.extend_from_slice(&txin_sig_hash);
    blake2b_256_personal(&data, ZTXID_TRANSPARENT_PERSONAL)
}

/// Combine the five ZIP-244 component digests into the outer signature (SIGHASH) digest, using
/// the same `ZcashTxHash_`+branch-id personalization as the txid.
fn v6_sig_digest_from_transparent(tx: &ZcashV6Transaction, transparent: [u8; 32]) -> [u8; 32] {
    let header = header_digest(tx);
    let sapling = blake2b_256_personal(&[], ZTXID_SAPLING_PERSONAL);
    let orchard = orchard_v6_empty_digest();
    let ironwood = ironwood_digest(tx.ironwood_bundle.as_ref());

    let mut data = Vec::with_capacity(32 * 5);
    data.extend_from_slice(&header);
    data.extend_from_slice(&transparent);
    data.extend_from_slice(&sapling);
    data.extend_from_slice(&orchard);
    data.extend_from_slice(&ironwood);

    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(ZCASH_TXID_PERSONAL_PREFIX);
    personal[12..].copy_from_slice(&tx.consensus_branch_id.to_le_bytes());
    blake2b_256_personal(&data, &personal)
}

/// ZIP-244 v6 **shielded** signature hash (SIGHASH_ALL) — the message the Ironwood binding
/// signature (and any shielded spend-auth signature) signs.
///
/// `input_amounts` / `input_script_pubkeys` describe the spent outputs, one per transparent input
/// in input order. Result is a 32-byte digest in internal order (not a txid; not reversed).
pub fn compute_v6_sig_digest(
    tx: &ZcashV6Transaction,
    input_amounts: &[i64],
    input_script_pubkeys: &[miniscript::bitcoin::ScriptBuf],
) -> [u8; 32] {
    // Shielded signature: the per-input (txin) sub-digest is the empty personalized hash.
    let txin_sig_hash = blake2b_256_personal(&[], ZTXID_TXIN_SIG_PERSONAL);
    let transparent =
        transparent_sig_digest_with_txin(tx, input_amounts, input_script_pubkeys, txin_sig_hash);
    v6_sig_digest_from_transparent(tx, transparent)
}

/// ZIP-244 v6 **transparent** per-input signature hash (SIGHASH_ALL) — the message the key
/// controlling transparent input `input_index` signs.
///
/// Per ZIP-244 §S.2g.iii (as implemented by `zcash_primitives::transaction::sighash_v5::
/// transparent_sig_digest`, shared by v6), the per-input field committed here is the spent
/// output's **scriptPubKey** — not the redeem/witness script ("scriptCode") used to actually
/// execute the input's scriptSig. Those two coincide for P2PKH (which is all the "golden"
/// production fixture exercises), but differ for P2SH/P2WSH, where using the redeem/witness
/// script here instead produces a sighash real consensus rules reject. `input_amounts` /
/// `input_script_pubkeys` are the spent outputs' values and scriptPubKeys for every input, in
/// input order; `input_script_pubkeys[input_index]` is also the value used for this input's own
/// per-input field.
pub fn compute_v6_transparent_sighash(
    tx: &ZcashV6Transaction,
    input_index: usize,
    input_amounts: &[i64],
    input_script_pubkeys: &[miniscript::bitcoin::ScriptBuf],
) -> Result<[u8; 32], ZcashV6Error> {
    let txin = tx
        .transparent
        .input
        .get(input_index)
        .ok_or(ZcashV6Error::UnexpectedEof)?;
    let amount = *input_amounts
        .get(input_index)
        .ok_or(ZcashV6Error::UnexpectedEof)?;
    let script_pubkey = input_script_pubkeys
        .get(input_index)
        .ok_or(ZcashV6Error::UnexpectedEof)?;

    // S.2g: prevout ‖ value(8, signed LE) ‖ scriptPubKey(length-prefixed) ‖ nSequence(4, LE).
    let mut txin_data = Vec::new();
    txin.previous_output
        .consensus_encode(&mut txin_data)
        .expect("vec write is infallible");
    txin_data.extend_from_slice(&amount.to_le_bytes());
    script_pubkey
        .consensus_encode(&mut txin_data)
        .expect("vec write is infallible");
    txin.sequence
        .consensus_encode(&mut txin_data)
        .expect("vec write is infallible");
    let txin_sig_hash = blake2b_256_personal(&txin_data, ZTXID_TXIN_SIG_PERSONAL);

    let transparent =
        transparent_sig_digest_with_txin(tx, input_amounts, input_script_pubkeys, txin_sig_hash);
    Ok(v6_sig_digest_from_transparent(tx, transparent))
}

/// A fully parsed Zcash v6 (Ironwood) transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZcashV6Transaction {
    /// Version group id (always [`ZCASH_IRONWOOD_VERSION_GROUP_ID`]).
    pub version_group_id: u32,
    /// Consensus branch id carried in the header (v5/v6 only).
    pub consensus_branch_id: u32,
    /// Transparent portion: inputs, outputs, and lock_time (version reads as 6).
    pub transparent: Transaction,
    /// Expiry height.
    pub expiry_height: u32,
    /// Sapling net value balance (0 for our flows; non-zero bundles are unsupported).
    pub sapling_value_balance: i64,
    /// Ironwood bundle, if any actions are present.
    pub ironwood_bundle: Option<IronwoodBundle>,
}

impl ZcashV6Transaction {
    /// Decode a v6 (Ironwood) transaction from raw wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZcashV6Error> {
        decode_v6_transaction(bytes)
    }

    /// Encode this transaction to raw v6 wire bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZcashV6Error> {
        encode_v6_transaction(self)
    }

    /// ZIP-244 txid in internal byte order.
    ///
    /// Wrap in [`miniscript::bitcoin::Txid`] for the canonical display-order string.
    pub fn txid(&self) -> [u8; 32] {
        compute_v6_txid(self)
    }
}

fn read_u32_le(r: &mut &[u8]) -> Result<u32, ZcashV6Error> {
    u32::consensus_decode(r).map_err(|e| ZcashV6Error::Decode(e.to_string()))
}

fn read_i64_le(r: &mut &[u8]) -> Result<i64, ZcashV6Error> {
    i64::consensus_decode(r).map_err(|e| ZcashV6Error::Decode(e.to_string()))
}

fn read_varint(r: &mut &[u8]) -> Result<u64, ZcashV6Error> {
    VarInt::consensus_decode(r)
        .map(|v| v.0)
        .map_err(|e| ZcashV6Error::Decode(e.to_string()))
}

fn take_bytes<'a>(r: &mut &'a [u8], n: usize) -> Result<&'a [u8], ZcashV6Error> {
    if r.len() < n {
        return Err(ZcashV6Error::UnexpectedEof);
    }
    let (head, tail) = r.split_at(n);
    *r = tail;
    Ok(head)
}

fn take_array<const N: usize>(r: &mut &[u8]) -> Result<[u8; N], ZcashV6Error> {
    let bytes = take_bytes(r, N)?;
    let mut a = [0u8; N];
    a.copy_from_slice(bytes);
    Ok(a)
}

/// Decode a v6 (Ironwood) transaction from its raw wire bytes.
pub fn decode_v6_transaction(bytes: &[u8]) -> Result<ZcashV6Transaction, ZcashV6Error> {
    let mut r = bytes;

    // --- Header ---
    let version = read_u32_le(&mut r)?;
    if version != ZCASH_V6_VERSION_HEADER {
        return Err(ZcashV6Error::UnexpectedVersion(version));
    }
    let version_group_id = read_u32_le(&mut r)?;
    if version_group_id != ZCASH_IRONWOOD_VERSION_GROUP_ID {
        return Err(ZcashV6Error::UnexpectedVersionGroupId(version_group_id));
    }
    let consensus_branch_id = read_u32_le(&mut r)?;
    let lock_time = read_u32_le(&mut r)?;
    let expiry_height = read_u32_le(&mut r)?;

    // --- Transparent ---
    let inputs: Vec<TxIn> =
        Vec::consensus_decode(&mut r).map_err(|e| ZcashV6Error::Decode(e.to_string()))?;
    let outputs: Vec<TxOut> =
        Vec::consensus_decode(&mut r).map_err(|e| ZcashV6Error::Decode(e.to_string()))?;

    let transparent = Transaction {
        version: miniscript::bitcoin::transaction::Version::non_standard(6),
        input: inputs,
        output: outputs,
        lock_time: miniscript::bitcoin::locktime::absolute::LockTime::from_consensus(lock_time),
    };

    // --- Sapling (empty-only support) ---
    let n_spends_sapling = read_varint(&mut r)?;
    let n_outputs_sapling = read_varint(&mut r)?;
    if n_spends_sapling != 0 || n_outputs_sapling != 0 {
        return Err(ZcashV6Error::UnsupportedSaplingBundle);
    }
    // valueBalanceSapling / anchor / proofs are only present when counts > 0, so nothing to read.
    let sapling_value_balance = 0i64;

    // --- Orchard v6 slot (empty-only support) ---
    let n_actions_orchard = read_varint(&mut r)?;
    if n_actions_orchard != 0 {
        return Err(ZcashV6Error::UnsupportedOrchardBundle);
    }

    // --- Ironwood bundle ---
    let n_actions_ironwood = read_varint(&mut r)?;
    let ironwood_bundle = if n_actions_ironwood == 0 {
        None
    } else {
        let n = usize::try_from(n_actions_ironwood).map_err(|_| ZcashV6Error::CountOverflow)?;
        // `n_actions_ironwood` is an untrusted CompactSize (up to 2^64-1) and
        // `VarInt` decoding does not cap it. Validate that the remaining input can
        // actually hold `n` actions *before* reserving, so a malformed count cannot
        // trigger a huge pre-allocation (OOM / WASM abort). This is a lower bound —
        // the flags/valueBalance/anchor/proof/sigs that follow need more bytes still,
        // but it is enough to bound the allocation to the real input size.
        let actions_bytes = n
            .checked_mul(IRONWOOD_ACTION_SIZE)
            .ok_or(ZcashV6Error::CountOverflow)?;
        if actions_bytes > r.len() {
            return Err(ZcashV6Error::TruncatedActions);
        }
        let mut actions = Vec::with_capacity(n);
        for _ in 0..n {
            let a = take_bytes(&mut r, IRONWOOD_ACTION_SIZE)?;
            actions.push(IronwoodAction::from_bytes(a)?);
        }
        let flags = *take_bytes(&mut r, 1)?.first().unwrap();
        let value_balance = read_i64_le(&mut r)?;
        let anchor = take_array::<32>(&mut r)?;
        let proof_size = read_varint(&mut r)?;
        let proof_size = usize::try_from(proof_size).map_err(|_| ZcashV6Error::CountOverflow)?;
        let proof = take_bytes(&mut r, proof_size)?.to_vec();
        let mut spend_auth_sigs = Vec::with_capacity(n);
        for _ in 0..n {
            spend_auth_sigs.push(take_array::<64>(&mut r)?);
        }
        let binding_sig = take_array::<64>(&mut r)?;
        Some(IronwoodBundle {
            actions,
            flags,
            value_balance,
            anchor,
            proof,
            spend_auth_sigs,
            binding_sig,
        })
    };

    if !r.is_empty() {
        return Err(ZcashV6Error::TrailingBytes);
    }

    Ok(ZcashV6Transaction {
        version_group_id,
        consensus_branch_id,
        transparent,
        expiry_height,
        sapling_value_balance,
        ironwood_bundle,
    })
}

/// Encode a v6 (Ironwood) transaction back to its raw wire bytes.
pub fn encode_v6_transaction(tx: &ZcashV6Transaction) -> Result<Vec<u8>, ZcashV6Error> {
    if tx.sapling_value_balance != 0 {
        return Err(ZcashV6Error::NonZeroSaplingValueBalance);
    }
    // Encoding into a `Vec` is infallible in practice; map any io error uniformly.
    let enc = |e: miniscript::bitcoin::io::Error| ZcashV6Error::Encode(e.to_string());
    let mut out = Vec::new();

    // --- Header ---
    ZCASH_V6_VERSION_HEADER
        .consensus_encode(&mut out)
        .map_err(enc)?;
    tx.version_group_id
        .consensus_encode(&mut out)
        .map_err(enc)?;
    tx.consensus_branch_id
        .consensus_encode(&mut out)
        .map_err(enc)?;
    tx.transparent
        .lock_time
        .consensus_encode(&mut out)
        .map_err(enc)?;
    tx.expiry_height.consensus_encode(&mut out).map_err(enc)?;

    // --- Transparent ---
    tx.transparent
        .input
        .consensus_encode(&mut out)
        .map_err(enc)?;
    tx.transparent
        .output
        .consensus_encode(&mut out)
        .map_err(enc)?;

    // --- Sapling (empty) ---
    VarInt(0).consensus_encode(&mut out).map_err(enc)?;
    VarInt(0).consensus_encode(&mut out).map_err(enc)?;

    // --- Orchard v6 slot (empty) ---
    VarInt(0).consensus_encode(&mut out).map_err(enc)?;

    // --- Ironwood bundle ---
    match &tx.ironwood_bundle {
        None => {
            VarInt(0).consensus_encode(&mut out).map_err(enc)?;
        }
        Some(bundle) => {
            let n = bundle.actions.len();
            if bundle.spend_auth_sigs.len() != n {
                return Err(ZcashV6Error::SpendAuthSigCountMismatch);
            }
            VarInt(n as u64).consensus_encode(&mut out).map_err(enc)?;
            for a in &bundle.actions {
                out.extend_from_slice(&a.to_bytes());
            }
            out.push(bundle.flags);
            bundle
                .value_balance
                .consensus_encode(&mut out)
                .map_err(enc)?;
            out.extend_from_slice(&bundle.anchor);
            VarInt(bundle.proof.len() as u64)
                .consensus_encode(&mut out)
                .map_err(enc)?;
            out.extend_from_slice(&bundle.proof);
            for sig in &bundle.spend_auth_sigs {
                out.extend_from_slice(sig);
            }
            out.extend_from_slice(&bundle.binding_sig);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniscript::bitcoin::hashes::Hash;
    use miniscript::bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Txid, Witness};

    fn sample_action(seed: u8) -> IronwoodAction {
        IronwoodAction {
            cv: [seed; 32],
            nullifier: [seed.wrapping_add(1); 32],
            rk: [seed.wrapping_add(2); 32],
            cmx: [seed.wrapping_add(3); 32],
            ephemeral_key: [seed.wrapping_add(4); 32],
            enc_ciphertext: [seed.wrapping_add(5); ENC_CIPHERTEXT_SIZE],
            out_ciphertext: [seed.wrapping_add(6); OUT_CIPHERTEXT_SIZE],
        }
    }

    fn sample_transparent(with_io: bool) -> Transaction {
        let (input, output) = if with_io {
            (
                vec![TxIn {
                    previous_output: OutPoint::new(Txid::all_zeros(), 0),
                    script_sig: ScriptBuf::from(vec![0x51u8, 0x52]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                vec![TxOut {
                    value: Amount::from_sat(12_345),
                    script_pubkey: ScriptBuf::from(vec![0x76u8, 0xa9, 0x14]),
                }],
            )
        } else {
            (vec![], vec![])
        };
        Transaction {
            version: miniscript::bitcoin::transaction::Version::non_standard(6),
            input,
            output,
            lock_time: miniscript::bitcoin::locktime::absolute::LockTime::from_consensus(0),
        }
    }

    fn action_round_trip(a: &IronwoodAction) {
        let bytes = a.to_bytes();
        assert_eq!(bytes.len(), IRONWOOD_ACTION_SIZE);
        assert_eq!(&IronwoodAction::from_bytes(&bytes).unwrap(), a);
    }

    #[test]
    fn action_bytes_round_trip() {
        action_round_trip(&sample_action(1));
        action_round_trip(&sample_action(200));
    }

    #[test]
    fn round_trip_ironwood_only() {
        let tx = ZcashV6Transaction {
            version_group_id: ZCASH_IRONWOOD_VERSION_GROUP_ID,
            consensus_branch_id: 0x37a5165b,
            transparent: sample_transparent(false),
            expiry_height: 0,
            sapling_value_balance: 0,
            ironwood_bundle: Some(IronwoodBundle {
                actions: vec![sample_action(1), sample_action(50)],
                flags: 0x07,
                value_balance: -1000,
                anchor: [9u8; 32],
                proof: vec![0xabu8; 300],
                spend_auth_sigs: vec![[1u8; 64], [2u8; 64]],
                binding_sig: [7u8; 64],
            }),
        };
        let bytes = encode_v6_transaction(&tx).unwrap();
        let decoded = decode_v6_transaction(&bytes).unwrap();
        assert_eq!(decoded, tx);
        // Re-encode is byte-stable.
        assert_eq!(encode_v6_transaction(&decoded).unwrap(), bytes);
    }

    #[test]
    fn round_trip_shield_with_transparent_inputs() {
        let tx = ZcashV6Transaction {
            version_group_id: ZCASH_IRONWOOD_VERSION_GROUP_ID,
            consensus_branch_id: 0x37a5165b,
            transparent: sample_transparent(true),
            expiry_height: 12_000,
            sapling_value_balance: 0,
            ironwood_bundle: Some(IronwoodBundle {
                actions: vec![sample_action(3)],
                flags: 0x07,
                value_balance: -5000,
                anchor: [4u8; 32],
                proof: vec![0xcdu8; 192],
                spend_auth_sigs: vec![[8u8; 64]],
                binding_sig: [6u8; 64],
            }),
        };
        let bytes = encode_v6_transaction(&tx).unwrap();
        assert_eq!(decode_v6_transaction(&bytes).unwrap(), tx);
    }

    #[test]
    fn round_trip_empty_ironwood_slot() {
        let tx = ZcashV6Transaction {
            version_group_id: ZCASH_IRONWOOD_VERSION_GROUP_ID,
            consensus_branch_id: 0x37a5165b,
            transparent: sample_transparent(true),
            expiry_height: 0,
            sapling_value_balance: 0,
            ironwood_bundle: None,
        };
        let bytes = encode_v6_transaction(&tx).unwrap();
        assert_eq!(decode_v6_transaction(&bytes).unwrap(), tx);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let tx = ZcashV6Transaction {
            version_group_id: ZCASH_IRONWOOD_VERSION_GROUP_ID,
            consensus_branch_id: 0x37a5165b,
            transparent: sample_transparent(false),
            expiry_height: 0,
            sapling_value_balance: 0,
            ironwood_bundle: None,
        };
        let mut bytes = encode_v6_transaction(&tx).unwrap();
        bytes.push(0xff);
        assert!(decode_v6_transaction(&bytes).is_err());
    }

    #[test]
    fn rejects_absurd_action_count_without_allocating() {
        // Regression for the untrusted pre-allocation: build a minimal valid v6
        // header/transparent/sapling/orchard prefix, then declare a huge
        // nActionsIronwood via a 9-byte CompactSize (0xff + u64::MAX). Decoding must
        // fail fast on the "remaining bytes" check, not attempt a 2^64-element
        // Vec::with_capacity (which would OOM / abort).
        let base = ZcashV6Transaction {
            version_group_id: ZCASH_IRONWOOD_VERSION_GROUP_ID,
            consensus_branch_id: 0x37a5165b,
            transparent: sample_transparent(false),
            expiry_height: 0,
            sapling_value_balance: 0,
            ironwood_bundle: None,
        };
        // Encoded `None` bundle ends with a single 0x00 (nActionsIronwood = 0).
        let mut bytes = encode_v6_transaction(&base).unwrap();
        assert_eq!(*bytes.last().unwrap(), 0x00);
        bytes.pop(); // drop the 0-count varint
        bytes.push(0xff); // CompactSize 9-byte prefix
        bytes.extend_from_slice(&u64::MAX.to_le_bytes()); // nActionsIronwood = 2^64-1

        let err = decode_v6_transaction(&bytes).unwrap_err();
        assert!(
            matches!(
                err,
                ZcashV6Error::CountOverflow | ZcashV6Error::TruncatedActions
            ),
            "unexpected error: {err}"
        );
    }

    fn sample_bundle() -> IronwoodBundle {
        IronwoodBundle {
            actions: vec![sample_action(1), sample_action(50)],
            flags: 0x07,
            value_balance: -1000,
            anchor: [9u8; 32],
            proof: vec![0xabu8; 300],
            spend_auth_sigs: vec![[1u8; 64], [2u8; 64]],
            binding_sig: [7u8; 64],
        }
    }

    fn sample_tx_with_inputs() -> ZcashV6Transaction {
        ZcashV6Transaction {
            version_group_id: ZCASH_IRONWOOD_VERSION_GROUP_ID,
            consensus_branch_id: 0x37a5165b,
            transparent: sample_transparent(true),
            expiry_height: 0,
            sapling_value_balance: 0,
            ironwood_bundle: Some(sample_bundle()),
        }
    }

    // ---- v6 signature-digest regression tests ----
    // (The full independent oracle — zebra recomputing these digests and verifying the binding
    // signature over them — runs in the ironwood_build build→prove→combine test, where a real
    // bundle with known input amounts/scripts exists.)

    #[test]
    fn sig_digest_is_deterministic() {
        let tx = sample_tx_with_inputs();
        let amounts = [12_345i64];
        let scripts = [ScriptBuf::from(vec![0x76u8, 0xa9, 0x14])];
        assert_eq!(
            compute_v6_sig_digest(&tx, &amounts, &scripts),
            compute_v6_sig_digest(&tx, &amounts, &scripts)
        );
    }

    #[test]
    fn shielded_sig_digest_commits_to_amounts_and_scripts() {
        let tx = sample_tx_with_inputs();
        let base = compute_v6_sig_digest(&tx, &[12_345], &[ScriptBuf::from(vec![0x76u8, 0xa9])]);
        // Differs from the txid (which does not commit to input amounts/scripts).
        assert_ne!(base, compute_v6_txid(&tx));
        assert_ne!(
            base,
            compute_v6_sig_digest(&tx, &[99_999], &[ScriptBuf::from(vec![0x76u8, 0xa9])])
        );
        assert_ne!(
            base,
            compute_v6_sig_digest(&tx, &[12_345], &[ScriptBuf::from(vec![0x51u8])])
        );
    }

    #[test]
    fn shielded_sig_digest_without_inputs_equals_txid() {
        let tx = ZcashV6Transaction {
            version_group_id: ZCASH_IRONWOOD_VERSION_GROUP_ID,
            consensus_branch_id: 0x37a5165b,
            transparent: sample_transparent(false),
            expiry_height: 0,
            sapling_value_balance: 0,
            ironwood_bundle: Some(sample_bundle()),
        };
        assert_eq!(compute_v6_sig_digest(&tx, &[], &[]), compute_v6_txid(&tx));
    }

    #[test]
    fn shielded_sig_digest_unshield_case_differs_from_txid() {
        // Unshield: transparent output present, no transparent inputs. The sig transparent
        // digest must NOT collapse to the txid digest here, since the txid digest omits
        // hash_type/amounts/scripts/txin while the sig digest includes them.
        let (_, output) = {
            let sample = sample_transparent(true);
            (sample.input, sample.output)
        };
        let transparent = Transaction {
            version: miniscript::bitcoin::transaction::Version::non_standard(6),
            input: vec![],
            output,
            lock_time: miniscript::bitcoin::locktime::absolute::LockTime::from_consensus(0),
        };
        let tx = ZcashV6Transaction {
            version_group_id: ZCASH_IRONWOOD_VERSION_GROUP_ID,
            consensus_branch_id: 0x37a5165b,
            transparent,
            expiry_height: 0,
            sapling_value_balance: 0,
            ironwood_bundle: Some(sample_bundle()),
        };
        assert_ne!(compute_v6_sig_digest(&tx, &[], &[]), compute_v6_txid(&tx));
    }

    #[test]
    fn transparent_sighash_differs_from_shielded_and_varies_by_input() {
        let tx = sample_tx_with_inputs();
        let amounts = [12_345i64];
        let scripts = [ScriptBuf::from(vec![0x76u8, 0xa9, 0x14])];

        let shielded = compute_v6_sig_digest(&tx, &amounts, &scripts);
        let transparent = compute_v6_transparent_sighash(&tx, 0, &amounts, &scripts).unwrap();
        // The per-input transparent sighash populates the txin component, so it must differ from
        // the shielded (empty-txin) digest over the same tx.
        assert_ne!(shielded, transparent);
        // Deterministic.
        assert_eq!(
            transparent,
            compute_v6_transparent_sighash(&tx, 0, &amounts, &scripts).unwrap()
        );
        // A different spent scriptPubKey changes the digest.
        let other_scripts = [ScriptBuf::from(vec![0x51u8])];
        assert_ne!(
            transparent,
            compute_v6_transparent_sighash(&tx, 0, &amounts, &other_scripts).unwrap()
        );
        // Out-of-range input index is an error, not a panic.
        assert!(compute_v6_transparent_sighash(&tx, 9, &amounts, &scripts).is_err());
    }

    /// Golden oracle for [`compute_v6_transparent_sighash`]: verify the **real** ECDSA signature
    /// carried in a signed transparent→Ironwood testnet tx against the sighash we compute.
    ///
    /// The tx is the `v6_shield1zec` fixture (one P2PKH transparent input → 1 ZEC Ironwood note).
    /// The spent output's value and scriptPubKey are not on the wire but are committed by ZIP-244;
    /// they come from the sandbox reference that produced this tx (prevout
    /// `058886a9…:0`, 313_990_000 zat, standard P2PKH). If the transaction's own signature verifies
    /// against our digest, the digest is byte-correct — an independent check, since the signature
    /// was produced by an external signer, not by this code.
    #[test]
    fn golden_transparent_sighash_verifies_real_signature() {
        use miniscript::bitcoin::script::Instruction;
        use miniscript::bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};

        let raw = hex::decode(load_zcash_fixture("v6_shield1zec_rawtx.hex").trim()).unwrap();
        let tx = decode_v6_transaction(&raw).unwrap();
        assert_eq!(tx.transparent.input.len(), 1);
        assert_eq!(tx.transparent.output.len(), 1);

        // Spent output (from the reference that built this tx); ZIP-244 commits to both.
        let prevout_value: i64 = 313_990_000;
        let prevout_script = ScriptBuf::from(
            hex::decode("76a9147c6b843a25873c036aff575516e3802bcc47f63488ac").unwrap(),
        );

        // P2PKH scriptSig = <DER sig ‖ SIGHASH_ALL> <pubkey>. The scriptCode signed for a P2PKH
        // input is its scriptPubKey.
        let pushes: Vec<Vec<u8>> = tx.transparent.input[0]
            .script_sig
            .instructions()
            .map(|i| i.expect("valid scriptSig"))
            .filter_map(|i| match i {
                Instruction::PushBytes(pb) => Some(pb.as_bytes().to_vec()),
                Instruction::Op(_) => None,
            })
            .collect();
        assert_eq!(pushes.len(), 2, "P2PKH scriptSig has sig + pubkey");
        let sig_bytes = &pushes[0];
        let pubkey_bytes = &pushes[1];
        assert_eq!(
            *sig_bytes.last().unwrap(),
            SIGHASH_ALL,
            "signature uses SIGHASH_ALL"
        );
        let der = &sig_bytes[..sig_bytes.len() - 1];

        let sighash = compute_v6_transparent_sighash(
            &tx,
            0,
            &[prevout_value],
            std::slice::from_ref(&prevout_script),
        )
        .unwrap();

        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest(sighash);
        let mut sig = Signature::from_der(der).expect("DER signature");
        sig.normalize_s();
        let pk = PublicKey::from_slice(pubkey_bytes).expect("valid pubkey");
        secp.verify_ecdsa(&msg, &sig, &pk)
            .expect("the tx's real signature verifies against compute_v6_transparent_sighash");
    }

    /// Regression test for the bug where `compute_v6_transparent_sighash` hashed the redeem
    /// script (scriptCode) into the ZIP-244 §S.2g.iii per-input field instead of the spent
    /// output's scriptPubKey. That distinction is invisible for a P2PKH input (its scriptCode
    /// *is* its scriptPubKey — see [`golden_transparent_sighash_verifies_real_signature`]
    /// above), but for a P2SH input they differ, and hashing the wrong one produces a sighash
    /// real consensus rules reject.
    ///
    /// The fixture is a real transaction — spending a 2-of-3 P2SH multisig transparent input —
    /// that was built with this codebase's CLI, submitted to a live Zcash testnet (NU6.3)
    /// `zebrad` node via `sendrawtransaction`, and **accepted into its mempool**: real
    /// consensus-rule validation of the transparent scriptSig, not merely self-consistency
    /// against this codebase's own sighash.
    #[test]
    fn golden_multisig_transparent_sighash_verifies_real_signature() {
        use miniscript::bitcoin::script::Instruction;
        use miniscript::bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};

        let raw = hex::decode(load_zcash_fixture("v6_shield_multisig_rawtx.hex").trim()).unwrap();
        let tx = decode_v6_transaction(&raw).unwrap();
        assert_eq!(tx.transparent.input.len(), 1);
        assert_eq!(tx.transparent.output.len(), 0);

        // Spent output (a synthetic 2-of-3 P2SH multisig address funded on Zcash testnet, then
        // spent by this tx); ZIP-244 commits to both.
        let prevout_value: i64 = 2_000_000;
        let prevout_script =
            ScriptBuf::from(hex::decode("a914ed68766fe37d9e2325758ed209ac78db505425a987").unwrap());
        let redeem_script = ScriptBuf::from(
            hex::decode(
                "5221023b4221b042fa25af6609d7e65d322fcb64c497b79ffc8f1891ea6b23d4e7d84a\
                 2102feaf8248a2f8dcc34f2e2f520201801bb88d20ab549baf47b48bc9f2f4dfcc93\
                 21030b82f01fd53e7dabe2d904938d64294e3352e9e836240af6ba2cfb9df8f837da53ae",
            )
            .unwrap(),
        );
        let pubkeys: Vec<Vec<u8>> = redeem_script
            .instructions()
            .map(|i| i.expect("valid redeem script"))
            .filter_map(|i| match i {
                Instruction::PushBytes(pb) => Some(pb.as_bytes().to_vec()),
                Instruction::Op(_) => None,
            })
            .collect();
        assert_eq!(pubkeys.len(), 3, "2-of-3 redeem script has 3 pubkeys");

        // scriptSig = OP_0 <sig1> <sig2> <redeemScript>; the two signatures correspond to
        // pubkeys[0] and pubkeys[2] (the redeem script's first and third keys).
        let pushes: Vec<Vec<u8>> = tx.transparent.input[0]
            .script_sig
            .instructions()
            .map(|i| i.expect("valid scriptSig"))
            .filter_map(|i| match i {
                Instruction::PushBytes(pb) if !pb.as_bytes().is_empty() => {
                    Some(pb.as_bytes().to_vec())
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            pushes.len(),
            3,
            "OP_0 dummy, 2 sigs, redeem script (dummy excluded above)"
        );
        let sig_pubkey_pairs = [(&pushes[0], &pubkeys[0]), (&pushes[1], &pubkeys[2])];

        let sighash = compute_v6_transparent_sighash(
            &tx,
            0,
            &[prevout_value],
            std::slice::from_ref(&prevout_script),
        )
        .unwrap();

        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest(sighash);
        for (sig_bytes, pubkey_bytes) in sig_pubkey_pairs {
            assert_eq!(
                *sig_bytes.last().unwrap(),
                SIGHASH_ALL,
                "signature uses SIGHASH_ALL"
            );
            let mut sig =
                Signature::from_der(&sig_bytes[..sig_bytes.len() - 1]).expect("DER signature");
            sig.normalize_s();
            let pk = PublicKey::from_slice(pubkey_bytes).expect("valid pubkey");
            secp.verify_ecdsa(&msg, &sig, &pk).expect(
                "the real mempool-accepted multisig tx's signature verifies against \
                 compute_v6_transparent_sighash",
            );
        }
    }

    #[test]
    fn digest_is_deterministic() {
        let b = sample_bundle();
        assert_eq!(b.digest(), b.digest());
    }

    #[test]
    fn digest_excludes_anchor_proof_and_sigs() {
        let b = sample_bundle();
        let base = b.digest();

        let mut b2 = b.clone();
        b2.anchor = [0xffu8; 32];
        b2.proof = vec![0u8; 10];
        b2.spend_auth_sigs = vec![[9u8; 64], [9u8; 64]];
        b2.binding_sig = [0xeeu8; 64];
        assert_eq!(
            b2.digest(),
            base,
            "anchor/proof/sigs must not affect the digest"
        );
    }

    #[test]
    fn digest_depends_on_flags_and_value_balance() {
        let b = sample_bundle();
        let base = b.digest();

        let mut b_flags = b.clone();
        b_flags.flags = 0x03;
        assert_ne!(b_flags.digest(), base);

        let mut b_vb = b.clone();
        b_vb.value_balance = 1000;
        assert_ne!(b_vb.digest(), base);
    }

    #[test]
    fn digest_depends_on_action_data() {
        let b = sample_bundle();
        let base = b.digest();

        let mut b2 = b.clone();
        b2.actions[0].cmx = [0xaau8; 32];
        assert_ne!(b2.digest(), base);
    }

    #[test]
    fn empty_ironwood_digest_is_empty_personalized_hash() {
        let expected = super::blake2b_256_personal(&[], super::ZTXID_IRONWOOD_HASH_PERSONAL);
        assert_eq!(ironwood_digest(None), expected);
    }

    #[test]
    fn ironwood_digest_dispatches_to_bundle() {
        let b = sample_bundle();
        assert_eq!(ironwood_digest(Some(&b)), b.digest());
    }

    #[test]
    fn personalization_strings_are_16_bytes() {
        assert_eq!(ZTXID_IRONWOOD_HASH_PERSONAL.len(), 16);
        assert_eq!(ZTXID_IRONWOOD_COMPACT_PERSONAL.len(), 16);
        assert_eq!(ZTXID_IRONWOOD_MEMOS_PERSONAL.len(), 16);
        assert_eq!(ZTXID_IRONWOOD_NONCOMPACT_PERSONAL.len(), 16);
        assert_eq!(ZTXID_ORCHARD_V6_HASH_PERSONAL.len(), 16);
    }

    /// Load a Zcash test fixture's contents from `test/fixtures/zcash/`.
    fn load_zcash_fixture(name: &str) -> String {
        crate::fixed_script_wallet::test_utils::fixtures::load_fixture(&format!("zcash/{}", name))
            .unwrap_or_else(|e| panic!("failed to load fixture {}: {}", name, e))
    }

    #[test]
    fn golden_shield_tx_parses_and_round_trips() {
        // Real testnet shielding transaction (branch id 37a5165b), captured from the
        // Ironwood reference sandbox: 2 transparent inputs, 0 outputs, 1 Ironwood action.
        let raw = hex::decode(load_zcash_fixture("v6_shield_rawtx.hex").trim()).unwrap();
        let tx = decode_v6_transaction(&raw).unwrap();

        assert_eq!(tx.version_group_id, ZCASH_IRONWOOD_VERSION_GROUP_ID);
        assert_eq!(tx.consensus_branch_id, 0x37a5165b);
        assert_eq!(tx.expiry_height, 0);
        assert_eq!(tx.transparent.input.len(), 2);
        assert_eq!(tx.transparent.output.len(), 0);

        let bundle = tx
            .ironwood_bundle
            .as_ref()
            .expect("ironwood bundle present");
        assert_eq!(bundle.actions.len(), 1);
        assert_eq!(bundle.flags, 0x07);
        assert_eq!(bundle.value_balance, -314_030_000);
        assert_eq!(bundle.proof.len(), 4992);
        assert_eq!(
            hex::encode(bundle.anchor),
            "078ea7c31d1eba2b82661ab6f5d6678b5c1e1d402ab1045a515c73ba7bee4535"
        );
        assert_eq!(
            hex::encode(bundle.actions[0].cmx),
            "fd897aeef33102e7142210f8ac1d3ea964a53f935fd6683d04f26ac6e359e80d"
        );
        // The action's on-wire nullifier field doubles as the paired output note's
        // `rho` input (see IronwoodAction::nullifier docs) — hence it equals the
        // reference's output_note.rho, not output_note.nullifier.
        assert_eq!(
            hex::encode(bundle.actions[0].nullifier),
            "e1316540f064433e164b1f85da6bd16317e1462db3a91b866600d62ab9d4c926"
        );

        // Re-encode must be byte-identical to the captured wire bytes.
        assert_eq!(encode_v6_transaction(&tx).unwrap(), raw);
    }

    #[test]
    fn golden_shield_tx_txid_matches() {
        let raw = hex::decode(load_zcash_fixture("v6_shield_rawtx.hex").trim()).unwrap();
        // compute_v6_txid returns internal byte order; the canonical txid is displayed reversed.
        let mut internal = compute_v6_txid_from_bytes(&raw).unwrap();
        internal.reverse();
        assert_eq!(
            hex::encode(internal),
            load_zcash_fixture("v6_shield_txid.hex").trim()
        );
    }

    /// Load a `(raw_tx, txid_display)` fixture pair and assert the transaction
    /// parses, re-encodes byte-identically, and reproduces its canonical txid.
    fn assert_golden(name: &str) {
        let raw =
            hex::decode(load_zcash_fixture(&format!("v6_{}_rawtx.hex", name)).trim()).unwrap();
        let txid_display = load_zcash_fixture(&format!("v6_{}_txid.hex", name));
        let tx = decode_v6_transaction(&raw).unwrap();
        assert_eq!(tx.version_group_id, ZCASH_IRONWOOD_VERSION_GROUP_ID);
        assert_eq!(
            encode_v6_transaction(&tx).unwrap(),
            raw,
            "re-encode must be byte-identical"
        );
        let mut internal = compute_v6_txid(&tx);
        internal.reverse();
        assert_eq!(hex::encode(internal), txid_display.trim(), "txid mismatch");
    }

    #[test]
    fn golden_selfsend_tx_parses_and_txid_matches() {
        // Ironwood -> Ironwood self-send: no transparent inputs or outputs
        // (exercises the empty transparent digest branch).
        assert_golden("selfsend");

        let raw = hex::decode(load_zcash_fixture("v6_selfsend_rawtx.hex").trim()).unwrap();
        let tx = decode_v6_transaction(&raw).unwrap();
        assert!(tx.transparent.input.is_empty());
        assert!(tx.transparent.output.is_empty());
        assert_eq!(tx.ironwood_bundle.unwrap().actions.len(), 1);
    }

    #[test]
    fn golden_shield_1zec_tx_parses_and_txid_matches() {
        // Transparent -> Ironwood shielding of 1 ZEC.
        assert_golden("shield1zec");
    }

    #[test]
    fn spend_auth_sig_count_mismatch_errors() {
        let tx = ZcashV6Transaction {
            version_group_id: ZCASH_IRONWOOD_VERSION_GROUP_ID,
            consensus_branch_id: 0x37a5165b,
            transparent: sample_transparent(false),
            expiry_height: 0,
            sapling_value_balance: 0,
            ironwood_bundle: Some(IronwoodBundle {
                actions: vec![sample_action(1), sample_action(2)],
                flags: 0x07,
                value_balance: 0,
                anchor: [0u8; 32],
                proof: vec![],
                spend_auth_sigs: vec![[1u8; 64]], // only one, but two actions
                binding_sig: [0u8; 64],
            }),
        };
        assert!(encode_v6_transaction(&tx).is_err());
    }

    /// Cross-check our decoding and ZIP-244 txid against `zebra-chain`, an independent
    /// NU6.3 implementation, for each real testnet fixture. This makes the golden txid
    /// a value an external Ironwood implementation agrees on, not one we generated.
    ///
    /// Native-only: `zebra-chain` is a `cfg(not(wasm32))` dev-dependency.
    #[cfg(not(target_arch = "wasm32"))]
    mod zebra_oracle {
        use super::*;
        use zebra_chain::serialization::ZcashDeserialize;
        use zebra_chain::transaction::Transaction as ZebraTx;

        fn cross_check(name: &str) {
            let raw =
                hex::decode(load_zcash_fixture(&format!("v6_{name}_rawtx.hex")).trim()).unwrap();
            let expected_txid = load_zcash_fixture(&format!("v6_{name}_txid.hex"))
                .trim()
                .to_string();

            // Our decode + ZIP-244 txid (internal order reversed to canonical display).
            let ours = decode_v6_transaction(&raw).unwrap();
            let mut our_txid = compute_v6_txid(&ours);
            our_txid.reverse();
            assert_eq!(hex::encode(our_txid), expected_txid, "our txid");

            // Zebra's independent decode of the same bytes.
            let zebra = ZebraTx::zcash_deserialize(&raw[..]).expect("zebra decodes the v6 tx");
            assert_eq!(zebra.version(), 6, "zebra sees a v6 tx");

            // The headline: zebra's ZIP-244 txid agrees with ours and the fixture.
            assert_eq!(
                zebra.hash().to_string(),
                expected_txid,
                "zebra txid == ours"
            );

            // Structural agreement: transparent I/O and Ironwood action counts.
            assert_eq!(zebra.inputs().len(), ours.transparent.input.len());
            assert_eq!(zebra.outputs().len(), ours.transparent.output.len());
            let our_actions = ours.ironwood_bundle.as_ref().map_or(0, |b| b.actions.len());
            assert_eq!(
                zebra.ironwood_actions().count(),
                our_actions,
                "action count"
            );
        }

        #[test]
        fn shield_matches_zebra() {
            cross_check("shield");
        }

        #[test]
        fn selfsend_matches_zebra() {
            cross_check("selfsend");
        }

        #[test]
        fn shield1zec_matches_zebra() {
            cross_check("shield1zec");
        }
    }
}
