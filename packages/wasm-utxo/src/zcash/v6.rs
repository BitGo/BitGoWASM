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
/// (little-endian) is appended to form the full 16-byte personalization.
pub const ZCASH_TXID_PERSONAL_PREFIX: &[u8; 12] = b"ZcashTxHash_";

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
