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

use super::transaction::{ZCASH_IRONWOOD_VERSION_GROUP_ID, ZCASH_V6_VERSION_HEADER};
use miniscript::bitcoin::consensus::{Decodable, Encodable};
use miniscript::bitcoin::{Transaction, TxIn, TxOut, VarInt};

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
    fn from_bytes(b: &[u8]) -> Result<Self, String> {
        if b.len() != IRONWOOD_ACTION_SIZE {
            return Err(format!(
                "Ironwood action must be {} bytes, got {}",
                IRONWOOD_ACTION_SIZE,
                b.len()
            ));
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

fn read_u32_le(r: &mut &[u8]) -> Result<u32, String> {
    u32::consensus_decode(r).map_err(|e| format!("v6: failed to read u32: {}", e))
}

fn read_i64_le(r: &mut &[u8]) -> Result<i64, String> {
    i64::consensus_decode(r).map_err(|e| format!("v6: failed to read i64: {}", e))
}

fn read_varint(r: &mut &[u8]) -> Result<u64, String> {
    VarInt::consensus_decode(r)
        .map(|v| v.0)
        .map_err(|e| format!("v6: failed to read varint: {}", e))
}

fn take_bytes<'a>(r: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
    if r.len() < n {
        return Err(format!("v6: expected {} bytes, only {} left", n, r.len()));
    }
    let (head, tail) = r.split_at(n);
    *r = tail;
    Ok(head)
}

fn take_array<const N: usize>(r: &mut &[u8]) -> Result<[u8; N], String> {
    let bytes = take_bytes(r, N)?;
    let mut a = [0u8; N];
    a.copy_from_slice(bytes);
    Ok(a)
}

/// Decode a v6 (Ironwood) transaction from its raw wire bytes.
pub fn decode_v6_transaction(bytes: &[u8]) -> Result<ZcashV6Transaction, String> {
    let mut r = bytes;

    // --- Header ---
    let version = read_u32_le(&mut r)?;
    if version != ZCASH_V6_VERSION_HEADER {
        return Err(format!(
            "v6: unexpected version header 0x{:08x} (expected 0x{:08x})",
            version, ZCASH_V6_VERSION_HEADER
        ));
    }
    let version_group_id = read_u32_le(&mut r)?;
    if version_group_id != ZCASH_IRONWOOD_VERSION_GROUP_ID {
        return Err(format!(
            "v6: unexpected version group id 0x{:08x} (expected 0x{:08x})",
            version_group_id, ZCASH_IRONWOOD_VERSION_GROUP_ID
        ));
    }
    let consensus_branch_id = read_u32_le(&mut r)?;
    let lock_time = read_u32_le(&mut r)?;
    let expiry_height = read_u32_le(&mut r)?;

    // --- Transparent ---
    let inputs: Vec<TxIn> =
        Vec::consensus_decode(&mut r).map_err(|e| format!("v6: failed to decode inputs: {}", e))?;
    let outputs: Vec<TxOut> = Vec::consensus_decode(&mut r)
        .map_err(|e| format!("v6: failed to decode outputs: {}", e))?;

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
        return Err("v6: non-empty Sapling bundle is not supported by this parser".to_string());
    }
    // valueBalanceSapling / anchor / proofs are only present when counts > 0, so nothing to read.
    let sapling_value_balance = 0i64;

    // --- Orchard v6 slot (empty-only support) ---
    let n_actions_orchard = read_varint(&mut r)?;
    if n_actions_orchard != 0 {
        return Err("v6: non-empty Orchard v6 bundle is not supported by this parser".to_string());
    }

    // --- Ironwood bundle ---
    let n_actions_ironwood = read_varint(&mut r)?;
    let ironwood_bundle = if n_actions_ironwood == 0 {
        None
    } else {
        let n = usize::try_from(n_actions_ironwood)
            .map_err(|_| "v6: action count overflow".to_string())?;
        let mut actions = Vec::with_capacity(n);
        for _ in 0..n {
            let a = take_bytes(&mut r, IRONWOOD_ACTION_SIZE)?;
            actions.push(IronwoodAction::from_bytes(a)?);
        }
        let flags = *take_bytes(&mut r, 1)?.first().unwrap();
        let value_balance = read_i64_le(&mut r)?;
        let anchor = take_array::<32>(&mut r)?;
        let proof_size = read_varint(&mut r)?;
        let proof_size =
            usize::try_from(proof_size).map_err(|_| "v6: proof size overflow".to_string())?;
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
        return Err(format!(
            "v6: {} trailing bytes after Ironwood bundle",
            r.len()
        ));
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
pub fn encode_v6_transaction(tx: &ZcashV6Transaction) -> Result<Vec<u8>, String> {
    if tx.sapling_value_balance != 0 {
        return Err(
            "v6: non-zero Sapling value balance is not supported by this encoder".to_string(),
        );
    }
    let mut out = Vec::new();

    // --- Header ---
    ZCASH_V6_VERSION_HEADER
        .consensus_encode(&mut out)
        .map_err(|e| format!("v6: failed to encode version: {}", e))?;
    tx.version_group_id
        .consensus_encode(&mut out)
        .map_err(|e| format!("v6: failed to encode version group id: {}", e))?;
    tx.consensus_branch_id
        .consensus_encode(&mut out)
        .map_err(|e| format!("v6: failed to encode consensus branch id: {}", e))?;
    tx.transparent
        .lock_time
        .consensus_encode(&mut out)
        .map_err(|e| format!("v6: failed to encode lock_time: {}", e))?;
    tx.expiry_height
        .consensus_encode(&mut out)
        .map_err(|e| format!("v6: failed to encode expiry_height: {}", e))?;

    // --- Transparent ---
    tx.transparent
        .input
        .consensus_encode(&mut out)
        .map_err(|e| format!("v6: failed to encode inputs: {}", e))?;
    tx.transparent
        .output
        .consensus_encode(&mut out)
        .map_err(|e| format!("v6: failed to encode outputs: {}", e))?;

    // --- Sapling (empty) ---
    VarInt(0)
        .consensus_encode(&mut out)
        .map_err(|e| format!("v6: failed to encode nSpendsSapling: {}", e))?;
    VarInt(0)
        .consensus_encode(&mut out)
        .map_err(|e| format!("v6: failed to encode nOutputsSapling: {}", e))?;

    // --- Orchard v6 slot (empty) ---
    VarInt(0)
        .consensus_encode(&mut out)
        .map_err(|e| format!("v6: failed to encode nActionsOrchard: {}", e))?;

    // --- Ironwood bundle ---
    match &tx.ironwood_bundle {
        None => {
            VarInt(0)
                .consensus_encode(&mut out)
                .map_err(|e| format!("v6: failed to encode nActionsIronwood: {}", e))?;
        }
        Some(bundle) => {
            let n = bundle.actions.len();
            if bundle.spend_auth_sigs.len() != n {
                return Err(format!(
                    "v6: spend_auth_sigs count {} does not match action count {}",
                    bundle.spend_auth_sigs.len(),
                    n
                ));
            }
            VarInt(n as u64)
                .consensus_encode(&mut out)
                .map_err(|e| format!("v6: failed to encode nActionsIronwood: {}", e))?;
            for a in &bundle.actions {
                out.extend_from_slice(&a.to_bytes());
            }
            out.push(bundle.flags);
            bundle
                .value_balance
                .consensus_encode(&mut out)
                .map_err(|e| format!("v6: failed to encode valueBalanceIronwood: {}", e))?;
            out.extend_from_slice(&bundle.anchor);
            VarInt(bundle.proof.len() as u64)
                .consensus_encode(&mut out)
                .map_err(|e| format!("v6: failed to encode proofsSize: {}", e))?;
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
}
