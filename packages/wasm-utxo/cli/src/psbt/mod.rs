use anyhow::Result;
use clap::{ArgGroup, Subcommand};
use std::path::PathBuf;

use crate::network::NetworkArg;

mod add_input;
mod add_output;
mod add_shielded_input;
mod add_shielded_output;
mod add_spend_signature;
mod build_witness;
mod combine_ironwood_proof;
mod common;
mod create;
mod create_zcash_v6;
mod extract_transparent_only;
mod out_ciphertexts;
mod parse;
mod prove;
mod set_spend_randomizer;
mod sign;
mod sign_v6_input;

#[derive(Subcommand)]
pub enum PsbtCommand {
    /// Parse a PSBT file and display its contents
    Parse {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Network for address formatting
        #[arg(long, short, value_enum)]
        network: NetworkArg,
        /// Disable colored output
        #[arg(long)]
        no_color: bool,
        /// Show raw key-value pairs instead of parsed structure
        #[arg(long)]
        raw: bool,
    },
    /// Create an empty PSBT. Prints the PSBT as hex to stdout.
    Create {
        /// Transaction version (default: 4, required for Zcash overwintered txs)
        #[arg(long, default_value_t = 4)]
        version: i32,
        /// Transaction lock time (default: 0)
        #[arg(long, default_value_t = 0)]
        lock_time: u32,
    },
    /// Add an input spending `{txid, vout, value, scriptPubKey}` to a PSBT, given a definite
    /// descriptor for the output (e.g. `pkh(<pubkey>)`, `wpkh(<pubkey>)`). Prints the updated
    /// PSBT as hex to stdout.
    AddInput {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Network (determines whether --prev-tx is required; e.g. tzec for Zcash regtest)
        #[arg(long, short, value_enum)]
        network: NetworkArg,
        /// Transaction ID of the output being spent
        #[arg(long)]
        txid: String,
        /// Output index being spent
        #[arg(long)]
        vout: u32,
        /// Value in satoshis of the output being spent
        #[arg(long)]
        value: u64,
        /// scriptPubKey of the output being spent, hex-encoded
        #[arg(long)]
        script: String,
        /// Definite descriptor for the output being spent, with concrete keys
        /// (e.g. `pkh(<pubkey>)`, `wpkh(<pubkey>)`); populates bip32_derivation/tap_key_origins
        #[arg(long)]
        descriptor: String,
        /// Sequence number (default: 0xFFFFFFFE)
        #[arg(long, default_value_t = 0xFFFFFFFE)]
        sequence: u32,
        /// Full previous transaction, hex-encoded (BIP174-safe path). Required unless --network
        /// is a value-committing network (Zcash, BCH-family) whose sighash already commits the
        /// input amount, making it safe to sign from --value/--script alone.
        #[arg(long = "prev-tx")]
        prev_tx: Option<String>,
    },
    /// Add an output to a PSBT. Prints the updated PSBT as hex to stdout.
    #[command(group(ArgGroup::new("target").required(true).args(["address", "script"])))]
    AddOutput {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Output address (requires --network)
        #[arg(long)]
        address: Option<String>,
        /// Output script, hex-encoded
        #[arg(long)]
        script: Option<String>,
        /// Value in satoshis
        #[arg(long)]
        value: u64,
        /// Network for --address (e.g. tzec for Zcash regtest, which reuses testnet prefixes)
        #[arg(long, short, value_enum)]
        network: Option<NetworkArg>,
    },
    /// Create an empty Zcash **v6 (Ironwood) shielding** PSBT, without embedding any xpubs.
    /// Prints the PSBT as hex to stdout. Follow with `add-input` (transparent inputs),
    /// `add-output` (transparent outputs), and `add-shielded-output` (the Ironwood output).
    CreateZcashV6 {
        /// Network (must be zec or tzec)
        #[arg(long, short, value_enum)]
        network: NetworkArg,
        /// Zcash consensus branch ID, hex (0x...) or decimal — must be at or after NU6.3
        /// (Ironwood) activation
        #[arg(long)]
        consensus_branch_id: String,
        /// Transaction lock time (default: 0)
        #[arg(long, default_value_t = 0)]
        lock_time: u32,
        /// Transaction expiry height (default: 0, no expiry)
        #[arg(long, default_value_t = 0)]
        expiry_height: u32,
    },
    /// Add the shielded (Ironwood) output to a v6 PSBT — the Constructor role. Exactly one
    /// shielded output is supported. Prints the updated PSBT as hex to stdout.
    AddShieldedOutput {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Network (must be zec or tzec)
        #[arg(long, short, value_enum)]
        network: NetworkArg,
        /// Raw 43-byte Orchard/Ironwood recipient address, hex-encoded
        #[arg(long)]
        recipient: String,
        /// Value in zatoshi
        #[arg(long)]
        value: u64,
        /// Current Ironwood note-commitment-tree root, hex-encoded (32 bytes)
        #[arg(long)]
        anchor: String,
        /// Raw outgoing viewing key, hex-encoded (32 bytes)
        #[arg(long)]
        ovk: Option<String>,
        /// Memo field, hex-encoded (512 bytes; default: all-zero)
        #[arg(long)]
        memo: Option<String>,
        /// Full Unified Address this output was addressed to, if known. Its Orchard receiver must
        /// match --recipient. Stored verbatim so it survives a serialize/deserialize round-trip
        /// instead of being reconstructed as a single-receiver UA when the PSBT is later parsed.
        #[arg(long)]
        unified_address: Option<String>,
    },
    /// Constructor role for the **spend** flow: add the shielded spends (and optionally
    /// shielded outputs) to a v6 PSBT as a single keyless orchard PCZT, from a JSON notes
    /// file. The PSBT must not carry transparent inputs, and only one call is supported per
    /// PSBT. Prints the updated PSBT as hex to stdout, with the action map on stderr.
    AddShieldedInput {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Network (must be zec or tzec)
        #[arg(long, short, value_enum)]
        network: NetworkArg,
        /// Notes file (JSON): `{"anchor", "spends": [{"recipient", "value", "rho", "rseed",
        /// "cmx", "witness": {"position", "authPath"}, "nullifier"?}], "outputs"?: [{"recipient",
        /// "amount", "memo"?, "unifiedAddress"?}]}`, bytes hex-encoded
        #[arg(long)]
        notes_file: PathBuf,
        /// Full viewing key file (96-byte hex): derives any missing nullifiers locally
        #[arg(long)]
        fvk_file: Option<PathBuf>,
        /// Current Ironwood note-commitment-tree root, hex-encoded (32 bytes). Overrides the
        /// anchor in the notes file.
        #[arg(long)]
        anchor: Option<String>,
    },
    /// The viewing-key holder's ciphertext round: request the pending real outputs, re-encrypt
    /// each under the FVK's external `ovk`, and apply the response. A PSBT with nothing pending
    /// passes through unchanged. Prints the PSBT as hex to stdout, with the served action
    /// indices on stderr.
    OutCiphertexts {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Network (must be zec or tzec)
        #[arg(long, short, value_enum)]
        network: NetworkArg,
        /// Full viewing key file (96-byte hex)
        #[arg(long)]
        fvk_file: PathBuf,
    },
    /// Install the randomized signing key `rk = ak.randomize(alpha)` for one real spend (the
    /// FROST stand-in). Only `rk` is stored; the alpha is needed again for
    /// `add-spend-signature` and `prove`. With no `--alpha`, a fresh random one is generated.
    /// Prints the updated PSBT as hex to stdout, with the alpha on stderr.
    SetSpendRandomizer {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Network (must be zec or tzec)
        #[arg(long, short, value_enum)]
        network: NetworkArg,
        /// Action index of the real spend (from `add-shielded-input`'s action map)
        #[arg(long)]
        action_index: usize,
        /// Full viewing key file (96-byte hex); its `ak` checks `rk == ak.randomize(alpha)`
        #[arg(long)]
        fvk_file: PathBuf,
        /// The randomizer scalar, hex-encoded (32 bytes). Random when omitted.
        #[arg(long)]
        alpha: Option<String>,
    },
    /// Sign one real spend's ZIP-244 spend sighash: locally with the spending key stand-in
    /// (`--sk-file` + `--alpha`, signing `ask.randomize(alpha)`) or ingest an externally
    /// produced RedPallas signature (`--signature`, the FROST case). Prints the updated PSBT as
    /// hex to stdout.
    #[command(group(ArgGroup::new("signer").required(true).args(["sk_file", "signature"])))]
    AddSpendSignature {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Network (must be zec or tzec)
        #[arg(long, short, value_enum)]
        network: NetworkArg,
        /// Action index of the real spend
        #[arg(long)]
        action_index: usize,
        /// The randomizer scalar `set-spend-randomizer` installed for this action, hex (32
        /// bytes). Required with --sk-file.
        #[arg(long, requires = "sk_file")]
        alpha: Option<String>,
        /// Spending key file (32-byte hex): signs locally with `ask.randomize(alpha)`
        #[arg(long, requires = "alpha")]
        sk_file: Option<PathBuf>,
        /// An externally produced 64-byte RedPallas signature, hex-encoded
        #[arg(long)]
        signature: Option<String>,
    },
    /// The prover role: with `--request`, print the alpha-patched PCZT bytes an external prover
    /// consumes; otherwise produce the Halo2 proof locally and print the proof hex for
    /// `combine-ironwood-proof --proof`. One `--alpha <action_index>:<hex32>` per real spend —
    /// the PSBT never stores the randomizers.
    Prove {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Network (must be zec or tzec)
        #[arg(long, short, value_enum)]
        network: NetworkArg,
        /// One randomizer per real spend, as `<action_index>:<hex32>` (repeatable)
        #[arg(long = "alpha")]
        alphas: Vec<String>,
        /// Full viewing key file (96-byte hex); required for local proving
        #[arg(long, required_unless_present = "request")]
        fvk_file: Option<PathBuf>,
        /// Print the alpha-patched proof request (the PCZT bytes) instead of proving locally
        #[arg(long, conflicts_with = "fvk_file")]
        request: bool,
    },
    /// Build (and validate) an Ironwood Merkle witness for a note commitment — from the full
    /// 32-entry sibling path or from a pruned shard + cap. Prints
    /// `{"position": <u32>, "authPath": ["<hex32>" × 32]}` as JSON to stdout.
    #[command(group(ArgGroup::new("source").required(true).args(["auth_path", "shard_file"])))]
    BuildWitness {
        /// The note commitment being witnessed, hex-encoded (32 bytes)
        #[arg(long)]
        cmx: String,
        /// The leaf's position in the note-commitment tree
        #[arg(long)]
        position: u32,
        /// The expected note-commitment-tree root, hex-encoded (32 bytes)
        #[arg(long)]
        anchor: String,
        /// The 32 sibling hashes: a JSON array of hex strings, 32 comma-separated hex hashes,
        /// or the flattened 1024-byte hex encoding
        #[arg(long)]
        auth_path: Option<String>,
        /// Pruned shard subtree containing --position (ShardTreeNode JSON)
        #[arg(long, requires_all = ["cap_file", "shard_height", "leaf_count"])]
        shard_file: Option<PathBuf>,
        /// Pruned cap above every shard (ShardTreeNode JSON)
        #[arg(long, requires = "shard_file")]
        cap_file: Option<PathBuf>,
        /// The shard root's level (its height in the tree)
        #[arg(long, requires = "shard_file")]
        shard_height: Option<u8>,
        /// Total leaves committed to the tree as of --anchor
        #[arg(long, requires = "shard_file")]
        leaf_count: Option<u64>,
    },
    /// Sign one transparent input of a v6 PSBT with a single private key, over the ZIP-244
    /// transparent sighash. Call once per required signature (2-of-3). Prints the updated PSBT
    /// as hex to stdout.
    SignV6Input {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Network (must be zec or tzec)
        #[arg(long, short, value_enum)]
        network: NetworkArg,
        /// Index of the transparent input to sign
        #[arg(long)]
        index: usize,
        /// Controlling private key (WIF or hex)
        #[arg(long)]
        privkey: String,
    },
    /// Transaction Extractor role: given the external prover's proof bytes, finalize the
    /// transparent inputs and splice in the shielded bundle to produce the broadcast-ready v6
    /// transaction. The PSBT must already carry every transparent input's signatures (via
    /// `sign-v6-input`) and the shielded output (via `add-shielded-output`). Prints the raw
    /// transaction as hex to stdout.
    CombineIronwoodProof {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Network (must be zec or tzec)
        #[arg(long, short, value_enum)]
        network: NetworkArg,
        /// Halo2 proof bytes from the external prover, hex-encoded
        #[arg(long)]
        proof: Option<String>,
        /// Produce the proof locally instead of supplying one via --proof (heavier: builds a
        /// halo2 proving key and synthesizes the circuit)
        #[arg(long)]
        local_proof: bool,
    },
    /// Finalize transparent inputs and extract the broadcast-ready v6 transaction for a PSBT
    /// that has **no shielded output** (no PCZT). This is the transparent-only v6 counterpart
    /// of `combine-ironwood-proof`. Prints the raw transaction as hex to stdout.
    ExtractTransparentOnly {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Network (must be zec or tzec)
        #[arg(long, short, value_enum)]
        network: NetworkArg,
    },
    /// Sign all inputs with a single private key, then finalize and extract. The sighash
    /// algorithm is selected by --network: plain for BTC-like networks, FORKID for the
    /// BCH family, or Zcash ZIP-243. Prints the signed wire hex to stdout (overwintered
    /// format for Zcash).
    Sign {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Network (selects the sighash algorithm: plain, FORKID, or Zcash ZIP-243)
        #[arg(long, short, value_enum)]
        network: NetworkArg,
        /// Controlling private key for all inputs (WIF or hex)
        #[arg(long)]
        privkey: String,
        /// Zcash consensus branch ID, hex (0x...) or decimal (required for Zcash, unused otherwise)
        #[arg(long)]
        consensus_branch_id: Option<String>,
        /// Zcash version group ID, hex or decimal (default: Sapling 0x892F2085; Zcash only)
        #[arg(long)]
        version_group_id: Option<String>,
        /// Transaction expiry height (default: 0, no expiry; Zcash only)
        #[arg(long, default_value_t = 0)]
        expiry_height: u32,
    },
}

pub fn handle_command(command: PsbtCommand) -> Result<()> {
    match command {
        PsbtCommand::Parse {
            path,
            no_color,
            raw,
            network,
        } => parse::handle_parse_command(path, no_color, raw, network.into()),
        PsbtCommand::Create { version, lock_time } => {
            create::handle_create_command(version, lock_time)
        }
        PsbtCommand::AddInput {
            path,
            network,
            txid,
            vout,
            value,
            script,
            descriptor,
            sequence,
            prev_tx,
        } => add_input::handle_add_input_command(
            path, network, txid, vout, value, script, descriptor, sequence, prev_tx,
        ),
        PsbtCommand::AddOutput {
            path,
            address,
            script,
            value,
            network,
        } => add_output::handle_add_output_command(path, network, address, script, value),
        PsbtCommand::CreateZcashV6 {
            network,
            consensus_branch_id,
            lock_time,
            expiry_height,
        } => create_zcash_v6::handle_create_zcash_v6_command(
            network.into(),
            consensus_branch_id,
            lock_time,
            expiry_height,
        ),
        PsbtCommand::AddShieldedOutput {
            path,
            network,
            recipient,
            value,
            anchor,
            ovk,
            memo,
            unified_address,
        } => add_shielded_output::handle_add_shielded_output_command(
            path,
            network.into(),
            recipient,
            value,
            anchor,
            ovk,
            memo,
            unified_address,
        ),
        PsbtCommand::AddShieldedInput {
            path,
            network,
            notes_file,
            fvk_file,
            anchor,
        } => add_shielded_input::handle_add_shielded_input_command(
            path,
            network.into(),
            notes_file,
            fvk_file,
            anchor,
        ),
        PsbtCommand::OutCiphertexts {
            path,
            network,
            fvk_file,
        } => out_ciphertexts::handle_out_ciphertexts_command(path, network.into(), fvk_file),
        PsbtCommand::SetSpendRandomizer {
            path,
            network,
            action_index,
            fvk_file,
            alpha,
        } => set_spend_randomizer::handle_set_spend_randomizer_command(
            path,
            network.into(),
            action_index,
            fvk_file,
            alpha,
        ),
        PsbtCommand::AddSpendSignature {
            path,
            network,
            action_index,
            alpha,
            sk_file,
            signature,
        } => add_spend_signature::handle_add_spend_signature_command(
            path,
            network.into(),
            action_index,
            alpha,
            sk_file,
            signature,
        ),
        PsbtCommand::Prove {
            path,
            network,
            alphas,
            fvk_file,
            request,
        } => prove::handle_prove_command(path, network.into(), alphas, fvk_file, request),
        PsbtCommand::BuildWitness {
            cmx,
            position,
            anchor,
            auth_path,
            shard_file,
            cap_file,
            shard_height,
            leaf_count,
        } => build_witness::handle_build_witness_command(build_witness::BuildWitnessArgs {
            cmx,
            position,
            anchor,
            auth_path,
            shard_file,
            cap_file,
            shard_height,
            leaf_count,
        }),
        PsbtCommand::SignV6Input {
            path,
            network,
            index,
            privkey,
        } => sign_v6_input::handle_sign_v6_input_command(path, network.into(), index, privkey),
        PsbtCommand::CombineIronwoodProof {
            path,
            network,
            proof,
            local_proof,
        } => combine_ironwood_proof::handle_combine_ironwood_proof_command(
            path,
            network.into(),
            proof,
            local_proof,
        ),
        PsbtCommand::ExtractTransparentOnly { path, network } => {
            extract_transparent_only::handle_extract_transparent_only_command(path, network.into())
        }
        PsbtCommand::Sign {
            path,
            network,
            privkey,
            consensus_branch_id,
            version_group_id,
            expiry_height,
        } => sign::handle_sign_command(
            path,
            network,
            privkey,
            consensus_branch_id,
            version_group_id,
            expiry_height,
        ),
    }
}
