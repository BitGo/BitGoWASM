use anyhow::Result;
use clap::{ArgGroup, Subcommand};
use std::path::PathBuf;

use crate::network::NetworkArg;

mod add_input;
mod add_output;
mod add_shielded_output;
mod combine_ironwood_proof;
mod common;
mod create;
mod create_zcash_v6;
mod parse;
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
        /// Halo2 proof bytes from the external proof service, hex-encoded
        #[arg(long)]
        proof: Option<String>,
        /// Produce the proof locally instead of supplying one via --proof (heavier: builds a
        /// halo2 proving key and synthesizes the circuit)
        #[arg(long)]
        local_proof: bool,
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
        } => add_shielded_output::handle_add_shielded_output_command(
            path,
            network.into(),
            recipient,
            value,
            anchor,
            ovk,
            memo,
        ),
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
