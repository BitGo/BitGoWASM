use anyhow::Result;
use clap::{ArgGroup, Subcommand};
use std::path::PathBuf;

use crate::network::NetworkArg;

mod add_input;
mod add_output;
mod common;
mod create;
mod parse;
mod sign;

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
