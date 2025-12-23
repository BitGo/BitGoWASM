use anyhow::Result;
use clap::Subcommand;

use crate::network::NetworkArg;

mod parse;

#[derive(Subcommand)]
pub enum PsbtCommand {
    /// Parse a PSBT file and display its contents
    Parse {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: std::path::PathBuf,
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
}

pub fn handle_command(command: PsbtCommand) -> Result<()> {
    match command {
        PsbtCommand::Parse {
            path,
            no_color,
            raw,
            network,
        } => parse::handle_parse_command(path, no_color, raw, network.into()),
    }
}
