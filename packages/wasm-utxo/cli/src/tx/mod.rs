use anyhow::Result;
use clap::Subcommand;

use crate::network::NetworkArg;

mod parse;

#[derive(Subcommand)]
pub enum TxCommand {
    /// Parse a transaction file and display its contents
    Parse {
        /// Path to the transaction file (use '-' to read from stdin)
        path: std::path::PathBuf,
        /// Network for address formatting
        #[arg(long, short, value_enum)]
        network: NetworkArg,
        /// Disable colored output
        #[arg(long)]
        no_color: bool,
    },
}

pub fn handle_command(command: TxCommand) -> Result<()> {
    match command {
        TxCommand::Parse {
            path,
            no_color,
            network,
        } => parse::handle_parse_command(path, no_color, network.into()),
    }
}
