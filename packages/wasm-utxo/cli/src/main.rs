use anyhow::Result;
use clap::{Parser, Subcommand};

mod address;
mod format;
mod input;
mod psbt;
mod tx;

#[cfg(test)]
mod parse_tests;
#[cfg(test)]
pub mod test_utils;

#[derive(Parser)]
#[command(name = "wasm-utxo-cli")]
#[command(about = "CLI tool for Bitcoin UTXO operations", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Address encoding and decoding operations
    Address {
        #[command(subcommand)]
        command: address::AddressCommand,
    },
    /// PSBT parsing and inspection operations
    Psbt {
        #[command(subcommand)]
        command: psbt::PsbtCommand,
    },
    /// Transaction parsing and inspection operations
    Tx {
        #[command(subcommand)]
        command: tx::TxCommand,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Address { command } => address::handle_command(command),
        Commands::Psbt { command } => psbt::handle_command(command),
        Commands::Tx { command } => tx::handle_command(command),
    }
}
