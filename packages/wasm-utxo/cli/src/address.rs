use anyhow::{Context, Result};
use clap::Subcommand;
use wasm_utxo::bitcoin::Script;
use wasm_utxo::{from_output_script_with_network, to_output_script_with_network, Network};

use crate::network::NetworkArg;

#[derive(Subcommand)]
pub enum AddressCommand {
    /// Decode an address to its output script (hex)
    Decode {
        /// The address to decode
        address: String,
        /// Network (btc, tbtc, ltc, bch, zec, etc.)
        #[arg(short, long, value_enum)]
        network: NetworkArg,
    },
    /// Encode an output script (hex) to an address
    Encode {
        /// Output script as hex
        script: String,
        /// Network (btc, tbtc, ltc, bch, zec, etc.)
        #[arg(short, long, value_enum)]
        network: NetworkArg,
    },
}

pub fn handle_command(command: AddressCommand) -> Result<()> {
    match command {
        AddressCommand::Decode { address, network } => {
            let network: Network = network.into();
            let script = to_output_script_with_network(&address, network)
                .context("Failed to decode address")?;
            println!("{}", hex::encode(script.as_bytes()));
            Ok(())
        }
        AddressCommand::Encode { script, network } => {
            let network: Network = network.into();
            let script_bytes =
                hex::decode(&script).context("Invalid hex string for output script")?;
            let script_obj = Script::from_bytes(&script_bytes);
            let address = from_output_script_with_network(script_obj, network)
                .context("Failed to encode output script to address")?;
            println!("{}", address);
            Ok(())
        }
    }
}
