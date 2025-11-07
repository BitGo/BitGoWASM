mod address;
mod error;
pub mod fixed_script_wallet;
mod networks;
#[cfg(test)]
mod test_utils;

// re-export bitcoin from the miniscript crate
// this package is transitioning to a all-purpose bitcoin package, so we want easy access
pub use ::miniscript::bitcoin;

pub use address::{
    from_output_script_with_coin, from_output_script_with_network, to_output_script_with_coin,
    to_output_script_with_network, utxolib_compat,
};

pub use networks::Network;
pub mod wasm;
pub use wasm::{WrapDescriptor, WrapMiniscript, WrapPsbt};
