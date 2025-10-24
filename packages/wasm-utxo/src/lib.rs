mod address;
mod descriptor;
mod error;
mod fixed_script_wallet;
mod miniscript;
mod psbt;
mod try_from_js_value;
mod try_into_js_value;

// re-export bitcoin from the miniscript crate
// this package is transitioning to a all-purpose bitcoin package, so we want easy access
pub use ::miniscript::bitcoin;

pub use address::utxolib_compat;
pub use address::*;
pub use descriptor::WrapDescriptor;
pub use miniscript::WrapMiniscript;
pub use psbt::WrapPsbt;

pub use crate::fixed_script_wallet::*;
