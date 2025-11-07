/// This module contains code for the BitGo Fixed Script Wallets.
/// These are not based on descriptors.
pub mod psbt_wallet_input;
mod wallet_keys;
pub mod wallet_scripts;

#[cfg(test)]
pub mod test_utils;

pub use wallet_keys::*;
pub use wallet_scripts::*;
