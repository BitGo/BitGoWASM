/// This module contains code for the BitGo Fixed Script Wallets.
/// These are not based on descriptors.
pub mod bitgo_psbt;
pub mod replay_protection;
mod wallet_keys;
pub mod wallet_scripts;

#[cfg(test)]
pub mod test_utils;

pub use replay_protection::*;
pub use wallet_keys::*;
pub use wallet_scripts::*;
