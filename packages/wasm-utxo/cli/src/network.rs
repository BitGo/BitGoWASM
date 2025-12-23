//! Network argument type for CLI commands

use clap::ValueEnum;
use wasm_utxo::Network;

/// CLI argument type for network selection
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum NetworkArg {
    Btc,
    Tbtc,
    Tbtc4,
    Ltc,
    Tltc,
    Bch,
    Tbch,
    Bcha,
    Tbcha,
    Btg,
    Tbtg,
    Bsv,
    Tbsv,
    Dash,
    Tdash,
    Doge,
    Tdoge,
    Zec,
    Tzec,
}

impl From<NetworkArg> for Network {
    fn from(arg: NetworkArg) -> Self {
        match arg {
            NetworkArg::Btc => Network::Bitcoin,
            NetworkArg::Tbtc => Network::BitcoinTestnet3,
            NetworkArg::Tbtc4 => Network::BitcoinTestnet4,
            NetworkArg::Ltc => Network::Litecoin,
            NetworkArg::Tltc => Network::LitecoinTestnet,
            NetworkArg::Bch => Network::BitcoinCash,
            NetworkArg::Tbch => Network::BitcoinCashTestnet,
            NetworkArg::Bcha => Network::Ecash,
            NetworkArg::Tbcha => Network::EcashTestnet,
            NetworkArg::Btg => Network::BitcoinGold,
            NetworkArg::Tbtg => Network::BitcoinGoldTestnet,
            NetworkArg::Bsv => Network::BitcoinSV,
            NetworkArg::Tbsv => Network::BitcoinSVTestnet,
            NetworkArg::Dash => Network::Dash,
            NetworkArg::Tdash => Network::DashTestnet,
            NetworkArg::Doge => Network::Dogecoin,
            NetworkArg::Tdoge => Network::DogecoinTestnet,
            NetworkArg::Zec => Network::Zcash,
            NetworkArg::Tzec => Network::ZcashTestnet,
        }
    }
}
