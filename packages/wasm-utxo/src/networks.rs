//! Definitions of various bitcoin-like networks
// Inspired by https://github.com/BitGo/BitGoJS/blob/master/modules/utxo-lib/src/networks.ts but
// with a few naming improvements.
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    // https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp
    // https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp
    Bitcoin,
    BitcoinTestnet3,
    BitcoinTestnet4,
    BitcoinPublicSignet,
    BitcoinBitGoSignet,

    // https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/master/src/validation.cpp
    // https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/master/src/chainparams.cpp
    BitcoinCash,
    BitcoinCashTestnet,

    // https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/validation.cpp
    // https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/chainparams.cpp
    Ecash,
    EcashTestnet,

    // https://github.com/BTCGPU/BTCGPU/blob/master/src/validation.cpp
    // https://github.com/BTCGPU/BTCGPU/blob/master/src/chainparams.cpp
    BitcoinGold,
    BitcoinGoldTestnet,

    // https://github.com/bitcoin-sv/bitcoin-sv/blob/master/src/validation.cpp
    // https://github.com/bitcoin-sv/bitcoin-sv/blob/master/src/chainparams.cpp
    BitcoinSV,
    BitcoinSVTestnet,

    // https://github.com/dashpay/dash/blob/master/src/validation.cpp
    // https://github.com/dashpay/dash/blob/master/src/chainparams.cpp
    Dash,
    DashTestnet,

    // https://github.com/dogecoin/dogecoin/blob/master/src/validation.cpp
    // https://github.com/dogecoin/dogecoin/blob/master/src/chainparams.cpp
    Dogecoin,
    DogecoinTestnet,

    // https://github.com/litecoin-project/litecoin/blob/master/src/validation.cpp
    // https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp
    Litecoin,
    LitecoinTestnet,

    // https://github.com/zcash/zcash/blob/master/src/validation.cpp
    // https://github.com/zcash/zcash/blob/master/src/chainparams.cpp
    Zcash,
    ZcashTestnet,
}

impl Network {
    /// Array containing all network variants
    pub const ALL: &'static [Network] = &[
        Network::Bitcoin,
        Network::BitcoinTestnet3,
        Network::BitcoinTestnet4,
        Network::BitcoinPublicSignet,
        Network::BitcoinBitGoSignet,
        Network::BitcoinCash,
        Network::BitcoinCashTestnet,
        Network::Ecash,
        Network::EcashTestnet,
        Network::BitcoinGold,
        Network::BitcoinGoldTestnet,
        Network::BitcoinSV,
        Network::BitcoinSVTestnet,
        Network::Dash,
        Network::DashTestnet,
        Network::Dogecoin,
        Network::DogecoinTestnet,
        Network::Litecoin,
        Network::LitecoinTestnet,
        Network::Zcash,
        Network::ZcashTestnet,
    ];

    /// Returns the canonical string name of this network
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Bitcoin => "Bitcoin",
            Network::BitcoinTestnet3 => "BitcoinTestnet3",
            Network::BitcoinTestnet4 => "BitcoinTestnet4",
            Network::BitcoinPublicSignet => "BitcoinPublicSignet",
            Network::BitcoinBitGoSignet => "BitcoinBitGoSignet",
            Network::BitcoinCash => "BitcoinCash",
            Network::BitcoinCashTestnet => "BitcoinCashTestnet",
            Network::Ecash => "Ecash",
            Network::EcashTestnet => "EcashTestnet",
            Network::BitcoinGold => "BitcoinGold",
            Network::BitcoinGoldTestnet => "BitcoinGoldTestnet",
            Network::BitcoinSV => "BitcoinSV",
            Network::BitcoinSVTestnet => "BitcoinSVTestnet",
            Network::Dash => "Dash",
            Network::DashTestnet => "DashTestnet",
            Network::Dogecoin => "Dogecoin",
            Network::DogecoinTestnet => "DogecoinTestnet",
            Network::Litecoin => "Litecoin",
            Network::LitecoinTestnet => "LitecoinTestnet",
            Network::Zcash => "Zcash",
            Network::ZcashTestnet => "ZcashTestnet",
        }
    }

    pub fn from_name_exact(name: &str) -> Option<Network> {
        match name {
            "Bitcoin" => Some(Network::Bitcoin),
            "BitcoinTestnet3" => Some(Network::BitcoinTestnet3),
            "BitcoinTestnet4" => Some(Network::BitcoinTestnet4),
            "BitcoinPublicSignet" => Some(Network::BitcoinPublicSignet),
            "BitcoinBitGoSignet" => Some(Network::BitcoinBitGoSignet),

            "BitcoinCash" => Some(Network::BitcoinCash),
            "BitcoinCashTestnet" => Some(Network::BitcoinCashTestnet),

            "Ecash" => Some(Network::Ecash),
            "EcashTestnet" => Some(Network::EcashTestnet),

            "BitcoinGold" => Some(Network::BitcoinGold),
            "BitcoinGoldTestnet" => Some(Network::BitcoinGoldTestnet),

            "BitcoinSV" => Some(Network::BitcoinSV),
            "BitcoinSVTestnet" => Some(Network::BitcoinSVTestnet),

            "Dash" => Some(Network::Dash),
            "DashTestnet" => Some(Network::DashTestnet),

            "Dogecoin" => Some(Network::Dogecoin),
            "DogecoinTestnet" => Some(Network::DogecoinTestnet),

            "Litecoin" => Some(Network::Litecoin),
            "LitecoinTestnet" => Some(Network::LitecoinTestnet),

            "Zcash" => Some(Network::Zcash),
            "ZcashTestnet" => Some(Network::ZcashTestnet),

            _ => None,
        }
    }

    /// Convert a network name from @bitgo/utxo-lib to a Network enum value.
    pub fn from_utxolib_name(name: &str) -> Option<Network> {
        // Using table from
        // https://github.com/BitGo/BitGoJS/blob/%40bitgo/utxo-lib%4011.13.0/modules/utxo-lib/src/networks.ts
        match name {
            "bitcoin" => Some(Network::Bitcoin),
            "testnet" => Some(Network::BitcoinTestnet3),
            "bitcoinPublicSignet" => Some(Network::BitcoinPublicSignet),
            "bitcoinTestnet4" => Some(Network::BitcoinTestnet4),
            "bitcoinBitGoSignet" => Some(Network::BitcoinBitGoSignet),
            "bitcoincash" => Some(Network::BitcoinCash),
            "bitcoincashTestnet" => Some(Network::BitcoinCashTestnet),
            "ecash" => Some(Network::Ecash),
            "ecashTest" => Some(Network::EcashTestnet),
            "bitcoingold" => Some(Network::BitcoinGold),
            "bitcoingoldTestnet" => Some(Network::BitcoinGoldTestnet),
            "bitcoinsv" => Some(Network::BitcoinSV),
            "bitcoinsvTestnet" => Some(Network::BitcoinSVTestnet),
            "dash" => Some(Network::Dash),
            "dashTest" => Some(Network::DashTestnet),
            "dogecoin" => Some(Network::Dogecoin),
            "dogecoinTest" => Some(Network::DogecoinTestnet),
            "litecoin" => Some(Network::Litecoin),
            "litecoinTest" => Some(Network::LitecoinTestnet),
            "zcash" => Some(Network::Zcash),
            "zcashTest" => Some(Network::ZcashTestnet),
            _ => None,
        }
    }

    pub fn to_utxolib_name(&self) -> &'static str {
        match self {
            Network::Bitcoin => "bitcoin",
            Network::BitcoinTestnet3 => "testnet",
            Network::BitcoinTestnet4 => "bitcoinTestnet4",
            Network::BitcoinPublicSignet => "bitcoinPublicSignet",
            Network::BitcoinBitGoSignet => "bitcoinBitGoSignet",
            Network::BitcoinCash => "bitcoincash",
            Network::BitcoinCashTestnet => "bitcoincashTestnet",
            Network::Ecash => "ecash",
            Network::EcashTestnet => "ecashTest",
            Network::BitcoinGold => "bitcoingold",
            Network::BitcoinGoldTestnet => "bitcoingoldTestnet",
            Network::BitcoinSV => "bitcoinsv",
            Network::BitcoinSVTestnet => "bitcoinsvTestnet",
            Network::Dash => "dash",
            Network::DashTestnet => "dashTest",
            Network::Dogecoin => "dogecoin",
            Network::DogecoinTestnet => "dogecoinTest",
            Network::Litecoin => "litecoin",
            Network::LitecoinTestnet => "litecoinTest",
            Network::Zcash => "zcash",
            Network::ZcashTestnet => "zcashTest",
        }
    }

    /// Convert from a bitgo coin name to a Network enum value.
    pub fn from_coin_name(name: &str) -> Option<Network> {
        match name {
            "btc" => Some(Network::Bitcoin),
            "tbtc" => Some(Network::BitcoinTestnet3),
            "tbtc4" => Some(Network::BitcoinTestnet4),
            "tbtcsig" => Some(Network::BitcoinPublicSignet),
            "tbtcbgsig" => Some(Network::BitcoinBitGoSignet),
            "bch" => Some(Network::BitcoinCash),
            "tbch" => Some(Network::BitcoinCashTestnet),
            "bcha" => Some(Network::Ecash),
            "tbcha" => Some(Network::EcashTestnet),
            "btg" => Some(Network::BitcoinGold),
            "tbtg" => Some(Network::BitcoinGoldTestnet),
            "bsv" => Some(Network::BitcoinSV),
            "tbsv" => Some(Network::BitcoinSVTestnet),
            "dash" => Some(Network::Dash),
            "tdash" => Some(Network::DashTestnet),
            "doge" => Some(Network::Dogecoin),
            "tdoge" => Some(Network::DogecoinTestnet),
            "ltc" => Some(Network::Litecoin),
            "tltc" => Some(Network::LitecoinTestnet),
            "zec" => Some(Network::Zcash),
            "tzec" => Some(Network::ZcashTestnet),
            _ => None,
        }
    }

    /// Convert to a BitGo coin name.
    pub fn to_coin_name(&self) -> &'static str {
        match self {
            Network::Bitcoin => "btc",
            Network::BitcoinTestnet3 => "tbtc",
            Network::BitcoinTestnet4 => "tbtc4",
            Network::BitcoinPublicSignet => "tbtcsig",
            Network::BitcoinBitGoSignet => "tbtcbgsig",
            Network::BitcoinCash => "bch",
            Network::BitcoinCashTestnet => "tbch",
            Network::Ecash => "bcha",
            Network::EcashTestnet => "tbcha",
            Network::BitcoinGold => "btg",
            Network::BitcoinGoldTestnet => "tbtg",
            Network::BitcoinSV => "bsv",
            Network::BitcoinSVTestnet => "tbsv",
            Network::Dash => "dash",
            Network::DashTestnet => "tdash",
            Network::Dogecoin => "doge",
            Network::DogecoinTestnet => "tdoge",
            Network::Litecoin => "ltc",
            Network::LitecoinTestnet => "tltc",
            Network::Zcash => "zec",
            Network::ZcashTestnet => "tzec",
        }
    }

    pub fn mainnet(self) -> Network {
        match self {
            Network::Bitcoin
            | Network::BitcoinTestnet3
            | Network::BitcoinTestnet4
            | Network::BitcoinPublicSignet
            | Network::BitcoinBitGoSignet => Network::Bitcoin,

            Network::BitcoinCash => Network::BitcoinCash,
            Network::BitcoinCashTestnet => Network::BitcoinCash,

            Network::Ecash => Network::Ecash,
            Network::EcashTestnet => Network::Ecash,

            Network::BitcoinGold => Network::BitcoinGold,
            Network::BitcoinGoldTestnet => Network::BitcoinGold,

            Network::BitcoinSV => Network::BitcoinSV,
            Network::BitcoinSVTestnet => Network::BitcoinSV,

            Network::Dash => Network::Dash,
            Network::DashTestnet => Network::Dash,

            Network::Dogecoin => Network::Dogecoin,
            Network::DogecoinTestnet => Network::Dogecoin,

            Network::Litecoin => Network::Litecoin,
            Network::LitecoinTestnet => Network::Litecoin,

            Network::Zcash => Network::Zcash,
            Network::ZcashTestnet => Network::Zcash,
        }
    }

    pub fn is_mainnet(self) -> bool {
        self == self.mainnet()
    }

    pub fn is_testnet(self) -> bool {
        !self.is_mainnet()
    }

    /// Convert to bitcoin crate Network type for address encoding
    pub fn to_bitcoin_network(self) -> crate::bitcoin::Network {
        use crate::bitcoin::Network as BitcoinNetwork;
        match self {
            Network::Bitcoin => BitcoinNetwork::Bitcoin,
            Network::BitcoinTestnet3 => BitcoinNetwork::Testnet,
            Network::BitcoinTestnet4 => BitcoinNetwork::Testnet,
            Network::BitcoinPublicSignet => BitcoinNetwork::Signet,
            Network::BitcoinBitGoSignet => BitcoinNetwork::Signet,
            // Non-Bitcoin networks - use Bitcoin mainnet/testnet based on whether they're mainnet
            _ => {
                if self.is_mainnet() {
                    BitcoinNetwork::Bitcoin
                } else {
                    BitcoinNetwork::Testnet
                }
            }
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Network::from_name_exact(s).ok_or_else(|| format!("Unknown network: {}", s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_utxolib_name_all() {
        let names = vec![
            ("bitcoin", Network::Bitcoin),
            ("testnet", Network::BitcoinTestnet3),
            ("bitcoinPublicSignet", Network::BitcoinPublicSignet),
            ("bitcoinTestnet4", Network::BitcoinTestnet4),
            ("bitcoinBitGoSignet", Network::BitcoinBitGoSignet),
            ("bitcoincash", Network::BitcoinCash),
            ("bitcoincashTestnet", Network::BitcoinCashTestnet),
            ("ecash", Network::Ecash),
            ("ecashTest", Network::EcashTestnet),
            ("bitcoingold", Network::BitcoinGold),
            ("bitcoingoldTestnet", Network::BitcoinGoldTestnet),
            ("bitcoinsv", Network::BitcoinSV),
            ("bitcoinsvTestnet", Network::BitcoinSVTestnet),
            ("dash", Network::Dash),
            ("dashTest", Network::DashTestnet),
            ("dogecoin", Network::Dogecoin),
            ("dogecoinTest", Network::DogecoinTestnet),
            ("litecoin", Network::Litecoin),
            ("litecoinTest", Network::LitecoinTestnet),
            ("zcash", Network::Zcash),
            ("zcashTest", Network::ZcashTestnet),
        ];

        for (name, network) in names {
            assert_eq!(
                Network::from_utxolib_name(name),
                Some(network),
                "Failed for name: {}",
                name
            );
            assert_eq!(
                network.to_utxolib_name(),
                name,
                "Failed for network: {}",
                network
            );
        }
    }

    #[test]
    fn test_all_networks() {
        // Verify ALL contains all networks
        assert_eq!(Network::ALL.len(), 21);

        // Verify no duplicates
        for (i, network1) in Network::ALL.iter().enumerate() {
            for (j, network2) in Network::ALL.iter().enumerate() {
                if i != j {
                    assert_ne!(network1, network2);
                }
            }
        }
    }

    #[test]
    fn test_display() {
        assert_eq!(Network::Bitcoin.to_string(), "Bitcoin");
        assert_eq!(Network::BitcoinTestnet3.to_string(), "BitcoinTestnet3");
        assert_eq!(Network::BitcoinCash.to_string(), "BitcoinCash");
        assert_eq!(Network::Ecash.to_string(), "Ecash");
        assert_eq!(Network::Litecoin.to_string(), "Litecoin");
    }

    #[test]
    fn test_from_str() {
        assert_eq!("Bitcoin".parse::<Network>().unwrap(), Network::Bitcoin);
        assert_eq!(
            "BitcoinTestnet3".parse::<Network>().unwrap(),
            Network::BitcoinTestnet3
        );
        assert_eq!(
            "BitcoinCash".parse::<Network>().unwrap(),
            Network::BitcoinCash
        );
        assert_eq!("Ecash".parse::<Network>().unwrap(), Network::Ecash);

        // Test invalid network
        assert!("InvalidNetwork".parse::<Network>().is_err());
    }

    #[test]
    fn test_roundtrip_all_networks() {
        // Test that all networks can be converted to string and back
        for &network in Network::ALL {
            let string = network.to_string();
            let parsed = string.parse::<Network>().unwrap();
            assert_eq!(network, parsed, "Round-trip failed for {}", string);
        }
    }

    #[test]
    fn test_roundtrip_as_str() {
        // Test that as_str() matches to_string() and round-trips correctly
        for &network in Network::ALL {
            let as_str = network.as_str();
            let to_string = network.to_string();
            assert_eq!(
                as_str, to_string,
                "as_str and to_string mismatch for {:?}",
                network
            );

            let parsed = Network::from_name_exact(as_str).unwrap();
            assert_eq!(
                network, parsed,
                "Round-trip via as_str failed for {}",
                as_str
            );
        }
    }

    #[test]
    fn test_mainnet_mapping() {
        // Test that mainnet() correctly maps testnets to mainnets
        assert_eq!(Network::Bitcoin.mainnet(), Network::Bitcoin);
        assert_eq!(Network::BitcoinTestnet3.mainnet(), Network::Bitcoin);
        assert_eq!(Network::BitcoinTestnet4.mainnet(), Network::Bitcoin);
        assert_eq!(Network::BitcoinPublicSignet.mainnet(), Network::Bitcoin);
        assert_eq!(Network::BitcoinBitGoSignet.mainnet(), Network::Bitcoin);

        assert_eq!(Network::BitcoinCash.mainnet(), Network::BitcoinCash);
        assert_eq!(Network::BitcoinCashTestnet.mainnet(), Network::BitcoinCash);

        assert_eq!(Network::Litecoin.mainnet(), Network::Litecoin);
        assert_eq!(Network::LitecoinTestnet.mainnet(), Network::Litecoin);
    }

    #[test]
    fn test_is_mainnet() {
        assert!(Network::Bitcoin.is_mainnet());
        assert!(!Network::BitcoinTestnet3.is_mainnet());
        assert!(!Network::BitcoinTestnet4.is_mainnet());
        assert!(Network::BitcoinCash.is_mainnet());
        assert!(!Network::BitcoinCashTestnet.is_mainnet());
        assert!(Network::Litecoin.is_mainnet());
        assert!(!Network::LitecoinTestnet.is_mainnet());
    }

    #[test]
    fn test_is_testnet() {
        assert!(!Network::Bitcoin.is_testnet());
        assert!(Network::BitcoinTestnet3.is_testnet());
        assert!(Network::BitcoinTestnet4.is_testnet());
        assert!(!Network::BitcoinCash.is_testnet());
        assert!(Network::BitcoinCashTestnet.is_testnet());
        assert!(!Network::Litecoin.is_testnet());
        assert!(Network::LitecoinTestnet.is_testnet());
    }

    #[test]
    fn test_coin_name_round_trip() {
        // Test that all networks can be converted to coin name and back
        for &network in Network::ALL {
            let coin_name = network.to_coin_name();
            let parsed = Network::from_coin_name(coin_name).unwrap();
            assert_eq!(
                network, parsed,
                "Round-trip failed for {:?} (coin_name: {})",
                network, coin_name
            );
        }
    }

    #[test]
    fn test_to_coin_name() {
        assert_eq!(Network::Bitcoin.to_coin_name(), "btc");
        assert_eq!(Network::BitcoinTestnet3.to_coin_name(), "tbtc");
        assert_eq!(Network::BitcoinTestnet4.to_coin_name(), "tbtc4");
        assert_eq!(Network::BitcoinCash.to_coin_name(), "bch");
        assert_eq!(Network::Litecoin.to_coin_name(), "ltc");
        assert_eq!(Network::Zcash.to_coin_name(), "zec");
    }
}
