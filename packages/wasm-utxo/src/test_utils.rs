//! Test utilities for wasm-utxo

// Re-export fixtures from fixed_script_wallet test_utils
pub use crate::fixed_script_wallet::test_utils::fixtures;

/// Macro to generate rstest test function with #[case] for all networks in Network::ALL
/// This ensures the test cases stay in sync with Network::ALL
#[macro_export]
macro_rules! test_all_networks {
    ($test_name:ident, $network:ident, $body:block) => {
        #[rstest::rstest]
        #[case::bitcoin($crate::Network::Bitcoin)]
        #[case::bitcoin_testnet3($crate::Network::BitcoinTestnet3)]
        #[case::bitcoin_testnet4($crate::Network::BitcoinTestnet4)]
        #[case::bitcoin_public_signet($crate::Network::BitcoinPublicSignet)]
        #[case::bitcoin_bitgo_signet($crate::Network::BitcoinBitGoSignet)]
        #[case::bitcoin_cash($crate::Network::BitcoinCash)]
        #[case::bitcoin_cash_testnet($crate::Network::BitcoinCashTestnet)]
        #[case::ecash($crate::Network::Ecash)]
        #[case::ecash_testnet($crate::Network::EcashTestnet)]
        #[case::bitcoin_gold($crate::Network::BitcoinGold)]
        #[case::bitcoin_gold_testnet($crate::Network::BitcoinGoldTestnet)]
        #[case::bitcoin_sv($crate::Network::BitcoinSV)]
        #[case::bitcoin_sv_testnet($crate::Network::BitcoinSVTestnet)]
        #[case::dash($crate::Network::Dash)]
        #[case::dash_testnet($crate::Network::DashTestnet)]
        #[case::dogecoin($crate::Network::Dogecoin)]
        #[case::dogecoin_testnet($crate::Network::DogecoinTestnet)]
        #[case::litecoin($crate::Network::Litecoin)]
        #[case::litecoin_testnet($crate::Network::LitecoinTestnet)]
        #[case::zcash($crate::Network::Zcash)]
        #[case::zcash_testnet($crate::Network::ZcashTestnet)]
        #[case::pearl($crate::Network::Pearl)]
        #[case::pearl_testnet($crate::Network::PearlTestnet)]
        #[case::pearl_regtest($crate::Network::PearlRegtest)]
        fn $test_name(#[case] $network: $crate::Network) $body
    };
}
