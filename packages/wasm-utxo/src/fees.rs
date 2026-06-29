//! Per-coin fee-rate thresholds — the canonical source of truth for UTXO fee policy.
//!
//! Ported from wallet-platform `config/env/utxoCoins/fees.ts`. The values here are
//! the **production** per-coin defaults and are intentionally env-agnostic: this is a
//! pure compute library and does not know about wallet-platform environments
//! (`production` / `testnet` / `local_test_suite` / ...). Callers that need
//! env-specific overrides (e.g. `local_test_suite` lowers the DOGE min from
//! 50_000_000 to 1_000_000) layer those on top via the parametric `max_fee_rate`
//! override on `BitGoPsbt::extract_tx_with_fee_rate`.
//!
//! Units are **base units per 1000 virtual bytes** (sat/kvB), matching
//! `coin.config.tx.maxFeeRateSatPerKB` in wallet-platform. `1 vB = 4 wu`, so
//! `sat/kvB = sat_per_vB * 1000`.

use crate::Network;
use miniscript::bitcoin::FeeRate;

/// Maximum fee rate for a coin, in base units per 1000 virtual bytes.
///
/// Returns `None` to signal "unlimited" — the caller should skip the absurd-fee
/// check entirely (`Psbt::extract_tx_unchecked_fee_rate`).
///
/// - DOGE / tDOGE: unlimited. The DOGE base unit is low-value (~$0.076), so a
///   normal DOGE fee in base units far exceeds rust-bitcoin's BTC-calibrated
///   `DEFAULT_MAX_FEE_RATE` (25_000 sat/vB) and would be falsely rejected.
/// - All other UTXO coins: `1_000_000_000` (1e9 sat/kvB = 1e6 sat/vB) —
///   effectively unlimited but finite, matching wallet-platform's historical
///   default. The real fee sanity check is enforced upstream by wallet-platform's
///   circuit breakers and the build path's `maximumFeeRate`.
pub fn get_max_fee_rate_sat_per_kb(network: Network) -> Option<u64> {
    if network.mainnet() == Network::Dogecoin {
        return None;
    }
    Some(1_000_000_000)
}

/// Minimum fee rate for a coin, in base units per 1000 virtual bytes.
///
/// Production values. `local_test_suite` overrides (DOGE → 1_000_000, LTC → 1_001)
/// are applied by the wallet-platform wrapper, not here.
pub fn get_min_fee_rate_sat_per_kb(network: Network) -> u64 {
    match network {
        Network::Bitcoin
        | Network::BitcoinTestnet3
        | Network::BitcoinTestnet4
        | Network::BitcoinPublicSignet
        | Network::BitcoinBitGoSignet
        | Network::BitcoinRegtest => 101,

        Network::Litecoin => 1_000,
        Network::LitecoinTestnet => 1_001,

        Network::BitcoinCash
        | Network::BitcoinCashTestnet
        | Network::Ecash
        | Network::EcashTestnet
        | Network::BitcoinGold
        | Network::BitcoinGoldTestnet
        | Network::BitcoinSV
        | Network::BitcoinSVTestnet => 1_000,

        Network::Dash => 10_000,
        Network::DashTestnet => 1_001,

        // Production/testnet value. local_test_suite overrides to 1_000_000.
        Network::Dogecoin | Network::DogecoinTestnet => 50_000_000,

        Network::Zcash | Network::ZcashTestnet => 150_000,
    }
}

/// Default fee rate for a coin, in base units per 1000 virtual bytes.
///
/// Used when the caller does not supply an explicit fee rate. Production values.
pub fn get_default_fee_rate_sat_per_kb(network: Network) -> u64 {
    match network.mainnet() {
        Network::Bitcoin => 10_000,
        Network::BitcoinCash | Network::BitcoinSV | Network::Ecash => 2_000,
        Network::BitcoinGold => 5_000,
        Network::Dash => {
            if network.is_mainnet() {
                11_000
            } else {
                1_100
            }
        }
        Network::Dogecoin => get_min_fee_rate_sat_per_kb(network),
        Network::Litecoin => 1_100,
        Network::Zcash => 150_000,
        // Unreachable: mainnet() covers all variants.
        _ => 10_000,
    }
}

/// Fee-rate policy for `BitGoPsbt::extract_tx_with_fee_rate`.
///
/// Controls whether the absurd-fee check runs during PSBT extraction and at what
/// threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeRateLimit {
    /// Use the per-coin default from [`get_max_fee_rate_sat_per_kb`].
    Default,
    /// Skip the absurd-fee check entirely (`extract_tx_unchecked_fee_rate`).
    Unlimited,
    /// Explicit per-call override. `FeeRate` is in rust-bitcoin's internal units
    /// (sat/kwu); construct it via [`FeeRateLimit::from_sat_per_kb`] or
    /// [`FeeRateLimit::from_sat_per_vb`].
    Limited(FeeRate),
}

impl FeeRateLimit {
    /// Build a `Limited` override from a sat/kvB value (wallet-platform's
    /// `maxFeeRateSatPerKB` unit). `sat_per_kb / 1000` yields sat/vB.
    pub fn from_sat_per_kb(sat_per_kb: u64) -> Self {
        let sat_per_vb = sat_per_kb / 1000;
        FeeRateLimit::Limited(FeeRate::from_sat_per_vb_unchecked(sat_per_vb))
    }

    /// Build a `Limited` override from a sat/vB value.
    pub fn from_sat_per_vb(sat_per_vb: u64) -> Self {
        FeeRateLimit::Limited(FeeRate::from_sat_per_vb_unchecked(sat_per_vb))
    }

    /// Resolve `Default` against a network into a concrete `Unlimited` or
    /// `Limited` policy. `Unlimited` and `Limited` pass through unchanged.
    pub fn resolve(self, network: Network) -> Self {
        match self {
            FeeRateLimit::Default => match get_max_fee_rate_sat_per_kb(network) {
                None => FeeRateLimit::Unlimited,
                Some(sat_per_kb) => Self::from_sat_per_kb(sat_per_kb),
            },
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doge_max_is_unlimited() {
        assert_eq!(get_max_fee_rate_sat_per_kb(Network::Dogecoin), None);
        assert_eq!(get_max_fee_rate_sat_per_kb(Network::DogecoinTestnet), None);
    }

    #[test]
    fn non_doge_max_is_finite() {
        assert_eq!(
            get_max_fee_rate_sat_per_kb(Network::Bitcoin),
            Some(1_000_000_000)
        );
        assert_eq!(
            get_max_fee_rate_sat_per_kb(Network::LitecoinTestnet),
            Some(1_000_000_000)
        );
        assert_eq!(
            get_max_fee_rate_sat_per_kb(Network::Zcash),
            Some(1_000_000_000)
        );
    }

    #[test]
    fn min_fee_rates() {
        assert_eq!(get_min_fee_rate_sat_per_kb(Network::Bitcoin), 101);
        assert_eq!(get_min_fee_rate_sat_per_kb(Network::BitcoinTestnet4), 101);
        assert_eq!(get_min_fee_rate_sat_per_kb(Network::Dogecoin), 50_000_000);
        assert_eq!(
            get_min_fee_rate_sat_per_kb(Network::DogecoinTestnet),
            50_000_000
        );
        assert_eq!(get_min_fee_rate_sat_per_kb(Network::Litecoin), 1_000);
        assert_eq!(get_min_fee_rate_sat_per_kb(Network::LitecoinTestnet), 1_001);
        assert_eq!(get_min_fee_rate_sat_per_kb(Network::Dash), 10_000);
        assert_eq!(get_min_fee_rate_sat_per_kb(Network::DashTestnet), 1_001);
        assert_eq!(get_min_fee_rate_sat_per_kb(Network::Zcash), 150_000);
    }

    #[test]
    fn default_fee_rates() {
        assert_eq!(get_default_fee_rate_sat_per_kb(Network::Bitcoin), 10_000);
        assert_eq!(
            get_default_fee_rate_sat_per_kb(Network::Dogecoin),
            50_000_000
        );
        assert_eq!(get_default_fee_rate_sat_per_kb(Network::Dash), 11_000);
        assert_eq!(get_default_fee_rate_sat_per_kb(Network::DashTestnet), 1_100);
        assert_eq!(get_default_fee_rate_sat_per_kb(Network::Litecoin), 1_100);
        assert_eq!(get_default_fee_rate_sat_per_kb(Network::Zcash), 150_000);
    }

    #[test]
    fn default_resolves_to_unlimited_for_doge() {
        assert_eq!(
            FeeRateLimit::Default.resolve(Network::Dogecoin),
            FeeRateLimit::Unlimited
        );
        assert_eq!(
            FeeRateLimit::Default.resolve(Network::DogecoinTestnet),
            FeeRateLimit::Unlimited
        );
    }

    #[test]
    fn default_resolves_to_limited_for_btc() {
        match FeeRateLimit::Default.resolve(Network::Bitcoin) {
            FeeRateLimit::Limited(_) => {}
            other => panic!("expected Limited, got {:?}", other),
        }
    }

    #[test]
    fn unlimited_and_limited_pass_through_resolve() {
        assert_eq!(
            FeeRateLimit::Unlimited.resolve(Network::Bitcoin),
            FeeRateLimit::Unlimited
        );
        let limited = FeeRateLimit::from_sat_per_kb(1_000_000_000);
        assert_eq!(limited.resolve(Network::Dogecoin), limited);
    }
}
