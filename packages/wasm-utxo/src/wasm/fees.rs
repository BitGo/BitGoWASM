//! JS-exposed fee-rate thresholds and fee-policy helpers.
//!
//! Mirrors `crate::fees` (the canonical per-coin thresholds) for JS callers.
//! Values are in **base units per 1000 virtual bytes** (sat/kvB), matching
//! wallet-platform's `coin.config.tx.maxFeeRateSatPerKB` unit.
//!
//! `maxFeeRate` overrides passed to `extractTransaction(maxFeeRate)` use the
//! same unit and the JS `Infinity` value signals "unlimited" (skip the
//! absurd-fee check).

use wasm_bindgen::prelude::*;

use crate::error::WasmUtxoError;
use crate::fees::{self, FeeRateLimit};
use crate::networks::Network;

/// Parse a network from a utxolib name or coin name (mirrors the private
/// `parse_network` in `wasm::fixed_script_wallet`).
fn parse_network(network_str: &str) -> Result<Network, WasmUtxoError> {
    Network::from_utxolib_name(network_str)
        .or_else(|| Network::from_coin_name(network_str))
        .ok_or_else(|| {
            WasmUtxoError::new(&format!(
                "Unknown network '{}'. Expected a utxolib name (e.g., 'bitcoin', 'testnet') or coin name (e.g., 'btc', 'tbtc')",
                network_str
            ))
        })
}

/// Convert a JS `maxFeeRate` override (sat/kvB, `Infinity` allowed) into a
/// `FeeRateLimit`. `None`/`null`/`undefined` → `Default` (per-coin lookup),
/// `Infinity` → `Unlimited`, any finite number → `Limited`.
pub(crate) fn fee_rate_limit_from_js(max_fee_rate: Option<f64>, network: Network) -> FeeRateLimit {
    match max_fee_rate {
        None => FeeRateLimit::Default,
        Some(x) if x.is_infinite() => FeeRateLimit::Unlimited,
        Some(x) if x <= 0.0 => {
            // A non-positive limit is nonsensical for extraction; treat as
            // unlimited to avoid spuriously rejecting every non-zero-fee tx.
            FeeRateLimit::Unlimited
        }
        Some(x) => {
            let sat_per_vb = (x / 1000.0).round() as u64;
            if sat_per_vb == 0 {
                FeeRateLimit::Unlimited
            } else {
                FeeRateLimit::from_sat_per_vb(sat_per_vb)
            }
        }
    }
    .resolve_default_against(network)
}

impl FeeRateLimit {
    /// `Default` cannot be returned to JS callers meaningfully, so resolve it
    /// against the network here. Used by `fee_rate_limit_from_js`.
    fn resolve_default_against(self, network: Network) -> FeeRateLimit {
        match self {
            FeeRateLimit::Default => match fees::get_max_fee_rate_sat_per_kb(network) {
                None => FeeRateLimit::Unlimited,
                Some(sat_per_kb) => FeeRateLimit::from_sat_per_kb(sat_per_kb),
            },
            other => other,
        }
    }
}

/// JS-exposed per-coin fee-rate thresholds.
///
/// All getters take a network/coin name (utxolib name like `"bitcoin"` or coin
/// name like `"btc"` / `"tdoge"`) and return the production per-coin default.
/// Env-specific overrides (e.g. `local_test_suite`) are applied by the caller.
#[wasm_bindgen]
pub struct FeesNamespace;

#[wasm_bindgen]
impl FeesNamespace {
    /// Maximum fee rate (base units per 1000 virtual bytes) for the coin.
    ///
    /// Returns `Infinity` when the coin has no limit (DOGE/tDOGE); callers
    /// should pass `Infinity` to `extractTransaction(maxFeeRate)` to skip the
    /// absurd-fee check.
    #[wasm_bindgen(js_name = getMaxFeeRateSatPerKB)]
    pub fn get_max_fee_rate_sat_per_kb(coin: &str) -> Result<f64, WasmUtxoError> {
        let network = parse_network(coin)?;
        Ok(match fees::get_max_fee_rate_sat_per_kb(network) {
            None => f64::INFINITY,
            Some(v) => v as f64,
        })
    }

    /// Minimum fee rate (base units per 1000 virtual bytes) for the coin.
    #[wasm_bindgen(js_name = getMinFeeRateSatPerKB)]
    pub fn get_min_fee_rate_sat_per_kb(coin: &str) -> Result<f64, WasmUtxoError> {
        let network = parse_network(coin)?;
        Ok(fees::get_min_fee_rate_sat_per_kb(network) as f64)
    }

    /// Default fee rate (base units per 1000 virtual bytes) for the coin.
    #[wasm_bindgen(js_name = getDefaultFeeRateSatPerKB)]
    pub fn get_default_fee_rate_sat_per_kb(coin: &str) -> Result<f64, WasmUtxoError> {
        let network = parse_network(coin)?;
        Ok(fees::get_default_fee_rate_sat_per_kb(network) as f64)
    }
}
