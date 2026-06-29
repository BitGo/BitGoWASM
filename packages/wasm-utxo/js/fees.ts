import { FeesNamespace } from "./wasm/wasm_utxo.js";
import type { CoinName } from "./coinName.js";

/**
 * Maximum fee rate (base units per 1000 virtual bytes) for a coin.
 *
 * Returns `Infinity` when the coin has no fee-rate limit (DOGE/tDOGE). Callers
 * should forward `Infinity` to `BitGoPsbt.extractTransaction(maxFeeRate)` to
 * skip the absurd-fee check during extraction.
 *
 * Production per-coin default. Env-specific overrides (e.g. `local_test_suite`)
 * are applied by the caller (wallet-platform's `fees.ts` wrapper).
 *
 * @param coin - Coin name (e.g., "btc", "tbtc", "doge", "tdoge", "ltc")
 * @returns max fee rate in base units per 1000 virtual bytes, or `Infinity`
 *
 * @example
 * ```typescript
 * import { fixedScriptWallet } from '@bitgo/wasm-utxo';
 * const max = fixedScriptWallet.getMaxFeeRateSatPerKB('tdoge'); // Infinity
 * const maxBtc = fixedScriptWallet.getMaxFeeRateSatPerKB('btc'); // 1_000_000_000
 * ```
 */
export function getMaxFeeRateSatPerKB(coin: CoinName): number {
  return FeesNamespace.getMaxFeeRateSatPerKB(coin);
}

/**
 * Minimum fee rate (base units per 1000 virtual bytes) for a coin.
 *
 * Production per-coin default. Env-specific overrides (e.g. `local_test_suite`
 * lowers DOGE from 50_000_000 to 1_000_000) are applied by the caller.
 *
 * @param coin - Coin name (e.g., "btc", "doge", "ltc")
 * @returns min fee rate in base units per 1000 virtual bytes
 */
export function getMinFeeRateSatPerKB(coin: CoinName): number {
  return FeesNamespace.getMinFeeRateSatPerKB(coin);
}

/**
 * Default fee rate (base units per 1000 virtual bytes) for a coin.
 *
 * Used when the caller does not supply an explicit fee rate. Production
 * per-coin default.
 *
 * @param coin - Coin name (e.g., "btc", "doge", "ltc")
 * @returns default fee rate in base units per 1000 virtual bytes
 */
export function getDefaultFeeRateSatPerKB(coin: CoinName): number {
  return FeesNamespace.getDefaultFeeRateSatPerKB(coin);
}
