/**
 * Previous-transaction inclusion policy for fixed-script wallet PSBT inputs.
 *
 * Decides whether a p2sh input requires the full previous transaction
 * (PSBT_IN_NON_WITNESS_UTXO) or can be signed from witness_utxo-only.
 *
 * This is a pure-JS module (no WASM initialization) so callers can evaluate
 * the policy cheaply without loading the wasm-utxo module.
 */
import { type CoinName, getMainnet } from "../coinName.js";

/**
 * Whether a p2sh input requires the full previous transaction
 * (PSBT_IN_NON_WITNESS_UTXO). Callers are expected to have already
 * confirmed the input is p2sh (non-segwit) and that the tx format
 * includes prevTx (e.g. "psbt", not "psbt-lite"); this predicate only
 * answers the coin-level question.
 *
 * Returns false for value-committing coins whose sighash commits the
 * input amount, making `non_witness_utxo` (full prevTx) cryptographically
 * pointless for signing p2sh inputs — `witness_utxo` (value +
 * scriptPubKey) suffices:
 *
 * - Zcash (`zec`/`tzec`): ZIP-243 transparent sighash commits the amount.
 *   Including prevTx also crashes wasm-utxo, whose consensus::deserialize
 *   rejects Zcash overwintered transactions.
 * - BCH family (`bch`/`bcha`/`bsv`/`btg` + testnets): replay-protected
 *   BIP-143 sighash (SIGHASH_FORKID, the default for the whole family)
 *   commits the 8-byte value as preimage item #6. eCash is `bcha`/`tbcha`.
 *   For the BCH family, skipping prevTx is an optimization (no DB fetch)
 *   plus defense-in-depth, with the same fee-validation risk that the
 *   existing `psbt-lite` path already accepts for all coins.
 *
 * Testnets are normalized via `getMainnet` before the switch. True
 * otherwise.
 */
export function requiresPrevTxForP2sh(coinName: CoinName): boolean {
  switch (getMainnet(coinName)) {
    case "zec": // Zcash (ZIP-243)
    case "bch": // Bitcoin Cash (BIP-143/FORKID)
    case "bcha": // eCash (BIP-143/FORKID)
    case "bsv": // Bitcoin SV (BIP-143/FORKID)
    case "btg": // Bitcoin Gold (BIP-143/FORKID)
      return false;
    default:
      return true;
  }
}
