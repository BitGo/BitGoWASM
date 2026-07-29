/**
 * Regtest address helpers. Pearl regtest uses CoinName `tpearlreg` (HRP `rprl`).
 */
import { fromOutputScriptWithCoin, toOutputScriptWithCoin } from "../../js/address.js";
import type { CoinName } from "../../js/coinName.js";

/** Address for a script under a CoinName (use `tpearlreg` for Pearl regtest). */
export function toRegtestAddress(script: Uint8Array, coin: CoinName): string {
  return fromOutputScriptWithCoin(script, coin);
}

/** Decode a Pearl regtest (`rprl…`) address to scriptPubKey. */
export function fromPearlRegtestAddress(address: string): Uint8Array {
  return toOutputScriptWithCoin(address, "tpearlreg");
}
