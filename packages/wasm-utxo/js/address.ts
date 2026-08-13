import { AddressNamespace } from "./wasm/wasm_utxo.js";
import type { CoinName } from "./coinName.js";

/**
 * Most coins only have one unambiguous address format (base58check and bech32/bech32m)
 * For Bitcoin Cash and eCash, we can select between base58check and cashaddr.
 */
export type AddressFormat = "default" | "cashaddr";

/**
 * @param canBeShieldedOutput - When set and `address` is a ZIP-316 unified address carrying an
 * Orchard/Ironwood receiver, returns that raw 43-byte receiver instead of a transparent
 * scriptPubKey (there is no scriptPubKey for a shielded output). `address` is only even
 * attempted as a unified address when this is set. If `address` looks like a unified address for
 * this coin's network but is malformed, or has no Orchard/Ironwood receiver (e.g. Sapling-only),
 * this throws rather than falling back to the transparent path.
 */
export function toOutputScriptWithCoin(
  address: string,
  coin: CoinName,
  canBeShieldedOutput?: boolean,
): Uint8Array {
  return AddressNamespace.to_output_script_with_coin(address, coin, canBeShieldedOutput);
}

export function fromOutputScriptWithCoin(
  script: Uint8Array,
  coin: CoinName,
  format?: AddressFormat,
): string {
  return AddressNamespace.from_output_script_with_coin(script, coin, format);
}
