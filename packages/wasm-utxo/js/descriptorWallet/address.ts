/**
 * Descriptor address generation utilities.
 * Moved from @bitgo/utxo-core.
 */
import { Descriptor } from "../index.js";
import { fromOutputScriptWithCoin } from "../address.js";
import type { CoinName } from "../coinName.js";

export function createScriptPubKeyFromDescriptor(
  descriptor: Descriptor,
  index: number | undefined,
): Uint8Array {
  if (index === undefined) {
    return descriptor.scriptPubkey();
  }
  return createScriptPubKeyFromDescriptor(descriptor.atDerivationIndex(index), undefined);
}

export function createAddressFromDescriptor(
  descriptor: Descriptor,
  index: number | undefined,
  coin: CoinName,
): string {
  return fromOutputScriptWithCoin(createScriptPubKeyFromDescriptor(descriptor, index), coin);
}
