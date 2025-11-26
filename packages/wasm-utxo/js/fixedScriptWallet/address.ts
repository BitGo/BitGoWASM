import { FixedScriptWalletNamespace } from "../wasm/wasm_utxo.js";
import { type WalletKeysArg, RootWalletKeys } from "./RootWalletKeys.js";
import type { UtxolibNetwork } from "../utxolibCompat.js";
import { AddressFormat } from "../address.js";

/**
 * Create the output script for a given wallet keys and chain and index
 */
export function outputScript(
  keys: WalletKeysArg,
  chain: number,
  index: number,
  network: UtxolibNetwork,
): Uint8Array {
  const walletKeys = RootWalletKeys.from(keys);
  return FixedScriptWalletNamespace.output_script(walletKeys.wasm, chain, index, network);
}

/**
 * Create the address for a given wallet keys and chain and index and network.
 * Wrapper for outputScript that also encodes the script to an address.
 * @param keys - The wallet keys to use.
 * @param chain - The chain to use.
 * @param index - The index to use.
 * @param network - The network to use.
 * @param addressFormat - The address format to use.
 *   Only relevant for Bitcoin Cash and eCash networks, where:
 *   - "default" means base58check,
 *   - "cashaddr" means cashaddr.
 */
export function address(
  keys: WalletKeysArg,
  chain: number,
  index: number,
  network: UtxolibNetwork,
  addressFormat?: AddressFormat,
): string {
  const walletKeys = RootWalletKeys.from(keys);
  return FixedScriptWalletNamespace.address(walletKeys.wasm, chain, index, network, addressFormat);
}
