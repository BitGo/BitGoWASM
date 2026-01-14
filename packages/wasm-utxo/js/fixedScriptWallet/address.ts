import { FixedScriptWalletNamespace } from "../wasm/wasm_utxo.js";
import { type WalletKeysArg, RootWalletKeys } from "./RootWalletKeys.js";
import type { UtxolibNetwork } from "../utxolibCompat.js";
import type { UtxolibName } from "../utxolibCompat.js";
import type { CoinName } from "../coinName.js";
import { AddressFormat } from "../address.js";

export type NetworkName = UtxolibName | CoinName;

/**
 * Create the output script for a given wallet keys and chain and index
 * @param keys - The wallet keys to use
 * @param chain - The chain to use
 * @param index - The index to use
 * @param network - The network to use. Can be a network name string (e.g., "btc", "bitcoin", "testnet") or a UtxolibNetwork object
 */
export function outputScript(
  keys: WalletKeysArg,
  chain: number,
  index: number,
  network: NetworkName | UtxolibNetwork,
): Uint8Array {
  const walletKeys = RootWalletKeys.from(keys);
  if (typeof network === "string") {
    return FixedScriptWalletNamespace.output_script_with_network_str(
      walletKeys.wasm,
      chain,
      index,
      network,
    );
  } else {
    return FixedScriptWalletNamespace.output_script(walletKeys.wasm, chain, index, network);
  }
}

/**
 * Create the address for a given wallet keys and chain and index and network.
 * Wrapper for outputScript that also encodes the script to an address.
 * @param keys - The wallet keys to use.
 * @param chain - The chain to use.
 * @param index - The index to use.
 * @param network - The network to use. Can be a network name string (e.g., "btc", "bitcoin", "testnet") or a UtxolibNetwork object
 * @param addressFormat - The address format to use.
 *   Only relevant for Bitcoin Cash and eCash networks, where:
 *   - "default" means base58check,
 *   - "cashaddr" means cashaddr.
 */
export function address(
  keys: WalletKeysArg,
  chain: number,
  index: number,
  network: NetworkName | UtxolibNetwork,
  addressFormat?: AddressFormat,
): string {
  const walletKeys = RootWalletKeys.from(keys);
  if (typeof network === "string") {
    return FixedScriptWalletNamespace.address_with_network_str(
      walletKeys.wasm,
      chain,
      index,
      network,
      addressFormat,
    );
  } else {
    return FixedScriptWalletNamespace.address(
      walletKeys.wasm,
      chain,
      index,
      network,
      addressFormat,
    );
  }
}
