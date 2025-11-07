import { FixedScriptWalletNamespace } from "./wasm/wasm_utxo";
import type { UtxolibName, UtxolibNetwork, UtxolibRootWalletKeys } from "./utxolibCompat";
import type { CoinName } from "./coinName";
import { Triple } from "./triple";
import { AddressFormat } from "./address";

export type NetworkName = UtxolibName | CoinName;

export type WalletKeys =
  /** Just an xpub triple, will assume default derivation prefixes  */
  | Triple<string>
  /** Compatible with utxolib RootWalletKeys */
  | UtxolibRootWalletKeys;

/**
 * Create the output script for a given wallet keys and chain and index
 */
export function outputScript(
  keys: WalletKeys,
  chain: number,
  index: number,
  network: UtxolibNetwork,
): Uint8Array {
  return FixedScriptWalletNamespace.output_script(keys, chain, index, network);
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
  keys: WalletKeys,
  chain: number,
  index: number,
  network: UtxolibNetwork,
  addressFormat?: AddressFormat,
): string {
  return FixedScriptWalletNamespace.address(keys, chain, index, network, addressFormat);
}

type ReplayProtection =
  | {
      outputScripts: Uint8Array[];
    }
  | {
      addresses: string[];
    };

export type ScriptId = { chain: number; index: number };

export type ParsedInput = {
  address?: string;
  script: Uint8Array;
  value: bigint;
  scriptId: ScriptId | undefined;
};

export type ParsedOutput = {
  address?: string;
  script: Uint8Array;
  value: bigint;
  scriptId?: ScriptId;
};

export type ParsedTransaction = {
  inputs: ParsedInput[];
  outputs: ParsedOutput[];
  spendAmount: bigint;
  minerFee: bigint;
  virtualSize: number;
};

import { BitGoPsbt as WasmBitGoPsbt } from "./wasm/wasm_utxo";

export class BitGoPsbt {
  private constructor(private wasm: WasmBitGoPsbt) {}

  /**
   * Deserialize a PSBT from bytes
   * @param bytes - The PSBT bytes
   * @param network - The network to use for deserialization (either utxolib name like "bitcoin" or coin name like "btc")
   * @returns A BitGoPsbt instance
   */
  static fromBytes(bytes: Uint8Array, network: NetworkName): BitGoPsbt {
    const wasm = WasmBitGoPsbt.fromBytes(bytes, network);
    return new BitGoPsbt(wasm);
  }

  /**
   * Parse transaction with wallet keys to identify wallet inputs/outputs
   * @param walletKeys - The wallet keys to use for identification
   * @param replayProtection - Scripts that are allowed as inputs without wallet validation
   * @returns Parsed transaction information
   */
  parseTransactionWithWalletKeys(
    walletKeys: WalletKeys,
    replayProtection: ReplayProtection,
  ): ParsedTransaction {
    return this.wasm.parseTransactionWithWalletKeys(walletKeys, replayProtection);
  }
}
