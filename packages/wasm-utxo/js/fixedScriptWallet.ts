import { FixedScriptWalletNamespace } from "./wasm/wasm_utxo.js";
import type { UtxolibName, UtxolibNetwork, UtxolibRootWalletKeys } from "./utxolibCompat.js";
import type { CoinName } from "./coinName.js";
import { Triple } from "./triple.js";
import { AddressFormat } from "./address.js";

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
  address: string;
  script: Uint8Array;
  value: bigint;
  scriptId: ScriptId | null;
};

export type ParsedOutput = {
  address: string | null;
  script: Uint8Array;
  value: bigint;
  scriptId: ScriptId | null;
};

export type ParsedTransaction = {
  inputs: ParsedInput[];
  outputs: ParsedOutput[];
  spendAmount: bigint;
  minerFee: bigint;
  virtualSize: number;
};

import { BitGoPsbt as WasmBitGoPsbt } from "./wasm/wasm_utxo.js";

export class BitGoPsbt {
  private constructor(private wasm: WasmBitGoPsbt) {}

  /**
   * Deserialize a PSBT from bytes
   * @param bytes - The PSBT bytes
   * @param network - The network to use for deserialization (either utxolib name like "bitcoin" or coin name like "btc")
   * @returns A BitGoPsbt instance
   */
  static fromBytes(bytes: Uint8Array, network: NetworkName): BitGoPsbt {
    const wasm = WasmBitGoPsbt.from_bytes(bytes, network);
    return new BitGoPsbt(wasm);
  }

  /**
   * Get the unsigned transaction ID
   * @returns The unsigned transaction ID
   */
  unsignedTxid(): string {
    return this.wasm.unsigned_txid();
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
    return this.wasm.parse_transaction_with_wallet_keys(walletKeys, replayProtection);
  }

  /**
   * Parse outputs with wallet keys to identify which outputs belong to a wallet
   * with the given wallet keys.
   *
   * This is useful in cases where we want to identify outputs that belong to a different
   * wallet than the inputs.
   *
   * @param walletKeys - The wallet keys to use for identification
   * @returns Array of parsed outputs
   * @note This method does NOT validate wallet inputs. It only parses outputs.
   */
  parseOutputsWithWalletKeys(walletKeys: WalletKeys): ParsedOutput[] {
    return this.wasm.parse_outputs_with_wallet_keys(walletKeys);
  }

  /**
   * Verify if a valid signature exists for a given extended public key at the specified input index.
   *
   * This method derives the public key from the xpub using the derivation path found in the
   * PSBT input, then verifies the signature. It supports:
   * - ECDSA signatures (for legacy/SegWit inputs)
   * - Schnorr signatures (for Taproot script path inputs)
   * - MuSig2 partial signatures (for Taproot keypath MuSig2 inputs)
   *
   * @param inputIndex - The index of the input to check (0-based)
   * @param xpub - The extended public key as a base58-encoded string
   * @returns true if a valid signature exists, false if no signature exists
   * @throws Error if input index is out of bounds, xpub is invalid, or verification fails
   */
  verifySignature(inputIndex: number, xpub: string): boolean {
    return this.wasm.verify_signature(inputIndex, xpub);
  }

  /**
   * Verify if a replay protection input has a valid signature.
   *
   * This method checks if a given input is a replay protection input (like P2shP2pk) and verifies
   * the signature. Replay protection inputs don't use standard derivation paths, so this method
   * verifies signatures without deriving from xpub.
   *
   * For P2PK replay protection inputs, this:
   * - Extracts the signature from final_script_sig
   * - Extracts the public key from redeem_script
   * - Computes the legacy P2SH sighash
   * - Verifies the ECDSA signature cryptographically
   *
   * @param inputIndex - The index of the input to check (0-based)
   * @param replayProtection - Scripts that identify replay protection inputs (same format as parseTransactionWithWalletKeys)
   * @returns true if the input is a replay protection input and has a valid signature, false if no valid signature
   * @throws Error if the input is not a replay protection input, index is out of bounds, or scripts are invalid
   */
  verifyReplayProtectionSignature(inputIndex: number, replayProtection: ReplayProtection): boolean {
    return this.wasm.verify_replay_protection_signature(inputIndex, replayProtection);
  }
}
