import { FixedScriptWalletNamespace } from "./wasm/wasm_utxo.js";
import { type WalletKeysArg, RootWalletKeys } from "./WalletKeys.js";
import { type BIP32Arg, BIP32 } from "./bip32.js";
import { type ECPairArg, ECPair } from "./ecpair.js";
import type { UtxolibName, UtxolibNetwork } from "./utxolibCompat.js";
import type { CoinName } from "./coinName.js";
import { AddressFormat } from "./address.js";

export type NetworkName = UtxolibName | CoinName;

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

type ReplayProtection =
  | {
      outputScripts: Uint8Array[];
    }
  | {
      addresses: string[];
    };

export type ScriptId = { chain: number; index: number };

export type InputScriptType =
  | "p2shP2pk"
  | "p2sh"
  | "p2shP2wsh"
  | "p2wsh"
  | "p2trLegacy"
  | "p2trMusig2ScriptPath"
  | "p2trMusig2KeyPath";

export type ParsedInput = {
  address: string;
  script: Uint8Array;
  value: bigint;
  scriptId: ScriptId | null;
  scriptType: InputScriptType;
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
    walletKeys: WalletKeysArg,
    replayProtection: ReplayProtection,
  ): ParsedTransaction {
    const keys = RootWalletKeys.from(walletKeys);
    return this.wasm.parse_transaction_with_wallet_keys(
      keys.wasm,
      replayProtection,
    ) as ParsedTransaction;
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
  parseOutputsWithWalletKeys(walletKeys: WalletKeysArg): ParsedOutput[] {
    const keys = RootWalletKeys.from(walletKeys);
    return this.wasm.parse_outputs_with_wallet_keys(keys.wasm) as ParsedOutput[];
  }

  /**
   * Verify if a valid signature exists for a given key at the specified input index.
   *
   * This method can verify signatures using either:
   * - Extended public key (xpub): Derives the public key using the derivation path from PSBT
   * - ECPair (private key): Extracts the public key and verifies directly
   *
   * When using xpub, it supports:
   * - ECDSA signatures (for legacy/SegWit inputs)
   * - Schnorr signatures (for Taproot script path inputs)
   * - MuSig2 partial signatures (for Taproot keypath MuSig2 inputs)
   *
   * When using ECPair, it supports:
   * - ECDSA signatures (for legacy/SegWit inputs)
   * - Schnorr signatures (for Taproot script path inputs)
   * Note: MuSig2 inputs require xpubs for derivation
   *
   * @param inputIndex - The index of the input to check (0-based)
   * @param key - Either an extended public key (base58 string, BIP32 instance, or WasmBIP32) or an ECPair (private key Buffer, ECPair instance, or WasmECPair)
   * @returns true if a valid signature exists, false if no signature exists
   * @throws Error if input index is out of bounds, key is invalid, or verification fails
   *
   * @example
   * ```typescript
   * // Verify wallet input signature with xpub
   * const hasUserSig = psbt.verifySignature(0, userXpub);
   *
   * // Verify signature with ECPair (private key)
   * const ecpair = ECPair.fromPrivateKey(privateKeyBuffer);
   * const hasReplaySig = psbt.verifySignature(1, ecpair);
   *
   * // Or pass private key directly
   * const hasReplaySig2 = psbt.verifySignature(1, privateKeyBuffer);
   * ```
   */
  verifySignature(inputIndex: number, key: BIP32Arg | ECPairArg): boolean {
    // Try to parse as BIP32Arg first (string or BIP32 instance)
    if (typeof key === "string" || ("derive" in key && typeof key.derive === "function")) {
      const wasmKey = BIP32.from(key as BIP32Arg).wasm;
      return this.wasm.verify_signature_with_xpub(inputIndex, wasmKey);
    }

    // Otherwise it's an ECPairArg (Uint8Array, ECPair, or WasmECPair)
    const wasmECPair = ECPair.from(key as ECPairArg).wasm;
    return this.wasm.verify_signature_with_pub(inputIndex, wasmECPair);
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

  /**
   * Serialize the PSBT to bytes
   *
   * @returns The serialized PSBT as a byte array
   */
  serialize(): Uint8Array {
    return this.wasm.serialize();
  }

  /**
   * Finalize all inputs in the PSBT
   *
   * @throws Error if any input failed to finalize
   */
  finalizeAllInputs(): void {
    this.wasm.finalize_all_inputs();
  }

  /**
   * Extract the final transaction from a finalized PSBT
   *
   * @returns The serialized transaction bytes
   * @throws Error if the PSBT is not fully finalized or extraction fails
   */
  extractTransaction(): Uint8Array {
    return this.wasm.extract_transaction();
  }
}
