import type { PsbtInputData, PsbtOutputData, PsbtOutputDataWithAddress } from "./wasm/wasm_utxo.js";
import type { BIP32 } from "./bip32.js";
import type { ITransactionCommon } from "./transaction.js";
import type { PsbtKvKey } from "./fixedScriptWallet/BitGoKeySubtype.js";

/** Common interface for PSBT types */
export interface IPsbt extends ITransactionCommon<PsbtInputData, PsbtOutputData> {
  getGlobalXpubs(): BIP32[];
  unsignedTxId(): string;
  addInputAtIndex(
    index: number,
    txid: string,
    vout: number,
    value: bigint,
    script: Uint8Array,
    sequence?: number,
  ): number;
  addOutputAtIndex(index: number, script: Uint8Array, value: bigint): number;
  removeInput(index: number): void;
  removeOutput(index: number): void;
  setKV(key: PsbtKvKey, value: Uint8Array): void;
  getKV(key: PsbtKvKey): Uint8Array | undefined;
  deleteKV(key: PsbtKvKey): void;
  setInputKV(index: number, key: PsbtKvKey, value: Uint8Array): void;
  getInputKV(index: number, key: PsbtKvKey): Uint8Array | undefined;
  deleteInputKV(index: number, key: PsbtKvKey): void;
  setOutputKV(index: number, key: PsbtKvKey, value: Uint8Array): void;
  getOutputKV(index: number, key: PsbtKvKey): Uint8Array | undefined;
  deleteOutputKV(index: number, key: PsbtKvKey): void;
}

/** Extended PSBT with address resolution (no coin parameter needed) */
export interface IPsbtWithAddress extends IPsbt {
  getOutputsWithAddress(): PsbtOutputDataWithAddress[];
}

/** PSBT magic bytes: "psbt" (0x70 0x73 0x62 0x74) followed by separator 0xff */
const PSBT_MAGIC = new Uint8Array([0x70, 0x73, 0x62, 0x74, 0xff]);

/**
 * Check if a byte array has the PSBT magic bytes
 *
 * PSBTs start with the magic bytes "psbt" (0x70 0x73 0x62 0x74) followed by a separator 0xff.
 * This method checks if the given bytes start with these 5 magic bytes.
 *
 * @param bytes - The byte array to check
 * @returns true if the bytes start with PSBT magic, false otherwise
 *
 * @example
 * ```typescript
 * import { hasPsbtMagic } from "@bitgo/wasm-utxo";
 *
 * if (hasPsbtMagic(data)) {
 *   const psbt = BitGoPsbt.fromBytes(data, network);
 * }
 * ```
 */
export function hasPsbtMagic(bytes: Uint8Array): boolean {
  if (bytes.length < PSBT_MAGIC.length) {
    return false;
  }
  for (let i = 0; i < PSBT_MAGIC.length; i++) {
    if (bytes[i] !== PSBT_MAGIC[i]) {
      return false;
    }
  }
  return true;
}
