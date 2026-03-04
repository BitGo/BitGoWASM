import type { PsbtInputData, PsbtOutputData, PsbtOutputDataWithAddress } from "./wasm/wasm_utxo.js";
import type { BIP32 } from "./bip32.js";

/** Common interface for PSBT types */
export interface IPsbt {
  inputCount(): number;
  outputCount(): number;
  getInputs(): PsbtInputData[];
  getOutputs(): PsbtOutputData[];
  getGlobalXpubs(): BIP32[];
  version(): number;
  lockTime(): number;
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
