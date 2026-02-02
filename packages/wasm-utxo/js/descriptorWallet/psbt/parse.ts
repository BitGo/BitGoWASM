/**
 * PSBT parsing for descriptor wallets.
 * Moved from @bitgo/utxo-core.
 *
 * This version uses pure TypeScript with PSBT introspection primitives.
 */
import { Descriptor, Psbt } from "../../index.js";
import type { CoinName } from "../../coinName.js";
import { fromOutputScriptWithCoin } from "../../address.js";

import { DescriptorMap } from "../DescriptorMap.js";
import {
  findDescriptorForInput,
  findDescriptorForOutput,
  PsbtInput,
  PsbtOutput,
} from "./findDescriptors.js";
import { getVirtualSize } from "../VirtualSize.js";

/** WASM PsbtOutputData has script and value in addition to PsbtOutput fields */
type PsbtOutputData = PsbtOutput & { script: Uint8Array; value: bigint };

/** Identifier for a script derived from a descriptor */
export type ScriptId = {
  /** The descriptor that generated this script (reference-identical to the one in the map) */
  descriptor: Descriptor;
  /** The derivation index, or undefined for definite descriptors */
  index: number | undefined;
};

export type ParsedInput = {
  address: string;
  value: bigint;
  scriptId: ScriptId;
};

export type ParsedOutput = {
  /** Address string if available (null for non-standard outputs) */
  address: string | null;
  script: Uint8Array;
  value: bigint;
  /** Script identifier if the output matches a descriptor (undefined if no match) */
  scriptId: ScriptId | undefined;
};

export type ParsedDescriptorTransaction = {
  inputs: ParsedInput[];
  outputs: ParsedOutput[];
  spendAmount: bigint;
  minerFee: bigint;
  virtualSize: number;
};

/**
 * Try to get an address from a script, returning null for non-standard outputs.
 */
function tryGetAddress(script: Uint8Array, coin: CoinName): string | null {
  try {
    return fromOutputScriptWithCoin(script, coin);
  } catch {
    return null;
  }
}

/**
 * Parse a PSBT and extract descriptor information.
 *
 * This function uses PSBT introspection to match inputs/outputs against
 * the provided descriptor map.
 *
 * The returned descriptors are reference-identical to those in the input
 * descriptorMap, allowing for `===` comparison.
 *
 * @param psbt - The wasm-utxo Psbt to parse
 * @param descriptorMap - Map of descriptor names to descriptors
 * @param coin - The coin name for address conversion (e.g., "btc", "tbtc")
 * @returns Parsed transaction information
 */
export function parse(
  psbt: Psbt,
  descriptorMap: DescriptorMap,
  coin: CoinName,
): ParsedDescriptorTransaction {
  const rawInputs = psbt.getInputs() as PsbtInput[];
  const rawOutputs = psbt.getOutputs() as PsbtOutputData[];

  let totalInputValue = 0n;
  let totalOutputValue = 0n;
  let spendAmount = 0n;

  const inputs: ParsedInput[] = rawInputs.map((inputData, i) => {
    const witnessUtxo = inputData.witnessUtxo;
    if (!witnessUtxo) {
      throw new Error(`Missing witnessUtxo for input ${i}`);
    }

    const scriptIdResult = findDescriptorForInput(inputData, descriptorMap);
    if (!scriptIdResult) {
      throw new Error(`No descriptor found for input ${i}`);
    }

    const scriptId: ScriptId = {
      descriptor: scriptIdResult.descriptor,
      index: scriptIdResult.index,
    };

    totalInputValue += witnessUtxo.value;

    return {
      address: fromOutputScriptWithCoin(witnessUtxo.script, coin),
      value: witnessUtxo.value,
      scriptId,
    };
  });

  const outputs: ParsedOutput[] = rawOutputs.map((outputData) => {
    const scriptIdResult = findDescriptorForOutput(outputData.script, outputData, descriptorMap);

    const scriptId: ScriptId | undefined = scriptIdResult
      ? {
          descriptor: scriptIdResult.descriptor,
          index: scriptIdResult.index,
        }
      : undefined;

    totalOutputValue += outputData.value;

    // Outputs without a matching descriptor are external (spend) outputs
    if (!scriptId) {
      spendAmount += outputData.value;
    }

    return {
      address: tryGetAddress(outputData.script, coin),
      script: outputData.script,
      value: outputData.value,
      scriptId,
    };
  });

  const minerFee = totalInputValue - totalOutputValue;

  // Calculate virtual size using the descriptors from parsed inputs
  const virtualSize = getVirtualSize({
    inputs: inputs.map((input) => input.scriptId.descriptor),
    outputs: outputs.map((output) => ({ script: output.script })),
  });

  return {
    inputs,
    outputs,
    spendAmount,
    minerFee,
    virtualSize,
  };
}

/**
 * Parse a serialized PSBT buffer with descriptor information.
 *
 * This is a convenience function that creates a Psbt from bytes before parsing.
 *
 * @param psbtBytes - The serialized PSBT bytes
 * @param descriptorMap - Map of descriptor names to descriptors
 * @param coin - The coin name for address conversion
 * @returns Parsed transaction information
 */
export function parseFromBytes(
  psbtBytes: Uint8Array,
  descriptorMap: DescriptorMap,
  coin: CoinName,
): ParsedDescriptorTransaction {
  const psbt = Psbt.deserialize(psbtBytes);
  return parse(psbt, descriptorMap, coin);
}
