/**
 * PSBT creation for descriptor wallets.
 * Moved from @bitgo/utxo-core.
 *
 * This version uses wasm-utxo Psbt directly without the wrap/unwrap pattern.
 */
import { Miniscript, Psbt } from "../../index.js";

/** Taproot leaf script (inlined from bip174) */
export type TapLeafScript = {
  leafVersion: number;
  script: Uint8Array;
  controlBlock: Uint8Array;
};

import { DerivedDescriptorWalletOutput, WithOptDescriptor } from "../DescriptorOutput.js";
import { Output } from "../Output.js";

import { assertSatisfiable } from "./assertSatisfiable.js";

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Non-Final (Replaceable)
 * Reference: https://github.com/bitcoin/bitcoin/blob/v25.1/src/rpc/rawtransaction_util.cpp#L49
 * */
export const MAX_BIP125_RBF_SEQUENCE = 0xffffffff - 2;

export function findTapLeafScript(
  input: TapLeafScript[],
  script: Uint8Array | Miniscript,
): TapLeafScript {
  if (!(script instanceof Uint8Array)) {
    script = script.encode();
  }
  const scriptBytes = script;
  const matches = input.filter((leaf) => {
    return bytesEqual(leaf.script, scriptBytes);
  });
  if (matches.length === 0) {
    throw new Error(`No tapLeafScript found for script: ${toHex(scriptBytes)}`);
  }
  if (matches.length > 1) {
    throw new Error(`Multiple tapLeafScripts found for script: ${toHex(scriptBytes)}`);
  }
  return matches[0];
}

export type PsbtParams = {
  version?: number;
  locktime?: number;
  sequence?: number;
};

export type DerivedDescriptorTransactionInput = DerivedDescriptorWalletOutput & {
  selectTapLeafScript?: Miniscript;
  sequence?: number;
};

/**
 * Create a PSBT for descriptor wallet transactions.
 *
 * This function uses wasm-utxo Psbt directly without any wrap/unwrap conversions.
 *
 * @param params - PSBT parameters (version, locktime, sequence)
 * @param inputs - Descriptor wallet inputs
 * @param outputs - Outputs with optional descriptors for change
 * @returns A wasm-utxo Psbt instance
 */
export function createPsbt(
  params: PsbtParams,
  inputs: DerivedDescriptorTransactionInput[],
  outputs: WithOptDescriptor<Output>[],
): Psbt {
  const psbt = new Psbt(params.version ?? 2, params.locktime ?? 0);

  // Add inputs
  for (const input of inputs) {
    const sequence = input.sequence ?? params.sequence ?? MAX_BIP125_RBF_SEQUENCE;

    psbt.addInput(
      input.hash,
      input.index,
      input.witnessUtxo.value,
      input.witnessUtxo.script,
      sequence,
    );
  }

  // Add outputs
  for (const output of outputs) {
    psbt.addOutput(output.script, output.value);
  }

  // Update inputs with descriptor metadata
  for (const [inputIndex, input] of inputs.entries()) {
    assertSatisfiable(psbt, inputIndex, input.descriptor);
    psbt.updateInputWithDescriptor(inputIndex, input.descriptor);
  }

  // Update outputs with descriptor metadata (for change outputs)
  for (const [outputIndex, output] of outputs.entries()) {
    if (output.descriptor) {
      psbt.updateOutputWithDescriptor(outputIndex, output.descriptor);
    }
  }

  return psbt;
}
