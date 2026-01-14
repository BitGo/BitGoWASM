import { WasmDimensions } from "../wasm/wasm_utxo.js";
import type { BitGoPsbt, InputScriptType, SignPath } from "./BitGoPsbt.js";
import type { CoinName } from "../coinName.js";
import type { OutputScriptType } from "./scriptType.js";
import { toOutputScriptWithCoin } from "../address.js";

type FromInputParams = { chain: number; signPath?: SignPath } | { scriptType: InputScriptType };

/**
 * Options for input dimension calculation
 */
export type FromInputOptions = {
  /**
   * When true, use @bitgo/unspents-compatible signature sizes (72 bytes)
   * for the "max" calculation instead of true maximum (73 bytes).
   */
  utxolibCompat?: boolean;
};

/**
 * Dimensions class for estimating transaction virtual size.
 *
 * Tracks weight internally with min/max bounds to handle ECDSA signature variance.
 * Schnorr signatures have no variance (always 64 bytes).
 *
 * This is a thin wrapper over the WASM implementation.
 */
export class Dimensions {
  private constructor(private _wasm: WasmDimensions) {}

  /**
   * Create empty dimensions (zero weight)
   */
  static empty(): Dimensions {
    return new Dimensions(WasmDimensions.empty());
  }

  /**
   * Create dimensions from a BitGoPsbt
   *
   * Parses PSBT inputs and outputs to compute weight bounds without
   * requiring wallet keys. Input types are detected from BIP32 derivation
   * paths stored in the PSBT.
   */
  static fromPsbt(psbt: BitGoPsbt): Dimensions {
    return new Dimensions(WasmDimensions.from_psbt(psbt.wasm));
  }

  /**
   * Create dimensions for a single input
   *
   * @param params - Either `{ chain, signPath? }` or `{ scriptType }`
   * @param options - Optional settings like `{ utxolibCompat: true }` for @bitgo/unspents-compatible sizing
   */
  static fromInput(params: FromInputParams, options?: FromInputOptions): Dimensions {
    const compat = options?.utxolibCompat;
    if ("scriptType" in params) {
      return new Dimensions(WasmDimensions.from_input_script_type(params.scriptType, compat));
    }
    return new Dimensions(
      WasmDimensions.from_input(
        params.chain,
        params.signPath?.signer,
        params.signPath?.cosigner,
        compat,
      ),
    );
  }

  /**
   * Create dimensions for a single output from script bytes
   */
  static fromOutput(script: Uint8Array): Dimensions;
  /**
   * Create dimensions for a single output from an address
   */
  static fromOutput(address: string, network: CoinName): Dimensions;
  /**
   * Create dimensions for a single output from script length only
   */
  static fromOutput(params: { length: number }): Dimensions;
  /**
   * Create dimensions for a single output from script type
   */
  static fromOutput(params: { scriptType: OutputScriptType }): Dimensions;
  static fromOutput(
    params: Uint8Array | string | { length: number } | { scriptType: OutputScriptType },
    network?: CoinName,
  ): Dimensions {
    if (typeof params === "string") {
      if (network === undefined) {
        throw new Error("network is required when passing an address string");
      }
      const script = toOutputScriptWithCoin(params, network);
      return new Dimensions(WasmDimensions.from_output_script_length(script.length));
    }
    if (typeof params === "object" && "scriptType" in params) {
      return new Dimensions(WasmDimensions.from_output_script_type(params.scriptType));
    }
    // Both Uint8Array and { length: number } have .length
    return new Dimensions(WasmDimensions.from_output_script_length(params.length));
  }

  /**
   * Combine with another Dimensions instance
   */
  plus(other: Dimensions): Dimensions {
    return new Dimensions(this._wasm.plus(other._wasm));
  }

  /**
   * Multiply dimensions by a scalar
   */
  times(n: number): Dimensions {
    return new Dimensions(this._wasm.times(n));
  }

  /**
   * Whether any inputs are segwit (affects overhead calculation)
   */
  get hasSegwit(): boolean {
    return this._wasm.has_segwit();
  }

  /**
   * Get total weight (min or max)
   * @param size - "min" or "max", defaults to "max"
   */
  getWeight(size: "min" | "max" = "max"): number {
    return this._wasm.get_weight(size);
  }

  /**
   * Get virtual size (min or max)
   * @param size - "min" or "max", defaults to "max"
   */
  getVSize(size: "min" | "max" = "max"): number {
    return this._wasm.get_vsize(size);
  }

  /**
   * Get input weight only (min or max)
   * @param size - "min" or "max", defaults to "max"
   */
  getInputWeight(size: "min" | "max" = "max"): number {
    return this._wasm.get_input_weight(size);
  }

  /**
   * Get input virtual size (min or max)
   * @param size - "min" or "max", defaults to "max"
   */
  getInputVSize(size: "min" | "max" = "max"): number {
    return this._wasm.get_input_vsize(size);
  }

  /**
   * Get output weight
   */
  getOutputWeight(): number {
    return this._wasm.get_output_weight();
  }

  /**
   * Get output virtual size
   */
  getOutputVSize(): number {
    return this._wasm.get_output_vsize();
  }
}
