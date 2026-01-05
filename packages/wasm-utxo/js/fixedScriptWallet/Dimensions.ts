import { WasmDimensions } from "../wasm/wasm_utxo.js";
import type { BitGoPsbt, InputScriptType, SignPath } from "./BitGoPsbt.js";
import type { CoinName } from "../coinName.js";
import { toOutputScriptWithCoin } from "../address.js";

type FromInputParams = { chain: number; signPath?: SignPath } | { scriptType: InputScriptType };

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
   */
  static fromInput(params: FromInputParams): Dimensions {
    if ("scriptType" in params) {
      return new Dimensions(WasmDimensions.from_input_script_type(params.scriptType));
    }
    return new Dimensions(
      WasmDimensions.from_input(params.chain, params.signPath?.signer, params.signPath?.cosigner),
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
  static fromOutput(scriptOrAddress: Uint8Array | string, network?: CoinName): Dimensions {
    if (typeof scriptOrAddress === "string") {
      if (network === undefined) {
        throw new Error("network is required when passing an address string");
      }
      const script = toOutputScriptWithCoin(scriptOrAddress, network);
      return new Dimensions(WasmDimensions.from_output_script(script));
    }
    return new Dimensions(WasmDimensions.from_output_script(scriptOrAddress));
  }

  /**
   * Combine with another Dimensions instance
   */
  plus(other: Dimensions): Dimensions {
    return new Dimensions(this._wasm.plus(other._wasm));
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
}
