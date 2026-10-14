import { WasmZip317Dimensions } from "../wasm/wasm_utxo.js";
import type { BitGoPsbt } from "./BitGoPsbt.js";
import type { CoinName } from "../coinName.js";
import {
  hasOrchardReceiver,
  toShieldedReceiverWithCoin,
  toTransparentReceiverWithCoin,
} from "../zcashAddress.js";

/** The transparent input script types a Zcash wallet can spend. */
export const Zip317InputScriptType = ["p2sh", "p2shP2pk"] as const;
export type Zip317InputScriptType = (typeof Zip317InputScriptType)[number];

/**
 * Options for {@link Zip317Dimensions.fromOutput}.
 */
export type Zip317FromOutputOptions = {
  /**
   * Set when `address` may be a ZIP-316 Unified Address whose Orchard/Ironwood receiver should be
   * paid as a shielded output (one Ironwood output). Resolved like `ZcashDimensions.fromOutput`
   * (via `zcashAddress.toShieldedReceiverWithCoin`): a Unified Address without such a receiver,
   * or a malformed one, throws; an ordinary transparent address is sized as a transparent
   * output. When unset, the address's transparent receiver is sized as a transparent output.
   */
  isShielded?: boolean;
};

/**
 * ZIP-317 dimensions for Zcash conventional fee estimation.
 *
 * Tracks what ZIP-317 prices — the transparent inputs' and outputs' serialized sizes and the
 * Ironwood spends/outputs — rather than bitcoin weight. This is independent of `Dimensions` /
 * `ZcashDimensions`: callers pick the estimator they want (`vsize × feeRate` from those, or
 * {@link Zip317Dimensions.getConventionalFee} from this).
 *
 * Ironwood spends and outputs are tracked separately because bundles are unpadded: the action
 * count is `max(spends, outputs)`, not their sum.
 *
 * This is a thin wrapper over the WASM implementation.
 */
export class Zip317Dimensions {
  private constructor(private _wasm: WasmZip317Dimensions) {}

  /**
   * Create empty dimensions
   */
  static empty(): Zip317Dimensions {
    return new Zip317Dimensions(WasmZip317Dimensions.empty());
  }

  /**
   * Create dimensions from a Zcash BitGoPsbt (any version)
   *
   * Transparent inputs are sized with the scriptSig they will finalize to (the real one once
   * finalized), transparent outputs exactly, and the Ironwood side from the real (non-dummy)
   * spends and outputs of the stored PCZT. After `combineProof` has dropped the PCZT, the counts
   * recorded at extraction are used, so a finalized PSBT still reports its actions and fee.
   *
   * @throws WasmUtxoError `Zip317Error.NotZcashPsbt` for a non-Zcash PSBT, or
   *   `Zip317Error.IronwoodPczt` if the stored PCZT cannot be read
   */
  static fromPsbt(psbt: BitGoPsbt): Zip317Dimensions {
    return new Zip317Dimensions(WasmZip317Dimensions.from_psbt(psbt.wasm));
  }

  /**
   * Create dimensions for a single transparent input
   *
   * @param params - Either `{ chain }` (Zcash wallets only have the P2SH chains 0 and 1) or
   *   `{ scriptType }`
   */
  static fromInput(
    params: { chain: number } | { scriptType: Zip317InputScriptType },
  ): Zip317Dimensions {
    if ("scriptType" in params) {
      return new Zip317Dimensions(WasmZip317Dimensions.from_input_script_type(params.scriptType));
    }
    return new Zip317Dimensions(WasmZip317Dimensions.from_input(params.chain));
  }

  /**
   * Create dimensions for a single transparent output from script bytes
   */
  static fromOutput(script: Uint8Array): Zip317Dimensions;
  /**
   * Create dimensions for a single output from a Zcash address for `network`.
   *
   * With `{ isShielded: true }`, a Unified Address is one Ironwood output (it must carry an
   * Orchard/Ironwood receiver, else this throws) and a transparent address is a transparent
   * output. Otherwise the address's transparent receiver is sized.
   */
  static fromOutput(
    address: string,
    network: CoinName,
    options?: Zip317FromOutputOptions,
  ): Zip317Dimensions;
  /**
   * Create dimensions for a single transparent output from script length only
   */
  static fromOutput(params: { length: number }): Zip317Dimensions;
  static fromOutput(
    params: Uint8Array | string | { length: number },
    network?: CoinName,
    options?: Zip317FromOutputOptions,
  ): Zip317Dimensions {
    if (typeof params === "string") {
      if (network === undefined) {
        throw new Error("network is required when passing an address string");
      }
      if (options?.isShielded && hasOrchardReceiver(params, network)) {
        return Zip317Dimensions.fromIronwoodOutputs(1);
      }
      // For `isShielded`, this throws for a Unified Address without an Orchard/Ironwood receiver
      // (or a malformed one) and returns a transparent address's scriptPubKey.
      const script = options?.isShielded
        ? toShieldedReceiverWithCoin(params, network)
        : toTransparentReceiverWithCoin(params, network);
      return new Zip317Dimensions(WasmZip317Dimensions.from_output_script_length(script.length));
    }
    // Both Uint8Array and { length: number } have .length
    return new Zip317Dimensions(WasmZip317Dimensions.from_output_script_length(params.length));
  }

  /**
   * Create dimensions for `count` Ironwood spends (shielded notes being spent)
   */
  static fromIronwoodSpends(count: number): Zip317Dimensions {
    return new Zip317Dimensions(WasmZip317Dimensions.from_ironwood_spends(count));
  }

  /**
   * Create dimensions for `count` Ironwood (shielded) outputs
   */
  static fromIronwoodOutputs(count: number): Zip317Dimensions {
    return new Zip317Dimensions(WasmZip317Dimensions.from_ironwood_outputs(count));
  }

  /**
   * Combine with another Zip317Dimensions instance
   */
  plus(other: Zip317Dimensions): Zip317Dimensions {
    return new Zip317Dimensions(this._wasm.plus(other._wasm));
  }

  /**
   * Multiply dimensions by a scalar
   */
  times(n: number): Zip317Dimensions {
    return new Zip317Dimensions(this._wasm.times(n));
  }

  /**
   * The sum of the transparent inputs' estimated final serialized sizes, in bytes
   */
  get txInTotalSize(): number {
    return this._wasm.get_tx_in_total_size();
  }

  /**
   * The sum of the transparent outputs' serialized sizes, in bytes
   */
  get txOutTotalSize(): number {
    return this._wasm.get_tx_out_total_size();
  }

  /**
   * The number of Ironwood spends
   */
  get ironwoodSpends(): number {
    return this._wasm.get_ironwood_spends();
  }

  /**
   * The number of Ironwood outputs
   */
  get ironwoodOutputs(): number {
    return this._wasm.get_ironwood_outputs();
  }

  /**
   * The number of Ironwood actions: `max(spends, outputs)`
   */
  get ironwoodActions(): number {
    return this._wasm.get_ironwood_actions();
  }

  /**
   * The ZIP-317 `logical_actions`
   */
  getLogicalActions(): number {
    return this._wasm.get_logical_actions();
  }

  /**
   * The ZIP-317 conventional fee in zatoshi: `5_000 × max(2, logical_actions)`
   */
  getConventionalFee(): bigint {
    return this._wasm.get_conventional_fee();
  }
}
