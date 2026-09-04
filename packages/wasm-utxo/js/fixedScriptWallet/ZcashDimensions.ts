import { WasmDimensions } from "../wasm/wasm_utxo.js";
import type { CoinName } from "../coinName.js";
import type { OutputScriptType } from "./scriptType.js";
import { toShieldedReceiverWithCoin, toTransparentReceiverWithCoin } from "../zcashAddress.js";
import { Dimensions } from "./Dimensions.js";

/**
 * Options for {@link ZcashDimensions.fromOutput}.
 */
export type ZcashFromOutputOptions = {
  /**
   * Set when `address` may be a ZIP-316 Unified Address whose Orchard receiver should be sized
   * as a shielded output. Forwarded to `zcashAddress.toShieldedReceiverWithCoin`; when unset,
   * `zcashAddress.toTransparentReceiverWithCoin` is used instead.
   */
  isShielded?: boolean;
};

/**
 * Zcash-specific dimensions: resolves ZIP-316 Unified Addresses (transparent or Orchard/Ironwood
 * shielded receiver) instead of the plain transparent-only decoding {@link Dimensions.fromOutput}
 * does for every other coin.
 */
export class ZcashDimensions extends Dimensions {
  /**
   * Create dimensions for a single output from script bytes
   */
  static fromOutput(script: Uint8Array): Dimensions;
  /**
   * Create dimensions for a single output from a Zcash address for `network`.
   *
   * Pass `{ isShielded: true }` when `address` may be a ZIP-316 Unified Address whose Orchard
   * receiver should be sized as a shielded output; otherwise its transparent receiver is
   * resolved (a UA with no transparent receiver throws rather than falling back to Orchard).
   */
  static fromOutput(
    address: string,
    network: CoinName,
    options?: ZcashFromOutputOptions,
  ): Dimensions;
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
    options?: ZcashFromOutputOptions,
  ): Dimensions {
    if (typeof params === "string") {
      if (network === undefined) {
        throw new Error("network is required when passing an address string");
      }
      const receiver = options?.isShielded
        ? toShieldedReceiverWithCoin(params, network)
        : toTransparentReceiverWithCoin(params, network);
      return new ZcashDimensions(WasmDimensions.from_output_script_length(receiver.length));
    }
    if (typeof params === "object" && "scriptType" in params) {
      return Dimensions.fromOutput(params);
    }
    // Both Uint8Array and { length: number } have .length
    return Dimensions.fromOutput(params);
  }
}
