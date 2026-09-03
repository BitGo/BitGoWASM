import { ZcashUnifiedAddress as WasmZcashUnifiedAddress } from "../wasm/wasm_utxo.js";
import type { ZcashNetworkName } from "./ZcashBitGoPsbt.js";

/**
 * A parsed ZIP-316 Unified Address.
 *
 * Decode once with {@link ZcashUnifiedAddress.parse}, then read each component
 * through its accessor (returns `undefined` when the receiver is absent). Membership
 * of another address is answered by {@link contains}.
 *
 * Ironwood reuses the Orchard receiver, so {@link orchardReceiver} is the shielded
 * receiver used to construct an Ironwood output note.
 *
 * @example
 * ```typescript
 * const ua = ZcashUnifiedAddress.parse(uaString, "zec");
 * const ironwood = ua.orchardReceiver;      // 43 bytes, or undefined
 * const script = ua.transparentScript;      // scriptPubKey bytes, or undefined
 * ua.hasOrchardReceiver;                    // true iff orchardReceiver is present
 * ua.hasTransparentReceiver;                // true iff transparentScript is present
 * ua.contains(transparentAddress);          // is it one of this UA's receivers?
 * ```
 */
export class ZcashUnifiedAddress {
  private constructor(private _wasm: WasmZcashUnifiedAddress) {}

  /**
   * Parse a Unified Address.
   *
   * @param address - The Bech32m unified address string
   * @param network - Zcash network name ("zcash", "zcashTest", "zec", "tzec")
   * @throws If the address is malformed or on the wrong network
   */
  static parse(address: string, network: ZcashNetworkName): ZcashUnifiedAddress {
    return new ZcashUnifiedAddress(WasmZcashUnifiedAddress.parse(address, network));
  }

  /**
   * The Orchard (a.k.a. Ironwood) receiver — 43 raw bytes (11-byte diversifier +
   * 32-byte pk_d) — or `undefined` if the UA has no Orchard receiver.
   */
  get orchardReceiver(): Uint8Array | undefined {
    return this._wasm.orchardReceiver;
  }

  /**
   * The Sapling receiver — 43 raw bytes (diversifier + pk_d) — or `undefined`.
   */
  get saplingReceiver(): Uint8Array | undefined {
    return this._wasm.saplingReceiver;
  }

  /**
   * The transparent receiver as scriptPubKey bytes (P2PKH or P2SH), ready to use as
   * a `TxOut.scriptPubKey`, or `undefined` if the UA has no transparent receiver.
   */
  get transparentScript(): Uint8Array | undefined {
    return this._wasm.transparentScript;
  }

  /**
   * Whether this Unified Address carries an Orchard/Ironwood receiver.
   *
   * Equivalent to `orchardReceiver !== undefined`; prefer this when only presence
   * matters, since it avoids copying the receiver bytes.
   */
  get hasOrchardReceiver(): boolean {
    return this._wasm.hasOrchardReceiver;
  }

  /**
   * Whether this Unified Address carries a transparent (P2PKH/P2SH) receiver.
   *
   * Equivalent to `transparentScript !== undefined`; prefer this when only presence
   * matters, since it avoids copying the script bytes.
   */
  get hasTransparentReceiver(): boolean {
    return this._wasm.hasTransparentReceiver;
  }

  /**
   * Whether `candidate` is a receiver of this unified address.
   *
   * @param candidate - Another Unified Address (matches if all of its receivers are
   *   contained here) or a transparent Zcash address (matches this UA's transparent
   *   receiver). Must be on the same network as this UA.
   * @throws If `candidate` is malformed or on the wrong network
   */
  contains(candidate: string): boolean {
    return this._wasm.contains(candidate);
  }

  /**
   * Encode a raw 43-byte Orchard/Ironwood receiver as a single-receiver Unified Address.
   *
   * Deliberately narrower than a general UA encoder: this always produces exactly one receiver,
   * so it can't reproduce a multi-receiver UA (transparent + Sapling + Orchard) a sender might
   * have originally pasted in — it only gives back *a* valid, usable address for the
   * Orchard/Ironwood receiver itself.
   *
   * @param receiver - 43-byte raw Orchard/Ironwood receiver
   * @param network - Zcash network name ("zcash", "zcashTest", "zec", "tzec")
   * @throws If `receiver` is not 43 bytes, or `network` is unrecognized
   */
  static encodeOrchardReceiver(receiver: Uint8Array, network: ZcashNetworkName): string {
    return WasmZcashUnifiedAddress.encodeOrchardReceiver(receiver, network);
  }

  /** @internal */
  get wasm(): WasmZcashUnifiedAddress {
    return this._wasm;
  }
}
