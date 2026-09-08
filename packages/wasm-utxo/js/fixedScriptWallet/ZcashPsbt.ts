import { BitGoPsbt as WasmBitGoPsbt } from "../wasm/wasm_utxo.js";
import { ZcashBitGoPsbt, type ZcashNetworkName } from "./ZcashBitGoPsbt.js";
import { ZcashIronwoodBitGoPsbt } from "./ZcashIronwoodBitGoPsbt.js";

export type ZcashPsbtInstance = ZcashBitGoPsbt | ZcashIronwoodBitGoPsbt;

/** Factory for deserializing either supported Zcash PSBT format. */
export class ZcashPsbt {
  private constructor() {}

  /**
   * Deserialize a Zcash PSBT and return the format-specific implementation.
   *
   * The version is read from the parsed Zcash metadata, so callers do not need to run a separate
   * byte-level detector or choose a concrete parser before deserializing.
   */
  static from(bytes: Uint8Array, network: ZcashNetworkName): ZcashPsbtInstance {
    const parsed = ZcashBitGoPsbt.fromWasm(WasmBitGoPsbt.from_bytes(bytes, network));
    return parsed.getVersion() === 6 ? ZcashIronwoodBitGoPsbt.fromWasm(parsed.wasm) : parsed;
  }

  static fromBytes(bytes: Uint8Array, network: ZcashNetworkName): ZcashPsbtInstance {
    return ZcashPsbt.from(bytes, network);
  }
}
