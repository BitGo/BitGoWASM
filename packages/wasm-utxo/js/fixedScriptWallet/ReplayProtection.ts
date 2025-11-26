import { WasmReplayProtection } from "../wasm/wasm_utxo.js";
import { type ECPairArg, ECPair } from "../ecpair.js";

/**
 * ReplayProtectionArg represents the various forms that replay protection can take
 * before being converted to a WasmReplayProtection instance
 */
export type ReplayProtectionArg =
  | ReplayProtection
  | WasmReplayProtection
  | {
      publicKeys: ECPairArg[];
    }
  | {
      /** @deprecated - use publicKeys instead */
      outputScripts: Uint8Array[];
    }
  | {
      /** @deprecated - use publicKeys instead */
      addresses: string[];
    };

/**
 * ReplayProtection wrapper class for PSBT replay protection inputs
 */
export class ReplayProtection {
  private constructor(private _wasm: WasmReplayProtection) {}

  /**
   * Create a ReplayProtection instance from a WasmReplayProtection instance (internal use)
   * @internal
   */
  static fromWasm(wasm: WasmReplayProtection): ReplayProtection {
    return new ReplayProtection(wasm);
  }

  /**
   * Convert ReplayProtectionArg to ReplayProtection instance
   * @param arg - The replay protection in various formats
   * @param network - Optional network string (required for addresses variant)
   * @returns ReplayProtection instance
   */
  static from(arg: ReplayProtectionArg, network?: string): ReplayProtection {
    // Short-circuit if already a ReplayProtection instance
    if (arg instanceof ReplayProtection) {
      return arg;
    }
    // If it's a WasmReplayProtection instance, wrap it
    if (arg instanceof WasmReplayProtection) {
      return new ReplayProtection(arg);
    }

    // Handle object variants
    if ("publicKeys" in arg) {
      // Convert ECPairArg to public key bytes
      const publicKeyBytes = arg.publicKeys.map((key) => ECPair.from(key).publicKey);
      const wasm = WasmReplayProtection.from_public_keys(publicKeyBytes);
      return new ReplayProtection(wasm);
    }

    if ("outputScripts" in arg) {
      const wasm = WasmReplayProtection.from_output_scripts(arg.outputScripts);
      return new ReplayProtection(wasm);
    }

    if ("addresses" in arg) {
      if (!network) {
        throw new Error("Network is required when using addresses variant");
      }
      const wasm = WasmReplayProtection.from_addresses(arg.addresses, network);
      return new ReplayProtection(wasm);
    }

    throw new Error("Invalid ReplayProtectionArg type");
  }

  /**
   * Create from public keys (derives P2SH-P2PK output scripts)
   * @param publicKeys - Array of ECPair instances or arguments
   * @returns ReplayProtection instance
   */
  static fromPublicKeys(publicKeys: ECPairArg[]): ReplayProtection {
    return ReplayProtection.from({ publicKeys });
  }

  /**
   * Create from output scripts
   * @param outputScripts - Array of output script buffers
   * @returns ReplayProtection instance
   */
  static fromOutputScripts(outputScripts: Uint8Array[]): ReplayProtection {
    return ReplayProtection.from({ outputScripts });
  }

  /**
   * Create from addresses
   * @param addresses - Array of address strings
   * @param network - Network string (e.g., "bitcoin", "testnet", "btc", "tbtc")
   * @returns ReplayProtection instance
   */
  static fromAddresses(addresses: string[], network: string): ReplayProtection {
    return ReplayProtection.from({ addresses }, network);
  }

  /**
   * Get the underlying WASM instance (internal use only)
   * @internal
   */
  get wasm(): WasmReplayProtection {
    return this._wasm;
  }
}
