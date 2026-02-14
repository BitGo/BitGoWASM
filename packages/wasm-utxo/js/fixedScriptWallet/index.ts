import { FixedScriptWalletNamespace } from "../wasm/wasm_utxo.js";
import type { CoinName } from "../coinName.js";

export { RootWalletKeys, type WalletKeysArg, type IWalletKeys } from "./RootWalletKeys.js";
export { ReplayProtection, type ReplayProtectionArg } from "./ReplayProtection.js";
export { outputScript, address } from "./address.js";
export { Dimensions } from "./Dimensions.js";
export {
  outputScriptTypes,
  inputScriptTypes,
  type OutputScriptType,
  type InputScriptType,
  type ScriptType,
} from "./scriptType.js";
export { ChainCode, chainCodes, assertChainCode, type Scope } from "./chains.js";

// Bitcoin-like PSBT (for all non-Zcash networks)
export {
  BitGoPsbt,
  type NetworkName,
  type ScriptId,
  type ParsedInput,
  type ParsedOutput,
  type ParsedTransaction,
  type SignPath,
  type CreateEmptyOptions,
  type AddInputOptions,
  type AddOutputOptions,
  type AddWalletInputOptions,
  type AddWalletOutputOptions,
} from "./BitGoPsbt.js";

// Zcash-specific PSBT subclass
export {
  ZcashBitGoPsbt,
  type ZcashNetworkName,
  type CreateEmptyZcashOptions,
} from "./ZcashBitGoPsbt.js";

// PSBT introspection types (re-exported for consumer convenience)
export type {
  PsbtBip32Derivation,
  PsbtInputData,
  PsbtOutputData,
  PsbtOutputDataWithAddress,
  PsbtWitnessUtxo,
} from "../wasm/wasm_utxo.js";

import type { ScriptType } from "./scriptType.js";

/**
 * Check if a network supports a given fixed-script wallet script type
 *
 * @param coin - Coin name (e.g., "btc", "ltc", "doge")
 * @param scriptType - Output script type or input script type to check
 * @returns `true` if the network supports the script type, `false` otherwise
 *
 * @example
 * ```typescript
 * // Bitcoin supports all script types
 * supportsScriptType("btc", "p2tr"); // true
 *
 * // Litecoin supports segwit but not taproot
 * supportsScriptType("ltc", "p2wsh"); // true
 * supportsScriptType("ltc", "p2tr"); // false
 *
 * // Dogecoin only supports legacy scripts
 * supportsScriptType("doge", "p2sh"); // true
 * supportsScriptType("doge", "p2wsh"); // false
 *
 * // Also works with input script types
 * supportsScriptType("btc", "p2trMusig2KeyPath"); // true
 * supportsScriptType("doge", "p2trLegacy"); // false
 * ```
 */
export function supportsScriptType(coin: CoinName, scriptType: ScriptType): boolean {
  return FixedScriptWalletNamespace.supports_script_type(coin, scriptType);
}

/**
 * Create an OP_RETURN output script with optional data
 *
 * @param data - Optional data bytes to include in the OP_RETURN script
 * @returns The OP_RETURN script as a Uint8Array
 *
 * @example
 * ```typescript
 * // Empty OP_RETURN
 * const script = createOpReturnScript();
 *
 * // OP_RETURN with data
 * const data = new Uint8Array([1, 2, 3, 4]);
 * const script = createOpReturnScript(data);
 * ```
 */
export function createOpReturnScript(data?: Uint8Array): Uint8Array {
  return FixedScriptWalletNamespace.create_op_return_script(data);
}
