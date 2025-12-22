import { BitGoPsbt as WasmBitGoPsbt } from "../wasm/wasm_utxo.js";
import { type WalletKeysArg, RootWalletKeys } from "./RootWalletKeys.js";
import { BitGoPsbt, type CreateEmptyOptions } from "./BitGoPsbt.js";

/** Zcash network names */
export type ZcashNetworkName = "zcash" | "zcashTest" | "zec" | "tzec";

/** Options for creating an empty Zcash PSBT (preferred method using block height) */
export type CreateEmptyZcashOptions = CreateEmptyOptions & {
  /** Block height to determine consensus branch ID automatically */
  blockHeight: number;
  /** Zcash version group ID (defaults to Sapling: 0x892F2085) */
  versionGroupId?: number;
  /** Zcash transaction expiry height */
  expiryHeight?: number;
};

/** Options for creating an empty Zcash PSBT with explicit consensus branch ID (advanced use) */
export type CreateEmptyZcashWithConsensusBranchIdOptions = CreateEmptyOptions & {
  /** Zcash consensus branch ID (required, e.g., 0xC2D6D0B4 for NU5, 0x76B809BB for Sapling) */
  consensusBranchId: number;
  /** Zcash version group ID (defaults to Sapling: 0x892F2085) */
  versionGroupId?: number;
  /** Zcash transaction expiry height */
  expiryHeight?: number;
};

/**
 * Zcash-specific PSBT implementation
 *
 * This class extends BitGoPsbt with Zcash-specific functionality:
 * - Required consensus branch ID for sighash computation
 * - Version group ID for Zcash transaction format
 * - Expiry height for transaction validity
 *
 * All Zcash-specific getters return non-optional types since they're
 * guaranteed to be present for Zcash PSBTs.
 *
 * @example
 * ```typescript
 * // Create a new Zcash PSBT
 * const psbt = ZcashBitGoPsbt.createEmpty("zcash", walletKeys, {
 *   consensusBranchId: 0x76B809BB,  // Sapling
 * });
 *
 * // Deserialize from bytes
 * const psbt = ZcashBitGoPsbt.fromBytes(bytes, "zcash");
 * ```
 */
export class ZcashBitGoPsbt extends BitGoPsbt {
  /**
   * Create an empty Zcash PSBT with consensus branch ID determined from block height
   *
   * **This is the preferred method for creating Zcash PSBTs.** It automatically determines
   * the correct consensus branch ID based on the network and block height using Zcash
   * network upgrade activation heights, eliminating the need to manually look up branch IDs.
   *
   * @param network - Zcash network name ("zcash", "zcashTest", "zec", "tzec")
   * @param walletKeys - The wallet's root keys (sets global xpubs in the PSBT)
   * @param options - Options including blockHeight to determine consensus rules
   * @returns A new ZcashBitGoPsbt instance
   * @throws Error if block height is before Overwinter activation
   *
   * @example
   * ```typescript
   * // Create PSBT for a specific block height (recommended)
   * const psbt = ZcashBitGoPsbt.createEmpty("zcash", walletKeys, {
   *   blockHeight: 1687104,  // Automatically uses Nu5 branch ID
   * });
   *
   * // Create PSBT for current block height
   * const currentHeight = await getBlockHeight();
   * const psbt = ZcashBitGoPsbt.createEmpty("zcash", walletKeys, {
   *   blockHeight: currentHeight,
   * });
   * ```
   */
  static override createEmpty(
    network: ZcashNetworkName,
    walletKeys: WalletKeysArg,
    options: CreateEmptyZcashOptions,
  ): ZcashBitGoPsbt {
    const keys = RootWalletKeys.from(walletKeys);
    const wasm = WasmBitGoPsbt.create_empty_zcash_at_height(
      network,
      keys.wasm,
      options.blockHeight,
      options.version,
      options.lockTime,
      options.versionGroupId,
      options.expiryHeight,
    );
    return new ZcashBitGoPsbt(wasm);
  }

  /**
   * Create an empty Zcash PSBT with explicit consensus branch ID
   *
   * **Advanced use only.** This method requires manually specifying the consensus branch ID.
   * In most cases, you should use `createEmpty()` instead, which automatically determines
   * the correct branch ID from the block height.
   *
   * @param network - Zcash network name ("zcash", "zcashTest", "zec", "tzec")
   * @param walletKeys - The wallet's root keys (sets global xpubs in the PSBT)
   * @param options - Zcash-specific options including required consensusBranchId
   * @returns A new ZcashBitGoPsbt instance
   *
   * @example
   * ```typescript
   * // Only use this if you need explicit control over the branch ID
   * const psbt = ZcashBitGoPsbt.createEmptyWithConsensusBranchId("zcash", walletKeys, {
   *   consensusBranchId: 0xC2D6D0B4,  // Nu5 branch ID
   * });
   * ```
   */
  static createEmptyWithConsensusBranchId(
    network: ZcashNetworkName,
    walletKeys: WalletKeysArg,
    options: CreateEmptyZcashWithConsensusBranchIdOptions,
  ): ZcashBitGoPsbt {
    const keys = RootWalletKeys.from(walletKeys);
    const wasm = WasmBitGoPsbt.create_empty_zcash(
      network,
      keys.wasm,
      options.consensusBranchId,
      options.version,
      options.lockTime,
      options.versionGroupId,
      options.expiryHeight,
    );
    return new ZcashBitGoPsbt(wasm);
  }

  /**
   * Deserialize a Zcash PSBT from bytes
   *
   * @param bytes - The PSBT bytes
   * @param network - Zcash network name ("zcash", "zcashTest", "zec", "tzec")
   * @returns A ZcashBitGoPsbt instance
   */
  static override fromBytes(bytes: Uint8Array, network: ZcashNetworkName): ZcashBitGoPsbt {
    const wasm = WasmBitGoPsbt.from_bytes(bytes, network);
    return new ZcashBitGoPsbt(wasm);
  }

  // --- Zcash-specific getters ---

  /**
   * Get the Zcash version group ID
   * @returns The version group ID (e.g., 0x892F2085 for Sapling)
   */
  get versionGroupId(): number {
    return this.wasm.version_group_id();
  }

  /**
   * Get the Zcash expiry height
   * @returns The expiry height (0 if not set)
   */
  get expiryHeight(): number {
    return this.wasm.expiry_height();
  }
}
