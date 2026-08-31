import {
  BitGoPsbt as WasmBitGoPsbt,
  zcash_branch_id_for_height,
  zcash_ironwood_version_group_id,
} from "../wasm/wasm_utxo.js";
import { type WalletKeysArg, RootWalletKeys } from "./RootWalletKeys.js";
import {
  BitGoPsbt,
  type CreateEmptyOptions,
  type HydrationUnspent,
  type ParsedOutput,
} from "./BitGoPsbt.js";
import { ZcashTransaction, type ITransaction } from "../transaction.js";

/** Zcash network names */
export type ZcashNetworkName = "zcash" | "zcashTest" | "zec" | "tzec";

export type ZcashParsedOutput = ParsedOutput & {
  /**
   * True for a shielded (Orchard/Ironwood) output. Such an output has no `unsigned_tx` entry of
   * its own — it lives in the PSBT's proprietary-map PCZT, read from its plaintext (not
   * encrypted/decrypted) recipient field. `address` is a single-receiver ZIP-316 unified address
   * (`u1...`/`utest1...`) encoding that receiver — a real, usable Zcash address, though not
   * necessarily byte-identical to whatever multi-receiver UA the sender originally pasted in (a
   * UA with a transparent/Sapling receiver too would round-trip to a different string carrying
   * only the Orchard one). `script` holds the same receiver as raw 43 bytes.
   */
  isShielded: boolean;
};

/**
 * Zcash v6 (Ironwood) version group id (0xd884b698). Its presence marks a PSBT as v6 — see
 * `ZcashIronwoodBitGoPsbt`.
 *
 * Read from the wasm layer rather than hard-coded, so it cannot drift from
 * `ZCASH_IRONWOOD_VERSION_GROUP_ID` in `src/zcash/transaction.rs`: a divergence would make the
 * v4/v6 discrimination in {@link ZcashBitGoPsbt.fromBytes} silently classify v6 bytes as v4.
 */
export const IRONWOOD_VERSION_GROUP_ID: number = zcash_ironwood_version_group_id();

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
export class ZcashBitGoPsbt extends BitGoPsbt<ZcashParsedOutput> {
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
   * @throws Error if the deserialized PSBT is a v6 (Ironwood) PSBT — use
   *   {@link ZcashIronwoodBitGoPsbt.fromBytes} instead
   * @returns A ZcashBitGoPsbt instance
   */
  static override fromBytes(bytes: Uint8Array, network: ZcashNetworkName): ZcashBitGoPsbt {
    const wasm = WasmBitGoPsbt.from_bytes(bytes, network);
    const psbt = new ZcashBitGoPsbt(wasm);
    if (psbt.versionGroupId === IRONWOOD_VERSION_GROUP_ID) {
      throw new Error("this is a v6 (Ironwood) PSBT: use ZcashIronwoodBitGoPsbt.fromBytes instead");
    }
    return psbt;
  }

  /**
   * Reconstruct a Zcash PSBT from a network-format transaction (unsigned, half-signed, or fully-signed).
   *
   * This is the Zcash equivalent of `BitGoPsbt.fromNetworkFormat()`. It decodes the Zcash wire
   * format (which includes version_group_id, expiry_height, and sapling fields), extracts any
   * partial signatures present, and reconstructs a proper Zcash PSBT with consensus metadata.
   *
   * Use this as the modern replacement for `fromHalfSignedLegacyTransaction`. Signature-count
   * discovery (unsigned / half-signed / fully-signed) is left to the caller.
   *
   * Supports two modes for determining consensus_branch_id:
   * - **Recommended**: Pass `blockHeight` to auto-determine consensus_branch_id via network upgrade activation heights
   * - **Advanced**: Pass `consensusBranchId` directly if you already know it (e.g., 0xC2D6D0B4 for NU5)
   *
   * @param txBytesOrTx - Either serialized Zcash transaction bytes or a decoded ZcashTransaction instance
   * @param network - Zcash network name ("zcash", "zcashTest", "zec", "tzec")
   * @param walletKeys - The wallet's root keys
   * @param unspents - Chain, index, and value for each input
   * @param options - Either `{ blockHeight: number }` or `{ consensusBranchId: number }`
   * @returns A ZcashBitGoPsbt instance
   */
  static fromNetworkFormat(
    txBytesOrTx: Uint8Array | ITransaction,
    network: ZcashNetworkName,
    walletKeys: WalletKeysArg,
    unspents: HydrationUnspent[],
    options: { blockHeight: number } | { consensusBranchId: number },
  ): ZcashBitGoPsbt {
    const keys = RootWalletKeys.from(walletKeys);
    const tx =
      txBytesOrTx instanceof Uint8Array
        ? ZcashTransaction.fromBytes(txBytesOrTx)
        : (txBytesOrTx as ZcashTransaction);

    if ("blockHeight" in options) {
      const wasm = WasmBitGoPsbt.from_network_format_zcash_with_block_height(
        tx.wasm,
        network,
        keys.wasm,
        unspents,
        options.blockHeight,
      );
      return new ZcashBitGoPsbt(wasm);
    } else {
      const wasm = WasmBitGoPsbt.from_network_format_zcash_with_branch_id(
        tx.wasm,
        network,
        keys.wasm,
        unspents,
        options.consensusBranchId,
      );
      return new ZcashBitGoPsbt(wasm);
    }
  }

  /**
   * Reconstruct a Zcash PSBT from a half-signed legacy transaction.
   *
   * @deprecated Use `fromNetworkFormat()` instead. Signature-count enforcement
   * (exactly 1 sig per wallet input) is moving to the caller.
   *
   * @param txBytesOrTx - Either serialized Zcash transaction bytes or a decoded ZcashTransaction instance
   * @param network - Zcash network name ("zcash", "zcashTest", "zec", "tzec")
   * @param walletKeys - The wallet's root keys
   * @param unspents - Chain, index, and value for each input
   * @param options - Either `{ blockHeight: number }` or `{ consensusBranchId: number }`
   * @returns A ZcashBitGoPsbt instance
   */
  static fromHalfSignedLegacyTransaction(
    txBytesOrTx: Uint8Array | ITransaction,
    network: ZcashNetworkName,
    walletKeys: WalletKeysArg,
    unspents: HydrationUnspent[],
    options: { blockHeight: number } | { consensusBranchId: number },
  ): ZcashBitGoPsbt {
    const keys = RootWalletKeys.from(walletKeys);
    const tx =
      txBytesOrTx instanceof Uint8Array
        ? ZcashTransaction.fromBytes(txBytesOrTx)
        : (txBytesOrTx as ZcashTransaction);

    if ("blockHeight" in options) {
      const wasm = WasmBitGoPsbt.from_network_format_zcash_with_block_height(
        tx.wasm,
        network,
        keys.wasm,
        unspents,
        options.blockHeight,
      );
      return new ZcashBitGoPsbt(wasm);
    } else {
      const wasm = WasmBitGoPsbt.from_network_format_zcash_with_branch_id(
        tx.wasm,
        network,
        keys.wasm,
        unspents,
        options.consensusBranchId,
      );
      return new ZcashBitGoPsbt(wasm);
    }
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

  /**
   * Get the Zcash consensus branch ID stored in the PSBT proprietary map.
   * Returns undefined for v5 PSBTs or PSBTs without the key.
   */
  get consensusBranchId(): number | undefined {
    return this.wasm.consensus_branch_id();
  }

  /**
   * Return the Zcash consensus branch ID active at `height` on `network`.
   * Returns undefined if `height` is before Overwinter activation.
   */
  static branchIdForHeight(network: ZcashNetworkName, height: number): number | undefined {
    return zcash_branch_id_for_height(network, height);
  }

  /**
   * Extract the final Zcash transaction from a finalized PSBT
   *
   * @param maxFeeRate Optional maximum fee rate in **sat/vB**. `Infinity` skips
   *   the absurd-fee check; `undefined` uses rust-bitcoin's default check.
   *   Callers holding sat/kB thresholds must divide by 1000 before passing.
   * @returns The extracted Zcash transaction instance
   * @throws Error if the PSBT is not fully finalized or extraction fails
   */
  override extractTransaction(maxFeeRate?: number): ZcashTransaction {
    return ZcashTransaction.fromWasm(this.wasm.extract_zcash_transaction(maxFeeRate));
  }

  /**
   * Add a plain transparent output. Just `script`/`value` (no `unifiedAddress`) is the same as
   * the generic {@link BitGoPsbt.addOutput}, unchanged.
   *
   * If `unifiedAddress` is given, it must be a Unified Address whose transparent receiver is
   * exactly `script` — mismatches throw rather than being silently stored. It is then kept
   * verbatim, keyed by this output's index, so {@link ZcashBitGoPsbt.transparentOutputUnifiedAddress}
   * can later return the original UA string rather than just the bare scriptPubkey.
   *
   * `unifiedAddress` is only supported on a legacy v4 `ZcashBitGoPsbt` — the v6 (Ironwood)
   * shielded side has its own UA path (`ZcashIronwoodBitGoPsbt.addShieldedOutput`'s
   * `unifiedAddress` option).
   *
   * @param script - The output scriptPubkey
   * @param value - The value in zatoshi
   * @param unifiedAddress - Optional full Unified Address `script` was resolved from
   * @returns The index of the newly added output
   */
  addTransparentOutput(script: Uint8Array, value: bigint, unifiedAddress?: string): number {
    return this.wasm.add_transparent_output(script, value, unifiedAddress);
  }

  /**
   * The Unified Address stored by {@link ZcashBitGoPsbt.addTransparentOutput} for output `index`,
   * if one was supplied — `undefined` otherwise.
   */
  transparentOutputUnifiedAddress(index: number): string | undefined {
    return this.wasm.transparent_output_unified_address(index);
  }
}
