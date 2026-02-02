/**
 * Descriptor wallet utilities.
 * Moved from @bitgo/utxo-core.
 *
 * This module provides descriptor wallet functionality using wasm-utxo directly,
 * eliminating the need for utxo-lib in descriptor wallet code paths.
 *
 * ## Migration from utxo-core
 *
 * If you were previously importing from `@bitgo/utxo-core/descriptor`, you should
 * now import from `@bitgo/wasm-utxo`:
 *
 * ```typescript
 * // Before (deprecated)
 * import { DescriptorMap, createPsbt } from '@bitgo/utxo-core/descriptor';
 *
 * // After
 * import { descriptorWallet } from '@bitgo/wasm-utxo';
 * const { DescriptorMap, createPsbt } = descriptorWallet;
 * ```
 *
 * @see {@link ./MIGRATION.md} for detailed migration instructions.
 *
 * @remarks
 * The following imports from `@bitgo/utxo-core/descriptor` are now deprecated
 * and should use this module instead:
 * - DescriptorMap, toDescriptorMap
 * - createPsbt, parse, findDescriptorForInput, findDescriptorForOutput
 * - getDescriptorAtIndex, getDescriptorAtIndexCheckScript
 * - createScriptPubKeyFromDescriptor, createAddressFromDescriptor
 * - getVirtualSize, getVirtualSizeEstimateForPsbt
 * - signWithKey, getNewSignatureCount
 * - assertSatisfiable, getRequiredLocktime
 * - PatternMatcher
 */

// Core types and utilities
export * from "./Output.js";
export * from "./DescriptorMap.js";
export * from "./derive.js";
export * from "./DescriptorOutput.js";
export * from "./address.js";
export * from "./VirtualSize.js";

// PSBT utilities
export * from "./psbt/index.js";

// Pattern matching
export * from "./parse/PatternMatcher.js";
