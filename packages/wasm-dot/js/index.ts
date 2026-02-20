/**
 * wasm-dot: WASM bindings for Polkadot/DOT transaction operations
 *
 * This module provides:
 * - Transaction parsing: parseTransaction(bytes) → DotTransaction (inspect + sign)
 * - Transaction explanation: explainTransaction(bytes, options) → ExplainedTransaction
 * - Transaction building: buildTransaction(intent, context) → DotTransaction
 *
 * Pattern matches wasm-solana:
 * - parseTransaction(bytes) returns a Transaction object (not plain data)
 * - Transaction.parse() returns decoded instruction/method data
 * - explainTransaction() is a standalone function for high-level explanation
 */

import {
  WasmTransaction,
  ParserNamespace,
  BuilderNamespace,
  MaterialJs,
  ValidityJs,
  ParseContextJs,
} from "./wasm/wasm_dot";

// Export WASM classes for advanced usage
export {
  WasmTransaction,
  ParserNamespace,
  ParserNamespace as DotParser,
  BuilderNamespace,
  MaterialJs,
  ValidityJs,
  ParseContextJs,
};

// Re-export types
export * from "./types";
export * from "./transaction";
export * from "./parser";
export * from "./builder";
export * from "./explain";

// =============================================================================
// parseTransaction — Top-level entry point (returns DotTransaction)
// =============================================================================

import { DotTransaction } from "./transaction";
import type { ParseContext } from "./types";

/**
 * Parse a DOT transaction from bytes or hex, returning a DotTransaction
 * that can be both inspected and signed.
 *
 * This is the standard entry point for working with DOT transactions,
 * matching wasm-solana's `parseTransaction(bytes) → Transaction` pattern.
 *
 * Use `.parse()` for decoded method data, `.addSignature()` for signing,
 * `.toBytes()` for serialization.
 *
 * For low-level parsed data without a Transaction object, use
 * `parseTransactionData()` instead.
 *
 * @param input - Raw bytes or hex string (with or without 0x)
 * @param context - Parsing context with chain material
 * @returns DotTransaction instance
 *
 * @example
 * ```typescript
 * import { parseTransaction } from '@bitgo/wasm-dot';
 *
 * const tx = parseTransaction(txHex, { material });
 *
 * // Inspect decoded method data
 * const parsed = tx.parse();
 * console.log(parsed.method.pallet); // "balances"
 *
 * // Sign and serialize
 * tx.addSignature(signature, pubkey);
 * const signedBytes = tx.toBytes();
 * ```
 */
export function parseTransaction(
  input: Uint8Array | string,
  context?: ParseContext,
): DotTransaction {
  if (typeof input === "string") {
    return DotTransaction.fromHex(input, context);
  }
  return DotTransaction.fromBytes(input, context);
}
