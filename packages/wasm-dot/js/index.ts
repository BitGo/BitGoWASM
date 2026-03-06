/**
 * wasm-dot: WASM bindings for Polkadot/DOT transaction operations
 *
 * This module provides:
 * - Transaction parsing: parseTransaction(tx, context) → ParsedTransaction
 * - Transaction building: buildTransaction(intent, context) → DotTransaction
 * - Transaction signing: DotTransaction.fromBytes(bytes) → inspect + sign
 */

import {
  WasmTransaction,
  ParserNamespace,
  BuilderNamespace,
  MaterialJs,
  ValidityJs,
  ParseContextJs,
} from "./wasm/wasm_dot.js";

// Export WASM classes for advanced usage
export {
  WasmTransaction,
  ParserNamespace,
  BuilderNamespace,
  MaterialJs,
  ValidityJs,
  ParseContextJs,
};

// Re-export all public API
export * from "./types.js";
export * from "./transaction.js";
export * from "./parser.js";
export * from "./builder.js";
