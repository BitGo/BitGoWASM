/**
 * wasm-dot: WASM bindings for Polkadot/DOT transaction operations
 *
 * This module provides:
 * - Transaction parsing (decode extrinsics)
 * - Signature operations (add signatures to unsigned transactions)
 * - Transaction building from intents (following wasm-solana pattern)
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
