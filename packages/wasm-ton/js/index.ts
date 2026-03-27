/**
 * wasm-ton: WASM bindings for TON transaction operations
 *
 * This module provides:
 * - Address encoding/decoding/validation
 * - Transaction deserialization and signing
 * - Transaction parsing with type detection
 * - Transaction building from intents (Phase 3)
 */

import {
  AddressNamespace,
  WasmTransaction,
  ParserNamespace,
  BuilderNamespace,
} from "./wasm/wasm_ton.js";

// Export WASM classes for advanced usage
export { AddressNamespace, WasmTransaction, ParserNamespace, BuilderNamespace };

// Re-export all public API
export * from "./address.js";
export * from "./transaction.js";
export * from "./parser.js";
export * from "./builder.js";
