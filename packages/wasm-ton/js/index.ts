/**
 * wasm-ton: WASM bindings for TON transaction operations
 *
 * This module provides:
 * - Address derivation: Ed25519 pubkey -> V4R2 wallet address
 * - Address encoding/decoding: user-friendly base64url format
 * - Address validation
 * - Transaction parsing: BOC -> structured data
 * - Transaction signing: add Ed25519 signature to BOC
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
