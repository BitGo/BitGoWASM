/**
 * wasm-dot: WASM bindings for Polkadot/DOT transaction operations
 *
 * This module provides:
 * - Transaction parsing (decode extrinsics)
 * - Signature operations (add signatures to unsigned transactions)
 * - Transaction building from intents
 */

import {
  WasmTransaction,
  ParserNamespace,
  BuilderNamespace,
  MaterialJs,
  ValidityJs,
  ParseContextJs,
  BuildContextJs,
  MaterialBuilderJs,
  ValidityBuilderJs,
} from './wasm/wasm_dot';

export {
  WasmTransaction,
  ParserNamespace,
  BuilderNamespace,
  MaterialJs,
  ValidityJs,
  ParseContextJs,
  BuildContextJs,
  MaterialBuilderJs,
  ValidityBuilderJs,
};

// Re-export types
export * from './types';
export * from './transaction';
export * from './parser';
export * from './builder';
