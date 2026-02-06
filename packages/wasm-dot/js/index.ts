/**
 * wasm-dot: WASM bindings for Polkadot/DOT transaction operations
 *
 * This module provides:
 * - Transaction parsing (decode extrinsics)
 * - Signature operations (add signatures to unsigned transactions)
 * - Transaction building from intents
 */

import init, {
  WasmTransaction,
  ParserNamespace,
  BuilderNamespace,
  MaterialJs,
  ValidityJs,
  ParseContextJs,
  BuildContextJs,
  MaterialBuilderJs,
  ValidityBuilderJs,
} from '../pkg/wasm_dot';

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

let wasmInitialized = false;

/**
 * Initialize the WASM module
 *
 * Must be called before using any other functions
 */
export async function initWasm(): Promise<void> {
  if (!wasmInitialized) {
    await init();
    wasmInitialized = true;
  }
}

/**
 * Check if WASM is initialized
 */
export function isWasmInitialized(): boolean {
  return wasmInitialized;
}

/**
 * Ensure WASM is initialized (throws if not)
 */
export function ensureWasmInitialized(): void {
  if (!wasmInitialized) {
    throw new Error('WASM not initialized. Call initWasm() first.');
  }
}
