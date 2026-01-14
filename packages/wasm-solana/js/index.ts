import * as wasm from "./wasm/wasm_solana.js";

// Force webpack to include the WASM module
void wasm;

// Namespace exports for explicit imports
export * as keypair from "./keypair.js";
export * as pubkey from "./pubkey.js";

// Top-level class exports for convenience
export { Keypair } from "./keypair.js";
export { Pubkey } from "./pubkey.js";
