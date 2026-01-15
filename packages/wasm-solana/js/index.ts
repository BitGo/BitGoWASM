import * as wasm from "./wasm/wasm_solana.js";

// Force webpack to include the WASM module
void wasm;

// Namespace exports for explicit imports
export * as keypair from "./keypair.js";
export * as pubkey from "./pubkey.js";
export * as transaction from "./transaction.js";
export * as instructions from "./instructions.js";

// Top-level class exports for convenience
export { Keypair } from "./keypair.js";
export { Pubkey } from "./pubkey.js";
export { Transaction } from "./transaction.js";

// Instruction decoder exports
export { SystemInstruction, StakeInstruction, ComputeBudgetInstruction } from "./instructions.js";

// Type exports
export type { AccountMeta, Instruction } from "./transaction.js";
export type {
  SystemInstructionType,
  DecodedSystemInstruction,
  StakeInstructionType,
  StakeAuthorize,
  DecodedStakeInstruction,
  ComputeBudgetInstructionType,
  DecodedComputeBudgetInstruction,
} from "./instructions.js";
