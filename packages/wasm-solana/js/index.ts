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
export {
  // Functions
  isSystemProgram,
  decodeSystemInstruction,
  isStakeProgram,
  decodeStakeInstruction,
  isComputeBudgetProgram,
  decodeComputeBudgetInstruction,
  // Constants
  SYSTEM_PROGRAM_ID,
  STAKE_PROGRAM_ID,
  COMPUTE_BUDGET_PROGRAM_ID,
} from "./instructions.js";

// Type exports
export type { AccountMeta, Instruction } from "./transaction.js";
export type {
  // System instruction types (commonly used)
  SystemInstruction,
  SystemCreateAccount,
  SystemTransfer,
  SystemAdvanceNonceAccount,
  SystemInitializeNonceAccount,
  // Stake instruction types (commonly used)
  StakeInstruction,
  StakeLockup,
  StakeInitialize,
  StakeAuthorize,
  StakeDelegateStake,
  StakeSplit,
  StakeWithdraw,
  StakeDeactivate,
  StakeMerge,
  // ComputeBudget instruction types
  ComputeBudgetInstruction,
  ComputeBudgetSetComputeUnitLimit,
  ComputeBudgetSetComputeUnitPrice,
} from "./instructions.js";
