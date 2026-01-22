import * as wasm from "./wasm/wasm_solana.js";

// Force webpack to include the WASM module
void wasm;

// Namespace exports for explicit imports
export * as keypair from "./keypair.js";
export * as pubkey from "./pubkey.js";
export * as transaction from "./transaction.js";
export * as parser from "./parser.js";

// Top-level class exports for convenience
export { Keypair } from "./keypair.js";
export { Pubkey } from "./pubkey.js";
export { Transaction } from "./transaction.js";

// Top-level function exports
export { parseTransaction } from "./parser.js";

// Type exports
export type { AccountMeta, Instruction } from "./transaction.js";
export type {
  ParsedTransaction,
  DurableNonce,
  InstructionParams,
  TransferParams,
  CreateAccountParams,
  NonceAdvanceParams,
  CreateNonceAccountParams,
  StakingActivateParams,
  StakingDeactivateParams,
  StakingWithdrawParams,
  StakingDelegateParams,
  StakingAuthorizeParams,
  SetComputeUnitLimitParams,
  SetPriorityFeeParams,
  TokenTransferParams,
  CreateAtaParams,
  CloseAtaParams,
  MemoParams,
  UnknownInstructionParams,
} from "./parser.js";
