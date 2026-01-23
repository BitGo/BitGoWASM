import * as wasm from "./wasm/wasm_solana.js";

// Force webpack to include the WASM module
void wasm;

// Namespace exports for explicit imports
export * as keypair from "./keypair.js";
export * as pubkey from "./pubkey.js";
export * as transaction from "./transaction.js";
export * as parser from "./parser.js";
export * as builder from "./builder.js";

// Top-level class exports for convenience
export { Keypair } from "./keypair.js";
export { Pubkey } from "./pubkey.js";
export { Transaction } from "./transaction.js";

// Top-level function exports
export { parseTransaction } from "./parser.js";
export { buildTransaction } from "./builder.js";

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
  StakeInitializeParams,
  SetComputeUnitLimitParams,
  SetPriorityFeeParams,
  TokenTransferParams,
  CreateAtaParams,
  CloseAtaParams,
  MemoParams,
  StakePoolDepositSolParams,
  StakePoolWithdrawStakeParams,
  UnknownInstructionParams,
} from "./parser.js";

// Builder type exports (prefixed to avoid conflict with parser/transaction types)
export type {
  TransactionIntent,
  NonceSource,
  BlockhashNonceSource,
  DurableNonceSource,
  Instruction as BuilderInstruction,
  TransferInstruction,
  CreateAccountInstruction,
  NonceAdvanceInstruction,
  NonceInitializeInstruction,
  AllocateInstruction,
  AssignInstruction,
  MemoInstruction,
  ComputeBudgetInstruction,
  // Stake Program
  StakeInitializeInstruction,
  StakeDelegateInstruction,
  StakeDeactivateInstruction,
  StakeWithdrawInstruction,
  StakeAuthorizeInstruction,
  // SPL Token
  TokenTransferInstruction,
  CreateAssociatedTokenAccountInstruction,
  CloseAssociatedTokenAccountInstruction,
  // Jito Stake Pool
  StakePoolDepositSolInstruction,
  StakePoolWithdrawStakeInstruction,
} from "./builder.js";
