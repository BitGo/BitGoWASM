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

// Versioned transaction support
export { VersionedTransaction, isVersionedTransaction } from "./versioned.js";
export type { AddressLookupTableData } from "./versioned.js";

// Top-level function exports
export { parseTransaction } from "./parser.js";
export { buildTransaction, buildFromVersionedData } from "./builder.js";

// Program ID constants (from WASM)
export {
  system_program_id as systemProgramId,
  stake_program_id as stakeProgramId,
  compute_budget_program_id as computeBudgetProgramId,
  memo_program_id as memoProgramId,
  token_program_id as tokenProgramId,
  token_2022_program_id as token2022ProgramId,
  ata_program_id as ataProgramId,
  stake_pool_program_id as stakePoolProgramId,
  stake_account_space as stakeAccountSpace,
  nonce_account_space as nonceAccountSpace,
  // Sysvar addresses
  sysvar_recent_blockhashes as sysvarRecentBlockhashes,
  // PDA derivation functions (eliminates @solana/web3.js dependency)
  get_associated_token_address as getAssociatedTokenAddress,
  find_withdraw_authority_program_address as findWithdrawAuthorityProgramAddress,
} from "./wasm/wasm_solana.js";

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
  NonceInitializeParams,
  StakeInitializeParams,
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
  AddressLookupTable as BuilderAddressLookupTable,
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
  StakeSplitInstruction,
  // SPL Token
  TokenTransferInstruction,
  CreateAssociatedTokenAccountInstruction,
  CloseAssociatedTokenAccountInstruction,
  MintToInstruction,
  BurnInstruction,
  ApproveInstruction,
  // Jito Stake Pool
  StakePoolDepositSolInstruction,
  StakePoolWithdrawStakeInstruction,
  // Custom Instruction
  CustomInstruction as BuilderCustomInstruction,
  CustomAccountMeta,
  // Raw Versioned Transaction Data (for fromVersionedTransactionData path)
  RawVersionedTransactionData,
  VersionedInstruction as BuilderVersionedInstruction,
  MessageHeader,
} from "./builder.js";
