import * as wasm from "./wasm/wasm_solana.js";

// Force webpack to include the WASM module
void wasm;

// Namespace exports for explicit imports
export * as keypair from "./keypair.js";
export * as pubkey from "./pubkey.js";
export * as transaction from "./transaction.js";
export * as parser from "./parser.js";
export * as builder from "./builder.js";
export * as explain from "./explain.js";

// Top-level class exports for convenience
export { Keypair } from "./keypair.js";
export { Pubkey } from "./pubkey.js";
export { Transaction } from "./transaction.js";

// Versioned transaction support
export { VersionedTransaction, isVersionedTransaction } from "./versioned.js";
export type { AddressLookupTableData } from "./versioned.js";

// Top-level function exports
export { parseTransactionData } from "./parser.js";
export { buildFromVersionedData } from "./builder.js";
export { buildFromIntent, buildFromIntent as buildTransactionFromIntent } from "./intentBuilder.js";
export { explainTransaction, TransactionType } from "./explain.js";

// Re-export Transaction import for parseTransaction
import { Transaction as _Transaction } from "./transaction.js";

/**
 * Parse a Solana transaction from raw bytes.
 *
 * Returns a `Transaction` instance that can be both inspected and signed.
 * Use `.parse()` on the returned Transaction to get decoded instruction data.
 *
 * This is the single entry point for working with transactions — like
 * `BitGoPsbt.fromBytes()` in wasm-utxo.
 *
 * @param bytes - Raw transaction bytes
 * @returns A Transaction that can be inspected (`.parse()`) and signed (`.addSignature()`)
 *
 * @example
 * ```typescript
 * import { parseTransaction } from '@bitgo/wasm-solana';
 *
 * const tx = parseTransaction(txBytes);
 *
 * // Inspect
 * const parsed = tx.parse();
 * console.log(parsed.feePayer);
 * for (const instr of parsed.instructionsData) {
 *   if (instr.type === 'Transfer') {
 *     console.log(`${instr.amount} lamports to ${instr.toAddress}`);
 *   }
 * }
 *
 * // Sign
 * tx.addSignature(pubkey, signature);
 * const signedBytes = tx.toBytes();
 * ```
 */
export function parseTransaction(bytes: Uint8Array): _Transaction {
  return _Transaction.fromBytes(bytes);
}

// Intent builder type exports
export type {
  BaseIntent,
  PaymentIntent,
  StakeIntent,
  UnstakeIntent,
  ClaimIntent,
  DeactivateIntent,
  DelegateIntent,
  EnableTokenIntent,
  CloseAtaIntent,
  ConsolidateIntent,
  AuthorizeIntent,
  CustomTxIntent,
  CustomTxInstruction,
  CustomTxKey,
  SolanaIntent,
  StakePoolConfig,
  BuildFromIntentParams,
  BuildFromIntentResult,
  GeneratedKeypair,
  NonceSource,
  BlockhashNonce,
  DurableNonce,
} from "./intentBuilder.js";

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
  DurableNonce as ParsedDurableNonce,
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

// Explain types
export type {
  ExplainedTransaction,
  ExplainedOutput,
  ExplainedInput,
  ExplainOptions,
  TokenEnablement,
  StakingAuthorizeInfo,
} from "./explain.js";

// Versioned transaction builder type exports
export type {
  AddressLookupTable as BuilderAddressLookupTable,
  RawVersionedTransactionData,
  VersionedInstruction as BuilderVersionedInstruction,
  MessageHeader,
} from "./builder.js";
