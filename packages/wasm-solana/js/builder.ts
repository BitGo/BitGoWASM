/**
 * Transaction building from high-level intents.
 *
 * Provides types and functions for building Solana transactions from a
 * declarative intent structure, without requiring the full @solana/web3.js dependency.
 */

import { BuilderNamespace } from "./wasm/wasm_solana.js";

// =============================================================================
// Nonce Types
// =============================================================================

/** Use a recent blockhash for the transaction */
export interface BlockhashNonceSource {
  type: "blockhash";
  /** The recent blockhash value (base58) */
  value: string;
}

/** Use a durable nonce account for the transaction */
export interface DurableNonceSource {
  type: "durable";
  /** The nonce account address (base58) */
  address: string;
  /** The nonce authority address (base58) */
  authority: string;
  /** The nonce value stored in the account (base58) - this becomes the blockhash */
  value: string;
}

/** Nonce source for the transaction */
export type NonceSource = BlockhashNonceSource | DurableNonceSource;

// =============================================================================
// Instruction Types
// =============================================================================

/** SOL transfer instruction */
export interface TransferInstruction {
  type: "transfer";
  /** Source account (base58) */
  from: string;
  /** Destination account (base58) */
  to: string;
  /** Amount in lamports (as string for BigInt compatibility) */
  lamports: string;
}

/** Create new account instruction */
export interface CreateAccountInstruction {
  type: "createAccount";
  /** Funding account (base58) */
  from: string;
  /** New account address (base58) */
  newAccount: string;
  /** Lamports to transfer (as string) */
  lamports: string;
  /** Space to allocate in bytes */
  space: number;
  /** Owner program (base58) */
  owner: string;
}

/** Advance durable nonce instruction */
export interface NonceAdvanceInstruction {
  type: "nonceAdvance";
  /** Nonce account address (base58) */
  nonce: string;
  /** Nonce authority (base58) */
  authority: string;
}

/** Initialize nonce account instruction */
export interface NonceInitializeInstruction {
  type: "nonceInitialize";
  /** Nonce account address (base58) */
  nonce: string;
  /** Nonce authority (base58) */
  authority: string;
}

/** Allocate space instruction */
export interface AllocateInstruction {
  type: "allocate";
  /** Account to allocate (base58) */
  account: string;
  /** Space to allocate in bytes */
  space: number;
}

/** Assign account to program instruction */
export interface AssignInstruction {
  type: "assign";
  /** Account to assign (base58) */
  account: string;
  /** New owner program (base58) */
  owner: string;
}

/** Memo instruction */
export interface MemoInstruction {
  type: "memo";
  /** The memo message */
  message: string;
}

/** Compute budget instruction */
export interface ComputeBudgetInstruction {
  type: "computeBudget";
  /** Compute unit limit (optional) */
  unitLimit?: number;
  /** Compute unit price in micro-lamports (optional) */
  unitPrice?: number;
}

// =============================================================================
// Stake Program Instructions
// =============================================================================

/** Initialize a stake account instruction */
export interface StakeInitializeInstruction {
  type: "stakeInitialize";
  /** Stake account address (base58) */
  stake: string;
  /** Authorized staker pubkey (base58) */
  staker: string;
  /** Authorized withdrawer pubkey (base58) */
  withdrawer: string;
}

/** Delegate stake to a validator instruction */
export interface StakeDelegateInstruction {
  type: "stakeDelegate";
  /** Stake account address (base58) */
  stake: string;
  /** Vote account (validator) to delegate to (base58) */
  vote: string;
  /** Stake authority (base58) */
  authority: string;
}

/** Deactivate a stake account instruction */
export interface StakeDeactivateInstruction {
  type: "stakeDeactivate";
  /** Stake account address (base58) */
  stake: string;
  /** Stake authority (base58) */
  authority: string;
}

/** Withdraw from a stake account instruction */
export interface StakeWithdrawInstruction {
  type: "stakeWithdraw";
  /** Stake account address (base58) */
  stake: string;
  /** Recipient address (base58) */
  recipient: string;
  /** Amount in lamports to withdraw (as string) */
  lamports: string;
  /** Withdraw authority (base58) */
  authority: string;
}

/** Change stake account authorization instruction */
export interface StakeAuthorizeInstruction {
  type: "stakeAuthorize";
  /** Stake account address (base58) */
  stake: string;
  /** New authority pubkey (base58) */
  newAuthority: string;
  /** Authorization type: "staker" or "withdrawer" */
  authorizeType: "staker" | "withdrawer";
  /** Current authority (base58) */
  authority: string;
}

// =============================================================================
// SPL Token Instructions
// =============================================================================

/** Transfer tokens instruction (uses TransferChecked) */
export interface TokenTransferInstruction {
  type: "tokenTransfer";
  /** Source token account (base58) */
  source: string;
  /** Destination token account (base58) */
  destination: string;
  /** Token mint address (base58) */
  mint: string;
  /** Amount of tokens (as string, in smallest units) */
  amount: string;
  /** Number of decimals for the token */
  decimals: number;
  /** Owner/authority of the source account (base58) */
  authority: string;
  /** Token program ID (optional, defaults to SPL Token) */
  programId?: string;
}

/** Create an Associated Token Account instruction */
export interface CreateAssociatedTokenAccountInstruction {
  type: "createAssociatedTokenAccount";
  /** Payer for account creation (base58) */
  payer: string;
  /** Owner of the new ATA (base58) */
  owner: string;
  /** Token mint address (base58) */
  mint: string;
  /** Token program ID (optional, defaults to SPL Token) */
  tokenProgramId?: string;
}

/** Close an Associated Token Account instruction */
export interface CloseAssociatedTokenAccountInstruction {
  type: "closeAssociatedTokenAccount";
  /** Token account to close (base58) */
  account: string;
  /** Destination for remaining lamports (base58) */
  destination: string;
  /** Authority of the account (base58) */
  authority: string;
  /** Token program ID (optional, defaults to SPL Token) */
  programId?: string;
}

// =============================================================================
// Jito Stake Pool Instructions
// =============================================================================

/** Deposit SOL into a stake pool (Jito liquid staking) */
export interface StakePoolDepositSolInstruction {
  type: "stakePoolDepositSol";
  /** Stake pool address (base58) */
  stakePool: string;
  /** Withdraw authority PDA (base58) */
  withdrawAuthority: string;
  /** Reserve stake account (base58) */
  reserveStake: string;
  /** Funding account (SOL source, signer) (base58) */
  fundingAccount: string;
  /** Destination for pool tokens (base58) */
  destinationPoolAccount: string;
  /** Manager fee account (base58) */
  managerFeeAccount: string;
  /** Referral pool account (base58) */
  referralPoolAccount: string;
  /** Pool mint address (base58) */
  poolMint: string;
  /** Amount in lamports to deposit (as string) */
  lamports: string;
}

/** Withdraw stake from a stake pool (Jito liquid staking) */
export interface StakePoolWithdrawStakeInstruction {
  type: "stakePoolWithdrawStake";
  /** Stake pool address (base58) */
  stakePool: string;
  /** Validator list account (base58) */
  validatorList: string;
  /** Withdraw authority PDA (base58) */
  withdrawAuthority: string;
  /** Validator stake account to split from (base58) */
  validatorStake: string;
  /** Destination stake account (uninitialized) (base58) */
  destinationStake: string;
  /** Authority for the destination stake account (base58) */
  destinationStakeAuthority: string;
  /** Source pool token account authority (signer) (base58) */
  sourceTransferAuthority: string;
  /** Source pool token account (base58) */
  sourcePoolAccount: string;
  /** Manager fee account (base58) */
  managerFeeAccount: string;
  /** Pool mint address (base58) */
  poolMint: string;
  /** Amount of pool tokens to burn (as string) */
  poolTokens: string;
}

/** Union of all instruction types */
export type Instruction =
  | TransferInstruction
  | CreateAccountInstruction
  | NonceAdvanceInstruction
  | NonceInitializeInstruction
  | AllocateInstruction
  | AssignInstruction
  | MemoInstruction
  | ComputeBudgetInstruction
  | StakeInitializeInstruction
  | StakeDelegateInstruction
  | StakeDeactivateInstruction
  | StakeWithdrawInstruction
  | StakeAuthorizeInstruction
  | TokenTransferInstruction
  | CreateAssociatedTokenAccountInstruction
  | CloseAssociatedTokenAccountInstruction
  | StakePoolDepositSolInstruction
  | StakePoolWithdrawStakeInstruction;

// =============================================================================
// TransactionIntent
// =============================================================================

/**
 * A declarative intent to build a Solana transaction.
 *
 * @example
 * ```typescript
 * const intent: TransactionIntent = {
 *   feePayer: 'DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB',
 *   nonce: {
 *     type: 'blockhash',
 *     value: 'GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4'
 *   },
 *   instructions: [
 *     { type: 'transfer', from: '...', to: '...', lamports: '1000000' }
 *   ]
 * };
 * ```
 */
export interface TransactionIntent {
  /** The fee payer's public key (base58) */
  feePayer: string;
  /** The nonce source (blockhash or durable nonce) */
  nonce: NonceSource;
  /** List of instructions to include */
  instructions: Instruction[];
}

// =============================================================================
// buildTransaction function
// =============================================================================

/**
 * Build a Solana transaction from a high-level intent.
 *
 * This function takes a declarative TransactionIntent and produces serialized
 * transaction bytes that can be signed and submitted to the network.
 *
 * The returned transaction is unsigned - signatures should be added before
 * broadcasting.
 *
 * @param intent - The transaction intent describing what to build
 * @returns Serialized unsigned transaction bytes (Uint8Array)
 * @throws Error if the intent cannot be built (e.g., invalid addresses)
 *
 * @example
 * ```typescript
 * import { buildTransaction } from '@bitgo/wasm-solana';
 *
 * // Build a simple SOL transfer
 * const txBytes = buildTransaction({
 *   feePayer: sender,
 *   nonce: { type: 'blockhash', value: blockhash },
 *   instructions: [
 *     { type: 'transfer', from: sender, to: recipient, lamports: '1000000' }
 *   ]
 * });
 *
 * // The returned bytes can be signed and broadcast
 * ```
 *
 * @example
 * ```typescript
 * // Build with durable nonce and priority fee
 * const txBytes = buildTransaction({
 *   feePayer: sender,
 *   nonce: { type: 'durable', address: nonceAccount, authority: sender, value: nonceValue },
 *   instructions: [
 *     { type: 'computeBudget', unitLimit: 200000, unitPrice: 5000 },
 *     { type: 'transfer', from: sender, to: recipient, lamports: '1000000' },
 *     { type: 'memo', message: 'BitGo transfer' }
 *   ]
 * });
 * ```
 */
export function buildTransaction(intent: TransactionIntent): Uint8Array {
  return BuilderNamespace.build_transaction(intent);
}
