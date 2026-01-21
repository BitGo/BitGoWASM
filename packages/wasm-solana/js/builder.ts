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

/** Union of all instruction types */
export type Instruction =
  | TransferInstruction
  | CreateAccountInstruction
  | NonceAdvanceInstruction
  | NonceInitializeInstruction
  | AllocateInstruction
  | AssignInstruction
  | MemoInstruction
  | ComputeBudgetInstruction;

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
