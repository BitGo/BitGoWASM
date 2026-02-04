/**
 * High-level intent-based transaction building.
 *
 * This module provides `buildFromIntent()` which accepts BitGo intent objects
 * directly and builds Solana transactions without requiring the caller to
 * construct low-level instructions.
 *
 * The intent → transaction mapping happens entirely in Rust/WASM for simplicity.
 *
 * Usage:
 * ```typescript
 * import { buildFromIntent } from '@bitgo/wasm-solana';
 *
 * const result = buildFromIntent(intent, {
 *   feePayer: walletRootAddress,
 *   nonce: { type: 'blockhash', value: recentBlockhash },
 * });
 *
 * // result.transaction - Transaction object
 * // result.generatedKeypairs - any keypairs generated (e.g., stake accounts)
 * ```
 */

import { IntentNamespace, WasmTransaction } from "./wasm/wasm_solana.js";
import { Transaction } from "./transaction.js";

/** Internal type for WASM result - matches what Rust returns */
interface WasmBuildResult {
  transaction: WasmTransaction;
  generatedKeypairs: GeneratedKeypair[];
}

// =============================================================================
// Types
// =============================================================================

/** Nonce source - blockhash or durable nonce */
export type NonceSource = BlockhashNonce | DurableNonce;

export interface BlockhashNonce {
  type: "blockhash";
  value: string;
}

export interface DurableNonce {
  type: "durable";
  address: string;
  authority: string;
  value: string;
}

/** Parameters for building a transaction from intent */
export interface BuildFromIntentParams {
  /** Fee payer address (wallet root) */
  feePayer: string;
  /** Nonce source - blockhash or durable nonce */
  nonce: NonceSource;
}

/** A keypair generated during transaction building */
export interface GeneratedKeypair {
  /** Purpose of this keypair */
  purpose: "stakeAccount" | "unstakeAccount" | "transferAuthority";
  /** Public address (base58) */
  address: string;
  /** Secret key (base58) */
  secretKey: string;
}

/** Result from building a transaction from intent */
export interface BuildFromIntentResult {
  /** The built transaction */
  transaction: Transaction;
  /** Generated keypairs (for stake accounts, etc.) */
  generatedKeypairs: GeneratedKeypair[];
}

// =============================================================================
// Intent Types (for TypeScript users)
// =============================================================================

/** Base intent - all intents have intentType */
export interface BaseIntent {
  intentType: string;
  memo?: string;
}

/** Payment intent */
export interface PaymentIntent extends BaseIntent {
  intentType: "payment";
  recipients?: Array<{
    address?: { address: string };
    amount?: { value: bigint; symbol?: string };
  }>;
}

/** Stake intent */
export interface StakeIntent extends BaseIntent {
  intentType: "stake";
  validatorAddress: string;
  amount?: { value: bigint };
  stakingType?: "NATIVE" | "JITO" | "MARINADE";
  stakePoolConfig?: StakePoolConfig;
}

/** Stake pool configuration (for Jito) */
export interface StakePoolConfig {
  stakePoolAddress: string;
  withdrawAuthority: string;
  reserveStake: string;
  destinationPoolAccount: string;
  managerFeeAccount: string;
  referralPoolAccount?: string;
  poolMint: string;
  validatorList?: string;
  sourcePoolAccount?: string;
}

/** Unstake intent */
export interface UnstakeIntent extends BaseIntent {
  intentType: "unstake";
  stakingAddress: string;
  validatorAddress?: string;
  amount?: { value: bigint };
  remainingStakingAmount?: { value: bigint };
  stakingType?: "NATIVE" | "JITO" | "MARINADE";
  stakePoolConfig?: StakePoolConfig;
}

/** Claim intent (withdraw from deactivated stake) */
export interface ClaimIntent extends BaseIntent {
  intentType: "claim";
  stakingAddress: string;
  amount?: { value: bigint };
}

/** Deactivate intent */
export interface DeactivateIntent extends BaseIntent {
  intentType: "deactivate";
  stakingAddress?: string;
  stakingAddresses?: string[];
}

/** Delegate intent */
export interface DelegateIntent extends BaseIntent {
  intentType: "delegate";
  validatorAddress: string;
  stakingAddress?: string;
  stakingAddresses?: string[];
}

/** Enable token intent (create ATA) */
export interface EnableTokenIntent extends BaseIntent {
  intentType: "enableToken";
  recipientAddress?: string;
  tokenAddress?: string;
  tokenProgramId?: string;
}

/** Close ATA intent */
export interface CloseAtaIntent extends BaseIntent {
  intentType: "closeAssociatedTokenAccount";
  tokenAccountAddress?: string;
  tokenProgramId?: string;
}

/** Consolidate intent - transfer from child address to root */
export interface ConsolidateIntent extends BaseIntent {
  intentType: "consolidate";
  /** The child address to consolidate from (sender) */
  receiveAddress: string;
  /** Recipients (root address for SOL, ATAs for tokens) */
  recipients?: Array<{
    address?: { address: string };
    amount?: { value: bigint };
  }>;
}

/** Union of all supported intent types */
export type SolanaIntent =
  | PaymentIntent
  | StakeIntent
  | UnstakeIntent
  | ClaimIntent
  | DeactivateIntent
  | DelegateIntent
  | EnableTokenIntent
  | CloseAtaIntent
  | ConsolidateIntent;

// =============================================================================
// Main Function
// =============================================================================

/**
 * Build a Solana transaction from a BitGo intent.
 *
 * This function passes the intent directly to Rust/WASM which handles
 * all the intent-to-transaction mapping internally.
 *
 * @param intent - The BitGo intent (with intentType, etc.)
 * @param params - Build parameters (feePayer, nonce)
 * @returns Transaction object and any generated keypairs
 *
 * @example
 * ```typescript
 * // Payment intent
 * const result = buildFromIntent(
 *   {
 *     intentType: 'payment',
 *     recipients: [{ address: { address: recipient }, amount: { value: 1000000n } }]
 *   },
 *   { feePayer: walletRoot, nonce: { type: 'blockhash', value: blockhash } }
 * );
 *
 * // Native staking - generates a new stake account keypair
 * const result = buildFromIntent(
 *   {
 *     intentType: 'stake',
 *     validatorAddress: validator,
 *     amount: { value: 1000000000n }
 *   },
 *   { feePayer: walletRoot, nonce: { type: 'blockhash', value: blockhash } }
 * );
 * // result.generatedKeypairs[0] contains the stake account keypair
 * ```
 */
export function buildFromIntent(
  intent: BaseIntent,
  params: BuildFromIntentParams,
): BuildFromIntentResult {
  const result = IntentNamespace.build_from_intent(intent, params) as WasmBuildResult;

  return {
    transaction: Transaction.fromWasm(result.transaction),
    generatedKeypairs: result.generatedKeypairs,
  };
}
