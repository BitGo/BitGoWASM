/**
 * Intent-based transaction building for TON.
 *
 * Each intent represents a single user action (payment, staking, etc.).
 * Low-level cell composition happens in Rust; callers provide
 * business-level parameters.
 *
 * All monetary amounts must be passed as bigint.
 */

import { BuilderNamespace } from "./wasm/wasm_ton.js";
import { Transaction } from "./transaction.js";

// =============================================================================
// Intent Types
// =============================================================================

/** Native TON transfer */
export interface PaymentIntent {
  intentType: "Payment";
  /** Recipient address (user-friendly) */
  recipient: string;
  /** Amount in nanoTON */
  amount: bigint;
  /** Optional text memo */
  memo?: string;
  /** Whether recipient is bounceable (default false) */
  bounceable?: boolean;
}

/** Jetton (token) transfer */
export interface JettonTransferIntent {
  intentType: "JettonTransfer";
  /** Sender's jetton wallet address */
  jettonWalletAddress: string;
  /** Final recipient of the tokens */
  recipient: string;
  /** Token amount (in token's smallest unit) */
  tokenAmount: bigint;
  /** TON amount to attach (default 0.1 TON) */
  tonAmount?: bigint;
  /** TON forwarded to recipient (default 100 nanoTON) */
  forwardTonAmount?: bigint;
  /** Optional text memo */
  memo?: string;
  /** Query ID (default 0) */
  queryId?: bigint;
}

/** Single nominator withdraw */
export interface SingleNominatorWithdrawIntent {
  intentType: "SingleNominatorWithdraw";
  /** Validator/nominator contract address */
  validatorAddress: string;
  /** TON amount to send (covers fees, default 1 TON) */
  amount?: bigint;
  /** Amount to withdraw from the nominator */
  withdrawAmount: bigint;
  /** Query ID (default 0) */
  queryId?: bigint;
}

/** TON Whales staking pool deposit */
export interface TonWhalesDepositIntent {
  intentType: "TonWhalesDeposit";
  /** Validator/pool address */
  validatorAddress: string;
  /** Amount to stake in nanoTON */
  amount: bigint;
  /** Query ID (default 0) */
  queryId?: bigint;
}

/** TON Whales staking pool withdrawal */
export interface TonWhalesWithdrawalIntent {
  intentType: "TonWhalesWithdrawal";
  /** Validator/pool address */
  validatorAddress: string;
  /** TON amount to send (covers fees) */
  amount: bigint;
  /** Amount to unstake (0 = full withdrawal) */
  withdrawalAmount: bigint;
  /** Query ID (default 0) */
  queryId?: bigint;
}

/** TON Whales vesting deposit */
export interface TonWhalesVestingDepositIntent {
  intentType: "TonWhalesVestingDeposit";
  /** Vesting contract address */
  contractAddress: string;
  /** Amount to deposit in nanoTON */
  amount: bigint;
}

/** TON Whales vesting withdrawal */
export interface TonWhalesVestingWithdrawalIntent {
  intentType: "TonWhalesVestingWithdrawal";
  /** Vesting contract address */
  contractAddress: string;
  /** Amount to withdraw in nanoTON */
  amount: bigint;
}

/** All supported intent types */
export type TonIntent =
  | PaymentIntent
  | JettonTransferIntent
  | SingleNominatorWithdrawIntent
  | TonWhalesDepositIntent
  | TonWhalesWithdrawalIntent
  | TonWhalesVestingDepositIntent
  | TonWhalesVestingWithdrawalIntent;

// =============================================================================
// Build Context
// =============================================================================

/** Context provided by the caller for all intents */
export interface TonBuildContext {
  /** Sender address (user-friendly) */
  sender: string;
  /** Hex-encoded Ed25519 public key (32 bytes) */
  publicKey: string;
  /** Wallet sequence number */
  seqno: number;
  /** Unix timestamp for transaction expiration */
  expireTime: bigint;
  /** Wallet ID (default 698983191, 268 for vesting) */
  walletId?: number;
  /** Address format flag */
  bounceable?: boolean;
}

// =============================================================================
// buildTransaction function
// =============================================================================

/**
 * Build an unsigned transaction from a business intent.
 *
 * Returns a Transaction that can be inspected, signed, and serialized.
 *
 * @param intent - A tagged intent object describing the user action
 * @param context - Build context with sender, publicKey, seqno, expireTime
 * @returns A Transaction ready for signing
 *
 * @example
 * ```typescript
 * import { buildTransaction, Transaction } from '@bitgo/wasm-ton';
 *
 * const tx = buildTransaction(
 *   {
 *     intentType: 'Payment',
 *     recipient: 'UQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBX1aD',
 *     amount: 500000000n,
 *     memo: 'hello',
 *   },
 *   {
 *     sender: 'UQAbJug-k-tufWMjEC1RKSM0iiJTDUcYkC7zWANHrkT55Afg',
 *     publicKey: 'c0c3b9dc09932121ee351b2448c50a3ae2571b12951245c85f3bd95d5e7a06f8',
 *     seqno: 1,
 *     expireTime: 1234567890n,
 *   }
 * );
 *
 * // Sign and broadcast
 * const payload = tx.signablePayload();
 * tx.addSignature(pubkey, signature);
 * const broadcastTx = tx.toBroadcastFormat();
 * ```
 */
export function buildTransaction(intent: TonIntent, context: TonBuildContext): Transaction {
  // Convert bigint amounts to strings for serde_wasm_bindgen compatibility.
  // serde_wasm_bindgen handles BigInt natively in newer versions,
  // but we convert to ensure reliable deserialization.
  const serializedIntent = serializeBigInts(intent);
  const serializedContext = serializeBigInts(context);

  const wasm = BuilderNamespace.buildTransaction(serializedIntent, serializedContext);
  return Transaction.fromWasm(wasm);
}

/**
 * Recursively convert bigint values to strings for serde compatibility.
 * @internal
 */
function serializeBigInts(obj: unknown): unknown {
  if (typeof obj === "bigint") {
    return obj.toString();
  }
  if (Array.isArray(obj)) {
    return obj.map(serializeBigInts);
  }
  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = serializeBigInts(value);
    }
    return result;
  }
  return obj;
}
