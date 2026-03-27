/**
 * Intent-based transaction building for TON.
 *
 * This module provides `buildTransaction()` which accepts a business intent
 * and build context, returning an unsigned Transaction ready for signing.
 *
 * The intent -> transaction mapping happens entirely in Rust/WASM.
 *
 * @example
 * ```typescript
 * import { buildTransaction, TonStakingType } from '@bitgo/wasm-ton';
 *
 * const tx = buildTransaction(
 *   {
 *     intentType: 'payment',
 *     recipients: [{ address: 'EQ...', amount: '1000000000' }],
 *     memo: 'hello',
 *   },
 *   {
 *     senderAddress: 'EQ...',
 *     seqno: 5,
 *     expireTime: 1700000000,
 *   }
 * );
 *
 * const payload = tx.signablePayload(); // 32 bytes to sign
 * tx.addSignature(signature);
 * const broadcast = tx.toBroadcastFormat(); // base64 BOC
 * ```
 */

import { BuilderNamespace } from "./wasm/wasm_ton.js";
import { Transaction } from "./transaction.js";

// =============================================================================
// Staking type enum
// =============================================================================

/** TON staking provider type */
export enum TonStakingType {
  TonWhales = "TonWhales",
  SingleNominator = "SingleNominator",
  MultiNominator = "MultiNominator",
}

// =============================================================================
// Recipient
// =============================================================================

/** A transfer recipient */
export interface Recipient {
  /** Destination address (user-friendly or raw format) */
  address: string;
  /** Amount in nanotons (as string or number, converted to u64 in WASM) */
  amount: bigint | string | number;
}

// =============================================================================
// Build context
// =============================================================================

/** Parameters needed to build any TON transaction */
export interface BuildContext {
  /** Sender (wallet) address */
  senderAddress: string;
  /** Sequence number */
  seqno: number;
  /** Public key (hex, needed when seqno == 0 for StateInit) */
  publicKey?: string;
  /** Expiration time (unix timestamp) */
  expireTime: bigint | number;
  /** Whether destination addresses are bounceable (default: false) */
  bounceable?: boolean;
  /** Whether this is a vesting contract wallet (default: false) */
  isVestingContract?: boolean;
  /** Sub-wallet ID (698983191 default, 268 for vesting) */
  subWalletId?: number;
}

// =============================================================================
// Intent types (discriminated union)
// =============================================================================

/** Base fields for all intents */
interface BaseIntent {
  intentType: string;
}

/** Native TON transfer */
export interface PaymentIntent extends BaseIntent {
  intentType: "payment";
  recipients: Recipient[];
  memo?: string;
  isToken?: false;
}

/** Jetton (token) transfer */
export interface TokenPaymentIntent extends BaseIntent {
  intentType: "payment";
  recipients: Recipient[];
  memo?: string;
  isToken: true;
  senderJettonAddress: string;
  tonAmount?: bigint | string | number;
  forwardTonAmount?: bigint | string | number;
}

/** Self-send for seqno advancement (native) */
export interface FillNonceIntent extends BaseIntent {
  intentType: "fillNonce";
  isToken?: false;
}

/** Self-send for seqno advancement (token) */
export interface TokenFillNonceIntent extends BaseIntent {
  intentType: "fillNonce";
  isToken: true;
  senderJettonAddress: string;
  tonAmount?: bigint | string | number;
}

/** Sweep funds to receive address (native) */
export interface ConsolidateIntent extends BaseIntent {
  intentType: "consolidate";
  recipients: Recipient[];
  isToken?: false;
}

/** Sweep funds to receive address (token) */
export interface TokenConsolidateIntent extends BaseIntent {
  intentType: "consolidate";
  recipients: Recipient[];
  isToken: true;
  senderJettonAddress: string;
  tonAmount?: bigint | string | number;
  forwardTonAmount?: bigint | string | number;
}

/** Staking deposit */
export interface DelegateIntent extends BaseIntent {
  intentType: "delegate";
  stakingType: TonStakingType;
  validatorAddress: string;
  amount: bigint | string | number;
}

/** Staking withdrawal */
export interface UndelegateIntent extends BaseIntent {
  intentType: "undelegate";
  stakingType: TonStakingType;
  validatorAddress: string;
  amount: bigint | string | number;
  withdrawalAmount?: bigint | string | number;
}

/** All supported intent types */
export type TonTransactionIntent =
  | PaymentIntent
  | TokenPaymentIntent
  | FillNonceIntent
  | TokenFillNonceIntent
  | ConsolidateIntent
  | TokenConsolidateIntent
  | DelegateIntent
  | UndelegateIntent;

// =============================================================================
// buildTransaction function
// =============================================================================

/**
 * Build an unsigned transaction from a business intent.
 *
 * @param intent - The transaction intent (payment, delegate, etc.)
 * @param context - Build context (sender address, seqno, expire time, etc.)
 * @returns An unsigned Transaction ready for signing
 */
export function buildTransaction(intent: TonTransactionIntent, context: BuildContext): Transaction {
  // Convert bigint amounts to strings for serde deserialization
  const serializedIntent = serializeForWasm(intent);
  const serializedContext = serializeForWasm(context);

  const wasmTx = BuilderNamespace.buildTransaction(serializedIntent, serializedContext);
  return Transaction.fromWasm(wasmTx);
}

// =============================================================================
// Helpers
// =============================================================================

/**
 * Convert an object for WASM consumption, turning bigint values to strings.
 * serde_wasm_bindgen cannot deserialize BigInt directly, so we convert to strings
 * which the custom deserializer handles.
 */
function serializeForWasm(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === "bigint") return obj.toString();
  if (Array.isArray(obj)) return obj.map(serializeForWasm);
  if (typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[key] = serializeForWasm(value);
    }
    return result;
  }
  return obj;
}
