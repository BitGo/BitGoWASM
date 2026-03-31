/**
 * Transaction building via intents.
 *
 * Intents and context are passed directly to WASM as JS objects.
 * serde-wasm-bindgen handles deserialization, including BigInt to u64.
 */

import { BuilderNamespace } from "./wasm/wasm_ton.js";
import { Transaction } from "./transaction.js";

/** Staking provider types */
export const TonStakingType = ["TonWhales", "SingleNominator", "MultiNominator"] as const;
export type TonStakingType = (typeof TonStakingType)[number];

/** Transaction type */
export const TonTransactionType = [
  "Transfer",
  "TokenTransfer",
  "WhalesDeposit",
  "WhalesVestingDeposit",
  "WhalesWithdraw",
  "WhalesVestingWithdraw",
  "SingleNominatorWithdraw",
  "Unknown",
] as const;
export type TonTransactionType = (typeof TonTransactionType)[number];

/** Build context for constructing transactions */
export interface BuildContext {
  sender: string;
  seqno: number;
  expireTime: bigint;
  publicKey?: string;
  walletVersion?: number;
  isVestingContract?: boolean;
  subWalletId?: bigint;
}

/** Native TON payment intent */
export interface PaymentIntent {
  type: "payment";
  to: string;
  amount: bigint;
  bounceable?: boolean;
  memo?: string;
}

/** Token (jetton) payment intent */
export interface TokenPaymentIntent {
  type: "tokenPayment";
  to: string;
  amount: bigint;
  jettonAddress: string;
  tonAmount?: bigint;
  forwardTonAmount?: bigint;
  memo?: string;
}

/** Fill nonce intent */
export interface FillNonceIntent {
  type: "fillNonce";
  isToken?: boolean;
  jettonAddress?: string;
}

/** Consolidate intent */
export interface ConsolidateIntent {
  type: "consolidate";
  isToken?: boolean;
  jettonAddress?: string;
}

/** Delegate (staking) intent */
export interface DelegateIntent {
  type: "delegate";
  amount: bigint;
  validatorAddress: string;
  stakingType: TonStakingType;
  queryId?: bigint;
}

/** Undelegate (unstaking) intent */
export interface UndelegateIntent {
  type: "undelegate";
  amount?: bigint;
  validatorAddress: string;
  stakingType: TonStakingType;
}

/** Union of all intent types */
export type TonIntent =
  | PaymentIntent
  | TokenPaymentIntent
  | FillNonceIntent
  | ConsolidateIntent
  | DelegateIntent
  | UndelegateIntent;

/**
 * Build a transaction from an intent and context.
 *
 * @param intent - Transaction intent
 * @param context - Build context (sender, seqno, expireTime, etc.)
 * @returns A Transaction ready for signing
 */
export function buildTransaction(intent: TonIntent, context: BuildContext): Transaction {
  const bytes = BuilderNamespace.buildTransaction(intent, context);
  return Transaction.fromBytes(bytes);
}
