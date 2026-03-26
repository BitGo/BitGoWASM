/**
 * Transaction building from high-level business intents.
 *
 * Provides the `buildTransaction()` function for building TON transactions.
 * The crate handles intent composition internally (e.g., delegate with Whales
 * automatically produces the correct opcode cell layout).
 */

import { BuilderNamespace } from "./wasm/wasm_ton.js";
import { Transaction } from "./transaction.js";

// =============================================================================
// Intent Types
// =============================================================================

/** TON staking protocol type */
export enum TonStakingType {
  TonWhales = "TON_WHALES",
  SingleNominator = "SINGLE_NOMINATOR",
  MultiNominator = "MULTI_NOMINATOR",
}

/** A recipient for a payment or consolidation intent */
export interface Recipient {
  /** Destination address (base64url TON address) */
  address: string;
  /** Amount in nanotons */
  amount: bigint;
}

/** Native TON transfer or Jetton (token) transfer */
export interface PaymentIntent {
  intentType: "payment";
  /** Recipients with addresses and amounts */
  recipients: Recipient[];
  /** Optional text memo/comment */
  memo?: string;
  /** Whether destination addresses are bounceable */
  bounceable?: boolean;
  /** Whether this is a token (Jetton) transfer */
  isToken?: boolean;
  /** Sender's Jetton wallet address (required when isToken=true) */
  senderJettonWalletAddress?: string;
}

/** Self-send to fill a seqno gap */
export interface FillNonceIntent {
  intentType: "fillNonce";
  /** Sender address (recipient = sender) */
  sender: string;
  /** Whether the address is bounceable */
  bounceable?: boolean;
}

/** Sweep funds to a destination */
export interface ConsolidateIntent {
  intentType: "consolidate";
  /** Recipients with addresses and amounts */
  recipients: Recipient[];
  /** Receive address for the consolidation */
  receiveAddress: string;
  /** Whether this is a token (Jetton) consolidation */
  isToken?: boolean;
  /** Sender's Jetton wallet address (required when isToken=true) */
  senderJettonWalletAddress?: string;
}

/** Staking deposit */
export interface DelegateIntent {
  intentType: "delegate";
  /** Validator/pool address */
  validatorAddress: string;
  /** Amount to stake in nanotons */
  amount: bigint;
  /** Staking protocol type */
  stakingType: TonStakingType;
}

/** Staking withdrawal */
export interface UndelegateIntent {
  intentType: "undelegate";
  /** Validator/pool address */
  validatorAddress: string;
  /** Amount to unstake in nanotons (0 = full withdrawal for Whales/SingleNom) */
  amount: bigint;
  /** Staking protocol type */
  stakingType: TonStakingType;
  /** Withdrawal amount for Whales (the actual TON to withdraw) */
  withdrawalAmount?: bigint;
}

/** Union of all transaction intent types */
export type TransactionIntent =
  | PaymentIntent
  | FillNonceIntent
  | ConsolidateIntent
  | DelegateIntent
  | UndelegateIntent;

/** Build context provided by the caller */
export interface BuildContext {
  /** Wallet address (base64url) */
  sender: string;
  /** Hex-encoded Ed25519 public key (32 bytes) */
  publicKey: string;
  /** Current sequence number */
  seqno: number;
  /** Unix timestamp for transaction expiry */
  expireTime: number;
  /** Wallet version string ("V3R2", "V4R2", "V5R1") */
  walletVersion?: string;
  /** Sub-wallet ID (default 698983191) */
  walletId?: number;
}

// =============================================================================
// Build Function
// =============================================================================

/**
 * Serialize an intent for WASM consumption.
 *
 * Converts bigint amounts to string for serde_wasm_bindgen deserialization.
 */
function serializeIntent(intent: TransactionIntent): unknown {
  switch (intent.intentType) {
    case "payment":
      return {
        ...intent,
        recipients: intent.recipients.map((r) => ({
          ...r,
          amount: String(r.amount),
        })),
      };
    case "consolidate":
      return {
        ...intent,
        recipients: intent.recipients.map((r) => ({
          ...r,
          amount: String(r.amount),
        })),
      };
    case "delegate":
      return {
        ...intent,
        amount: String(intent.amount),
      };
    case "undelegate":
      return {
        ...intent,
        amount: String(intent.amount),
        withdrawalAmount:
          intent.withdrawalAmount !== undefined ? String(intent.withdrawalAmount) : undefined,
      };
    case "fillNonce":
      return intent;
    default:
      return intent;
  }
}

/**
 * Build a TON transaction from a business-level intent and context.
 *
 * The intent describes *what* to do (payment, stake, etc.) and the context
 * provides *how* to build it (sender, seqno, expireTime, etc.).
 *
 * @param intent - Business intent (payment, delegate, undelegate, fillNonce, consolidate)
 * @param context - Build context (sender, publicKey, seqno, expireTime, etc.)
 * @returns An unsigned Transaction ready for signing
 * @throws Error if the intent cannot be built (e.g., missing Jetton wallet address)
 *
 * @example
 * ```typescript
 * import { buildTransaction, TonStakingType } from '@bitgo/wasm-ton';
 *
 * // Native payment
 * const tx = buildTransaction(
 *   {
 *     intentType: 'payment',
 *     recipients: [{ address: 'EQA0i8...', amount: 10000000n }],
 *   },
 *   { sender: 'EQBJAx...', publicKey: 'f61b63...', seqno: 5, expireTime: 1700000000 }
 * );
 *
 * // Stake with Whales
 * const stakeTx = buildTransaction(
 *   {
 *     intentType: 'delegate',
 *     validatorAddress: 'EQDr9S...',
 *     amount: 10000000000n,
 *     stakingType: TonStakingType.TonWhales,
 *   },
 *   context
 * );
 * ```
 */
export function buildTransaction(intent: TransactionIntent, context: BuildContext): Transaction {
  const serializedIntent = serializeIntent(intent);
  const inner = BuilderNamespace.buildTransaction(serializedIntent, context);
  return Transaction.fromWasm(inner);
}
