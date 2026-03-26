/**
 * Transaction building from business-level intents.
 *
 * Provides the `buildTransaction()` function for building TON transactions.
 * The crate handles message construction internally (V4R2 wallet message
 * wrapping, jetton transfer encoding, staking opcodes, etc.).
 */

import { BuilderNamespace } from "./wasm/wasm_ton.js";
import { Transaction } from "./transaction.js";

// =============================================================================
// Intent Type Enum
// =============================================================================

/** Discriminator for TON transaction intents. */
export enum TonIntentType {
  Payment = "payment",
  FillNonce = "fillNonce",
  Consolidate = "consolidate",
  Delegate = "delegate",
  Undelegate = "undelegate",
}

// =============================================================================
// Staking Type Enum
// =============================================================================

/** TON staking protocol variants. */
export enum TonStakingType {
  TonWhales = "TON_WHALES",
  SingleNominator = "SINGLE_NOMINATOR",
  MultiNominator = "MULTI_NOMINATOR",
}

// =============================================================================
// Recipient
// =============================================================================

/** A recipient with address and amount. */
export interface Recipient {
  /** Destination address (user-friendly TON format) */
  address: string;
  /** Amount in nanoTON */
  amount: bigint;
}

// =============================================================================
// Intent Types
// =============================================================================

/** Common fields for all intents that have wallet context. */
interface WalletContext {
  /** Wallet sequence number */
  seqno: number;
  /** Expiration unix timestamp */
  expireAt: number;
  /** Hex-encoded Ed25519 public key */
  publicKey: string;
}

/** Transfer TON or jetton tokens to recipient(s). */
export interface PaymentIntent extends WalletContext {
  intentType: TonIntentType.Payment;
  /** Recipients with address and amount */
  recipients: Recipient[];
  /** Optional text memo */
  memo?: string;
  /** Whether destination addresses are bounceable (default: false) */
  bounceable?: boolean;
  /** Sender wallet address */
  sender: string;
  /** Sender's jetton wallet address (if present, this is a jetton transfer) */
  senderJettonAddress?: string;
}

/** Self-send to advance the wallet nonce. */
export interface FillNonceIntent extends WalletContext {
  intentType: TonIntentType.FillNonce;
  /** Self-send target address */
  address: string;
  /** Sender's jetton wallet address (optional, for token fill nonce) */
  senderJettonAddress?: string;
}

/** Consolidate funds to recipient(s). */
export interface ConsolidateIntent extends WalletContext {
  intentType: TonIntentType.Consolidate;
  /** Recipients with address and amount */
  recipients: Recipient[];
  /** Sender wallet address */
  sender: string;
  /** Sender's jetton wallet address (optional, for token consolidation) */
  senderJettonAddress?: string;
}

/** Delegate (stake) TON with a validator. */
export interface DelegateIntent extends WalletContext {
  intentType: TonIntentType.Delegate;
  /** Validator/pool address */
  validatorAddress: string;
  /** Amount in nanoTON */
  amount: bigint;
  /** Staking protocol type */
  stakingType: TonStakingType;
  /** Sender wallet address */
  sender: string;
  /** Whether this is a vesting contract wallet (default: false) */
  isVesting?: boolean;
  /** Custom sub-wallet ID for vesting contracts (required when isVesting=true) */
  subWalletId?: number;
}

/** Undelegate (unstake) TON from a validator. */
export interface UndelegateIntent extends WalletContext {
  intentType: TonIntentType.Undelegate;
  /** Validator/pool address */
  validatorAddress: string;
  /** Amount in nanoTON (transfer amount to validator) */
  amount: bigint;
  /** Withdrawal amount for whales pool (0 = full withdrawal) */
  withdrawalAmount?: bigint;
  /** Staking protocol type */
  stakingType: TonStakingType;
  /** Sender wallet address */
  sender: string;
  /** Whether this is a vesting contract wallet (default: false) */
  isVesting?: boolean;
  /** Custom sub-wallet ID for vesting contracts (required when isVesting=true) */
  subWalletId?: number;
}

/** Union of all TON transaction intent types. */
export type TonTransactionIntent =
  | PaymentIntent
  | FillNonceIntent
  | ConsolidateIntent
  | DelegateIntent
  | UndelegateIntent;

// =============================================================================
// buildTransaction function
// =============================================================================

/**
 * Build a TON transaction from a business-level intent.
 *
 * The intent describes what to do (payment, stake, etc.) and includes
 * all wallet context (sender, seqno, expireAt, publicKey).
 * The crate handles V4R2 message wrapping internally.
 *
 * @param intent - Business intent (payment, fillNonce, consolidate, delegate, undelegate)
 * @returns An unsigned Transaction ready for signing
 * @throws Error if the intent cannot be built (e.g., invalid addresses)
 *
 * @example
 * ```typescript
 * import { buildTransaction, TonIntentType } from '@bitgo/wasm-ton';
 *
 * // Native payment
 * const tx = buildTransaction({
 *   intentType: TonIntentType.Payment,
 *   recipients: [{ address: 'UQA0i8-C...', amount: 1000000000n }],
 *   sender: 'UQMyWallet...',
 *   seqno: 1,
 *   expireAt: 1700000000,
 *   publicKey: '0101...0101',
 * });
 *
 * // Stake with TON Whales
 * const stakeTx = buildTransaction({
 *   intentType: TonIntentType.Delegate,
 *   validatorAddress: 'EQWhalesPool...',
 *   amount: 5000000000n,
 *   stakingType: TonStakingType.TonWhales,
 *   sender: 'UQMyWallet...',
 *   seqno: 2,
 *   expireAt: 1700000000,
 *   publicKey: '0101...0101',
 * });
 * ```
 */
export function buildTransaction(intent: TonTransactionIntent): Transaction {
  // Convert bigint amounts to strings for serde compatibility
  const serializable = serializeIntent(intent);
  const wasm = BuilderNamespace.buildTransaction(serializable);
  return Transaction.fromWasm(wasm);
}

/**
 * Convert an intent with bigint amounts to a JSON-serializable object.
 * serde_wasm_bindgen deserializes bigints as strings for u64 fields.
 */
function serializeIntent(intent: TonTransactionIntent): unknown {
  switch (intent.intentType) {
    case TonIntentType.Payment:
      return {
        ...intent,
        recipients: intent.recipients.map((r) => ({
          ...r,
          amount: String(r.amount),
        })),
      };
    case TonIntentType.FillNonce:
      return intent;
    case TonIntentType.Consolidate:
      return {
        ...intent,
        recipients: intent.recipients.map((r) => ({
          ...r,
          amount: String(r.amount),
        })),
      };
    case TonIntentType.Delegate:
      return {
        ...intent,
        amount: String(intent.amount),
      };
    case TonIntentType.Undelegate:
      return {
        ...intent,
        amount: String(intent.amount),
        withdrawalAmount:
          intent.withdrawalAmount !== undefined ? String(intent.withdrawalAmount) : undefined,
      };
  }
}
