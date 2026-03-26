/**
 * Transaction parsing - standalone function that decodes a TON Transaction
 * into structured data (sender, destination, amount, memo, etc.).
 *
 * This is separate from the Transaction class, which handles signing.
 * Use Transaction.fromBytes() when you need to sign.
 * Use parseTransaction() when you need decoded data.
 *
 * All monetary amounts (amount, withdrawAmount) are returned as bigint.
 */

import { ParserNamespace } from "./wasm/wasm_ton.js";
import type { Transaction } from "./transaction.js";

// =============================================================================
// Transaction Types
// =============================================================================

/** Known TON transaction types */
export enum TonTransactionType {
  Send = "Send",
  SendToken = "SendToken",
  TonWhalesDeposit = "TonWhalesDeposit",
  TonWhalesWithdrawal = "TonWhalesWithdrawal",
  SingleNominatorWithdraw = "SingleNominatorWithdraw",
  Unknown = "Unknown",
}

// =============================================================================
// ParsedTonTransaction
// =============================================================================

/**
 * A fully parsed TON transaction with decoded fields.
 *
 * Matches the shape expected by BitGoJS's explainTransaction and toJson.
 */
export interface ParsedTonTransaction {
  /** Transaction ID (base64url-encoded hash), undefined if unsigned */
  id?: string;
  /** Sender (wallet) address, user-friendly bounceable format */
  sender: string;
  /** Destination address, user-friendly format */
  destination?: string;
  /** Destination address raw format (workchain:hex) */
  destinationAlias?: string;
  /** Transfer amount in nanoTON */
  amount: bigint;
  /** Withdrawal amount (for staking operations) */
  withdrawAmount?: bigint;
  /** Text memo (if present in the transfer body) */
  memo?: string;
  /** Sequence number */
  seqno: number;
  /** Expiration time (unix timestamp) */
  expirationTime: bigint;
  /** Whether the destination address is bounceable */
  bounceable: boolean;
  /** The detected transaction type */
  transactionType: string;
  /** Sub-wallet ID */
  subWalletId: number;
  /** Whether the transaction is signed */
  isSigned: boolean;
  /** Send mode flags */
  sendMode?: number;
}

// =============================================================================
// parseTransaction function
// =============================================================================

/**
 * Parse a Transaction into a plain data object with decoded fields.
 *
 * This is the main parsing function that returns structured data with
 * amounts as bigint.
 *
 * Accepts a `Transaction` object (from `Transaction.fromBytes()` or
 * `Transaction.fromBase64()`), avoiding double deserialization.
 *
 * @param tx - A Transaction instance
 * @returns A ParsedTonTransaction with all fields decoded
 *
 * @example
 * ```typescript
 * const tx = Transaction.fromBase64(bocBase64);
 * const parsed = parseTransaction(tx);
 * console.log(parsed.destination); // "UQA0i8-..."
 * console.log(parsed.amount);     // 10000000n
 * ```
 */
export function parseTransaction(tx: Transaction): ParsedTonTransaction {
  return ParserNamespace.parseFromTransaction(tx.wasm) as ParsedTonTransaction;
}
