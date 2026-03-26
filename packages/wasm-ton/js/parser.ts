/**
 * High-level transaction parsing.
 *
 * Provides types and a standalone function for parsing TON transactions
 * into structured data matching BitGoJS's format.
 *
 * All monetary amounts (amount, tokenAmount) are returned as bigint.
 */

import { ParserNamespace } from "./wasm/wasm_ton.js";
import type { Transaction } from "./transaction.js";

// =============================================================================
// Transaction Types
// =============================================================================

/** TON transaction type */
export type TonTransactionType =
  | "Send"
  | "SendToken"
  | "SingleNominatorWithdraw"
  | "TonWhalesDeposit"
  | "TonWhalesWithdrawal"
  | "TonWhalesVestingDeposit"
  | "TonWhalesVestingWithdrawal";

// =============================================================================
// ParsedTransaction
// =============================================================================

/**
 * A fully parsed TON transaction with decoded fields.
 *
 * All monetary amounts are returned as bigint directly from WASM.
 */
export interface ParsedTransaction {
  /** Transaction type */
  type: TonTransactionType;

  /** Sender address (user-friendly, non-bounceable) */
  sender: string;

  /** Recipient address (user-friendly) */
  recipient: string;

  /** Transfer amount in nanoTON */
  amount: bigint;

  /** Whether the recipient address is bounceable */
  bounceable: boolean;

  /** Wallet sequence number */
  seqno: number;

  /** Wallet ID */
  walletId: number;

  /** Expiration timestamp (unix) */
  expireTime: bigint;

  /** Optional memo/comment */
  memo?: string;

  /** Signature hex string (empty if unsigned) */
  signature: string;

  /** Public key hex (from StateInit, when seqno=0) */
  publicKey?: string;

  /** Token amount as bigint (for jetton transfers) */
  tokenAmount?: bigint;

  /** Token recipient address (for jetton transfers) */
  tokenRecipient?: string;
}

// =============================================================================
// parseTransaction function
// =============================================================================

/**
 * Parse a Transaction into a plain data object with decoded fields.
 *
 * This is the main parsing function that returns structured data with
 * amounts as bigint. It is a STANDALONE function, not a method on Transaction.
 *
 * @param tx - A Transaction instance (from Transaction.fromBoc())
 * @returns A ParsedTransaction with all fields decoded
 *
 * @example
 * ```typescript
 * const tx = Transaction.fromBoc(base64Boc);
 * const parsed = parseTransaction(tx);
 * console.log(parsed.type); // "Send"
 * console.log(parsed.amount); // 123400000n
 * ```
 */
export function parseTransaction(tx: Transaction): ParsedTransaction {
  return ParserNamespace.parseTransaction(tx.wasm) as unknown as ParsedTransaction;
}
