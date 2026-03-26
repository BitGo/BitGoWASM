/**
 * High-level TON transaction parsing.
 *
 * Provides types and a standalone `parseTransaction` function that extracts
 * structured data from a Transaction, including recipients, Jetton transfers,
 * and staking operations.
 *
 * All monetary amounts are returned as bigint.
 */

import { ParserNamespace } from "./wasm/wasm_ton.js";
import type { Transaction } from "./transaction.js";

// =============================================================================
// Transaction Types
// =============================================================================

/** Transaction type classification */
export enum TransactionType {
  Send = "Send",
  SendToken = "SendToken",
  SingleNominatorWithdraw = "SingleNominatorWithdraw",
  TonWhalesDeposit = "TonWhalesDeposit",
  TonWhalesWithdrawal = "TonWhalesWithdrawal",
}

// =============================================================================
// Parsed Data Types
// =============================================================================

/** A recipient of a TON transfer */
export interface ParsedRecipient {
  /** Base64url-encoded TON address */
  address: string;
  /** Amount in nanotons */
  amount: bigint;
  /** Whether the destination address is bounceable */
  bounceable: boolean;
}

/** Jetton (token) transfer details */
export interface ParsedJettonTransfer {
  /** Jetton transfer query ID */
  queryId: bigint;
  /** Jetton amount as string (arbitrary precision) */
  amount: string;
  /** Destination address for the Jetton transfer */
  destination: string;
  /** Response destination address */
  responseDestination: string;
  /** TON amount forwarded with the Jetton transfer */
  forwardTonAmount: bigint;
  /** Optional text comment in the forward payload */
  forwardPayloadComment?: string;
}

/** Fully parsed TON transaction */
export interface ParsedTransaction {
  /** Sender wallet address (base64url, bounceable) */
  sender: string;
  /** Array of TON transfer recipients */
  recipients: ParsedRecipient[];
  /** Sequence number */
  seqno: number;
  /** Expiration unix timestamp */
  expireTime: number;
  /** Sub-wallet ID */
  walletId: number;
  /** Optional text memo/comment */
  memo?: string;
  /** Transaction type classification */
  transactionType: TransactionType;
  /** Transaction ID (base64url hash), undefined if unsigned */
  id?: string;
  /** Jetton transfer details, present when transactionType is SendToken */
  jettonTransfer?: ParsedJettonTransfer;
  /** Wallet version string ("V3R2", "V4R2", "V5R1") */
  walletVersion: string;
}

// =============================================================================
// Parse Function
// =============================================================================

/**
 * Parse a Transaction into structured data.
 *
 * Extracts recipients, transaction type, Jetton transfer details,
 * staking operation classification, and other metadata.
 *
 * @param tx - A Transaction instance (from Transaction.fromBytes or Transaction.fromBase64)
 * @returns Fully parsed transaction data
 *
 * @example
 * ```typescript
 * import { Transaction, parseTransaction } from '@bitgo/wasm-ton';
 *
 * const tx = Transaction.fromBase64(bocBase64);
 * const parsed = parseTransaction(tx);
 *
 * if (parsed.transactionType === 'Send') {
 *   for (const r of parsed.recipients) {
 *     console.log(`${r.amount} nanotons to ${r.address}`);
 *   }
 * }
 * ```
 */
export function parseTransaction(tx: Transaction): ParsedTransaction {
  return ParserNamespace.parseFromTransaction(tx.wasm) as ParsedTransaction;
}
