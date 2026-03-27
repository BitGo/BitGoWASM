/**
 * Transaction parsing -- standalone function that decodes a Transaction
 * into structured data (type, outputs, amounts, memo, etc.).
 *
 * This is separate from the Transaction class, which handles signing.
 * Use Transaction.fromBytes() when you need to sign.
 * Use parseTransaction() when you need decoded data.
 *
 * All monetary amounts (outputAmount, jettonAmount, etc.) are returned as bigint.
 */

import { ParserNamespace } from "./wasm/wasm_ton.js";
import type { Transaction } from "./transaction.js";

// =============================================================================
// Transaction types matching BitGoJS
// =============================================================================

/** TON transaction type strings */
export enum TonTransactionType {
  Send = "Send",
  SendToken = "SendToken",
  TonWhalesDeposit = "TonWhalesDeposit",
  TonWhalesWithdrawal = "TonWhalesWithdrawal",
  SingleNominatorWithdraw = "SingleNominatorWithdraw",
  TonWhalesVestingDeposit = "TonWhalesVestingDeposit",
  TonWhalesVestingWithdrawal = "TonWhalesVestingWithdrawal",
}

// =============================================================================
// Parsed output (recipient)
// =============================================================================

/** A single output (recipient) from the transaction */
export interface ParsedOutput {
  /** Recipient address (raw format: workchain:hex) */
  address: string;
  /** Amount in nanotons as bigint */
  amount: bigint;
}

// =============================================================================
// ParsedTransaction
// =============================================================================

/**
 * Fully parsed TON transaction with decoded fields.
 *
 * All monetary amounts are returned as bigint directly from WASM.
 */
export interface ParsedTransaction {
  /** Transaction type */
  type: TonTransactionType;
  /** Wallet ID */
  walletId: number;
  /** Sequence number */
  seqno: number;
  /** Expiration time as bigint (unix timestamp) */
  expireTime: bigint;
  /** Outputs (recipients with amounts) */
  outputs: ParsedOutput[];
  /** Total output amount in nanotons as bigint */
  outputAmount: bigint;
  /** Whether the destination is bounceable */
  bounceable: boolean;
  /** Optional memo/comment */
  memo?: string;
  /** Send mode of the first inner message */
  sendMode: number;
  /** Withdrawal amount (for Whales/SingleNominator) as bigint */
  withdrawAmount?: bigint;
  /** Jetton amount (for SendToken) as bigint */
  jettonAmount?: bigint;
  /** Jetton destination address (for SendToken) */
  jettonDestination?: string;
  /** Forward TON amount (for SendToken) as bigint */
  forwardTonAmount?: bigint;
}

// =============================================================================
// parseTransaction function
// =============================================================================

/**
 * Parse a Transaction into a plain data object with decoded fields.
 *
 * This is the main parsing function that returns structured data with
 * transaction type detection and decoded amounts as bigint.
 *
 * Accepts a `Transaction` object (from `Transaction.fromBytes()`), avoiding
 * double deserialization.
 *
 * @param tx - A Transaction instance
 * @returns A ParsedTransaction with all fields decoded
 *
 * @example
 * ```typescript
 * const tx = Transaction.fromBytes(bocBytes);
 * const parsed = parseTransaction(tx);
 * if (parsed.type === 'Send') {
 *   console.log(`${parsed.outputAmount} nanotons to ${parsed.outputs[0].address}`);
 * }
 * ```
 */
export function parseTransaction(tx: Transaction): ParsedTransaction {
  return ParserNamespace.parseTransaction(tx.wasm) as unknown as ParsedTransaction;
}
