/**
 * High-level transaction parsing.
 *
 * All monetary amounts are returned as bigint directly from WASM.
 */

import { ParserNamespace } from "./wasm/wasm_ton.js";
import type { Transaction } from "./transaction.js";

/** Jetton transfer fields */
export interface JettonTransferFields {
  queryId: bigint;
  amount: bigint;
  destination: string;
  responseDestination: string;
  forwardTonAmount: bigint;
}

/** A single send action from the transaction */
export interface ParsedSendAction {
  mode: number;
  destination: string;
  destinationBounceable: string;
  amount: bigint;
  bounce: boolean;
  stateInit: boolean;
  bodyOpcode?: number;
  memo?: string;
  jettonTransfer?: JettonTransferFields;
}

/** A fully parsed TON transaction */
export interface ParsedTransaction {
  transactionType: string;
  sender: string;
  walletId: number;
  seqno: number;
  expireAt: bigint;
  signature: string;
  sendActions: ParsedSendAction[];
}

/**
 * Parse a Transaction into structured data.
 *
 * @param tx - A Transaction instance
 * @returns A ParsedTransaction with decoded actions
 */
export function parseTransaction(tx: Transaction): ParsedTransaction {
  return ParserNamespace.parseFromTransaction(tx.wasm) as ParsedTransaction;
}

/**
 * Parse raw BOC bytes into structured data.
 *
 * @param bytes - Raw BOC bytes
 * @returns A ParsedTransaction
 */
export function parseTransactionBytes(bytes: Uint8Array): ParsedTransaction {
  return ParserNamespace.parseTransaction(bytes) as ParsedTransaction;
}
