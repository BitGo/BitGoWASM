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

export const EffectiveAmountKinds = ["Exact", "CarryInboundValue", "AllRemainingBalance"] as const;
export type EffectiveAmountKind = (typeof EffectiveAmountKinds)[number];

interface ParsedSendActionFields {
  mode: number;
  /** Grams encoded in the message; the send mode can change the outgoing value. */
  nominalAmount: bigint;
  payFeesSeparately: boolean;
  ignoreActionErrors: boolean;
  bounceOnActionFail: boolean;
  destroyAccountIfZero: boolean;
  destination: string;
  destinationBounceable: string;
  bounce: boolean;
  stateInit: boolean;
  bodyOpcode?: number;
  memo?: string;
  jettonTransfer?: JettonTransferFields;
  /** Withdraw amount from the message body (SingleNominator/Whales withdrawal types). */
  withdrawAmount?: bigint;
}

/** A send action with its TON send-mode value semantics decoded. */
type EffectiveAmountSemantics =
  | {
      effectiveAmountKind: "Exact";
      carriesInboundValue: false;
      carriesAllBalance: false;
    }
  | {
      effectiveAmountKind: "CarryInboundValue";
      carriesInboundValue: true;
      carriesAllBalance: false;
    }
  | {
      effectiveAmountKind: "AllRemainingBalance";
      carriesInboundValue: false;
      carriesAllBalance: true;
    };

export type ParsedSendAction = ParsedSendActionFields & EffectiveAmountSemantics;

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
