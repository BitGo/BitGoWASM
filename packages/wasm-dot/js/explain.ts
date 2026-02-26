/**
 * Transaction explanation — business logic layer.
 *
 * Rust decodes extrinsic bytes → ParsedTransaction (pallet, method, args).
 * This module derives transaction types, extracts outputs/inputs, and builds
 * the structured ExplainedTransaction that consumers expect.
 */

import { parseTransaction, type TransactionInput } from "./parser";
import type { Era, ParseContext, ParsedMethod } from "./types";

const MAX_NESTING_DEPTH = 10;

// =============================================================================
// Types
// =============================================================================

export enum TransactionType {
  Send = "Send",
  StakingActivate = "StakingActivate",
  StakingUnlock = "StakingUnlock",
  StakingWithdraw = "StakingWithdraw",
  StakingUnvote = "StakingUnvote",
  StakingClaim = "StakingClaim",
  AddressInitialization = "AddressInitialization",
  Batch = "Batch",
  Unknown = "Unknown",
}

export interface ExplainedOutput {
  address: string;
  amount: string;
}

export interface ExplainedInput {
  address: string;
  value: string;
}

export interface ExplainedTransaction {
  /** Derived transaction type */
  type: TransactionType;
  /** Transaction ID (hash, if signed) */
  id: string | undefined;
  /** Sender address */
  sender: string | undefined;
  /** Output destinations and amounts */
  outputs: ExplainedOutput[];
  /** Input sources (sender for each output) */
  inputs: ExplainedInput[];
  /** Total output amount (sum of outputs, as string) */
  outputAmount: string;
  /** Tip amount (in planck). Note: DOT fees are runtime-computed and not
   *  deterministic from extrinsic bytes alone. This field only contains
   *  the optional tip, which is usually "0". */
  tip: string;
  /** Transaction era (mortal or immortal) */
  era: Era;
  /** Raw decoded method (pallet + name + args) */
  method: ParsedMethod;
  /** Whether transaction is signed */
  isSigned: boolean;
  /** Account nonce */
  nonce: number;

  // --- Context pass-through fields ---
  // These are NOT decoded from extrinsic bytes — they come from the caller's
  // context (material + build params). Included here so consumers get a
  // complete picture without post-processing.

  /** Chain genesis hash (from material) */
  genesisHash?: string;
  /** Runtime spec version (from material) */
  specVersion?: number;
  /** Transaction format version (from material) */
  transactionVersion?: number;
  /** Chain name (from material) */
  chainName?: string;
  /** Reference block hash (from context — not in extrinsic bytes) */
  referenceBlock?: string;
  /** Block number / firstValid (from context — not in extrinsic bytes) */
  blockNumber?: number;
}

// =============================================================================
// Public API
// =============================================================================

/**
 * Explain a DOT transaction: decode bytes → derive type → extract outputs.
 *
 * This is the main entry point for consumers who need structured transaction data.
 *
 * @param input - Raw bytes, hex string, or DotTransaction
 * @param options - Optional parsing context
 */
export function explainTransaction(
  input: TransactionInput,
  options?: { context?: ParseContext },
): ExplainedTransaction {
  const parsed = parseTransaction(input, options?.context);
  const type_ = deriveTransactionType(parsed.method, 0);
  const outputs = extractOutputs(parsed.method, 0);
  const sender = parsed.sender ?? undefined;

  const inputs: ExplainedInput[] = sender
    ? outputs.map((o) => ({ address: sender, value: o.amount }))
    : [];

  const outputAmount = outputs.reduce((sum, o) => {
    if (o.amount === "ALL") return sum;
    return (BigInt(sum) + BigInt(o.amount)).toString();
  }, "0");

  // Extract context pass-through fields from material + context
  const ctx = options?.context;
  const material = ctx?.material;

  return {
    type: type_,
    id: parsed.id ?? undefined,
    sender,
    outputs,
    inputs,
    outputAmount,
    tip: parsed.tip,
    era: parsed.era,
    method: parsed.method,
    isSigned: parsed.isSigned,
    nonce: parsed.nonce,
    // Context pass-through fields (not decoded from bytes)
    genesisHash: material?.genesisHash,
    specVersion: material?.specVersion,
    transactionVersion: material?.txVersion,
    chainName: material?.chainName,
    referenceBlock: ctx?.referenceBlock,
    blockNumber: ctx?.blockNumber,
  };
}

// =============================================================================
// Type Derivation
// =============================================================================

function deriveTransactionType(method: ParsedMethod, depth: number): TransactionType {
  const key = `${method.pallet}.${method.name}`;
  switch (key) {
    case "balances.transfer":
    case "balances.transferKeepAlive":
    case "balances.transferAllowDeath":
    case "balances.transferAll":
      return TransactionType.Send;

    case "staking.bond":
    case "staking.bondExtra":
      return TransactionType.StakingActivate;

    case "staking.unbond":
      return TransactionType.StakingUnlock;

    case "staking.withdrawUnbonded":
      return TransactionType.StakingWithdraw;

    case "staking.chill":
      return TransactionType.StakingUnvote;

    case "staking.payoutStakers":
      return TransactionType.StakingClaim;

    case "proxy.addProxy":
    case "proxy.removeProxy":
    case "proxy.createPure":
      return TransactionType.AddressInitialization;

    case "utility.batch":
    case "utility.batchAll":
      return TransactionType.Batch;

    case "proxy.proxy": {
      if (depth >= MAX_NESTING_DEPTH) return TransactionType.Unknown;
      const call = method.args?.call as ParsedMethod | undefined;
      if (call?.pallet && call?.name) return deriveTransactionType(call, depth + 1);
      return TransactionType.Unknown;
    }

    default:
      return TransactionType.Unknown;
  }
}

// =============================================================================
// Output Extraction
// =============================================================================

function extractOutputs(method: ParsedMethod, depth: number): ExplainedOutput[] {
  const args = method.args;
  const key = `${method.pallet}.${method.name}`;

  switch (key) {
    case "balances.transfer":
    case "balances.transferKeepAlive":
    case "balances.transferAllowDeath":
      return [
        {
          address: String(args.dest ?? ""),
          amount: String(args.value ?? "0"),
        },
      ];

    case "balances.transferAll":
      return [{ address: String(args.dest ?? ""), amount: "ALL" }];

    case "staking.bond":
    case "staking.bondExtra":
    case "staking.unbond":
      return [{ address: "STAKING", amount: String(args.value ?? "0") }];

    case "utility.batch":
    case "utility.batchAll": {
      if (depth >= MAX_NESTING_DEPTH) return [];
      const calls = (args.calls ?? []) as ParsedMethod[];
      return calls.filter((c) => c?.pallet && c?.name).flatMap((c) => extractOutputs(c, depth + 1));
    }

    case "proxy.proxy": {
      if (depth >= MAX_NESTING_DEPTH) return [];
      const call = args.call as ParsedMethod | undefined;
      return call?.pallet && call?.name ? extractOutputs(call, depth + 1) : [];
    }

    default:
      return [];
  }
}
