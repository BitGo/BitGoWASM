/**
 * TypeScript type definitions for wasm-dot
 *
 * Follows wallet-platform pattern: buildTransaction(intent, context)
 * - intent: what to do (transfer, stake, etc.) - single operation
 * - context: how to build it (sender, nonce, material, validity)
 */

// =============================================================================
// Chain Metadata Types
// =============================================================================

/**
 * Chain material metadata required for transaction encoding/decoding
 */
export interface Material {
  /** Chain genesis hash (e.g., "0x91b171bb158e2d...") */
  genesisHash: string;
  /** Chain name (e.g., "Polkadot", "Westend") */
  chainName: string;
  /** Runtime spec name (e.g., "polkadot", "westmint") */
  specName: string;
  /** Runtime spec version */
  specVersion: number;
  /** Transaction format version */
  txVersion: number;
  /** Runtime metadata bytes (hex encoded) - required for encoding calls */
  metadataHex: string;
}

/**
 * Validity window for mortal transactions
 */
export interface Validity {
  /** Block number when transaction becomes valid */
  firstValid: number;
  /** Maximum duration in blocks (default: 2400, ~4 hours) */
  maxDuration: number;
}

/**
 * Context for parsing transactions
 */
export interface ParseContext {
  /** Chain material metadata */
  material: Material;
  /** Sender address (optional, helps with decoding) */
  sender?: string;
}

// =============================================================================
// Build Context (how to build the transaction)
// =============================================================================

/**
 * Build context - contains all non-intent data needed to build a transaction
 *
 * Matches wallet-platform's material + nonce + validity pattern.
 */
export interface BuildContext {
  /** Sender address (SS58 encoded) */
  sender: string;
  /** Account nonce */
  nonce: number;
  /** Optional tip amount (in planck, as string for BigInt) */
  tip?: string;
  /** Chain material metadata */
  material: Material;
  /** Validity window */
  validity: Validity;
  /** Reference block hash for mortality */
  referenceBlock: string;
}

// =============================================================================
// Transaction Intent (what to do)
// =============================================================================

/**
 * Transaction intent - a single operation to perform
 *
 * Discriminated union using the `type` field.
 * For multiple operations, use the `batch` intent type.
 */
export type TransactionIntent =
  | TransferIntent
  | TransferAllIntent
  | StakeIntent
  | UnstakeIntent
  | WithdrawUnbondedIntent
  | ChillIntent
  | AddProxyIntent
  | RemoveProxyIntent
  | BatchIntent;

export interface TransferIntent {
  type: "transfer";
  /** Recipient address (SS58) */
  to: string;
  /** Amount in planck (as string or bigint) */
  amount: string | bigint;
  /** Use transferKeepAlive (default: true) */
  keepAlive?: boolean;
}

export interface TransferAllIntent {
  type: "transferAll";
  /** Recipient address (SS58) */
  to: string;
  /** Keep account alive after transfer */
  keepAlive?: boolean;
}

export interface StakeIntent {
  type: "stake";
  /** Amount to stake in planck (as string or bigint) */
  amount: string | bigint;
  /** Where to send staking rewards */
  payee?: StakePayee;
}

export type StakePayee =
  | { type: "staked" }
  | { type: "stash" }
  | { type: "controller" }
  | { type: "account"; address: string };

export interface UnstakeIntent {
  type: "unstake";
  /** Amount to unstake in planck (as string or bigint) */
  amount: string | bigint;
}

export interface WithdrawUnbondedIntent {
  type: "withdrawUnbonded";
  /** Number of slashing spans (usually 0) */
  slashingSpans?: number;
}

export interface ChillIntent {
  type: "chill";
}

export interface AddProxyIntent {
  type: "addProxy";
  /** Delegate address (SS58) */
  delegate: string;
  /** Proxy type (Any, NonTransfer, Staking, etc.) */
  proxyType: string;
  /** Delay in blocks */
  delay?: number;
}

export interface RemoveProxyIntent {
  type: "removeProxy";
  /** Delegate address (SS58) */
  delegate: string;
  /** Proxy type */
  proxyType: string;
  /** Delay in blocks */
  delay?: number;
}

export interface BatchIntent {
  type: "batch";
  /** List of intents to execute */
  calls: TransactionIntent[];
  /** Use batchAll (atomic) instead of batch (default: true) */
  atomic?: boolean;
}

// =============================================================================
// Parsed Transaction Types
// =============================================================================

/**
 * Transaction era (mortal or immortal)
 */
export type Era = { type: "immortal" } | { type: "mortal"; period: number; phase: number };

/**
 * Parsed transaction method/call
 */
export interface ParsedMethod {
  /** Pallet name (e.g., "balances") */
  pallet: string;
  /** Method name (e.g., "transferKeepAlive") */
  name: string;
  /** Pallet index */
  palletIndex: number;
  /** Method index */
  methodIndex: number;
  /** Method arguments (decoded if known) */
  args: unknown;
}

/**
 * Transaction output (recipient)
 */
export interface TransactionOutput {
  /** Recipient address */
  address: string;
  /** Amount (in planck, as string for BigInt) */
  amount: string;
}

/**
 * Fee information
 */
export interface FeeInfo {
  /** Fee/tip amount */
  fee: string;
  /** Fee type (always "tip" for DOT) */
  type: string;
}

/**
 * Parsed transaction data
 */
export interface ParsedTransaction {
  /** Transaction ID (hash, if signed) */
  id: string | null;
  /** Sender address (SS58 encoded) */
  sender: string | null;
  /** Account nonce */
  nonce: number;
  /** Tip amount (in planck, as string for BigInt) */
  tip: string;
  /** Transaction era */
  era: Era;
  /** Decoded method/call */
  method: ParsedMethod;
  /** Transaction outputs (recipients and amounts) */
  outputs: TransactionOutput[];
  /** Fee information */
  fee: FeeInfo;
  /** Transaction type */
  type: string;
  /** Whether transaction is signed */
  isSigned: boolean;
}

/**
 * SS58 address format prefixes
 */
export enum AddressFormat {
  /** Polkadot mainnet (prefix 0, addresses start with '1') */
  Polkadot = 0,
  /** Kusama (prefix 2) */
  Kusama = 2,
  /** Substrate generic (prefix 42, addresses start with '5') */
  Substrate = 42,
}
