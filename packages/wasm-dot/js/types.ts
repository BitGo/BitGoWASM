/**
 * TypeScript type definitions for wasm-dot
 *
 * buildTransaction(intent, context)
 * - intent: business-level intent (payment, stake, unstake, etc.)
 * - context: how to build it (sender, nonce, material, validity)
 *
 * The crate handles intent composition internally. For example, a stake
 * intent with a proxy address produces a batchAll(bond, addProxy) extrinsic.
 */

// =============================================================================
// Chain Metadata Types
// =============================================================================

/**
 * Chain material metadata required for transaction encoding/decoding.
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
  /**
   * Runtime metadata as a 0x-prefixed hex string, matching the Substrate
   * `state_getMetadata` RPC wire format.
   *
   * This is a string rather than Uint8Array because metadata is returned as
   * hex from the Substrate RPC and typically stored/transported as hex through
   * JSON APIs. The hex-to-bytes decode happens once internally right before
   * SCALE decoding.
   */
  metadata: string;
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
  /** Reference block hash (not in extrinsic bytes, pass-through for consumers) */
  referenceBlock?: string;
  /** Block number when transaction becomes valid (not in extrinsic bytes, pass-through for consumers) */
  blockNumber?: number;
}

// =============================================================================
// Build Context (how to build the transaction)
// =============================================================================

/**
 * Build context: contains all non-intent data needed to build a transaction.
 */
export interface BuildContext {
  /** Sender address (SS58 encoded) */
  sender: string;
  /** Account nonce */
  nonce: number;
  /** Optional tip amount (in planck) */
  tip?: bigint;
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
 * Business-level transaction intent.
 *
 * Discriminated union using the `type` field. The crate handles composing
 * these into the correct Polkadot extrinsic calls, including automatic
 * batching when multiple calls are needed (e.g., stake with proxy).
 */
export type TransactionIntent =
  | PaymentIntent
  | ConsolidateIntent
  | StakeIntent
  | UnstakeIntent
  | ClaimIntent
  | FillNonceIntent;

/** Transfer DOT to a recipient */
export interface PaymentIntent {
  type: "payment";
  /** Recipient address (SS58) */
  to: string;
  /** Amount in planck */
  amount: bigint;
  /** Use transferKeepAlive to prevent reaping (default: true) */
  keepAlive?: boolean;
}

/** Sweep all DOT to a recipient (transferAll) */
export interface ConsolidateIntent {
  type: "consolidate";
  /** Recipient address (SS58) */
  to: string;
  /** Keep sender account alive after transfer (default: true) */
  keepAlive?: boolean;
}

/**
 * Stake DOT.
 *
 * - With `proxyAddress`: new stake, produces batchAll(bond, addProxy)
 * - Without `proxyAddress`: top-up, produces bondExtra
 */
export interface StakeIntent {
  type: "stake";
  /** Amount to stake in planck */
  amount: bigint;
  /** Reward destination (default: Staked / compound) */
  payee?: StakePayee;
  /** Proxy address for new stake. Absent means top-up (bondExtra). */
  proxyAddress?: string;
}

export type StakePayee =
  | { type: "staked" }
  | { type: "stash" }
  | { type: "controller" }
  | { type: "account"; address: string };

/**
 * Unstake DOT.
 *
 * - `stopStaking=true` + `proxyAddress`: full unstake, produces
 *   batchAll(removeProxy, chill, unbond)
 * - `stopStaking=false`: partial unstake, produces unbond
 */
export interface UnstakeIntent {
  type: "unstake";
  /** Amount to unstake in planck */
  amount: bigint;
  /** Full unstake (remove proxy + chill) or partial (just unbond). Default: false */
  stopStaking?: boolean;
  /** Proxy address to remove (required when stopStaking=true) */
  proxyAddress?: string;
}

/** Claim (withdraw unbonded) DOT after the unbonding period */
export interface ClaimIntent {
  type: "claim";
  /** Number of slashing spans (default: 0) */
  slashingSpans?: number;
}

/** Zero-value self-transfer to advance the account nonce */
export interface FillNonceIntent {
  type: "fillNonce";
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
  args: Record<string, unknown>;
}

/**
 * Parsed transaction data (raw decode output from Rust, no business logic)
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
