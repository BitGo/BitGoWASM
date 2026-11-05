/**
 * Transaction building from high-level business intents.
 *
 * Provides the `buildTransaction()` function for building DOT transactions.
 * The crate handles intent composition internally (e.g., stake with proxy
 * automatically produces a batchAll of bond + addProxy).
 */

import { BuilderNamespace } from "./wasm/wasm_dot.js";
import { DotTransaction } from "./transaction.js";
import type { TransactionIntent, BuildContext } from "./types.js";

/**
 * Build a DOT transaction from a business-level intent and context.
 *
 * The intent describes *what* to do (payment, stake, etc.) and the context
 * provides *how* to build it (sender, nonce, material, validity).
 * Multi-call intents are batched automatically. Destinations must have the
 * SS58 prefix of context.material.chainName (Polkadot 0, Kusama 2, Westend 42).
 * Other chains must supply material.ss58AddressPolicy.prefix. Generic prefix 42
 * is only accepted on another chain with allowGeneric: true; because calls
 * encode AccountId32 without a prefix, parseTransaction will display its
 * canonical chain-form address. The caller must show and obtain approval for
 * that canonical address before using allowGeneric.
 * A wrong-domain destination throws an Error with code "WrongNetwork",
 * actualPrefix, and expectedPrefix.
 *
 * @param intent - Business intent (payment, stake, unstake, claim, etc.)
 * @param context - Build context (sender, nonce, material, validity, referenceBlock)
 * @returns An unsigned DotTransaction ready for signing
 * @throws Error if the intent cannot be built (e.g., invalid addresses)
 *
 * @example
 * ```typescript
 * import { buildTransaction } from '@bitgo/wasm-dot';
 *
 * // These prefix-42 examples assume Westend material in context.
 * // Payment
 * const tx = buildTransaction(
 *   { type: 'payment', to: '5FHneW46...', amount: 1000000000000n },
 *   context
 * );
 *
 * // New stake (produces batchAll of bond + addProxy)
 * const stakeTx = buildTransaction(
 *   { type: 'stake', amount: 5000000000000n, proxyAddress: '5Grwva...' },
 *   context
 * );
 *
 * // Full unstake (produces batchAll of removeProxy + chill + unbond)
 * const unstakeTx = buildTransaction(
 *   { type: 'unstake', amount: 5000000000000n, stopStaking: true, proxyAddress: '5Grwva...' },
 *   context
 * );
 * ```
 */
export function buildTransaction(intent: TransactionIntent, context: BuildContext): DotTransaction {
  const inner = BuilderNamespace.buildTransaction(intent, context);
  return DotTransaction.fromInner(inner);
}

// Re-export types for convenience
export type { TransactionIntent, BuildContext } from "./types.js";
