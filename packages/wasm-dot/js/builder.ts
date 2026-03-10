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
 * Multi-call intents are batched automatically.
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
