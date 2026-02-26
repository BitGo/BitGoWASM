/**
 * Transaction building from high-level intents.
 *
 * Provides the `buildTransaction()` function for building DOT transactions.
 * Follows wallet-platform pattern: buildTransaction(intent, context)
 */

import { BuilderNamespace } from "./wasm/wasm_dot";
import { DotTransaction } from "./transaction";
import type { TransactionIntent, BuildContext } from "./types";

/**
 * Build a DOT transaction from an intent and context.
 *
 * This function takes a declarative TransactionIntent and BuildContext,
 * producing a Transaction object that can be inspected, signed, and serialized.
 *
 * The returned transaction is unsigned - signatures should be added via
 * `addSignature()` before serializing with `toBytes()` and broadcasting.
 *
 * @param intent - What to do (transfer, stake, etc.)
 * @param context - How to build it (sender, nonce, material, validity, referenceBlock)
 * @returns A Transaction object that can be inspected, signed, and serialized
 * @throws Error if the intent cannot be built (e.g., invalid addresses)
 *
 * @example
 * ```typescript
 * import { buildTransaction } from '@bitgo/wasm-dot';
 *
 * // Build a simple DOT transfer
 * const tx = buildTransaction(
 *   { type: 'transfer', to: '5FHneW46...', amount: 1000000000000n, keepAlive: true },
 *   {
 *     sender: '5EGoFA95omzemRssELLDjVenNZ68aXyUeqtKQScXSEBvVJkr',
 *     nonce: 5,
 *     material: {
 *       genesisHash: '0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3',
 *       chainName: 'Polkadot',
 *       specName: 'polkadot',
 *       specVersion: 9150,
 *       txVersion: 9
 *     },
 *     validity: { firstValid: 1000, maxDuration: 2400 },
 *     referenceBlock: '0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3'
 *   }
 * );
 *
 * // Inspect the transaction
 * console.log(tx.nonce);
 *
 * // Get the signable payload for signing
 * const payload = tx.signablePayload();
 *
 * // Add signature and serialize
 * tx.addSignature(signerPubkey, signature);
 * const txBytes = tx.toBytes();
 * ```
 *
 * @example
 * ```typescript
 * // Build with batch (multiple operations)
 * const tx = buildTransaction(
 *   {
 *     type: 'batch',
 *     calls: [
 *       { type: 'transfer', to: recipient, amount: 1000000000000n },
 *       { type: 'stake', amount: 5000000000000n, payee: { type: 'staked' } }
 *     ],
 *     atomic: true
 *   },
 *   context
 * );
 * ```
 */
export function buildTransaction(intent: TransactionIntent, context: BuildContext): DotTransaction {
  const inner = BuilderNamespace.buildTransaction(intent, context);
  return DotTransaction.fromInner(inner as any);
}

// Re-export types for convenience
export type { TransactionIntent, BuildContext } from "./types";
