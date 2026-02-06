/**
 * TypeScript wrapper for BuilderNamespace
 */

import {
  BuilderNamespace,
  BuildContextJs,
  MaterialBuilderJs,
  ValidityBuilderJs,
} from '../pkg/wasm_dot';
import { ensureWasmInitialized } from './index';
import { DotTransaction } from './transaction';
import type { BuildContext, TransactionIntent } from './types';

/**
 * DOT Transaction Builder
 *
 * Provides methods for building DOT transactions from intents
 */
export class DotBuilder {
  /**
   * Build a transaction from an intent
   *
   * @param intent - Transaction intent describing what to do
   * @param context - Build context with sender, nonce, material, validity
   * @returns Transaction ready for signing
   *
   * @example
   * ```typescript
   * const tx = DotBuilder.buildTransaction({
   *   type: 'transfer',
   *   to: '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty',
   *   amount: '1000000000000',
   *   keepAlive: true,
   * }, context);
   * ```
   */
  static buildTransaction(intent: TransactionIntent, context: BuildContext): DotTransaction {
    ensureWasmInitialized();
    const ctx = createBuildContext(context);
    const inner = BuilderNamespace.buildTransaction(intent, ctx);
    return new DotTransaction(inner as any);
  }

  /**
   * Build a transfer transaction
   *
   * Convenience method for simple transfers
   *
   * @param to - Recipient address (SS58)
   * @param amount - Amount in planck (as string for BigInt)
   * @param keepAlive - Use transferKeepAlive (default: true)
   * @param context - Build context
   * @returns Transaction ready for signing
   */
  static buildTransfer(
    to: string,
    amount: string,
    keepAlive: boolean,
    context: BuildContext
  ): DotTransaction {
    ensureWasmInitialized();
    const ctx = createBuildContext(context);
    const inner = BuilderNamespace.buildTransfer(to, amount, keepAlive, ctx);
    return new DotTransaction(inner as any);
  }

  /**
   * Build a staking (bond) transaction
   *
   * @param amount - Amount to stake in planck (as string for BigInt)
   * @param payee - Where to send staking rewards ("staked", "stash", "controller", or address)
   * @param context - Build context
   * @returns Transaction ready for signing
   */
  static buildStake(amount: string, payee: string, context: BuildContext): DotTransaction {
    ensureWasmInitialized();
    const ctx = createBuildContext(context);
    const inner = BuilderNamespace.buildStake(amount, payee, ctx);
    return new DotTransaction(inner as any);
  }

  /**
   * Build an unstake (unbond) transaction
   *
   * @param amount - Amount to unstake in planck (as string for BigInt)
   * @param context - Build context
   * @returns Transaction ready for signing
   */
  static buildUnstake(amount: string, context: BuildContext): DotTransaction {
    ensureWasmInitialized();
    const ctx = createBuildContext(context);
    const inner = BuilderNamespace.buildUnstake(amount, ctx);
    return new DotTransaction(inner as any);
  }
}

/**
 * Create a BuildContextJs from BuildContext
 */
function createBuildContext(ctx: BuildContext): BuildContextJs {
  const material = new MaterialBuilderJs(
    ctx.material.genesisHash,
    ctx.material.chainName,
    ctx.material.specName,
    ctx.material.specVersion,
    ctx.material.txVersion
  );
  const validity = new ValidityBuilderJs(ctx.validity.firstValid, ctx.validity.maxDuration);
  return new BuildContextJs(
    ctx.sender,
    ctx.nonce,
    ctx.tip ?? '0',
    material,
    validity,
    ctx.referenceBlock
  );
}
