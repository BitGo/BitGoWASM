/**
 * Transaction parsing.
 *
 * Provides the `parseTransaction()` function for parsing DOT transactions.
 * Accepts raw bytes, hex string, or a DotTransaction object.
 */

import { ParserNamespace, MaterialJs, ParseContextJs } from "./wasm/wasm_dot";
import { DotTransaction } from "./transaction";
import type { ParseContext, ParsedTransaction } from "./types";

/**
 * Input type for parseTransaction — accepts raw bytes, hex string, or DotTransaction.
 */
export type TransactionInput = Uint8Array | string | DotTransaction;

/**
 * Parse a DOT transaction from bytes, hex, or a DotTransaction object.
 *
 * This is the standard entry point for parsing DOT transactions, matching
 * the pattern used by wasm-solana's parseTransaction().
 *
 * @param input - Raw bytes, hex string (with or without 0x), or DotTransaction
 * @param context - Parsing context with chain material (required for decoding)
 * @returns Parsed transaction data
 *
 * @example
 * ```typescript
 * import { parseTransaction } from '@bitgo/wasm-dot';
 *
 * const parsed = parseTransaction(txHex, { material });
 * console.log(parsed.method.pallet); // "balances"
 * console.log(parsed.method.name);   // "transferKeepAlive"
 * ```
 */
export function parseTransaction(
  input: TransactionInput,
  context?: ParseContext,
): ParsedTransaction {
  const ctx = context ? createParseContext(context) : undefined;

  if (typeof input === "string") {
    return ParserNamespace.parseTransactionHex(input, ctx) as ParsedTransaction;
  }

  if (input instanceof DotTransaction) {
    const hex = input.toHex();
    return ParserNamespace.parseTransactionHex(hex, ctx) as ParsedTransaction;
  }

  return ParserNamespace.parseTransaction(input, ctx) as ParsedTransaction;
}

/**
 * Create a ParseContextJs from ParseContext
 */
function createParseContext(ctx: ParseContext): ParseContextJs {
  const material = new MaterialJs(
    ctx.material.genesisHash,
    ctx.material.chainName,
    ctx.material.specName,
    ctx.material.specVersion,
    ctx.material.txVersion,
    ctx.material.metadata,
  );
  return new ParseContextJs(material, ctx.sender ?? null);
}
