/**
 * Low-level transaction parsing.
 *
 * Provides `parseTransactionData()` — the low-level parser that returns
 * a plain `ParsedTransaction` object (pallet, method, args, nonce, etc.).
 *
 * For the high-level entry point that returns a `DotTransaction` (with
 * signing + `.parse()` methods), use `parseTransaction()` from index.ts.
 */

import { ParserNamespace, MaterialJs, ParseContextJs } from "./wasm/wasm_dot";
import { DotTransaction } from "./transaction";
import type { ParseContext, ParsedTransaction } from "./types";

/**
 * Input type for parsing — accepts raw bytes, hex string, or DotTransaction.
 */
export type TransactionInput = Uint8Array | string | DotTransaction;

/**
 * Parse a DOT transaction into structured data (low-level).
 *
 * Returns a plain `ParsedTransaction` object with decoded pallet, method,
 * args, nonce, tip, era, etc. This is the raw decoded output — no type
 * derivation or output extraction.
 *
 * For a `DotTransaction` object (with signing methods + `.parse()`),
 * use `parseTransaction()` instead.
 *
 * @param input - Raw bytes, hex string (with or without 0x), or DotTransaction
 * @param context - Parsing context with chain material (required for decoding)
 * @returns Parsed transaction data
 *
 * @example
 * ```typescript
 * import { parseTransactionData } from '@bitgo/wasm-dot';
 *
 * const parsed = parseTransactionData(txHex, { material });
 * console.log(parsed.method.pallet); // "balances"
 * console.log(parsed.method.name);   // "transferKeepAlive"
 * ```
 */
export function parseTransactionData(
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
