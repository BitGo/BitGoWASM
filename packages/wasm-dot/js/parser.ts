/**
 * Transaction parsing — standalone function that decodes extrinsic bytes
 * into structured data (pallet, method, args, nonce, etc.).
 *
 * This is separate from the DotTransaction class, which handles signing.
 * Use DotTransaction.fromBytes() when you need to sign.
 * Use parseTransaction() when you need decoded data.
 */

import { ParserNamespace, MaterialJs, ParseContextJs } from "./wasm/wasm_dot";
import { DotTransaction } from "./transaction";
import type { ParseContext, ParsedTransaction } from "./types";

/**
 * Input type for parsing — accepts raw bytes, hex string, or DotTransaction.
 */
export type TransactionInput = Uint8Array | string | DotTransaction;

/**
 * Parse a DOT transaction into structured data.
 *
 * Returns a plain `ParsedTransaction` object with decoded pallet, method,
 * args, nonce, tip, era, etc.
 *
 * For a signable `DotTransaction` object, use `DotTransaction.fromBytes()` instead.
 *
 * @param input - Raw bytes, hex string (with or without 0x), or DotTransaction
 * @param context - Parsing context with chain material (required for decoding)
 * @returns Parsed transaction data
 *
 * @example
 * ```typescript
 * import { parseTransaction } from '@bitgo/wasm-dot';
 *
 * const parsed = parseTransaction(txBytes, { material });
 * console.log(parsed.method.pallet); // "balances"
 * console.log(parsed.method.name);   // "transferKeepAlive"
 * ```
 */
export function parseTransaction(
  input: TransactionInput,
  context?: ParseContext,
): ParsedTransaction {
  const ctx = context ? createParseContext(context) : undefined;

  if (input instanceof DotTransaction) {
    return ParserNamespace.parseTransaction(input.toBytes(), ctx) as ParsedTransaction;
  }

  if (input instanceof Uint8Array) {
    return ParserNamespace.parseTransaction(input, ctx) as ParsedTransaction;
  }

  // String input — let WASM handle hex parsing
  return ParserNamespace.parseTransactionHex(input, ctx) as ParsedTransaction;
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
