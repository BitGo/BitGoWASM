/**
 * Transaction parsing — standalone function that decodes a DotTransaction
 * into structured data (pallet, method, args, nonce, etc.).
 *
 * This is separate from the DotTransaction class, which handles signing.
 * Use DotTransaction.fromBytes() when you need to sign.
 * Use parseTransaction() when you need decoded data.
 */

import { ParserNamespace, MaterialJs, ParseContextJs } from "./wasm/wasm_dot";
import type { DotTransaction } from "./transaction";
import type { ParseContext, ParsedTransaction } from "./types";

/**
 * Parse a DOT transaction into structured data.
 *
 * Accepts a `DotTransaction` object (from `DotTransaction.fromBytes()`),
 * avoiding double deserialization.
 *
 * Returns a plain `ParsedTransaction` object with decoded pallet, method,
 * args, nonce, tip, era, etc.
 *
 * @param tx - A DotTransaction instance (from DotTransaction.fromBytes())
 * @param context - Parsing context with chain material (required for decoding)
 * @returns Parsed transaction data
 *
 * @example
 * ```typescript
 * import { DotTransaction, parseTransaction } from '@bitgo/wasm-dot';
 *
 * const tx = DotTransaction.fromBytes(txBytes, context);
 * const parsed = parseTransaction(tx, { material });
 * console.log(parsed.method.pallet); // "balances"
 * console.log(parsed.method.name);   // "transferKeepAlive"
 * ```
 */
export function parseTransaction(tx: DotTransaction, context?: ParseContext): ParsedTransaction {
  const ctx = context ? createParseContext(context) : undefined;
  return ParserNamespace.parseFromTransaction(tx.wasm, ctx) as ParsedTransaction;
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
