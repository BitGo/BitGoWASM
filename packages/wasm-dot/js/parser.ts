/**
 * TypeScript wrapper for ParserNamespace
 */

import { ParserNamespace, MaterialJs, ParseContextJs } from "./wasm/wasm_dot";
import type { ParseContext, ParsedTransaction, TransactionOutput } from "./types";

/**
 * DOT Transaction Parser
 *
 * Provides methods for parsing DOT transactions
 */
export class DotParser {
  /**
   * Parse a transaction from raw bytes
   *
   * @param bytes - Raw extrinsic bytes
   * @param context - Optional parsing context with chain material
   * @returns Parsed transaction data
   */
  static parseTransaction(bytes: Uint8Array, context?: ParseContext): ParsedTransaction {
    const ctx = context ? createParseContext(context) : undefined;
    return ParserNamespace.parseTransaction(bytes, ctx) as ParsedTransaction;
  }

  /**
   * Parse a transaction from hex string
   *
   * @param hex - Hex-encoded extrinsic bytes (with or without 0x prefix)
   * @param context - Optional parsing context
   * @returns Parsed transaction data
   */
  static parseTransactionHex(hex: string, context?: ParseContext): ParsedTransaction {
    const ctx = context ? createParseContext(context) : undefined;
    return ParserNamespace.parseTransactionHex(hex, ctx) as ParsedTransaction;
  }

  /**
   * Get the transaction type from raw bytes
   *
   * Quickly determines the transaction type without full parsing
   *
   * @param bytes - Raw extrinsic bytes
   * @returns Transaction type string
   */
  static getTransactionType(bytes: Uint8Array): string {
    return ParserNamespace.getTransactionType(bytes);
  }

  /**
   * Extract outputs (recipients and amounts) from transaction
   *
   * @param bytes - Raw extrinsic bytes
   * @param context - Optional parsing context
   * @returns Array of transaction outputs
   */
  static getOutputs(bytes: Uint8Array, context?: ParseContext): TransactionOutput[] {
    const ctx = context ? createParseContext(context) : undefined;
    return ParserNamespace.getOutputs(bytes, ctx) as TransactionOutput[];
  }
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
    ctx.material.metadataHex,
  );
  return new ParseContextJs(material, ctx.sender ?? null);
}
