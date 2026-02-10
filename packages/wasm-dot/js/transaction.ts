/**
 * TypeScript wrapper for WasmTransaction
 */

import { WasmTransaction, MaterialJs, ValidityJs, ParseContextJs } from "./wasm/wasm_dot";
import type { Material, Validity, ParseContext, Era } from "./types";

/**
 * DOT Transaction wrapper
 *
 * Provides a high-level interface for working with DOT transactions
 */
export class DotTransaction {
  private inner: WasmTransaction;

  private constructor(inner: WasmTransaction) {
    this.inner = inner;
  }

  /**
   * Create a transaction from raw bytes
   */
  static fromBytes(bytes: Uint8Array, context?: ParseContext): DotTransaction {
    const ctx = context ? createParseContext(context) : undefined;
    const inner = new WasmTransaction(bytes, ctx);
    return new DotTransaction(inner);
  }

  /**
   * Create from hex string
   */
  static fromHex(hex: string, context?: ParseContext): DotTransaction {
    const ctx = context ? createParseContext(context) : undefined;
    const inner = WasmTransaction.fromHex(hex, ctx);
    return new DotTransaction(inner);
  }

  /**
   * Get the transaction ID (hash) if signed
   */
  get id(): string | undefined {
    return this.inner.id ?? undefined;
  }

  /**
   * Get sender address (SS58 encoded)
   *
   * @param prefix - SS58 address prefix (0 for Polkadot, 2 for Kusama, 42 for generic)
   */
  sender(prefix: number = 0): string | undefined {
    return this.inner.sender(prefix) ?? undefined;
  }

  /**
   * Get account nonce
   */
  get nonce(): number {
    return this.inner.nonce;
  }

  /**
   * Get tip amount as bigint
   */
  get tip(): bigint {
    return this.inner.tip;
  }

  /**
   * Check if transaction is signed
   */
  get isSigned(): boolean {
    return this.inner.isSigned;
  }

  /**
   * Get the call data
   */
  get callData(): Uint8Array {
    return this.inner.callData();
  }

  /**
   * Get call data as hex string
   */
  get callDataHex(): string {
    return this.inner.callDataHex();
  }

  /**
   * Get the signable payload
   *
   * Returns the bytes that should be signed with Ed25519.
   * Requires context to be set.
   */
  signablePayload(): Uint8Array {
    return this.inner.signablePayload();
  }

  /**
   * Get signable payload as hex
   */
  signablePayloadHex(): string {
    return this.inner.signablePayloadHex();
  }

  /**
   * Set the signing context (material, validity, reference block)
   *
   * Required before calling signablePayload if transaction was created without context
   */
  setContext(material: Material, validity: Validity, referenceBlock: string): void {
    const materialJs = new MaterialJs(
      material.genesisHash,
      material.chainName,
      material.specName,
      material.specVersion,
      material.txVersion,
      material.metadata,
    );
    const validityJs = new ValidityJs(validity.firstValid, validity.maxDuration);
    this.inner.setContext(materialJs, validityJs, referenceBlock);
  }

  /**
   * Set account nonce (mutates in-place, reflected on next toBytes/toHex)
   */
  setNonce(nonce: number): void {
    this.inner.setNonce(nonce);
  }

  /**
   * Set tip amount (mutates in-place, reflected on next toBytes/toHex)
   */
  setTip(tip: bigint): void {
    this.inner.setTip(tip);
  }

  /**
   * Add a signature to the transaction
   *
   * @param signature - 64-byte Ed25519 signature
   * @param pubkey - 32-byte public key
   */
  addSignature(signature: Uint8Array, pubkey: Uint8Array): void {
    this.inner.addSignature(signature, pubkey);
  }

  /**
   * Serialize to bytes
   */
  toBytes(): Uint8Array {
    return this.inner.toBytes();
  }

  /**
   * Serialize to hex string
   */
  toHex(): string {
    return this.inner.toHex();
  }

  /**
   * Get era information
   */
  get era(): Era {
    return this.inner.era as Era;
  }

  /**
   * Get the underlying WASM transaction (for advanced use)
   */
  getInner(): WasmTransaction {
    return this.inner;
  }

  /**
   * Create a DotTransaction from an inner WasmTransaction
   * @internal
   */
  static fromInner(inner: WasmTransaction): DotTransaction {
    return new DotTransaction(inner);
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
    ctx.material.metadata,
  );
  return new ParseContextJs(material, ctx.sender ?? null);
}
