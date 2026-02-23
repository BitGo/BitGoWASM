/**
 * TypeScript wrapper for WasmTransaction
 */

import { WasmTransaction, MaterialJs, ValidityJs } from "./wasm/wasm_dot";
import type { Material, Validity, Era } from "./types";

/**
 * DOT Transaction wrapper
 *
 * Provides a high-level interface for working with DOT transactions.
 * Handles signing context and serialization — parsing is separate
 * (use `parseTransactionData()` from parser.ts).
 */
export class DotTransaction {
  private _wasm: WasmTransaction;

  private constructor(inner: WasmTransaction) {
    this._wasm = inner;
  }

  /**
   * Create a transaction from raw bytes
   */
  static fromBytes(bytes: Uint8Array): DotTransaction {
    const inner = new WasmTransaction(bytes);
    return new DotTransaction(inner);
  }

  /**
   * Get the transaction ID (hash) if signed
   */
  get id(): string | undefined {
    return this._wasm.id ?? undefined;
  }

  /**
   * Get sender address (SS58 encoded)
   *
   * @param prefix - SS58 address prefix (0 for Polkadot, 2 for Kusama, 42 for generic)
   */
  sender(prefix: number = 0): string | undefined {
    return this._wasm.sender(prefix) ?? undefined;
  }

  /**
   * Get account nonce
   */
  get nonce(): number {
    return this._wasm.nonce;
  }

  /**
   * Get tip amount as bigint
   */
  get tip(): bigint {
    return this._wasm.tip;
  }

  /**
   * Check if transaction is signed
   */
  get isSigned(): boolean {
    return this._wasm.isSigned;
  }

  /**
   * Get the call data
   */
  get callData(): Uint8Array {
    return this._wasm.callData();
  }

  /**
   * Get the signable payload
   *
   * Returns the bytes that should be signed with Ed25519.
   * Requires context to be set via `setContext()`.
   */
  signablePayload(): Uint8Array {
    return this._wasm.signablePayload();
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
    this._wasm.setContext(materialJs, validityJs, referenceBlock);
  }

  /**
   * Set account nonce (mutates in-place, reflected on next toBytes)
   */
  setNonce(nonce: number): void {
    this._wasm.setNonce(nonce);
  }

  /**
   * Set tip amount (mutates in-place, reflected on next toBytes)
   */
  setTip(tip: bigint): void {
    this._wasm.setTip(tip);
  }

  /**
   * Add a signature to the transaction
   *
   * @param signature - 64-byte Ed25519 signature
   * @param pubkey - 32-byte public key
   */
  addSignature(signature: Uint8Array, pubkey: Uint8Array): void {
    this._wasm.addSignature(signature, pubkey);
  }

  /**
   * Serialize to bytes
   */
  toBytes(): Uint8Array {
    return this._wasm.toBytes();
  }

  /**
   * Get era information
   */
  get era(): Era {
    return this._wasm.era as Era;
  }

  /**
   * Get the underlying WASM transaction
   * @internal
   */
  get wasm(): WasmTransaction {
    return this._wasm;
  }

  /**
   * Create a DotTransaction from an inner WasmTransaction
   * @internal
   */
  static fromInner(inner: WasmTransaction): DotTransaction {
    return new DotTransaction(inner);
  }
}
