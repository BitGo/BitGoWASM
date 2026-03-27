/**
 * TON Transaction -- deserialization wrapper for signing and serialization.
 *
 * Use `Transaction.fromBytes(bytes)` to create.
 * Use `parseTransaction(tx)` from parser.ts to get decoded instruction data.
 *
 * @example
 * ```typescript
 * import { Transaction, parseTransaction } from '@bitgo/wasm-ton';
 *
 * const tx = Transaction.fromBytes(bocBytes);
 * const parsed = parseTransaction(tx);
 *
 * // Sign and serialize
 * tx.addSignature(signature);
 * const broadcast = tx.toBroadcastFormat();
 * ```
 */

import { WasmTransaction } from "./wasm/wasm_ton.js";

export class Transaction {
  private constructor(private _wasm: WasmTransaction) {}

  /**
   * Deserialize a transaction from raw BOC bytes.
   * @param bytes - Raw BOC bytes
   */
  static fromBytes(bytes: Uint8Array): Transaction {
    const wasm = WasmTransaction.fromBytes(bytes);
    return new Transaction(wasm);
  }

  /**
   * Create a Transaction from a WasmTransaction instance.
   * @internal Used by builder functions
   */
  static fromWasm(wasm: WasmTransaction): Transaction {
    return new Transaction(wasm);
  }

  /**
   * Get the signable payload (SHA-256 hash of sign body Cell).
   * Returns 32 bytes that should be signed with Ed25519.
   */
  signablePayload(): Uint8Array {
    return this._wasm.signablePayload();
  }

  /**
   * Add a 64-byte Ed25519 signature to the transaction.
   * @param signature - 64-byte Ed25519 signature
   */
  addSignature(signature: Uint8Array): void {
    this._wasm.addSignature(signature);
  }

  /**
   * Serialize the transaction to raw BOC bytes.
   */
  toBytes(): Uint8Array {
    return this._wasm.toBytes();
  }

  /**
   * Serialize to base64 broadcast format (standard TON wire format).
   */
  toBroadcastFormat(): string {
    return this._wasm.toBroadcastFormat();
  }

  /**
   * Get the sequence number.
   */
  get seqno(): number {
    return this._wasm.seqno;
  }

  /**
   * Get the wallet ID.
   */
  get walletId(): number {
    return this._wasm.walletId;
  }

  /**
   * Get the expiration time (unix timestamp).
   */
  get expireTime(): number {
    return this._wasm.expireTime;
  }

  /**
   * Whether the transaction has a StateInit (seqno == 0 deploy).
   */
  get hasStateInit(): boolean {
    return this._wasm.hasStateInit;
  }

  /**
   * Get the underlying WASM instance.
   * @internal
   */
  get wasm(): WasmTransaction {
    return this._wasm;
  }
}
