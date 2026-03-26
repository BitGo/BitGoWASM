import { WasmTransaction } from "./wasm/wasm_ton.js";

/**
 * TON Transaction -- deserialization wrapper for signing and serialization.
 *
 * Use `Transaction.fromBytes(bytes)` or `Transaction.fromBase64(b64)` to create an instance.
 * Use `parseTransaction(tx)` from parser.ts to get decoded transaction data.
 *
 * @example
 * ```typescript
 * import { Transaction, parseTransaction } from '@bitgo/wasm-ton';
 *
 * const tx = Transaction.fromBase64(bocBase64);
 * const parsed = parseTransaction(tx);
 * console.log(parsed.transactionType, parsed.recipients);
 *
 * // Sign and serialize
 * tx.addSignature(signature);
 * const broadcastable = tx.toBroadcastFormat(); // base64
 * ```
 */
export class Transaction {
  private constructor(private _wasm: WasmTransaction) {}

  /**
   * Deserialize a transaction from raw BOC bytes.
   * @param bytes - The raw BOC bytes
   * @returns A Transaction instance
   */
  static fromBytes(bytes: Uint8Array): Transaction {
    return new Transaction(WasmTransaction.fromBytes(bytes));
  }

  /**
   * Deserialize a transaction from base64-encoded BOC.
   * @param b64 - Base64-encoded BOC string
   * @returns A Transaction instance
   */
  static fromBase64(b64: string): Transaction {
    return new Transaction(WasmTransaction.fromBase64(b64));
  }

  /**
   * Get the transaction ID (base64url hash of the signed message cell).
   * Returns `undefined` if the transaction is unsigned.
   */
  get id(): string | undefined {
    return this._wasm.id;
  }

  /**
   * Get the sequence number.
   */
  get seqno(): number {
    return this._wasm.seqno;
  }

  /**
   * Get the expiration time (unix timestamp).
   */
  get expireTime(): number {
    return this._wasm.expireTime;
  }

  /**
   * Get the sub-wallet ID.
   */
  get walletId(): number {
    return this._wasm.walletId;
  }

  /**
   * Get the wallet version as a string ("V3R2", "V4R2", "V5R1").
   */
  get walletVersion(): string {
    return this._wasm.walletVersion;
  }

  /**
   * Check if the transaction has a signature.
   */
  get isSigned(): boolean {
    return this._wasm.isSigned;
  }

  /**
   * Get the signable payload (32-byte cell hash of the unsigned body).
   * This is the data that gets signed with Ed25519.
   * @returns 32-byte Uint8Array
   */
  signablePayload(): Uint8Array {
    return this._wasm.signablePayload();
  }

  /**
   * Add a 64-byte Ed25519 signature to the transaction.
   * @param signature - The 64-byte Ed25519 signature
   */
  addSignature(signature: Uint8Array): void {
    this._wasm.addSignature(signature);
  }

  /**
   * Serialize the transaction to BOC bytes.
   * @returns The serialized BOC bytes
   */
  toBytes(): Uint8Array {
    return this._wasm.toBytes();
  }

  /**
   * Serialize to network broadcast format.
   * For TON, this is base64-encoded BOC.
   * @returns Base64 string ready for broadcast
   */
  toBroadcastFormat(): string {
    return this._wasm.toBase64();
  }

  /**
   * @internal Create a Transaction from a WasmTransaction (used by builder).
   */
  static fromWasm(wasm: WasmTransaction): Transaction {
    return new Transaction(wasm);
  }

  /**
   * @internal Access the underlying WASM transaction for parser use.
   */
  get wasm(): WasmTransaction {
    return this._wasm;
  }
}
