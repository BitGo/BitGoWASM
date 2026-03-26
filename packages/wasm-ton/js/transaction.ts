/**
 * TON Transaction - deserialization wrapper for signing and serialization.
 *
 * Use `Transaction.fromBytes(bytes)` or `Transaction.fromBase64(b64)` to create.
 * Use `parseTransaction(tx)` from parser.ts to get decoded transaction data.
 *
 * @example
 * ```typescript
 * import { Transaction, parseTransaction } from '@bitgo/wasm-ton';
 *
 * const tx = Transaction.fromBase64(bocBase64);
 * const parsed = parseTransaction(tx);
 * console.log(`${parsed.amount} nanoTON to ${parsed.destination}`);
 *
 * // Sign and serialize
 * tx.addSignature(signature);
 * const broadcastStr = tx.toBroadcastFormat();
 * ```
 */
import { WasmTransaction } from "./wasm/wasm_ton.js";

export class Transaction {
  private constructor(private _wasm: WasmTransaction) {}

  /**
   * Deserialize a transaction from raw BOC bytes.
   * @param bytes - Raw BOC bytes
   * @returns A Transaction instance
   */
  static fromBytes(bytes: Uint8Array): Transaction {
    const wasm = WasmTransaction.fromBytes(bytes);
    return new Transaction(wasm);
  }

  /**
   * Deserialize a transaction from base64-encoded BOC.
   * @param b64 - Base64-encoded BOC string
   * @returns A Transaction instance
   */
  static fromBase64(b64: string): Transaction {
    const wasm = WasmTransaction.fromBase64(b64);
    return new Transaction(wasm);
  }

  /**
   * Deserialize a transaction from hex-encoded BOC.
   * @param hex - Hex-encoded BOC string
   * @returns A Transaction instance
   */
  static fromHex(hex: string): Transaction {
    const wasm = WasmTransaction.fromHex(hex);
    return new Transaction(wasm);
  }

  /**
   * Get the signable payload (SHA-256 hash of the signing body cell).
   *
   * This is the 32-byte hash that should be signed with Ed25519.
   * @returns 32-byte Uint8Array
   */
  signablePayload(): Uint8Array {
    return this._wasm.signablePayload();
  }

  /**
   * Add an Ed25519 signature to the transaction.
   *
   * Places the 64-byte signature in the external body and rebuilds
   * the message cell.
   *
   * @param signature - 64-byte Ed25519 signature
   */
  addSignature(signature: Uint8Array): void {
    this._wasm.addSignature(signature);
  }

  /**
   * Serialize the transaction to BOC bytes.
   * @returns Raw BOC bytes
   */
  toBytes(): Uint8Array {
    return this._wasm.toBytes();
  }

  /**
   * Serialize to broadcast format (base64-encoded BOC).
   *
   * TON nodes accept base64-encoded BOC for broadcasting via sendBoc RPC.
   * @returns Base64-encoded BOC string
   */
  toBroadcastFormat(): string {
    return this._wasm.toBroadcastFormat();
  }

  /**
   * Get the transaction ID (hash of the external message cell).
   *
   * Returns undefined if the transaction is unsigned (all-zero signature).
   */
  get id(): string | undefined {
    return this._wasm.id ?? undefined;
  }

  /**
   * Get the underlying WASM instance (internal use only).
   * @internal
   */
  get wasm(): WasmTransaction {
    return this._wasm;
  }

  /**
   * Create a Transaction from a WasmTransaction instance (internal use only).
   * Used by the builder to wrap the result.
   * @internal
   */
  static fromWasm(wasm: WasmTransaction): Transaction {
    return new Transaction(wasm);
  }
}
