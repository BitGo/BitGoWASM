import { TransactionNamespace, WasmTransaction } from "./wasm/wasm_ton.js";

/**
 * TON Transaction wrapper for signing and serialization.
 *
 * Use `Transaction.fromBytes(bytes)` to create.
 * Use `parseTransaction(tx)` from parser.ts to get decoded instruction data.
 */
export class Transaction {
  private constructor(private _wasm: WasmTransaction) {}

  /**
   * Deserialize a transaction from raw BOC bytes.
   */
  static fromBytes(bytes: Uint8Array): Transaction {
    const wasm = TransactionNamespace.fromBytes(bytes);
    return new Transaction(wasm);
  }

  /**
   * Get the signable payload (SHA-256 hash of the sign body cell).
   * @returns 32-byte hash as Uint8Array
   */
  signablePayload(): Uint8Array {
    return this._wasm.signablePayload();
  }

  /**
   * Add a 64-byte Ed25519 signature.
   */
  addSignature(signature: Uint8Array): void {
    this._wasm.addSignature(signature);
  }

  /**
   * Serialize to BOC bytes.
   */
  toBytes(): Uint8Array {
    return this._wasm.toBytes();
  }

  /**
   * Serialize to broadcast format (raw BOC bytes).
   * Callers convert to base64 at serialization boundaries:
   *   Buffer.from(tx.toBroadcastFormat()).toString('base64')
   */
  toBroadcastFormat(): Uint8Array {
    return this._wasm.toBroadcastFormat();
  }

  /**
   * Get the transaction ID.
   */
  get id(): string {
    return this._wasm.id;
  }

  /**
   * Get the destination address.
   */
  get destination(): string | undefined {
    return this._wasm.destination ?? undefined;
  }

  /**
   * Get the current signature as hex string.
   */
  get signature(): string {
    return this._wasm.signature;
  }

  /**
   * Get the underlying WASM instance (internal use only).
   * @internal
   */
  get wasm(): WasmTransaction {
    return this._wasm;
  }
}

/**
 * Convenience function to create a Transaction from bytes.
 */
export function transactionFromBytes(bytes: Uint8Array): Transaction {
  return Transaction.fromBytes(bytes);
}
