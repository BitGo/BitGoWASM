import { WasmTransaction } from "./wasm/wasm_ton.js";

/**
 * TON Transaction - deserialization wrapper for signing and serialization.
 *
 * Use `Transaction.fromBoc(base64)` to create an instance for signing.
 * Use `parseTransaction(tx)` from parser.ts to get decoded transaction data.
 *
 * @example
 * ```typescript
 * import { Transaction, parseTransaction } from '@bitgo/wasm-ton';
 *
 * const tx = Transaction.fromBoc(base64Boc);
 *
 * // Parse for decoded fields
 * const parsed = parseTransaction(tx);
 * console.log(`${parsed.amount} nanoTON to ${parsed.recipient}`);
 *
 * // Sign and serialize
 * tx.addSignature(pubkey, signature);
 * const broadcastTx = tx.toBroadcastFormat();
 * ```
 */
export class Transaction {
  private constructor(private _wasm: WasmTransaction) {}

  /**
   * Deserialize a transaction from base64-encoded BOC.
   * @param boc - Base64-encoded BOC string
   * @returns A Transaction instance
   */
  static fromBoc(boc: string): Transaction {
    const wasm = WasmTransaction.fromBoc(boc);
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
   * Get the transaction ID (base64url of external message cell hash).
   *
   * Uses the TON convention: base64url without padding.
   */
  get id(): string {
    return this._wasm.id;
  }

  /**
   * Get the wallet sequence number.
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
   * Check if the transaction has a state init (wallet deploy at seqno=0).
   */
  get hasStateInit(): boolean {
    return this._wasm.hasStateInit;
  }

  /**
   * Get the signable payload (SHA-256 hash of sign body cell).
   *
   * Returns a 32-byte Uint8Array that should be signed with Ed25519.
   */
  signablePayload(): Uint8Array {
    return this._wasm.signablePayload();
  }

  /**
   * Add a pre-computed signature to the transaction.
   *
   * @param pubkey - 32-byte Ed25519 public key as Uint8Array
   * @param signature - 64-byte Ed25519 signature as Uint8Array
   */
  addSignature(pubkey: Uint8Array, signature: Uint8Array): void {
    this._wasm.addSignature(pubkey, signature);
  }

  /**
   * Serialize to base64 BOC (broadcast format).
   *
   * This is the format used to broadcast transactions to the TON network.
   */
  toBroadcastFormat(): string {
    return this._wasm.toBroadcastFormat();
  }

  /**
   * Serialize to raw BOC bytes.
   */
  toBytes(): Uint8Array {
    return this._wasm.toBytes();
  }

  /**
   * Get the underlying WASM transaction.
   * @internal
   */
  get wasm(): WasmTransaction {
    return this._wasm;
  }
}
