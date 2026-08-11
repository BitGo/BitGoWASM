import { ZcashV6Transaction as WasmZcashV6Transaction } from "../wasm/wasm_utxo.js";

/**
 * A parsed Zcash v6 (Ironwood / NU6.3) transaction — for inspection and txid.
 *
 * The transaction id is an instance method ({@link getId}) returning the canonical
 * display-order hex, consistent with the `getId()` convention on the other
 * transaction/PSBT wrappers. Callers never pass raw bytes to a txid function or have
 * to reverse internal byte order themselves.
 *
 * @example
 * ```typescript
 * const tx = ZcashV6Transaction.fromBytes(rawV6Bytes);
 * tx.getId();                 // canonical (display-order) txid hex
 * tx.ironwoodActionCount;     // 0 when the Ironwood slot is empty
 * ```
 */
export class ZcashV6Transaction {
  private constructor(private _wasm: WasmZcashV6Transaction) {}

  /**
   * Decode a v6 transaction from raw wire bytes.
   * @throws If the bytes are not a valid v6 (Ironwood) transaction
   */
  static fromBytes(bytes: Uint8Array): ZcashV6Transaction {
    return new ZcashV6Transaction(WasmZcashV6Transaction.fromBytes(bytes));
  }

  /** Serialize back to raw v6 wire bytes. */
  toBytes(): Uint8Array {
    return this._wasm.toBytes();
  }

  /** The canonical (display-order) ZIP-244 txid as a lowercase hex string. */
  getId(): string {
    return this._wasm.getId();
  }

  /** The ZIP-244 txid in internal (non-reversed) byte order. */
  txidBytes(): Uint8Array {
    return this._wasm.txidBytes();
  }

  /** Consensus branch id carried in the v6 header. */
  get consensusBranchId(): number {
    return this._wasm.consensusBranchId;
  }

  /** Expiry height. */
  get expiryHeight(): number {
    return this._wasm.expiryHeight;
  }

  /** Number of Ironwood actions (0 when the Ironwood slot is empty). */
  get ironwoodActionCount(): number {
    return this._wasm.ironwoodActionCount;
  }

  /** Net value crossing the Ironwood pool boundary (0 when there is no bundle). */
  get ironwoodValueBalance(): bigint {
    return this._wasm.ironwoodValueBalance;
  }

  /** The Ironwood bundle flag byte, or `undefined` when there is no bundle. */
  get ironwoodFlags(): number | undefined {
    return this._wasm.ironwoodFlags;
  }

  /** The Ironwood note-commitment tree anchor (32 bytes), or `undefined`. */
  get ironwoodAnchor(): Uint8Array | undefined {
    return this._wasm.ironwoodAnchor;
  }

  /**
   * The ZIP-244 per-input transparent sighash (32 bytes) for transparent input `index` —
   * for a transaction inspected directly from its raw bytes rather than one built via a
   * PSBT (e.g. independently verifying an already-broadcast transaction's signatures).
   *
   * `inputAmounts`/`inputScriptPubkeys` are the spent outputs' values (zatoshi) and
   * scriptPubKeys for *every* transparent input of this transaction, in input order.
   */
  transparentSighash(
    index: number,
    inputAmounts: bigint[],
    inputScriptPubkeys: Uint8Array[],
  ): Uint8Array {
    return this._wasm.transparentSighash(
      index,
      BigInt64Array.from(inputAmounts),
      inputScriptPubkeys,
    );
  }

  /** @internal */
  get wasm(): WasmZcashV6Transaction {
    return this._wasm;
  }
}
