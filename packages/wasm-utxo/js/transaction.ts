import { WasmDashTransaction, WasmTransaction, WasmZcashTransaction } from "./wasm/wasm_utxo.js";

/**
 * Transaction wrapper (Bitcoin-like networks)
 *
 * Provides a camelCase, strongly-typed API over the snake_case WASM bindings.
 */
export class Transaction {
  private constructor(private _wasm: WasmTransaction) {}

  static fromBytes(bytes: Uint8Array): Transaction {
    return new Transaction(WasmTransaction.from_bytes(bytes));
  }

  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }

  /**
   * Get the virtual size of the transaction
   *
   * Virtual size accounts for the segwit discount on witness data.
   *
   * @returns The virtual size in virtual bytes (vbytes)
   */
  getVSize(): number {
    return this._wasm.get_vsize();
  }

  /**
   * @internal
   */
  get wasm(): WasmTransaction {
    return this._wasm;
  }
}

/**
 * Zcash Transaction wrapper
 *
 * Provides a camelCase, strongly-typed API over the snake_case WASM bindings.
 */
export class ZcashTransaction {
  private constructor(private _wasm: WasmZcashTransaction) {}

  static fromBytes(bytes: Uint8Array): ZcashTransaction {
    return new ZcashTransaction(WasmZcashTransaction.from_bytes(bytes));
  }

  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }

  /**
   * @internal
   */
  get wasm(): WasmZcashTransaction {
    return this._wasm;
  }
}

/**
 * Dash Transaction wrapper (supports EVO special transactions)
 *
 * Round-trip only: bytes -> parse -> bytes.
 */
export class DashTransaction {
  private constructor(private _wasm: WasmDashTransaction) {}

  static fromBytes(bytes: Uint8Array): DashTransaction {
    return new DashTransaction(WasmDashTransaction.from_bytes(bytes));
  }

  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }

  /**
   * @internal
   */
  get wasm(): WasmDashTransaction {
    return this._wasm;
  }
}
