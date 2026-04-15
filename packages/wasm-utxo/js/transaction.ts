import { WasmDashTransaction, WasmTransaction, WasmZcashTransaction } from "./wasm/wasm_utxo.js";
import type { TxInputData, TxOutputData, TxOutputDataWithAddress } from "./wasm/wasm_utxo.js";
import type { CoinName } from "./coinName.js";
import { TransactionBase } from "./transactionBase.js";

/** Common read-only interface shared by transactions and PSBTs */
export interface ITransactionCommon<TInput, TOutput> {
  inputCount(): number;
  outputCount(): number;
  version(): number;
  lockTime(): number;
  getInputs(): TInput[];
  getOutputs(): TOutput[];
}

/** Common interface for all transaction types */
export interface ITransaction extends ITransactionCommon<TxInputData, TxOutputData> {
  toBytes(): Uint8Array;
  getId(): string;
  getOutputsWithAddress(coin: CoinName): TxOutputDataWithAddress[];
}

/**
 * Transaction wrapper (Bitcoin-like networks)
 *
 * Provides a camelCase, strongly-typed API over the snake_case WASM bindings.
 */
export class Transaction extends TransactionBase<WasmTransaction> {
  private constructor(wasm: WasmTransaction) {
    super(wasm);
  }

  /**
   * Check if a coin is supported by this transaction class.
   * Bitcoin-like transactions support all coins except Zcash and Dash.
   */
  static supportsCoin(coin: CoinName): boolean {
    return !ZcashTransaction.supportsCoin(coin) && !DashTransaction.supportsCoin(coin);
  }

  /**
   * Create an empty transaction (version 1, locktime 0)
   */
  static create(): Transaction {
    return new Transaction(WasmTransaction.create());
  }

  static fromBytes(bytes: Uint8Array): Transaction;
  static fromBytes(bytes: Uint8Array, coin: "zec" | "tzec"): ZcashTransaction;
  static fromBytes(bytes: Uint8Array, coin: "dash" | "tdash"): DashTransaction;
  static fromBytes(
    bytes: Uint8Array,
    coin: CoinName,
  ): Transaction | ZcashTransaction | DashTransaction;
  static fromBytes(
    bytes: Uint8Array,
    coin?: CoinName,
  ): Transaction | ZcashTransaction | DashTransaction {
    if (coin !== undefined) {
      if (ZcashTransaction.supportsCoin(coin)) return ZcashTransaction.fromBytes(bytes);
      if (DashTransaction.supportsCoin(coin)) return DashTransaction.fromBytes(bytes);
    }
    return new Transaction(WasmTransaction.from_bytes(bytes));
  }

  /** @internal Create from WASM instance directly (avoids re-parsing bytes) */
  static fromWasm(wasm: WasmTransaction): Transaction {
    return new Transaction(wasm);
  }

  /**
   * Add an input to the transaction
   * @param txid - Previous transaction ID (hex string)
   * @param vout - Output index being spent
   * @param sequence - Optional sequence number (default: 0xFFFFFFFF)
   * @returns The index of the newly added input
   */
  addInputAtIndex(index: number, txid: string, vout: number, sequence?: number): number {
    return this._wasm.add_input_at_index(index, txid, vout, sequence);
  }

  addInput(txid: string, vout: number, sequence?: number): number {
    return this._wasm.add_input(txid, vout, sequence);
  }

  addOutputAtIndex(index: number, script: Uint8Array, value: bigint): number {
    return this._wasm.add_output_at_index(index, script, value);
  }

  addOutput(script: Uint8Array, value: bigint): number {
    return this._wasm.add_output(script, value);
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

  /** @internal */
  get wasm(): WasmTransaction {
    return this._wasm;
  }
}

/**
 * Zcash Transaction wrapper
 *
 * Provides a camelCase, strongly-typed API over the snake_case WASM bindings.
 */
export class ZcashTransaction extends TransactionBase<WasmZcashTransaction> {
  private constructor(wasm: WasmZcashTransaction) {
    super(wasm);
  }

  /**
   * Check if a coin is supported by this transaction class.
   * Zcash transactions support Zcash mainnet and testnet.
   */
  static supportsCoin(coin: CoinName): boolean {
    return coin === "zec" || coin === "tzec";
  }

  static fromBytes(bytes: Uint8Array): ZcashTransaction {
    return new ZcashTransaction(WasmZcashTransaction.from_bytes(bytes));
  }

  /** @internal Create from WASM instance directly (avoids re-parsing bytes) */
  static fromWasm(wasm: WasmZcashTransaction): ZcashTransaction {
    return new ZcashTransaction(wasm);
  }

  /** @internal */
  get wasm(): WasmZcashTransaction {
    return this._wasm;
  }
}

/**
 * Dash Transaction wrapper (supports EVO special transactions)
 *
 * Round-trip only: bytes -> parse -> bytes.
 */
export class DashTransaction extends TransactionBase<WasmDashTransaction> {
  private constructor(wasm: WasmDashTransaction) {
    super(wasm);
  }

  /**
   * Check if a coin is supported by this transaction class.
   * Dash transactions support Dash mainnet and testnet.
   */
  static supportsCoin(coin: CoinName): boolean {
    return coin === "dash" || coin === "tdash";
  }

  static fromBytes(bytes: Uint8Array): DashTransaction {
    return new DashTransaction(WasmDashTransaction.from_bytes(bytes));
  }

  /** @internal Create from WASM instance directly (avoids re-parsing bytes) */
  static fromWasm(wasm: WasmDashTransaction): DashTransaction {
    return new DashTransaction(wasm);
  }

  /** @internal */
  get wasm(): WasmDashTransaction {
    return this._wasm;
  }
}
