import {
  WasmDashTransaction,
  WasmTransaction,
  WasmZcashTransaction,
  type TxInputData,
  type TxOutputData,
  type TxOutputDataWithAddress,
} from "./wasm/wasm_utxo.js";
import type { CoinName } from "./coinName.js";

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
export class Transaction implements ITransaction {
  private constructor(private _wasm: WasmTransaction) {}

  /**
   * Create an empty transaction (version 1, locktime 0)
   */
  static create(): Transaction {
    return new Transaction(WasmTransaction.create());
  }

  static fromBytes(bytes: Uint8Array): Transaction {
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

  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }

  /**
   * Get the transaction ID (txid)
   *
   * The txid is the double SHA256 of the transaction bytes (excluding witness
   * data for segwit transactions), displayed in reverse byte order as is standard.
   *
   * @returns The transaction ID as a hex string
   */
  getId(): string {
    return this._wasm.get_txid();
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

  inputCount(): number {
    return this._wasm.input_count();
  }

  outputCount(): number {
    return this._wasm.output_count();
  }

  version(): number {
    return this._wasm.version();
  }

  lockTime(): number {
    return this._wasm.lock_time();
  }

  getInputs(): TxInputData[] {
    return this._wasm.get_inputs() as TxInputData[];
  }

  getOutputs(): TxOutputData[] {
    return this._wasm.get_outputs() as TxOutputData[];
  }

  getOutputsWithAddress(coin: CoinName): TxOutputDataWithAddress[] {
    return this._wasm.get_outputs_with_address(coin) as TxOutputDataWithAddress[];
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
export class ZcashTransaction implements ITransaction {
  private constructor(private _wasm: WasmZcashTransaction) {}

  static fromBytes(bytes: Uint8Array): ZcashTransaction {
    return new ZcashTransaction(WasmZcashTransaction.from_bytes(bytes));
  }

  /** @internal Create from WASM instance directly (avoids re-parsing bytes) */
  static fromWasm(wasm: WasmZcashTransaction): ZcashTransaction {
    return new ZcashTransaction(wasm);
  }

  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }

  /**
   * Get the transaction ID (txid)
   *
   * The txid is the double SHA256 of the full Zcash transaction bytes,
   * displayed in reverse byte order as is standard.
   *
   * @returns The transaction ID as a hex string
   */
  getId(): string {
    return this._wasm.get_txid();
  }

  inputCount(): number {
    return this._wasm.input_count();
  }

  outputCount(): number {
    return this._wasm.output_count();
  }

  version(): number {
    return this._wasm.version();
  }

  lockTime(): number {
    return this._wasm.lock_time();
  }

  getInputs(): TxInputData[] {
    return this._wasm.get_inputs() as TxInputData[];
  }

  getOutputs(): TxOutputData[] {
    return this._wasm.get_outputs() as TxOutputData[];
  }

  getOutputsWithAddress(coin: CoinName): TxOutputDataWithAddress[] {
    return this._wasm.get_outputs_with_address(coin) as TxOutputDataWithAddress[];
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
export class DashTransaction implements ITransaction {
  private constructor(private _wasm: WasmDashTransaction) {}

  static fromBytes(bytes: Uint8Array): DashTransaction {
    return new DashTransaction(WasmDashTransaction.from_bytes(bytes));
  }

  /** @internal Create from WASM instance directly (avoids re-parsing bytes) */
  static fromWasm(wasm: WasmDashTransaction): DashTransaction {
    return new DashTransaction(wasm);
  }

  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }

  /**
   * Get the transaction ID (txid)
   *
   * The txid is the double SHA256 of the full Dash transaction bytes,
   * displayed in reverse byte order as is standard.
   *
   * @returns The transaction ID as a hex string
   */
  getId(): string {
    return this._wasm.get_txid();
  }

  inputCount(): number {
    return this._wasm.input_count();
  }

  outputCount(): number {
    return this._wasm.output_count();
  }

  version(): number {
    return this._wasm.version();
  }

  lockTime(): number {
    return this._wasm.lock_time();
  }

  getInputs(): TxInputData[] {
    return this._wasm.get_inputs() as TxInputData[];
  }

  getOutputs(): TxOutputData[] {
    return this._wasm.get_outputs() as TxOutputData[];
  }

  getOutputsWithAddress(coin: CoinName): TxOutputDataWithAddress[] {
    return this._wasm.get_outputs_with_address(coin) as TxOutputDataWithAddress[];
  }

  /** @internal */
  get wasm(): WasmDashTransaction {
    return this._wasm;
  }
}
