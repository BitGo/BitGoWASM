import type { TxInputData, TxOutputData, TxOutputDataWithAddress } from "./wasm/wasm_utxo.js";
import type { CoinName } from "./coinName.js";
import type { ITransaction } from "./transaction.js";

interface WasmTransactionLike {
  input_count(): number;
  output_count(): number;
  version(): number;
  lock_time(): number;
  to_bytes(): Uint8Array;
  get_txid(): string;
  get_inputs(): unknown;
  get_outputs(): unknown;
  get_outputs_with_address(coin: string): unknown;
}

export abstract class TransactionBase<W extends WasmTransactionLike> implements ITransaction {
  protected _wasm: W;
  constructor(wasm: W) {
    this._wasm = wasm;
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

  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }

  getId(): string {
    return this._wasm.get_txid();
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
}
