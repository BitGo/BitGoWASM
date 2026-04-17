import type { PsbtInputData, PsbtOutputData, WasmBIP32 } from "./wasm/wasm_utxo.js";
import { BIP32 } from "./bip32.js";
import type { PsbtKvKey } from "./fixedScriptWallet/BitGoKeySubtype.js";

interface WasmPsbtBase {
  input_count(): number;
  output_count(): number;
  version(): number;
  lock_time(): number;
  unsigned_tx_id(): string;
  serialize(): Uint8Array;
  get_inputs(): unknown;
  get_outputs(): unknown;
  get_global_xpubs(): unknown;
  remove_input(index: number): void;
  remove_output(index: number): void;
  set_kv(key: unknown, value: Uint8Array): void;
  get_kv(key: unknown): Uint8Array | null | undefined;
  delete_kv(key: unknown): void;
  set_input_kv(index: number, key: unknown, value: Uint8Array): void;
  get_input_kv(index: number, key: unknown): Uint8Array | null | undefined;
  delete_input_kv(index: number, key: unknown): void;
  set_output_kv(index: number, key: unknown, value: Uint8Array): void;
  get_output_kv(index: number, key: unknown): Uint8Array | null | undefined;
  delete_output_kv(index: number, key: unknown): void;
}

export abstract class PsbtBase<W extends WasmPsbtBase> {
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
  unsignedTxId(): string {
    return this._wasm.unsigned_tx_id();
  }
  serialize(): Uint8Array {
    return this._wasm.serialize();
  }
  getInputs(): PsbtInputData[] {
    return this._wasm.get_inputs() as PsbtInputData[];
  }
  getOutputs(): PsbtOutputData[] {
    return this._wasm.get_outputs() as PsbtOutputData[];
  }
  getGlobalXpubs(): BIP32[] {
    return (this._wasm.get_global_xpubs() as WasmBIP32[]).map((w) => BIP32.fromWasm(w));
  }
  removeInput(index: number): void {
    this._wasm.remove_input(index);
  }
  removeOutput(index: number): void {
    this._wasm.remove_output(index);
  }
  setKV(key: PsbtKvKey, value: Uint8Array): void {
    this._wasm.set_kv(key, value);
  }
  getKV(key: PsbtKvKey): Uint8Array | undefined {
    return this._wasm.get_kv(key) ?? undefined;
  }
  setInputKV(index: number, key: PsbtKvKey, value: Uint8Array): void {
    this._wasm.set_input_kv(index, key, value);
  }
  getInputKV(index: number, key: PsbtKvKey): Uint8Array | undefined {
    return this._wasm.get_input_kv(index, key) ?? undefined;
  }
  setOutputKV(index: number, key: PsbtKvKey, value: Uint8Array): void {
    this._wasm.set_output_kv(index, key, value);
  }
  getOutputKV(index: number, key: PsbtKvKey): Uint8Array | undefined {
    return this._wasm.get_output_kv(index, key) ?? undefined;
  }
  deleteKV(key: PsbtKvKey): void {
    this._wasm.delete_kv(key);
  }
  deleteInputKV(index: number, key: PsbtKvKey): void {
    this._wasm.delete_input_kv(index, key);
  }
  deleteOutputKV(index: number, key: PsbtKvKey): void {
    this._wasm.delete_output_kv(index, key);
  }
}
