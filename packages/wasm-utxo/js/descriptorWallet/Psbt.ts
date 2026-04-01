import {
  WrapPsbt as WasmPsbt,
  type WasmBIP32,
  type WasmECPair,
  type WrapDescriptor,
  type PsbtOutputDataWithAddress,
} from "../wasm/wasm_utxo.js";
import type { IPsbt } from "../psbt.js";
import type { CoinName } from "../coinName.js";
import { Transaction } from "../transaction.js";
import { PsbtBase } from "../psbtBase.js";

export type SignPsbtResult = {
  [inputIndex: number]: [pubkey: string][];
};

export class Psbt extends PsbtBase<WasmPsbt> implements IPsbt {
  constructor(versionOrWasm?: number | WasmPsbt, lockTime?: number) {
    super(
      versionOrWasm instanceof WasmPsbt ? versionOrWasm : new WasmPsbt(versionOrWasm, lockTime),
    );
  }

  /** @internal Access the underlying WASM instance */
  get wasm(): WasmPsbt {
    return this._wasm;
  }

  // -- Static / Factory --

  static create(version?: number, lockTime?: number): Psbt {
    return new Psbt(new WasmPsbt(version, lockTime));
  }

  static deserialize(bytes: Uint8Array): Psbt {
    return new Psbt(WasmPsbt.deserialize(bytes));
  }

  // -- Serialization --

  clone(): Psbt {
    return new Psbt(this._wasm.clone());
  }

  // -- IPsbt: introspection --

  getOutputsWithAddress(coin: CoinName): PsbtOutputDataWithAddress[] {
    return this._wasm.get_outputs_with_address(coin) as PsbtOutputDataWithAddress[];
  }

  // -- IPsbt: mutation --

  addInputAtIndex(
    index: number,
    txid: string,
    vout: number,
    value: bigint,
    script: Uint8Array,
    sequence?: number,
  ): number {
    return this._wasm.add_input_at_index(index, txid, vout, value, script, sequence);
  }

  addInput(
    txid: string,
    vout: number,
    value: bigint,
    script: Uint8Array,
    sequence?: number,
  ): number {
    return this._wasm.add_input(txid, vout, value, script, sequence);
  }

  addOutputAtIndex(index: number, script: Uint8Array, value: bigint): number {
    return this._wasm.add_output_at_index(index, script, value);
  }

  addOutput(script: Uint8Array, value: bigint): number {
    return this._wasm.add_output(script, value);
  }

  // -- Descriptor updates --

  updateInputWithDescriptor(inputIndex: number, descriptor: WrapDescriptor): void {
    this._wasm.update_input_with_descriptor(inputIndex, descriptor);
  }

  updateOutputWithDescriptor(outputIndex: number, descriptor: WrapDescriptor): void {
    this._wasm.update_output_with_descriptor(outputIndex, descriptor);
  }

  // -- Signing --

  signWithXprv(xprv: string): SignPsbtResult {
    return this._wasm.sign_with_xprv(xprv) as unknown as SignPsbtResult;
  }

  signWithPrv(prv: Uint8Array): SignPsbtResult {
    return this._wasm.sign_with_prv(prv) as unknown as SignPsbtResult;
  }

  signAll(key: WasmBIP32): SignPsbtResult {
    return this._wasm.sign_all(key) as unknown as SignPsbtResult;
  }

  signAllWithEcpair(key: WasmECPair): SignPsbtResult {
    return this._wasm.sign_all_with_ecpair(key) as unknown as SignPsbtResult;
  }

  // -- Signature introspection --

  getPartialSignatures(inputIndex: number): Array<{ pubkey: Uint8Array; signature: Uint8Array }> {
    return this._wasm.get_partial_signatures(inputIndex) as Array<{
      pubkey: Uint8Array;
      signature: Uint8Array;
    }>;
  }

  hasPartialSignatures(inputIndex: number): boolean {
    return this._wasm.has_partial_signatures(inputIndex);
  }

  // -- Validation --

  validateSignatureAtInput(inputIndex: number, pubkey: Uint8Array): boolean {
    return this._wasm.validate_signature_at_input(inputIndex, pubkey);
  }

  verifySignatureWithKey(inputIndex: number, key: WasmBIP32): boolean {
    return this._wasm.verify_signature_with_key(inputIndex, key);
  }

  // -- Transaction extraction --

  getUnsignedTx(): Uint8Array {
    return this._wasm.get_unsigned_tx();
  }

  finalize(): void {
    this._wasm.finalize_mut();
  }

  extractTransaction(): Transaction {
    return Transaction.fromWasm(this._wasm.extract_transaction());
  }
}
