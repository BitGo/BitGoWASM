import * as wasm from "./wasm/wasm_utxo.js";

// we need to access the wasm module here, otherwise webpack gets all weird
// and forgets to include it in the bundle
void wasm;

// Most exports are namespaced to avoid polluting the top-level namespace
// and to make imports more explicit (e.g., `import { address } from '@bitgo/wasm-utxo'`)
export * as address from "./address.js";
export * as ast from "./ast/index.js";
export * as bip322 from "./bip322/index.js";
export * as inscriptions from "./inscriptions.js";
export * as message from "./message.js";
export * as utxolibCompat from "./utxolibCompat.js";
export * as fixedScriptWallet from "./fixedScriptWallet/index.js";
export * as descriptorWallet from "./descriptorWallet/index.js";
export * as bip32 from "./bip32.js";
export * as ecpair from "./ecpair.js";
// Only the most commonly used classes and types are exported at the top level for convenience
export { ECPair } from "./ecpair.js";
export { BIP32 } from "./bip32.js";
export { Dimensions } from "./fixedScriptWallet/Dimensions.js";

export type { CoinName } from "./coinName.js";
export type { Triple } from "./triple.js";
export type { AddressFormat } from "./address.js";
export type { TapLeafScript, PreparedInscriptionRevealData } from "./inscriptions.js";

// TODO: the exports below should be namespaced under `descriptor` in the future

export type DescriptorPkType = "derivable" | "definite" | "string";

export type ScriptContext = "tap" | "segwitv0" | "legacy";

export type SignPsbtResult = {
  [inputIndex: number]: [pubkey: string][];
};

declare module "./wasm/wasm_utxo.js" {
  interface WrapDescriptor {
    /** These are not the same types of nodes as in the ast module */
    node(): unknown;
  }

  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace WrapDescriptor {
    function fromString(descriptor: string, pkType: DescriptorPkType): WrapDescriptor;
    function fromStringDetectType(descriptor: string): WrapDescriptor;
  }

  interface WrapMiniscript {
    /** These are not the same types of nodes as in the ast module */
    node(): unknown;
  }

  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace WrapMiniscript {
    function fromString(miniscript: string, ctx: ScriptContext): WrapMiniscript;
    function fromBitcoinScript(script: Uint8Array, ctx: ScriptContext): WrapMiniscript;
  }

  /** BIP32 derivation data from a PSBT */
  interface PsbtBip32Derivation {
    pubkey: Uint8Array;
    path: string;
  }

  /** Witness UTXO data from a PSBT input */
  interface PsbtWitnessUtxo {
    script: Uint8Array;
    value: bigint;
  }

  /** Raw PSBT input data returned by getInputs() */
  interface PsbtInputData {
    witnessUtxo: PsbtWitnessUtxo | null;
    bip32Derivation: PsbtBip32Derivation[];
    tapBip32Derivation: PsbtBip32Derivation[];
  }

  /** Raw PSBT output data returned by getOutputs() */
  interface PsbtOutputData {
    script: Uint8Array;
    value: bigint;
    bip32Derivation: PsbtBip32Derivation[];
    tapBip32Derivation: PsbtBip32Derivation[];
  }

  /** PSBT output data with resolved address, returned by getOutputsWithAddress() */
  interface PsbtOutputDataWithAddress extends PsbtOutputData {
    address: string;
  }

  interface WrapPsbt {
    // Signing methods (legacy - kept for backwards compatibility)
    signWithXprv(this: WrapPsbt, xprv: string): SignPsbtResult;
    signWithPrv(this: WrapPsbt, prv: Uint8Array): SignPsbtResult;

    // Signing methods (new - using WasmBIP32/WasmECPair)
    signAll(this: WrapPsbt, key: WasmBIP32): SignPsbtResult;
    signAllWithEcpair(this: WrapPsbt, key: WasmECPair): SignPsbtResult;

    // Introspection methods
    inputCount(): number;
    outputCount(): number;
    getInputs(): PsbtInputData[];
    getOutputs(): PsbtOutputData[];
    getOutputsWithAddress(coin: import("./coinName.js").CoinName): PsbtOutputDataWithAddress[];
    getPartialSignatures(inputIndex: number): Array<{
      pubkey: Uint8Array;
      signature: Uint8Array;
    }>;
    hasPartialSignatures(inputIndex: number): boolean;

    // Validation methods
    validateSignatureAtInput(inputIndex: number, pubkey: Uint8Array): boolean;
    verifySignatureWithKey(inputIndex: number, key: WasmBIP32): boolean;

    // Extraction methods
    extractTransaction(): WasmTransaction;

    // Metadata methods
    unsignedTxId(): string;
    lockTime(): number;
    version(): number;
  }
}

export { WrapDescriptor as Descriptor } from "./wasm/wasm_utxo.js";
export { WrapMiniscript as Miniscript } from "./wasm/wasm_utxo.js";
export { WrapPsbt as Psbt } from "./wasm/wasm_utxo.js";
export { DashTransaction, Transaction, ZcashTransaction } from "./transaction.js";
export { hasPsbtMagic } from "./psbt.js";
