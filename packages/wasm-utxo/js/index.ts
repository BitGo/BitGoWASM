import * as wasm from "./wasm/wasm_utxo.js";

// we need to access the wasm module here, otherwise webpack gets all weird
// and forgets to include it in the bundle
void wasm;

export * as address from "./address.js";
export * as ast from "./ast/index.js";
export * as utxolibCompat from "./utxolibCompat.js";
export * as fixedScriptWallet from "./fixedScriptWallet.js";

export { ECPair } from "./ecpair.js";
export { BIP32 } from "./bip32.js";

export type { CoinName } from "./coinName.js";
export type { Triple } from "./triple.js";
export type { AddressFormat } from "./address.js";

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

  interface WrapPsbt {
    signWithXprv(this: WrapPsbt, xprv: string): SignPsbtResult;
    signWithPrv(this: WrapPsbt, prv: Uint8Array): SignPsbtResult;
  }
}

export { WrapDescriptor as Descriptor } from "./wasm/wasm_utxo.js";
export { WrapMiniscript as Miniscript } from "./wasm/wasm_utxo.js";
export { WrapPsbt as Psbt } from "./wasm/wasm_utxo.js";
