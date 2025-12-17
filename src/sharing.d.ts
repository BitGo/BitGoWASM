import * as t from "io-ts";
import { Descriptor, Miniscript } from "@bitgo/wasm-utxo";
import { ScriptContext } from "./codec";
export type Share = {
    descriptor: Descriptor;
} | {
    miniscript: Miniscript;
    scriptContext: ScriptContext;
} | {
    scriptBytes: Uint8Array;
};
declare const ShareJson: t.UnionC<[t.TypeC<{
    d: t.StringC;
}>, t.TypeC<{
    ms: t.StringC;
    sc: t.UnionC<[t.LiteralC<"tap">, t.LiteralC<"segwitv0">, t.LiteralC<"legacy">]>;
}>, t.TypeC<{
    sb: t.StringC;
}>]>;
type ShareJson = t.TypeOf<typeof ShareJson>;
export declare function setShare(share: Share): void;
export declare function getShare(v?: ShareJson | Record<string, object> | string | undefined): Share | undefined;
export {};
