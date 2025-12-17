import * as t from "io-ts";
export declare function decodeOrThrow<A, O, I>(codec: t.Type<A, O, I>, value: I): A;
export declare const ScriptContext: t.UnionC<[t.LiteralC<"tap">, t.LiteralC<"segwitv0">, t.LiteralC<"legacy">]>;
export type ScriptContext = t.TypeOf<typeof ScriptContext>;
