import * as t from "io-ts";
import * as tt from "io-ts-types";
type DropdownItem = {
    label: string;
    value: string;
};
export declare function getExampleOptions(index?: number | undefined): DropdownItem[];
export declare function getOptionsFromType(c: t.Type<any>): DropdownItem[];
export declare const Options: t.TypeC<{
    scriptContext: t.UnionC<[t.LiteralC<"tap">, t.LiteralC<"segwitv0">, t.LiteralC<"legacy">]>;
    example: t.StringC;
    derivationIndex: tt.NumberFromStringC;
}>;
export type Options = t.TypeOf<typeof Options>;
export declare function buildOptions(): void;
export declare function getOptions(): Options;
export {};
