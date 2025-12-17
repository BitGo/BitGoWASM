import * as t from "io-ts";
import { isLeft } from "fp-ts/Either";
import { PathReporter } from "io-ts/PathReporter";

export function decodeOrThrow<A, O, I>(codec: t.Type<A, O, I>, value: I): A {
  const result = codec.decode(value);
  if (isLeft(result)) {
    throw new Error(PathReporter.report(result).join("\n"));
  }
  return result.right;
}

export const ScriptContext = t.union([
  t.literal("tap"),
  t.literal("segwitv0"),
  t.literal("legacy"),
]);

export type ScriptContext = t.TypeOf<typeof ScriptContext>;
