import * as t from "io-ts";
import { Descriptor, Miniscript } from "@bitgo/wasm-utxo";
import { fromHex, toHex } from "./hex";
import { ScriptContext } from "./codec";

export type Share =
  | { descriptor: Descriptor }
  | { miniscript: Miniscript; scriptContext: ScriptContext }
  | { scriptBytes: Uint8Array };

const ShareJson = t.union([
  t.type({ d: t.string }),
  t.type({ ms: t.string, sc: ScriptContext }),
  t.type({ sb: t.string }),
]);

type ShareJson = t.TypeOf<typeof ShareJson>;

export function setShare(share: Share): void {
  const shareUrl = new URL(window.location.href);
  let shareHash: Record<string, unknown> = {};
  if ("descriptor" in share) {
    // set fragment
    shareHash = { d: share.descriptor.toString() };
  }
  if ("miniscript" in share) {
    shareHash = { ms: share.miniscript.toString(), sc: share.scriptContext };
  }
  if ("scriptBytes" in share) {
    shareHash = { sb: toHex(share.scriptBytes) };
  }
  shareUrl.hash = JSON.stringify(shareHash);
  window.history.replaceState({}, "", shareUrl.toString());
}

export function getShare(
  v: ShareJson | Record<string, object> | string | undefined = undefined,
): Share | undefined {
  if (v === undefined) {
    const shareUrl = new URL(window.location.href);
    try {
      return getShare(decodeURI(shareUrl.hash.slice(1)));
    } catch (e) {
      console.error("Error decoding share URL", shareUrl, e);
      throw e;
    }
  }

  if (typeof v === "string") {
    try {
      return getShare(JSON.parse(v));
    } catch (e) {
      console.error("Error parsing share JSON", v, e);
      throw e;
    }
  }

  if (typeof v === "object") {
    if (!ShareJson.is(v)) {
      console.error("Invalid share JSON", v);
      return undefined;
    }

    if ("d" in v) {
      return { descriptor: Descriptor.fromString(v.d, "derivable") };
    }
    if ("ms" in v && "sc" in v) {
      return {
        miniscript: Miniscript.fromString(v.ms, v.sc),
        scriptContext: v.sc,
      };
    }
    if ("sb" in v) {
      return { scriptBytes: fromHex(v.sb) };
    }
  }

  console.error("Invalid share", v);
}
