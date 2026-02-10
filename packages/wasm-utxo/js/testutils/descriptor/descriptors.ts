/**
 * Descriptor test utilities for building common descriptor templates.
 * Ported from @bitgo/utxo-core/testutil/descriptor/descriptors.ts.
 */
import assert from "assert";

import { BIP32 } from "../../bip32.js";
import type { BIP32Interface } from "../../bip32.js";
import { Descriptor, Miniscript, ast } from "../../index.js";
import type { Triple } from "../../triple.js";
import { DescriptorMap, PsbtParams } from "../../descriptorWallet/index.js";
import { getKeyTriple } from "../keys.js";

type KeyTriple = Triple<BIP32Interface>;

export type DescriptorTemplate =
  | "Wsh2Of3"
  | "Tr1Of3-NoKeyPath-Tree"
  // no xpubs, just plain keys
  | "Tr1Of3-NoKeyPath-Tree-Plain"
  | "Tr2Of3-NoKeyPath"
  | "Wsh2Of2"
  /**
   * Wrapped segwit 2of3 multisig with a relative locktime OP_DROP
   * (requiring a miniscript extension). Used in CoreDao staking transactions.
   */
  | "Wsh2Of3CltvDrop";

/**
 * Get the BIP-341 "Nothing Up My Sleeve" (NUMS) unspendable key.
 * This is the x-only public key with unknown discrete logarithm
 * constructed by hashing the uncompressed secp256k1 base point G.
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
 */
export function getUnspendableKey(): string {
  return "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
}

export function getDefaultXPubs(seed?: string): Triple<string> {
  return getKeyTriple(seed ?? "default").map((k) => k.neutered().toBase58()) as Triple<string>;
}

function toDescriptorMap(v: Record<string, string>): DescriptorMap {
  return new Map(Object.entries(v).map(([k, v]) => [k, Descriptor.fromString(v, "derivable")]));
}

function toXPub(k: BIP32Interface | string, path: string): string {
  if (typeof k === "string") {
    return k + "/" + path;
  }
  return k.neutered().toBase58() + "/" + path;
}

function toPlain(k: BIP32Interface | string, { xonly = false } = {}): string {
  if (typeof k === "string") {
    if (k.startsWith("xpub") || k.startsWith("xprv")) {
      return toPlain(BIP32.fromBase58(k), { xonly });
    }
    return k;
  }
  return toHex(k.publicKey.subarray(xonly ? 1 : 0));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function toXOnly(k: BIP32Interface | string): string {
  return toPlain(k, { xonly: true });
}

function multiArgs(
  m: number,
  n: number,
  keys: BIP32Interface[] | string[],
  path: string,
): [number, ...string[]] {
  if (n < m) {
    throw new Error(`Cannot create ${m} of ${n} multisig`);
  }
  if (keys.length < n) {
    throw new Error(`Not enough keys for ${m} of ${n} multisig: keys.length=${keys.length}`);
  }
  keys = keys.slice(0, n);
  return [m, ...keys.map((k: BIP32Interface | string) => toXPub(k, path))];
}

export function getPsbtParams(t: DescriptorTemplate): Partial<PsbtParams> {
  switch (t) {
    case "Wsh2Of3CltvDrop":
      return { locktime: 1 };
    default:
      return {};
  }
}

export function getDescriptorNode(
  template: DescriptorTemplate,
  keys: KeyTriple | string[] = getDefaultXPubs(),
  path = "0/*",
): ast.DescriptorNode {
  switch (template) {
    case "Wsh2Of3":
      return {
        wsh: { multi: multiArgs(2, 3, keys, path) },
      };
    case "Wsh2Of3CltvDrop": {
      const { locktime } = getPsbtParams(template);
      assert(locktime);
      return {
        wsh: {
          and_v: [{ "r:after": locktime }, { multi: multiArgs(2, 3, keys, path) }],
        },
      };
    }
    case "Wsh2Of2":
      return {
        wsh: { multi: multiArgs(2, 2, keys, path) },
      };
    case "Tr2Of3-NoKeyPath":
      return {
        tr: [getUnspendableKey(), { multi_a: multiArgs(2, 3, keys, path) }],
      };
    case "Tr1Of3-NoKeyPath-Tree":
      return {
        tr: [
          getUnspendableKey(),
          [
            { pk: toXPub(keys[0], path) },
            [{ pk: toXPub(keys[1], path) }, { pk: toXPub(keys[2], path) }],
          ],
        ],
      };
    case "Tr1Of3-NoKeyPath-Tree-Plain":
      return {
        tr: [
          getUnspendableKey(),
          [{ pk: toXOnly(keys[0]) }, [{ pk: toXOnly(keys[1]) }, { pk: toXOnly(keys[2]) }]],
        ],
      };
  }
  throw new Error(`Unknown descriptor template: ${template as string}`);
}

type TapTree = [TapTree, TapTree] | ast.MiniscriptNode;

function getTapLeafScriptNodes(t: ast.DescriptorNode | TapTree): ast.MiniscriptNode[] {
  if (Array.isArray(t)) {
    if (t.length !== 2) {
      throw new Error(`expected tuple, got: ${JSON.stringify(t)}`);
    }
    return t.map((v) => (Array.isArray(v) ? getTapLeafScriptNodes(v) : v)).flat();
  }

  if (typeof t === "object") {
    const node = t;
    if (!("tr" in node)) {
      throw new Error(
        `TapLeafScripts are only supported for Taproot descriptors, got: ${JSON.stringify(t)}`,
      );
    }
    if (!Array.isArray(node.tr) || node.tr.length !== 2) {
      throw new Error(`expected tuple, got: ${JSON.stringify(node.tr)}`);
    }
    const tapscript = node.tr[1];
    if (!Array.isArray(tapscript)) {
      throw new Error(`expected tapscript to be an array, got: ${JSON.stringify(tapscript)}`);
    }
    return getTapLeafScriptNodes(tapscript);
  }

  throw new Error(`Invalid input: ${JSON.stringify(t)}`);
}

export function containsKey(
  script: Miniscript | ast.MiniscriptNode,
  key: BIP32Interface | string,
): boolean {
  if (script instanceof Miniscript) {
    script = ast.fromMiniscript(script);
  }
  if ("pk" in script) {
    return script.pk === toXOnly(key);
  }
  throw new Error(`Unsupported script type: ${JSON.stringify(script)}`);
}

export function getTapLeafScripts(d: Descriptor): string[] {
  return getTapLeafScriptNodes(ast.fromDescriptor(d)).map((n) =>
    Miniscript.fromString(ast.formatNode(n), "tap").toString(),
  );
}

export function getDescriptor(
  template: DescriptorTemplate,
  keys: KeyTriple | string[] = getDefaultXPubs(),
  path = "0/*",
): Descriptor {
  return Descriptor.fromStringDetectType(ast.formatNode(getDescriptorNode(template, keys, path)));
}

export function getDescriptorMap(
  template: DescriptorTemplate,
  keys: KeyTriple | string[] = getDefaultXPubs(),
): DescriptorMap {
  return toDescriptorMap({
    external: getDescriptor(template, keys, "0/*").toString(),
    internal: getDescriptor(template, keys, "1/*").toString(),
  });
}
