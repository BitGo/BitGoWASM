import * as assert from "node:assert";
import * as fs from "fs/promises";
import * as utxolib from "@bitgo/utxo-lib";
import { DescriptorNode, MiniscriptNode, formatNode } from "../js/ast/index.js";

async function assertEqualJSON(path: string, value: unknown): Promise<void> {
  try {
    const data: unknown = JSON.parse(await fs.readFile(path, "utf8"));
    assert.deepStrictEqual(data, value);
  } catch (e: unknown) {
    if (typeof e === "object" && e !== null && "code" in e && e.code === "ENOENT") {
      await fs.writeFile(path, JSON.stringify(value, null, 2));
      throw new Error("Expected file not found, wrote it instead");
    }
    throw e;
  }
}

export async function assertEqualFixture(
  path: string,
  content: {
    descriptor: string;
    wasmNode: unknown;
    ast: DescriptorNode | MiniscriptNode;
  },
): Promise<void> {
  await assertEqualJSON(path, content);
}

/** Expand a template with the given root wallet keys and chain code */
function expand(rootWalletKeys: utxolib.bitgo.RootWalletKeys, keyIndex: number, chainCode: number) {
  if (keyIndex !== 0 && keyIndex !== 1 && keyIndex !== 2) {
    throw new Error("Invalid key index");
  }
  const xpub = rootWalletKeys.triple[keyIndex].neutered().toBase58();
  const prefix = rootWalletKeys.derivationPrefixes[keyIndex];
  return xpub + "/" + prefix + "/" + chainCode + "/*";
}

/**
 * Get a standard output descriptor that corresponds to the proprietary HD wallet setup
 * used in BitGo wallets.
 * Only supports a subset of script types.
 */
export function getDescriptorForScriptType(
  rootWalletKeys: utxolib.bitgo.RootWalletKeys,
  scriptType: utxolib.bitgo.outputScripts.ScriptType2Of3,
  scope: "internal" | "external",
): string {
  const chain =
    scope === "external"
      ? utxolib.bitgo.getExternalChainCode(scriptType)
      : utxolib.bitgo.getInternalChainCode(scriptType);
  const multi: MiniscriptNode = {
    multi: [2, ...rootWalletKeys.triple.map((_, i) => expand(rootWalletKeys, i, chain))],
  };
  switch (scriptType) {
    case "p2sh":
      return formatNode({ sh: multi });
    case "p2shP2wsh":
      return formatNode({ sh: { wsh: multi } });
    case "p2wsh":
      return formatNode({ wsh: multi });
    default:
      throw new Error(`Unsupported script type ${scriptType}`);
  }
}
