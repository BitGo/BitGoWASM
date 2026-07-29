import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type { CoinName } from "../../js/coinName.js";

const here = path.dirname(fileURLToPath(import.meta.url));

export function fixturesDir(coin: CoinName): string {
  // Pearl fixtures live under "pearl" for pearl / tpearl / tpearlreg
  const dir = coin === "tpearl" || coin === "tpearlreg" ? "pearl" : coin;
  return path.join(here, "fixtures", dir);
}

export async function writeFixture(coin: CoinName, name: string, data: unknown): Promise<string> {
  const dir = fixturesDir(coin);
  await mkdir(dir, { recursive: true });
  const file = path.join(dir, name);
  await writeFile(file, JSON.stringify(data, null, 2) + "\n", "utf8");
  return file;
}

export async function readFixture<T>(coin: CoinName, name: string): Promise<T> {
  const file = path.join(fixturesDir(coin), name);
  return JSON.parse(await readFile(file, "utf8")) as T;
}

export type AcidTestRegtestFixture = {
  coin: CoinName;
  /** AcidTest name, e.g. "tpearl fullsigned psbt" */
  acidTestName: string;
  networkInfo: { subversion: string; version?: number };
  /** Height after mining + funding */
  height: number;
  inputScriptTypes: string[];
  outputScriptTypes: string[];
  /** Fully signed extracted transaction hex accepted by the node */
  spendTxHex: string;
  spendTxId: string;
  /** Verbose getrawtransaction of the spend */
  spendTxVerbose: unknown;
};
