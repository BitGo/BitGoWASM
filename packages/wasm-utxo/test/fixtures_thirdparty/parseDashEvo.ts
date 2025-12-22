import * as assert from "assert/strict";
import { describe, it } from "mocha";
import { readdir, readFile } from "fs/promises";

import { DashTransaction } from "../../js/index.js";

type DashRpcTransaction = {
  hex: string;
};

async function readDashEvoTransactions(): Promise<DashRpcTransaction[]> {
  const rootDir = "test/fixtures_thirdparty/dashTestExtra";
  const files = (await readdir(rootDir)).filter((f) => f.endsWith(".json")).sort();
  return await Promise.all(
    files.map(
      async (filename) =>
        JSON.parse(await readFile(`${rootDir}/${filename}`, "utf8")) as DashRpcTransaction,
    ),
  );
}

describe("Dash", function () {
  it("round-trips Evolution (EVO) special transactions", async function () {
    const txs = await readDashEvoTransactions();
    assert.strictEqual(txs.length, 29);

    txs.forEach((tx, i) => {
      const buf = Buffer.from(tx.hex, "hex");
      const parsed = DashTransaction.fromBytes(buf);
      const roundTripped = Buffer.from(parsed.toBytes());
      assert.deepEqual(roundTripped, buf, `Dash EVO tx ${i} failed round-trip`);
    });
  });
});
