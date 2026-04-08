import * as assert from "assert";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { address } from "../js/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface TestVector {
  id: string;
  expected: {
    scriptPubKey?: string;
    bip350Address?: string;
  };
}

interface FixtureFile {
  version: number;
  test_vectors: TestVector[];
}

function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function loadFixture(name: string): FixtureFile {
  const filePath = path.join(__dirname, "fixtures", "p2mr", `${name}.json`);
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as FixtureFile;
}

describe("P2MR (BIP-360) address encoding", () => {
  const fixture = loadFixture("p2mr_construction");

  for (const vector of fixture.test_vectors) {
    if (!vector.expected.bip350Address || !vector.expected.scriptPubKey) continue;

    it(`should encode mainnet P2MR address for ${vector.id}`, () => {
      const scriptPubKey = fromHex(vector.expected.scriptPubKey);

      const addr = address.fromOutputScriptWithCoin(scriptPubKey, "btc");
      assert.strictEqual(addr, vector.expected.bip350Address);

      const decoded = address.toOutputScriptWithCoin(addr, "btc");
      assert.deepStrictEqual(Buffer.from(decoded), Buffer.from(scriptPubKey));
    });

    it(`should encode testnet P2MR address for ${vector.id}`, () => {
      const scriptPubKey = fromHex(vector.expected.scriptPubKey);

      const addr = address.fromOutputScriptWithCoin(scriptPubKey, "tbtc");
      assert.ok(addr.startsWith("tb1z"), `Expected tb1z prefix, got ${addr}`);
      const decoded = address.toOutputScriptWithCoin(addr, "tbtc");
      assert.deepStrictEqual(Buffer.from(decoded), Buffer.from(scriptPubKey));
    });
  }
});
