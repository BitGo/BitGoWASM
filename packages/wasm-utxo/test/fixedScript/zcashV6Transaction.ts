import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { ZcashV6Transaction } from "../../js/fixedScriptWallet/ZcashV6Transaction.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesZcash = path.resolve(__dirname, "../fixtures/zcash");

function readFixture(name: string): string {
  return fs.readFileSync(path.join(fixturesZcash, name), "utf8").trim();
}

describe("ZcashV6Transaction", function () {
  // Real testnet transactions captured from the Ironwood reference.
  for (const name of ["shield", "selfsend", "shield1zec"]) {
    it(`decodes, round-trips, and reports the canonical txid for ${name}`, function () {
      const raw = Buffer.from(readFixture(`v6_${name}_rawtx.hex`), "hex");
      const expectedTxid = readFixture(`v6_${name}_txid.hex`);

      const tx = ZcashV6Transaction.fromBytes(raw);

      // getId is the canonical display-order txid — no manual reversing needed.
      assert.strictEqual(tx.getId(), expectedTxid);
      // Internal-order bytes are the reverse of the display id.
      assert.strictEqual(Buffer.from(tx.txidBytes()).reverse().toString("hex"), expectedTxid);
      // Re-encode is byte-identical.
      assert.strictEqual(Buffer.from(tx.toBytes()).toString("hex"), raw.toString("hex"));
      // Every fixture has exactly one Ironwood action.
      assert.strictEqual(tx.ironwoodActionCount, 1);
    });
  }

  it("exposes inspection fields for the self-send (fully shielded) tx", function () {
    const tx = ZcashV6Transaction.fromBytes(
      Buffer.from(readFixture("v6_selfsend_rawtx.hex"), "hex"),
    );
    assert.strictEqual(tx.consensusBranchId, 0x37a5165b);
    assert.strictEqual(tx.expiryHeight, 0);
    assert.strictEqual(tx.ironwoodFlags, 0x07);
    assert.strictEqual(tx.ironwoodAnchor?.length, 32);
    assert.strictEqual(typeof tx.ironwoodValueBalance, "bigint");
  });

  it("throws on non-v6 bytes", function () {
    assert.throws(() => ZcashV6Transaction.fromBytes(Buffer.from("00010203", "hex")));
  });
});
