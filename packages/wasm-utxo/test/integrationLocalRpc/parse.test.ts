/**
 * Offline checks against committed integrationLocalRpc fixtures.
 * Not run on CI (directory ignored by default mocha); local only:
 *   npm run test:integrationLocalRpc
 */
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";

import { Transaction } from "../../js/index.js";
import { AcidTest } from "../../js/testutils/AcidTest.js";
import type { CoinName } from "../../js/coinName.js";
import { fixturesDir, readFixture, type AcidTestRegtestFixture } from "./fixtures.js";
import { PEARL_SIGN_COIN } from "./pearlConstants.js";

const COINS: CoinName[] = ["pearl"];

describe("integrationLocalRpc fixtures (offline)", function () {
  for (const coin of COINS) {
    describe(coin, function () {
      const fixturePath = path.join(fixturesDir(coin), "acidTest.fullsigned.json");

      it("has committed acidTest.fullsigned.json", function () {
        if (!existsSync(fixturePath)) {
          this.skip();
        }
      });

      it("spendTxHex parses and matches AcidTest input script types", async function () {
        if (!existsSync(fixturePath)) {
          this.skip();
        }
        const fixture = await readFixture<AcidTestRegtestFixture>(coin, "acidTest.fullsigned.json");
        assert.ok(fixture.spendTxHex.length > 0);
        assert.ok(fixture.spendTxId.length === 64);

        const tx = Transaction.fromBytes(Buffer.from(fixture.spendTxHex, "hex"));
        assert.strictEqual(tx.getId(), fixture.spendTxId);

        const signCoin = coin === "pearl" || coin === "tpearl" ? PEARL_SIGN_COIN : coin;
        const acid = AcidTest.withConfig(signCoin, "fullsigned", "psbt");
        assert.deepStrictEqual(
          fixture.inputScriptTypes,
          acid.inputs.map((i) => i.scriptType),
        );
        assert.ok(fixture.inputScriptTypes.includes("p2trLegacy"));
        assert.ok(fixture.inputScriptTypes.includes("p2trMusig2KeyPath"));
      });
    });
  }
});
