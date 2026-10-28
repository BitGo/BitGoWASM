import assert from "node:assert";
import { describe, it } from "mocha";

import {
  IRONWOOD_VERSION_GROUP_ID,
  ZcashBitGoPsbt,
} from "../../js/fixedScriptWallet/ZcashBitGoPsbt.js";
import {
  ZcashIronwoodBitGoPsbt,
  type CreateEmptyKeylessOptions,
  type ZcashShieldedParsedTransaction,
} from "../../js/fixedScriptWallet/ZcashIronwoodBitGoPsbt.js";
import { ZcashIronwoodWitness } from "../../js/fixedScriptWallet/ZcashIronwoodWitness.js";
import { getWalletKeysForSeed } from "../../js/testutils/index.js";
import type { ZcashShieldedSpendRequest } from "../../js/fixedScriptWallet/ZcashIronwoodTypes.js";
import {
  assertErrorCode,
  freshPsbt,
  hex,
  loadFixture,
  type IronwoodSpendFixture,
} from "./zcashIronwoodSpend.util.js";

const NU6_3_TESTNET_HEIGHT = 4134000;

/** The fixture's spend request, with witnesses rebuilt (and re-validated) from the raw path. */
function spendRequests(fixture: IronwoodSpendFixture): ZcashShieldedSpendRequest[] {
  return fixture.request.spends.map((spend) => ({
    recipient: hex(spend.recipient),
    value: BigInt(spend.value),
    rho: hex(spend.rho),
    rseed: hex(spend.rseed),
    cmx: hex(spend.cmx),
    witness: ZcashIronwoodWitness.build(
      hex(spend.cmx),
      spend.witness.position,
      spend.witness.authPath.map(hex),
      hex(fixture.request.anchor),
    ),
    nullifier: hex(spend.nullifier),
  }));
}

describe("ZcashIronwoodBitGoPsbt keyless MPC surface", function () {
  const createOptions = (blockHeight: number): CreateEmptyKeylessOptions => ({ blockHeight });

  describe("createEmptyKeyless (no wallet keys)", function () {
    it("builds a valid v6 (Ironwood) PSBT that round-trips", function () {
      const psbt = ZcashIronwoodBitGoPsbt.createEmptyKeyless("zcashTest", {
        blockHeight: NU6_3_TESTNET_HEIGHT,
        lockTime: 123,
        expiryHeight: 456,
      });
      assert.strictEqual(psbt.getVersion(), 6);
      assert.strictEqual(psbt.versionGroupId, IRONWOOD_VERSION_GROUP_ID);
      assert.strictEqual(psbt.expiryHeight, 456);

      const round = ZcashIronwoodBitGoPsbt.fromBytes(psbt.serialize(), "zcashTest");
      assert.strictEqual(round.versionGroupId, IRONWOOD_VERSION_GROUP_ID);
      assert.strictEqual(round.expiryHeight, 456);
    });

    it("rejects a block height before NU6.3 activation", function () {
      assert.throws(
        () =>
          ZcashIronwoodBitGoPsbt.createEmptyKeyless("zcashTest", {
            blockHeight: NU6_3_TESTNET_HEIGHT - 1,
          }),
        /NU6\.3/,
      );
    });

    it("drives a full keyless spend build without ever needing keys", function () {
      const fixture = loadFixture("deshield");
      const psbt = ZcashIronwoodBitGoPsbt.createEmptyKeyless(
        "zcashTest",
        createOptions(fixture.blockHeight),
      );

      psbt.addTransparentOutput(
        hex(fixture.request.transparentOutput.script),
        BigInt(fixture.request.transparentOutput.value),
      );
      assert.throws(() => psbt.parseShieldedTransaction(), /outputs exceed inputs/);

      const map = psbt.addShieldedSpends(spendRequests(fixture), [], {
        anchor: hex(fixture.request.anchor),
      });
      assert.strictEqual(map.spendActionIndices.length, 1);
      assert.strictEqual(psbt.zip317ConventionalFee(), BigInt(fixture.zip317ConventionalFee));
    });
  });

  describe("parseShieldedTransaction", function () {
    it("parses a keyless deshield build: the verified spend, the transparent output, fee, value balance", function () {
      const fixture = loadFixture("deshield");
      const psbt = ZcashIronwoodBitGoPsbt.createEmptyKeyless(
        "zcashTest",
        createOptions(fixture.blockHeight),
      );
      psbt.addTransparentOutput(
        hex(fixture.request.transparentOutput.script),
        BigInt(fixture.request.transparentOutput.value),
      );
      const map = psbt.addShieldedSpends(spendRequests(fixture), [], {
        anchor: hex(fixture.request.anchor),
      });

      const parsed: ZcashShieldedParsedTransaction = psbt.parseShieldedTransaction();
      assert.strictEqual(parsed.shieldedSpends.length, 1);
      assert.strictEqual(parsed.shieldedSpends[0].actionIndex, map.spendActionIndices[0]);
      assert.strictEqual(parsed.shieldedSpends[0].value, 100_000_000n);
      assert.strictEqual(parsed.shieldedSpends[0].randomizer, "placeholder");
      assert.strictEqual(parsed.shieldedSpends[0].signed, false);
      assert.match(parsed.shieldedSpends[0].address, /^utest1/);

      // The fixture's transparent payout script (`76a91488ac`) is not a standard address
      // script, so the keyless parse reports `address: null` rather than guessing.
      assert.strictEqual(parsed.outputs.length, 1);
      assert.strictEqual(parsed.outputs[0].isShielded, false);
      assert.strictEqual(parsed.outputs[0].actionIndex, null);
      assert.strictEqual(parsed.outputs[0].value, 99_990_000n);
      assert.strictEqual(parsed.outputs[0].address, null);
      assert.strictEqual(parsed.outputs[0].scriptId, null);
      assert.strictEqual(parsed.outputs[0].derivationPath, null);

      assert.strictEqual(parsed.fee, 10_000n);
      assert.strictEqual(parsed.valueBalance, 100_000_000n);
    });

    it("reports the change output and the bundle accounting for a build with change", function () {
      const spendFixture = loadFixture("deshield");
      const outputFixture = loadFixture("transfer");
      const psbt = ZcashIronwoodBitGoPsbt.createEmptyKeyless(
        "zcashTest",
        createOptions(spendFixture.blockHeight),
      );
      psbt.addShieldedSpends(
        spendRequests(spendFixture),
        [
          {
            recipient: hex(outputFixture.request.outputs[0].recipient),
            amount: 50_000_000n,
            memo: hex(outputFixture.request.outputs[0].memo),
          },
        ],
        {
          anchor: hex(spendFixture.request.anchor),
          change: { amount: 49_990_000n, spendIndex: 0 },
        },
      );

      const parsed = psbt.parseShieldedTransaction();
      assert.strictEqual(parsed.outputs.length, 2);
      const change = parsed.outputs.filter((output) => output.isChange);
      assert.strictEqual(change.length, 1);
      assert.strictEqual(change[0].isShielded, true);
      assert.strictEqual(change[0].value, 49_990_000n);
      assert.match(change[0].address, /^utest1/);
      assert.notStrictEqual(change[0].actionIndex, null);

      // 100M in (one spend), 50M + 49_990_000 out → the ZIP-317 conventional fee.
      assert.strictEqual(parsed.fee, 10_000n);
      assert.strictEqual(parsed.fee, psbt.zip317ConventionalFee());
      assert.strictEqual(parsed.valueBalance, 10_000n);
    });

    it("agrees with the wallet-keys parse on the fixture PSBTs", function () {
      const walletKeys = getWalletKeysForSeed("ironwood-ts");
      for (const name of ["deshield", "transfer"] as const) {
        const fixture = loadFixture(name);
        const psbt = freshPsbt(fixture);
        const keyless = psbt.parseShieldedTransaction();
        const keyed = psbt.parseTransactionWithWalletKeys(walletKeys, {
          replayProtection: { publicKeys: [] },
        });

        assert.deepStrictEqual(keyless.shieldedSpends, keyed.shieldedSpends, name);
        assert.deepStrictEqual(keyless.outputs, keyed.outputs, name);
        assert.strictEqual(keyless.valueBalance, keyed.valueBalance, name);
        assert.strictEqual(keyless.fee, keyed.minerFee, name);
      }
    });

    it("rejects a v4 (Sapling) PSBT with the typed code", function () {
      const walletKeys = getWalletKeysForSeed("ironwood-ts");
      // The keyless parse is v6-only: a v4 (Sapling) PSBT, reached through the internal
      // wasm handle, throws the typed error instead of silently reporting no shielded side.
      const v4 = ZcashBitGoPsbt.createEmpty("zcashTest", walletKeys, { blockHeight: 2_000_000 });
      assertErrorCode(
        () => ZcashIronwoodBitGoPsbt.fromWasm(v4.wasm).parseShieldedTransaction(),
        "ZcashParseTransactionError.NotIronwoodV6",
      );
    });
  });
});
