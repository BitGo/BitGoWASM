import assert from "node:assert";
import { describe, it } from "mocha";

import {
  getZcashTransactionVersion,
  ZcashBitGoPsbt,
  ZcashIronwoodBitGoPsbt,
  ZcashTransactionVersion,
} from "../../js/index.js";
import {
  BitGoPsbt,
  getZcashTransactionVersion as getVersionFromFixedScript,
  ZcashTransactionVersion as VersionFromFixedScript,
} from "../../js/fixedScriptWallet/index.js";
import { getKeyTriple, getWalletKeysForSeed } from "../../js/testutils/index.js";

const LEGACY_V4_MAINNET_HEIGHT = 1687104;
const NU6_3_TESTNET_HEIGHT = 4134000;
const NU6_3_BRANCH_ID = 0x37a5165b;

const RECIPIENT = Buffer.from(
  "4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d",
  "hex",
);

describe("ZcashTransactionVersion detection", function () {
  const walletKeys = getWalletKeysForSeed("zcash-version-detection-test");

  describe("ZcashTransactionVersion enum", function () {
    it("has expected values for V4 and V6", function () {
      assert.strictEqual(ZcashTransactionVersion.V4, "v4");
      assert.strictEqual(ZcashTransactionVersion.V6, "v6");
    });

    it("is re-exported from top-level and fixedScriptWallet namespaces", function () {
      assert.strictEqual(VersionFromFixedScript.V4, ZcashTransactionVersion.V4);
      assert.strictEqual(VersionFromFixedScript.V6, ZcashTransactionVersion.V6);
      assert.strictEqual(getVersionFromFixedScript, getZcashTransactionVersion);
    });

    it("allows branching with switch / case pattern matching", function () {
      function formatVersionDescription(version: ZcashTransactionVersion): string {
        switch (version) {
          case ZcashTransactionVersion.V4:
            return "Legacy (v4)";
          case ZcashTransactionVersion.V6:
            return "Ironwood / NU6.3 (v6)";
        }
      }

      assert.strictEqual(formatVersionDescription(ZcashTransactionVersion.V4), "Legacy (v4)");
      assert.strictEqual(
        formatVersionDescription(ZcashTransactionVersion.V6),
        "Ironwood / NU6.3 (v6)",
      );
    });
  });

  describe("detecting Zcash v4 PSBTs", function () {
    it("identifies an empty v4 PSBT created by block height (mainnet)", function () {
      const psbt = ZcashBitGoPsbt.createEmpty("zcash", walletKeys, {
        blockHeight: LEGACY_V4_MAINNET_HEIGHT,
      });
      const bytes = psbt.serialize();

      const version = getZcashTransactionVersion(bytes);
      assert.strictEqual(version, ZcashTransactionVersion.V4);

      // Verify static methods on ZcashBitGoPsbt
      assert.strictEqual(ZcashBitGoPsbt.getTransactionVersion(bytes), ZcashTransactionVersion.V4);
      assert.strictEqual(
        ZcashBitGoPsbt.getZcashTransactionVersion(bytes),
        ZcashTransactionVersion.V4,
      );
    });

    it("identifies a v4 PSBT with inputs and outputs added", function () {
      const psbt = ZcashBitGoPsbt.createEmpty("zcash", walletKeys, {
        blockHeight: LEGACY_V4_MAINNET_HEIGHT,
      });
      psbt.addWalletInput({ txid: "22".repeat(32), vout: 0, value: 500_000_000n }, walletKeys, {
        scriptId: { chain: 0, index: 0 },
      });
      psbt.addWalletOutput(walletKeys, { chain: 1, index: 0, value: 499_900_000n });
      const bytes = psbt.serialize();

      assert.strictEqual(getZcashTransactionVersion(bytes), ZcashTransactionVersion.V4);
      assert.strictEqual(ZcashBitGoPsbt.getTransactionVersion(bytes), ZcashTransactionVersion.V4);
    });

    it("identifies a v4 PSBT after deserialization round-trip", function () {
      const psbt = ZcashBitGoPsbt.createEmpty("zcash", walletKeys, {
        blockHeight: LEGACY_V4_MAINNET_HEIGHT,
      });
      psbt.addWalletInput({ txid: "22".repeat(32), vout: 0, value: 500_000_000n }, walletKeys, {
        scriptId: { chain: 0, index: 0 },
      });
      psbt.addWalletOutput(walletKeys, { chain: 1, index: 0, value: 499_900_000n });
      const bytes = psbt.serialize();
      const roundTrip = ZcashBitGoPsbt.fromBytes(bytes, "zcash");

      assert.strictEqual(
        getZcashTransactionVersion(roundTrip.serialize()),
        ZcashTransactionVersion.V4,
      );
    });
  });

  describe("detecting Zcash v6 (Ironwood) PSBTs", function () {
    it("identifies an empty v6 PSBT created by block height", function () {
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
        blockHeight: NU6_3_TESTNET_HEIGHT,
      });
      const bytes = psbt.serialize();

      const version = getZcashTransactionVersion(bytes);
      assert.strictEqual(version, ZcashTransactionVersion.V6);

      // Verify static methods on ZcashBitGoPsbt
      assert.strictEqual(ZcashBitGoPsbt.getTransactionVersion(bytes), ZcashTransactionVersion.V6);
      assert.strictEqual(
        ZcashBitGoPsbt.getZcashTransactionVersion(bytes),
        ZcashTransactionVersion.V6,
      );
    });

    it("identifies an empty v6 PSBT created with explicit consensusBranchId", function () {
      const psbt = ZcashIronwoodBitGoPsbt.createEmptyWithConsensusBranchId("tzec", walletKeys, {
        consensusBranchId: NU6_3_BRANCH_ID,
      });
      const bytes = psbt.serialize();

      assert.strictEqual(getZcashTransactionVersion(bytes), ZcashTransactionVersion.V6);
    });

    it("identifies a v6 PSBT with transparent inputs and outputs before shielding (pre-shield)", function () {
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
        blockHeight: NU6_3_TESTNET_HEIGHT,
      });
      psbt.addWalletInput({ txid: "33".repeat(32), vout: 0, value: 300_000_000n }, walletKeys, {
        scriptId: { chain: 0, index: 0 },
        signPath: { signer: "user", cosigner: "bitgo" },
      });
      psbt.addWalletOutput(walletKeys, { chain: 1, index: 0, value: 199_900_000n });
      const bytes = psbt.serialize();

      assert.strictEqual(getZcashTransactionVersion(bytes), ZcashTransactionVersion.V6);
      assert.strictEqual(ZcashBitGoPsbt.getTransactionVersion(bytes), ZcashTransactionVersion.V6);
    });

    it("identifies a v6 PSBT with shielded output added", function () {
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
        blockHeight: NU6_3_TESTNET_HEIGHT,
      });
      psbt.addWalletInput({ txid: "44".repeat(32), vout: 0, value: 200_000_000n }, walletKeys, {
        scriptId: { chain: 0, index: 0 },
        signPath: { signer: "user", cosigner: "bitgo" },
      });
      psbt.addWalletOutput(walletKeys, { chain: 1, index: 0, value: 99_900_000n });
      psbt.addShieldedOutput(RECIPIENT, 100_000_000n, {
        anchor: new Uint8Array(32).fill(7),
      });
      const bytes = psbt.serialize();

      assert.strictEqual(getZcashTransactionVersion(bytes), ZcashTransactionVersion.V6);
      assert.strictEqual(ZcashBitGoPsbt.getTransactionVersion(bytes), ZcashTransactionVersion.V6);
    });

    it("identifies a v6 PSBT after signing inputs", function () {
      const [userKey] = getKeyTriple("zcash-version-detection-test");
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
        blockHeight: NU6_3_TESTNET_HEIGHT,
      });
      psbt.addWalletInput({ txid: "55".repeat(32), vout: 0, value: 200_000_000n }, walletKeys, {
        scriptId: { chain: 0, index: 0 },
        signPath: { signer: "user", cosigner: "bitgo" },
      });
      psbt.addShieldedOutput(RECIPIENT, 199_980_000n, {
        anchor: new Uint8Array(32).fill(9),
      });
      psbt.sign(userKey, walletKeys);
      const bytes = psbt.serialize();

      assert.strictEqual(getZcashTransactionVersion(bytes), ZcashTransactionVersion.V6);
    });
  });

  describe("rejecting non-Zcash PSBTs and invalid inputs", function () {
    it("throws when given a Bitcoin PSBT", function () {
      const btcPsbt = BitGoPsbt.createEmpty("bitcoin", walletKeys);
      const bytes = btcPsbt.serialize();

      assert.throws(
        () => getZcashTransactionVersion(bytes),
        /Not a recognized Zcash PSBT|neither v4 nor v6/i,
      );
      assert.throws(
        () => ZcashBitGoPsbt.getTransactionVersion(bytes),
        /Not a recognized Zcash PSBT|neither v4 nor v6/i,
      );
    });

    it("throws when given a Litecoin PSBT", function () {
      const ltcPsbt = BitGoPsbt.createEmpty("litecoin", walletKeys);
      const bytes = ltcPsbt.serialize();

      assert.throws(
        () => getZcashTransactionVersion(bytes),
        /Not a recognized Zcash PSBT|neither v4 nor v6/i,
      );
    });

    it("throws when given a Dogecoin PSBT", function () {
      const dogePsbt = BitGoPsbt.createEmpty("dogecoin", walletKeys);
      const bytes = dogePsbt.serialize();

      assert.throws(
        () => getZcashTransactionVersion(bytes),
        /Not a recognized Zcash PSBT|neither v4 nor v6/i,
      );
    });

    it("throws when given non-PSBT random bytes", function () {
      assert.throws(
        () => getZcashTransactionVersion(new Uint8Array([1, 2, 3, 4, 5])),
        /Invalid PSBT/i,
      );
    });

    it("throws when given empty byte array", function () {
      assert.throws(() => getZcashTransactionVersion(new Uint8Array(0)), /Invalid PSBT/i);
    });

    it("throws when given corrupted PSBT bytes", function () {
      const corruptPsbt = new Uint8Array([0x70, 0x73, 0x62, 0x74, 0xff, 0x01, 0x02]);
      assert.throws(() => getZcashTransactionVersion(corruptPsbt), /PSBT/i);
    });
  });
});
