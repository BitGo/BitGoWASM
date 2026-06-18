import assert from "node:assert";
import { describe, it } from "mocha";

import { fixedScriptWallet } from "../../js/index.js";
import { ZcashBitGoPsbt } from "../../js/fixedScriptWallet/ZcashBitGoPsbt.js";
import {
  AcidTest,
  getKeyTriple,
  getDefaultWalletKeys,
  getWalletKeysForSeed,
} from "../../js/testutils/index.js";
import type { Input, Output } from "../../js/testutils/AcidTest.js";
import type { CoinName } from "../../js/coinName.js";

const SAPLING_ACTIVATION_HEIGHT = 419200;
const SAPLING_BRANCH_ID = 0x76b809bb;
const NU5_BRANCH_ID = 0xc2d6d0b4;

function makeAcidTest(coin: CoinName, inputs: Input[], outputs: Output[]): AcidTest {
  return new AcidTest(
    coin,
    "unsigned",
    "psbt",
    getDefaultWalletKeys(),
    getWalletKeysForSeed("too many secrets"),
    inputs,
    outputs,
    getKeyTriple("default"),
  );
}

function signCopy(
  unsignedBytes: Uint8Array,
  coin: CoinName,
  keyIndex: 0 | 1 | 2,
): fixedScriptWallet.BitGoPsbt {
  const [user, backup, bitgo] = getKeyTriple("default");
  const keys = [user, backup, bitgo];
  const psbt = fixedScriptWallet.BitGoPsbt.fromBytes(unsignedBytes, coin);
  psbt.sign(keys[keyIndex]);
  return psbt;
}

function makeZecAcidTest(inputs: Input[] = [{ scriptType: "p2sh", value: 100000n }]): AcidTest {
  const outputs: Output[] = [{ scriptType: "p2sh", value: 90000n, walletKeys: null }];
  return makeAcidTest("zec", inputs, outputs);
}

describe("BitGoPsbt.combineInputs", function () {
  describe("BTC (p2shP2wsh)", function () {
    const acidTest = makeAcidTest(
      "btc",
      [{ scriptType: "p2shP2wsh", value: 100000n }],
      [{ scriptType: "p2sh", value: 90000n, walletKeys: null }],
    );
    const unsignedBytes = acidTest.createPsbt().serialize();

    it("merges bitgo signatures into user-signed PSBT", function () {
      const request = signCopy(unsignedBytes, "btc", 0);
      const response = signCopy(unsignedBytes, "btc", 2);

      request.combineInputs(response.serialize());

      const rootWalletKeys = acidTest.rootWalletKeys;
      assert.ok(request.verifySignature(0, rootWalletKeys.userKey()), "user sig should be present");
      assert.ok(
        request.verifySignature(0, rootWalletKeys.bitgoKey()),
        "bitgo sig should be present",
      );
    });

    it("finalizes and extracts after combining user + bitgo", function () {
      const request = signCopy(unsignedBytes, "btc", 0);
      const response = signCopy(unsignedBytes, "btc", 2);

      request.combineInputs(response.serialize());
      request.finalizeAllInputs();
      const tx = request.extractTransaction();

      assert.ok(tx.getId(), "should have txid");
      assert.match(tx.getId(), /^[0-9a-f]{64}$/, "txid should be 64 hex chars");
      assert.ok(tx.toBytes().length > 0, "tx bytes should be non-empty");
    });

    it("does not add signatures when response is unsigned", function () {
      const request = signCopy(unsignedBytes, "btc", 0);
      const emptyResponse = fixedScriptWallet.BitGoPsbt.fromBytes(unsignedBytes, "btc");

      request.combineInputs(emptyResponse.serialize());

      const rootWalletKeys = acidTest.rootWalletKeys;
      assert.ok(request.verifySignature(0, rootWalletKeys.userKey()), "user sig should remain");
      assert.ok(
        !request.verifySignature(0, rootWalletKeys.bitgoKey()),
        "bitgo sig should be absent",
      );
    });

    it("is idempotent: combining the same response twice yields the same result", function () {
      const request1 = signCopy(unsignedBytes, "btc", 0);
      const request2 = fixedScriptWallet.BitGoPsbt.fromBytes(request1.serialize(), "btc");
      const response = signCopy(unsignedBytes, "btc", 2);
      const responseBytes = response.serialize();

      request1.combineInputs(responseBytes);
      request2.combineInputs(responseBytes);
      request2.combineInputs(responseBytes);

      assert.deepStrictEqual(
        Buffer.from(request1.serialize()).toString("hex"),
        Buffer.from(request2.serialize()).toString("hex"),
        "combining twice should yield the same PSBT",
      );
    });

    it("throws on malformed response bytes", function () {
      const request = signCopy(unsignedBytes, "btc", 0);

      assert.throws(
        () => request.combineInputs(Buffer.from("aabbccdd", "hex")),
        /Failed to (parse|combine)/,
      );
    });

    it("throws when input counts differ", function () {
      const twoInputTest = makeAcidTest(
        "btc",
        [
          { scriptType: "p2shP2wsh", value: 100000n },
          { scriptType: "p2shP2wsh", value: 200000n },
        ],
        [{ scriptType: "p2sh", value: 90000n, walletKeys: null }],
      );
      const twoInputBytes = twoInputTest.createPsbt().serialize();

      const request = signCopy(unsignedBytes, "btc", 0);
      const response = fixedScriptWallet.BitGoPsbt.fromBytes(twoInputBytes, "btc");

      assert.throws(() => request.combineInputs(response.serialize()), /input count mismatch/i);
    });
  });

  describe("LTC (p2shP2wsh)", function () {
    const acidTest = makeAcidTest(
      "ltc",
      [{ scriptType: "p2shP2wsh", value: 100000n }],
      [{ scriptType: "p2sh", value: 90000n, walletKeys: null }],
    );
    const unsignedBytes = acidTest.createPsbt().serialize();

    it("combines and finalizes for LTC", function () {
      const request = signCopy(unsignedBytes, "ltc", 0);
      const response = signCopy(unsignedBytes, "ltc", 2);

      request.combineInputs(response.serialize());
      request.finalizeAllInputs();
      const tx = request.extractTransaction();

      assert.ok(tx.getId(), "should have txid");
    });
  });

  describe("ZEC (p2sh)", function () {
    it("merges bitgo signatures from a ZEC response PSBT", function () {
      const acidTest = makeZecAcidTest();
      const unsignedBytes = acidTest.createPsbt().serialize();
      const [userKey, , bitgoKey] = getKeyTriple("default");

      const requestPsbt = fixedScriptWallet.BitGoPsbt.fromBytes(unsignedBytes, "zec");
      requestPsbt.sign(userKey);

      const responsePsbt = fixedScriptWallet.BitGoPsbt.fromBytes(unsignedBytes, "zec");
      responsePsbt.sign(bitgoKey);

      requestPsbt.combineInputs(responsePsbt.serialize());

      const rootWalletKeys = acidTest.rootWalletKeys;
      assert.ok(
        requestPsbt.verifySignature(0, rootWalletKeys.userKey()),
        "user sig should be present",
      );
      assert.ok(
        requestPsbt.verifySignature(0, rootWalletKeys.bitgoKey()),
        "bitgo sig should be present",
      );
    });

    it("finalizes and extracts after combining user + bitgo on ZEC", function () {
      const acidTest = makeZecAcidTest();
      const unsignedBytes = acidTest.createPsbt().serialize();
      const [userKey, , bitgoKey] = getKeyTriple("default");

      const requestPsbt = fixedScriptWallet.BitGoPsbt.fromBytes(unsignedBytes, "zec");
      requestPsbt.sign(userKey);

      const responsePsbt = fixedScriptWallet.BitGoPsbt.fromBytes(unsignedBytes, "zec");
      responsePsbt.sign(bitgoKey);

      requestPsbt.combineInputs(responsePsbt.serialize());
      requestPsbt.finalizeAllInputs();
      const tx = requestPsbt.extractTransaction();

      assert.ok(tx.getId(), "should produce a txid");
      assert.match(tx.getId(), /^[0-9a-f]{64}$/, "txid should be 64 hex chars");
    });

    it("works when response has no ZecConsensusBranchId (stripped HSM response)", function () {
      const acidTest = makeZecAcidTest();
      const unsignedBytes = acidTest.createPsbt().serialize();
      const [userKey, , bitgoKey] = getKeyTriple("default");

      const requestPsbt = fixedScriptWallet.BitGoPsbt.fromBytes(unsignedBytes, "zec");
      requestPsbt.sign(userKey);

      const responsePsbt = fixedScriptWallet.BitGoPsbt.fromBytes(unsignedBytes, "zec");
      responsePsbt.sign(bitgoKey);

      assert.doesNotThrow(() => requestPsbt.combineInputs(responsePsbt.serialize()));
    });

    it("signs user + bitgo on the same PSBT, finalizes, and extracts", function () {
      const acidTest = makeZecAcidTest();
      const [userKey, , bitgoKey] = getKeyTriple("default");

      const psbt = acidTest.createPsbt();
      psbt.sign(userKey);
      psbt.sign(bitgoKey);
      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction();

      assert.ok(tx.getId(), "should produce a txid");
      assert.match(tx.getId(), /^[0-9a-f]{64}$/, "txid should be 64 hex chars");
      assert.ok(tx.toBytes().length > 0, "tx bytes should be non-empty");
    });

    it("verifySignature reflects correct state after user + bitgo sign", function () {
      const acidTest = makeZecAcidTest();
      const [userKey, , bitgoKey] = getKeyTriple("default");
      const rootWalletKeys = acidTest.rootWalletKeys;

      const psbt = acidTest.createPsbt();
      assert.ok(!psbt.verifySignature(0, rootWalletKeys.userKey()), "no user sig before signing");

      psbt.sign(userKey);
      assert.ok(psbt.verifySignature(0, rootWalletKeys.userKey()), "user sig after sign");
      assert.ok(!psbt.verifySignature(0, rootWalletKeys.bitgoKey()), "no bitgo sig yet");

      psbt.sign(bitgoKey);
      assert.ok(psbt.verifySignature(0, rootWalletKeys.bitgoKey()), "bitgo sig after sign");
    });
  });

  describe("ZcashBitGoPsbt metadata", function () {
    it("consensusBranchId getter returns the branch ID stored in the PSBT", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const psbt = ZcashBitGoPsbt.createEmptyWithConsensusBranchId("zec", rootWalletKeys, {
        consensusBranchId: SAPLING_BRANCH_ID,
      });

      assert.strictEqual(psbt.consensusBranchId, SAPLING_BRANCH_ID);
    });

    it("branchIdForHeight returns Sapling branch ID at Sapling activation height", function () {
      const branchId = ZcashBitGoPsbt.branchIdForHeight("zec", SAPLING_ACTIVATION_HEIGHT);
      assert.strictEqual(branchId, SAPLING_BRANCH_ID);
    });

    it("branchIdForHeight returns NU5 branch ID at NU5 activation height (1687104)", function () {
      const NU5_ACTIVATION_HEIGHT = 1687104;
      const branchId = ZcashBitGoPsbt.branchIdForHeight("zec", NU5_ACTIVATION_HEIGHT);
      assert.strictEqual(branchId, NU5_BRANCH_ID);
    });

    it("branchIdForHeight returns undefined before Overwinter activation", function () {
      const branchId = ZcashBitGoPsbt.branchIdForHeight("zec", 1);
      assert.strictEqual(branchId, undefined);
    });

    it("ZcashBitGoPsbt.fromBytes throws when ZecConsensusBranchId is absent", function () {
      const btcBytes = makeAcidTest(
        "btc",
        [{ scriptType: "p2sh", value: 100000n }],
        [{ scriptType: "p2sh", value: 90000n, walletKeys: null }],
      )
        .createPsbt()
        .serialize();

      assert.throws(
        () => ZcashBitGoPsbt.fromBytes(btcBytes, "zec"),
        /ZecConsensusBranchId|consensus_branch_id|failed|invalid/i,
      );
    });
  });
});
