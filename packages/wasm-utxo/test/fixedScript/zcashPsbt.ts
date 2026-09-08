import assert from "node:assert";
import { describe, it } from "mocha";

import { ZcashBitGoPsbt, ZcashIronwoodBitGoPsbt, ZcashPsbt } from "../../js/index.js";
import { BitGoPsbt } from "../../js/fixedScriptWallet/index.js";
import { getWalletKeysForSeed } from "../../js/testutils/index.js";

const LEGACY_V4_MAINNET_HEIGHT = 1687104;
const NU6_3_TESTNET_HEIGHT = 4134000;

describe("ZcashPsbt", function () {
  const walletKeys = getWalletKeysForSeed("zcash-psbt-factory-test");

  it("returns the v4 implementation for a legacy PSBT", function () {
    const original = ZcashBitGoPsbt.createEmpty("zcash", walletKeys, {
      blockHeight: LEGACY_V4_MAINNET_HEIGHT,
    });

    const psbt = ZcashPsbt.from(original.serialize(), "zcash");

    assert(psbt instanceof ZcashBitGoPsbt);
    assert(!(psbt instanceof ZcashIronwoodBitGoPsbt));
    assert.strictEqual(psbt.getVersion(), 4);
  });

  it("returns the v6 implementation for a complete Ironwood PSBT", function () {
    const original = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
      blockHeight: NU6_3_TESTNET_HEIGHT,
    });

    const psbt = ZcashPsbt.fromBytes(original.serialize(), "zcashTest");

    assert(psbt instanceof ZcashIronwoodBitGoPsbt);
    assert.strictEqual(psbt.getVersion(), 6);
  });

  it("returns the v6 implementation before a shielded output is added", function () {
    const original = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
      blockHeight: NU6_3_TESTNET_HEIGHT,
    });
    original.addWalletOutput(walletKeys, { chain: 1, index: 0, value: 100n });

    const psbt = ZcashPsbt.from(original.serialize(), "zcashTest");

    assert(psbt instanceof ZcashIronwoodBitGoPsbt);
    assert.strictEqual(psbt.getVersion(), 6);
  });

  it("rejects a non-Zcash PSBT", function () {
    const bitcoinPsbt = BitGoPsbt.createEmpty("bitcoin", walletKeys);

    assert.throws(() => ZcashPsbt.from(bitcoinPsbt.serialize(), "zcash"), /Zcash|branch|PSBT/i);
  });
});
