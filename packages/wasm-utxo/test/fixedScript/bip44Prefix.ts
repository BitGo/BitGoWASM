import assert from "node:assert";

import { BIP32 } from "../../js/bip32.js";
import { isWasmUtxoError } from "../../js/index.js";
import {
  BitGoPsbt,
  RootWalletKeys,
  deriveWalletAccount,
  deriveWalletPrefix,
  getWalletKeysFromPsbt,
} from "../../js/fixedScriptWallet/index.js";
import type { Triple } from "../../js/triple.js";

const specTriple = (bitgoSeed: string): Triple<BIP32> => [
  BIP32.fromSeedSha256("wcn3907-u"),
  BIP32.fromSeedSha256("wcn3907-b"),
  BIP32.fromSeedSha256(bitgoSeed),
];

describe("BIP44-style wallet prefix", function () {
  describe("deriveWalletAccount / deriveWalletPrefix", function () {
    const vectors = [
      ["wcn3907-g1", 1528449227, 506574854],
      ["wcn3907-g2", 1401193521, 285195054],
      ["wcn3907-g", 1639221447, 1133889609],
    ] as const;

    for (const [bitgoSeed, h1, h2] of vectors) {
      it(`matches the spec vector for ${bitgoSeed}`, function () {
        assert.deepStrictEqual(deriveWalletAccount(specTriple(bitgoSeed)), [h1, h2]);
      });
    }

    it("is the same for xprvs and xpubs", function () {
      const xprvs = specTriple("wcn3907-g");
      const xpubs = xprvs.map((k) => k.neutered().toBase58()) as Triple<string>;
      assert.deepStrictEqual(deriveWalletAccount(xprvs), deriveWalletAccount(xpubs));
    });

    it("formats the prefix", function () {
      assert.strictEqual(
        deriveWalletPrefix(specTriple("wcn3907-g"), 0),
        "44/0/1639221447/1133889609",
      );
    });

    it("rejects a hardened coin type with a typed error", function () {
      assert.throws(
        () => deriveWalletPrefix(specTriple("wcn3907-g"), 0x80000000),
        (e: unknown) => isWasmUtxoError(e) && e.code === "WalletPrefixError.CoinTypeOutOfRange",
      );
      assert.throws(() => deriveWalletPrefix(specTriple("wcn3907-g"), -1), RangeError);
    });
  });

  describe("RootWalletKeys", function () {
    it("rejects a hardened derivation prefix with a typed error", function () {
      assert.throws(
        () =>
          RootWalletKeys.from({
            triple: specTriple("wcn3907-g"),
            derivationPrefixes: ["44'/0", "0/0", "0/0"],
          }),
        (e: unknown) => isWasmUtxoError(e) && e.code === "WalletKeysError.HardenedDerivationPrefix",
      );
    });

    it("withBip44CoinType exposes the canonical prefix", function () {
      const keys = RootWalletKeys.fromXpubs(
        specTriple("wcn3907-g").map((k) => k.neutered().toBase58()) as Triple<string>,
      );
      assert.strictEqual(keys.bip44Prefix(), undefined);
      assert.strictEqual(keys.withBip44CoinType(0).bip44Prefix(), "44/0/1639221447/1133889609");
    });
  });

  describe("parse", function () {
    const triple = specTriple("wcn3907-g");
    const xpubs = triple.map((k) => k.neutered().toBase58()) as Triple<string>;
    const bip44Prefix = deriveWalletPrefix(triple, 0);
    const legacyKeys = RootWalletKeys.fromXpubs(xpubs);
    const bip44BuildKeys = RootWalletKeys.from({
      triple: triple.map((k) => k.neutered()) as Triple<BIP32>,
      derivationPrefixes: [bip44Prefix, bip44Prefix, bip44Prefix],
    });

    function mixedPsbt(): BitGoPsbt {
      const psbt = BitGoPsbt.createEmpty("btc", legacyKeys, { version: 2, lockTime: 0 });
      const txid = "00".repeat(32);
      psbt.addWalletInput({ txid, vout: 0, value: 100_000n }, legacyKeys, {
        scriptId: { chain: 20, index: 0 },
      });
      psbt.addWalletInput({ txid, vout: 1, value: 100_000n }, bip44BuildKeys, {
        scriptId: { chain: 40, index: 0 },
        signPath: { signer: "user", cosigner: "bitgo" },
      });
      psbt.addWalletOutput(bip44BuildKeys, { chain: 41, index: 0, value: 90_000n });
      psbt.addWalletOutput(legacyKeys, { chain: 21, index: 3, value: 1_000n });
      return psbt;
    }

    it("parses mixed legacy and bip44 PSBTs with fromXpubs keys that know the coin type", function () {
      const parsed = mixedPsbt().parseTransactionWithWalletKeys(legacyKeys.withBip44CoinType(0), {
        replayProtection: { publicKeys: [] },
      });
      assert.deepStrictEqual(
        parsed.inputs.map((i) => i.derivationPath),
        ["0/0/20/0", `${bip44Prefix}/40/0`],
      );
      assert.deepStrictEqual(
        parsed.outputs.map((o) => o.derivationPath),
        [`${bip44Prefix}/41/0`, "0/0/21/3"],
      );
      assert.strictEqual(parsed.spendAmount, 0n);
    });

    it("rejects bip44 inputs without the coin type", function () {
      assert.throws(
        () =>
          mixedPsbt().parseTransactionWithWalletKeys(legacyKeys, {
            replayProtection: { publicKeys: [] },
          }),
        (e: unknown) =>
          isWasmUtxoError(e) &&
          e.code === "ParseTransactionError.Input/ParseInputError.WalletValidation",
      );
    });

    it("getWalletKeysFromPsbt resolves a mixed PSBT when given the coin type", function () {
      const shuffled = [triple[2], triple[0], triple[1]].map((k) => k.neutered());
      const keys = getWalletKeysFromPsbt(mixedPsbt(), shuffled, { bip44CoinType: 0 });
      assert.strictEqual(keys.userKey().toBase58(), xpubs[0]);
      assert.strictEqual(keys.bip44Prefix(), bip44Prefix);
    });
  });
});
