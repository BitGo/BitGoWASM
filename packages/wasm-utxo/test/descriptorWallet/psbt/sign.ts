import * as assert from "assert";
import { BIP32 } from "../../../js/bip32.js";
import { ECPair } from "../../../js/ecpair.js";
import {
  getNewSignatureCountForInput,
  getNewSignatureCount,
  SignPsbtInputResult,
  SignPsbtResult,
} from "../../../js/descriptorWallet/psbt/sign.js";

describe("descriptorWallet/psbt/sign", () => {
  describe("getNewSignatureCountForInput", () => {
    it("should count Ecdsa signatures", () => {
      const result: SignPsbtInputResult = {
        Ecdsa: ["pubkey1", "pubkey2"],
      };
      assert.strictEqual(getNewSignatureCountForInput(result), 2);
    });

    it("should count Schnorr signatures", () => {
      const result: SignPsbtInputResult = {
        Schnorr: ["pubkey1"],
      };
      assert.strictEqual(getNewSignatureCountForInput(result), 1);
    });

    it("should return 0 for empty signatures", () => {
      const result: SignPsbtInputResult = {
        Ecdsa: [],
      };
      assert.strictEqual(getNewSignatureCountForInput(result), 0);
    });
  });

  describe("getNewSignatureCount", () => {
    it("should sum signatures across all inputs", () => {
      const result: SignPsbtResult = {
        0: { Ecdsa: ["pub1", "pub2"] },
        1: { Ecdsa: ["pub3"] },
        2: { Schnorr: ["pub4", "pub5", "pub6"] },
      };
      assert.strictEqual(getNewSignatureCount(result), 6);
    });

    it("should return 0 for empty result", () => {
      const result: SignPsbtResult = {};
      assert.strictEqual(getNewSignatureCount(result), 0);
    });
  });

  describe("BIP32 key compatibility", () => {
    it("should create BIP32 from seed string", () => {
      const key = BIP32.fromSeedSha256("test-seed");
      assert.ok(key.privateKey);
      assert.ok(key.publicKey);
    });

    it("should derive keys from BIP32", () => {
      const master = BIP32.fromSeedSha256("test-seed");
      const derived = master.derivePath("m/44'/0'/0'/0/0");
      assert.ok(derived.privateKey);
      assert.notDeepStrictEqual(derived.publicKey, master.publicKey);
    });
  });

  describe("ECPair key compatibility", () => {
    it("should create ECPair from WIF", () => {
      // This is a test WIF - DO NOT USE IN PRODUCTION
      const wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
      const pair = ECPair.fromWIF(wif);
      assert.ok(pair.privateKey);
      assert.ok(pair.publicKey);
    });

    it("should create ECPair from private key", () => {
      // Create a deterministic private key for testing
      const privateKey = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) {
        privateKey[i] = i + 1;
      }
      const pair = ECPair.fromPrivateKey(privateKey);

      assert.ok(pair.privateKey);
      assert.ok(pair.publicKey);
      assert.strictEqual(pair.publicKey.length, 33); // Compressed public key
    });
  });
});
