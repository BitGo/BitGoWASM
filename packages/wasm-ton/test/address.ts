import * as assert from "assert";
import { encodeAddress, decodeAddress, validateAddress, toRawAddress } from "../js/address.js";

describe("TON Address", () => {
  // Deterministic 32-byte test public key
  const testPubkey = new Uint8Array(32).fill(1);

  describe("encodeAddress", () => {
    it("should encode a public key to a bounceable mainnet address", () => {
      const address = encodeAddress(testPubkey, true, false);
      assert.ok(address.length === 48, "Address should be 48 chars base64url");
      assert.ok(validateAddress(address), "Encoded address should be valid");
    });

    it("should encode a public key to a non-bounceable address", () => {
      const bounceable = encodeAddress(testPubkey, true, false);
      const nonBounceable = encodeAddress(testPubkey, false, false);
      assert.notStrictEqual(bounceable, nonBounceable);
    });

    it("should encode a public key to a testnet address", () => {
      const mainnet = encodeAddress(testPubkey, true, false);
      const testnet = encodeAddress(testPubkey, true, true);
      assert.notStrictEqual(mainnet, testnet);
    });

    it("should throw for invalid public key length", () => {
      const shortKey = new Uint8Array(16);
      assert.throws(() => encodeAddress(shortKey, true, false));
    });
  });

  describe("decodeAddress", () => {
    it("should decode a user-friendly address", () => {
      const address = encodeAddress(testPubkey, true, false);
      const decoded = decodeAddress(address);

      assert.strictEqual(decoded.workchainId, 0);
      assert.strictEqual(decoded.hash.length, 32);
      assert.strictEqual(decoded.bounceable, true);
      assert.strictEqual(decoded.testnet, false);
    });

    it("should decode flags correctly", () => {
      const bounceable = encodeAddress(testPubkey, true, false);
      const nonBounceable = encodeAddress(testPubkey, false, false);
      const testnet = encodeAddress(testPubkey, true, true);

      const decB = decodeAddress(bounceable);
      const decNB = decodeAddress(nonBounceable);
      const decT = decodeAddress(testnet);

      assert.strictEqual(decB.bounceable, true);
      assert.strictEqual(decB.testnet, false);

      assert.strictEqual(decNB.bounceable, false);
      assert.strictEqual(decNB.testnet, false);

      assert.strictEqual(decT.bounceable, true);
      assert.strictEqual(decT.testnet, true);
    });

    it("should decode the same hash regardless of flags", () => {
      const bounceable = encodeAddress(testPubkey, true, false);
      const nonBounceable = encodeAddress(testPubkey, false, false);

      const decB = decodeAddress(bounceable);
      const decNB = decodeAddress(nonBounceable);

      assert.deepStrictEqual(decB.hash, decNB.hash);
    });

    it("should throw for invalid address", () => {
      assert.throws(() => decodeAddress("invalid"));
    });
  });

  describe("validateAddress", () => {
    it("should validate a correctly encoded address", () => {
      const address = encodeAddress(testPubkey, true, false);
      assert.ok(validateAddress(address));
    });

    it("should reject invalid addresses", () => {
      assert.strictEqual(validateAddress("invalid"), false);
      assert.strictEqual(validateAddress(""), false);
    });

    it("should validate a known TON address", () => {
      // EQ prefix = bounceable mainnet address
      const addr = "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e";
      assert.ok(validateAddress(addr));
    });
  });

  describe("toRawAddress", () => {
    it("should convert user-friendly to raw format", () => {
      const address = encodeAddress(testPubkey, true, false);
      const raw = toRawAddress(address);

      assert.ok(raw.startsWith("0:"), "Raw address should start with workchain:hex");
      assert.ok(raw.includes(":"), "Raw address should contain colon");

      // Hex part should be 64 chars (32 bytes)
      const hexPart = raw.split(":")[1];
      assert.strictEqual(hexPart.length, 64);
    });

    it("should produce consistent raw addresses regardless of flags", () => {
      const bounceable = encodeAddress(testPubkey, true, false);
      const nonBounceable = encodeAddress(testPubkey, false, false);

      assert.strictEqual(toRawAddress(bounceable), toRawAddress(nonBounceable));
    });
  });

  describe("roundtrip", () => {
    it("should roundtrip encode -> decode -> re-encode", () => {
      const address = encodeAddress(testPubkey, true, false);
      const decoded = decodeAddress(address);

      // Re-encode with same pubkey and flags should give same address
      const reEncoded = encodeAddress(testPubkey, decoded.bounceable, decoded.testnet);
      assert.strictEqual(address, reEncoded);
    });

    it("should roundtrip raw address decode -> validate", () => {
      const address = encodeAddress(testPubkey, true, false);
      const raw = toRawAddress(address);
      assert.ok(validateAddress(raw));
    });
  });
});
