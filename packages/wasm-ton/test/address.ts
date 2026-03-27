import * as assert from "assert";
import {
  encodeAddress,
  decodeAddress,
  validateAddress,
  toUserFriendly,
  toRaw,
} from "../js/index.js";

describe("address", () => {
  // Known TON address from the ecosystem
  const KNOWN_ADDRESS = "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e";
  const KNOWN_RAW = "0:465d9f5d759796ca9c7c1242627872570f972dd1ba649aed18e18a18af734cd1";

  describe("encodeAddress", () => {
    it("should encode a public key to a bounceable address", () => {
      const pubkey = new Uint8Array(32).fill(42);
      const address = encodeAddress(pubkey, true, 0);
      assert.strictEqual(address.length, 48);
      assert.ok(
        address.startsWith("EQ"),
        `Bounceable address should start with EQ, got: ${address}`,
      );
    });

    it("should encode a public key to a non-bounceable address", () => {
      const pubkey = new Uint8Array(32).fill(42);
      const address = encodeAddress(pubkey, false, 0);
      assert.strictEqual(address.length, 48);
      assert.ok(
        address.startsWith("UQ"),
        `Non-bounceable address should start with UQ, got: ${address}`,
      );
    });

    it("should throw for invalid public key length", () => {
      const shortKey = new Uint8Array(16);
      assert.throws(() => encodeAddress(shortKey, true, 0));
    });

    it("should produce deterministic output", () => {
      const pubkey = new Uint8Array(32).fill(1);
      const addr1 = encodeAddress(pubkey, true, 0);
      const addr2 = encodeAddress(pubkey, true, 0);
      assert.strictEqual(addr1, addr2);
    });
  });

  describe("decodeAddress", () => {
    it("should decode a user-friendly address", () => {
      const decoded = decodeAddress(KNOWN_ADDRESS);
      assert.strictEqual(decoded.workchainId, 0);
      assert.strictEqual(decoded.hash.length, 32);
      assert.strictEqual(decoded.bounceable, true);
    });

    it("should decode a raw address", () => {
      const decoded = decodeAddress(KNOWN_RAW);
      assert.strictEqual(decoded.workchainId, 0);
      assert.strictEqual(decoded.hash.length, 32);
    });

    it("should throw for invalid address", () => {
      assert.throws(() => decodeAddress("invalid"));
    });

    it("should roundtrip encode -> decode for bounceable", () => {
      const pubkey = new Uint8Array(32).fill(99);
      const address = encodeAddress(pubkey, true, 0);
      const decoded = decodeAddress(address);
      assert.strictEqual(decoded.workchainId, 0);
      assert.strictEqual(decoded.bounceable, true);
      assert.strictEqual(decoded.hash.length, 32);
    });
  });

  describe("validateAddress", () => {
    it("should return true for valid user-friendly address", () => {
      assert.strictEqual(validateAddress(KNOWN_ADDRESS), true);
    });

    it("should return true for valid raw address", () => {
      assert.strictEqual(validateAddress(KNOWN_RAW), true);
    });

    it("should return false for invalid address", () => {
      assert.strictEqual(validateAddress("invalid"), false);
    });

    it("should return false for empty string", () => {
      assert.strictEqual(validateAddress(""), false);
    });
  });

  describe("toUserFriendly", () => {
    it("should convert raw to bounceable user-friendly", () => {
      const friendly = toUserFriendly(KNOWN_RAW, true);
      assert.strictEqual(friendly.length, 48);
      assert.ok(friendly.startsWith("EQ"));
    });

    it("should convert raw to non-bounceable user-friendly", () => {
      const friendly = toUserFriendly(KNOWN_RAW, false);
      assert.strictEqual(friendly.length, 48);
      assert.ok(friendly.startsWith("UQ"));
    });

    it("should convert user-friendly bounceable to non-bounceable", () => {
      const nonBounceable = toUserFriendly(KNOWN_ADDRESS, false);
      assert.ok(nonBounceable.startsWith("UQ"));

      // Both should decode to the same hash
      const decoded1 = decodeAddress(KNOWN_ADDRESS);
      const decoded2 = decodeAddress(nonBounceable);
      assert.deepStrictEqual(new Uint8Array(decoded1.hash), new Uint8Array(decoded2.hash));
    });
  });

  describe("toRaw", () => {
    it("should convert user-friendly to raw format", () => {
      const raw = toRaw(KNOWN_ADDRESS);
      assert.ok(raw.startsWith("0:"));
      assert.strictEqual(raw.length, 2 + 64); // "0:" + 64 hex chars
    });

    it("should roundtrip raw -> user-friendly -> raw", () => {
      const friendly = toUserFriendly(KNOWN_RAW, true);
      const raw = toRaw(friendly);
      assert.strictEqual(raw, KNOWN_RAW);
    });
  });
});
