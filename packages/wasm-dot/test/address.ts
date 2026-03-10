import * as assert from "assert";
import { encodeSs58, decodeSs58, validateAddress, AddressFormat } from "../js/index.js";

describe("address", () => {
  // Known test vector: public key → SS58 addresses
  const PUBLIC_KEY = new Uint8Array(
    Buffer.from("61b18c6dc02ddcabdeac56cb4f21a971cc41cc97640f6f85b073480008c53a0d", "hex"),
  );
  const SUBSTRATE_ADDRESS = "5EGoFA95omzemRssELLDjVenNZ68aXyUeqtKQScXSEBvVJkr";

  describe("encodeSs58", () => {
    it("should encode public key to Substrate address (prefix 42)", () => {
      const address = encodeSs58(PUBLIC_KEY, AddressFormat.Substrate);
      assert.strictEqual(address, SUBSTRATE_ADDRESS);
    });

    it("should encode public key to Polkadot address (prefix 0)", () => {
      const address = encodeSs58(PUBLIC_KEY, AddressFormat.Polkadot);
      assert.ok(address.startsWith("1"), "Polkadot addresses start with '1'");
    });

    it("should encode public key to Kusama address (prefix 2)", () => {
      const address = encodeSs58(PUBLIC_KEY, AddressFormat.Kusama);
      assert.ok(address.length > 0);
    });

    it("should throw for invalid public key length", () => {
      const shortKey = new Uint8Array(16);
      assert.throws(() => encodeSs58(shortKey, AddressFormat.Substrate));
    });
  });

  describe("decodeSs58", () => {
    it("should decode Substrate address to public key and prefix", () => {
      const decoded = decodeSs58(SUBSTRATE_ADDRESS);
      assert.strictEqual(decoded.prefix, 42);
      assert.deepStrictEqual(new Uint8Array(decoded.publicKey), PUBLIC_KEY);
    });

    it("should roundtrip encode → decode for all formats", () => {
      for (const format of [
        AddressFormat.Polkadot,
        AddressFormat.Kusama,
        AddressFormat.Substrate,
      ]) {
        const address = encodeSs58(PUBLIC_KEY, format);
        const decoded = decodeSs58(address);
        assert.strictEqual(decoded.prefix, format);
        assert.deepStrictEqual(new Uint8Array(decoded.publicKey), PUBLIC_KEY);
      }
    });

    it("should throw for invalid address", () => {
      assert.throws(() => decodeSs58("invalid"));
    });
  });

  describe("validateAddress", () => {
    it("should return true for valid address without format check", () => {
      assert.strictEqual(validateAddress(SUBSTRATE_ADDRESS), true);
    });

    it("should return true for valid address with correct format", () => {
      assert.strictEqual(validateAddress(SUBSTRATE_ADDRESS, AddressFormat.Substrate), true);
    });

    it("should return false for valid address with wrong format", () => {
      assert.strictEqual(validateAddress(SUBSTRATE_ADDRESS, AddressFormat.Polkadot), false);
    });

    it("should return false for invalid address", () => {
      assert.strictEqual(validateAddress("invalid"), false);
    });

    it("should validate Polkadot mainnet addresses", () => {
      const polkadotAddress = encodeSs58(PUBLIC_KEY, AddressFormat.Polkadot);
      assert.strictEqual(validateAddress(polkadotAddress, AddressFormat.Polkadot), true);
      assert.strictEqual(validateAddress(polkadotAddress, AddressFormat.Substrate), false);
    });
  });
});
