import * as assert from "assert";
import { Descriptor } from "../../js/index.js";
import {
  createScriptPubKeyFromDescriptor,
  createAddressFromDescriptor,
} from "../../js/descriptorWallet/address.js";

describe("descriptorWallet/address", () => {
  // A definite P2WPKH descriptor
  const definiteDescriptor =
    "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";

  // A derivable descriptor with wildcard
  const derivableDescriptor =
    "wpkh(xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5/0/*)";

  describe("createScriptPubKeyFromDescriptor", () => {
    it("should create scriptPubKey for definite descriptor", () => {
      const descriptor = Descriptor.fromStringDetectType(definiteDescriptor);
      const script = createScriptPubKeyFromDescriptor(descriptor, undefined);

      assert.ok(Buffer.isBuffer(script));
      // P2WPKH scripts are 22 bytes (OP_0 + 20 byte hash)
      assert.strictEqual(script.length, 22);
      assert.strictEqual(script[0], 0x00); // OP_0
      assert.strictEqual(script[1], 0x14); // 20 bytes
    });

    it("should create scriptPubKey for derived descriptor", () => {
      const descriptor = Descriptor.fromStringDetectType(derivableDescriptor);
      const script = createScriptPubKeyFromDescriptor(descriptor, 0);

      assert.ok(Buffer.isBuffer(script));
      assert.strictEqual(script.length, 22);
    });

    it("should create different scripts for different indices", () => {
      const descriptor = Descriptor.fromStringDetectType(derivableDescriptor);
      const script0 = createScriptPubKeyFromDescriptor(descriptor, 0);
      const script1 = createScriptPubKeyFromDescriptor(descriptor, 1);

      assert.notDeepStrictEqual(script0, script1);
    });
  });

  describe("createAddressFromDescriptor", () => {
    it("should create Bitcoin mainnet address", () => {
      const descriptor = Descriptor.fromStringDetectType(definiteDescriptor);
      const address = createAddressFromDescriptor(descriptor, undefined, "btc");

      assert.ok(typeof address === "string");
      // P2WPKH mainnet addresses start with bc1q
      assert.ok(address.startsWith("bc1q"), `Expected bc1q prefix, got: ${address}`);
    });

    it("should create Bitcoin testnet address", () => {
      const descriptor = Descriptor.fromStringDetectType(definiteDescriptor);
      const address = createAddressFromDescriptor(descriptor, undefined, "tbtc");

      assert.ok(typeof address === "string");
      // P2WPKH testnet addresses start with tb1q
      assert.ok(address.startsWith("tb1q"), `Expected tb1q prefix, got: ${address}`);
    });

    it("should create addresses for derived descriptors", () => {
      const descriptor = Descriptor.fromStringDetectType(derivableDescriptor);
      const address0 = createAddressFromDescriptor(descriptor, 0, "btc");
      const address1 = createAddressFromDescriptor(descriptor, 1, "btc");

      assert.notStrictEqual(address0, address1);
      assert.ok(address0.startsWith("bc1q"));
      assert.ok(address1.startsWith("bc1q"));
    });
  });
});
