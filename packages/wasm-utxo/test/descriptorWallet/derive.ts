import * as assert from "assert";
import { Descriptor } from "../../js/index.js";
import {
  getDescriptorAtIndex,
  getDescriptorAtIndexCheckScript,
} from "../../js/descriptorWallet/derive.js";

describe("descriptorWallet/derive", () => {
  // A definite descriptor (no wildcard)
  const definiteDescriptor =
    "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";

  // A derivable descriptor (with wildcard) - using a test xpub
  const derivableDescriptor =
    "wpkh(xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5/0/*)";

  describe("getDescriptorAtIndex", () => {
    it("should return definite descriptor without index", () => {
      const descriptor = Descriptor.fromStringDetectType(definiteDescriptor);
      const result = getDescriptorAtIndex(descriptor, undefined);

      assert.ok(result instanceof Descriptor);
      assert.strictEqual(result.hasWildcard(), false);
    });

    it("should throw for definite descriptor with index", () => {
      const descriptor = Descriptor.fromStringDetectType(definiteDescriptor);

      assert.throws(
        () => getDescriptorAtIndex(descriptor, 0),
        /Definite descriptor cannot be derived with index/,
      );
    });

    it("should derive derivable descriptor at index", () => {
      const descriptor = Descriptor.fromStringDetectType(derivableDescriptor);
      const result = getDescriptorAtIndex(descriptor, 0);

      assert.ok(result instanceof Descriptor);
      assert.strictEqual(result.hasWildcard(), false);
    });

    it("should throw for derivable descriptor without index", () => {
      const descriptor = Descriptor.fromStringDetectType(derivableDescriptor);

      assert.throws(
        () => getDescriptorAtIndex(descriptor, undefined),
        /Derivable descriptor requires an index/,
      );
    });

    it("should derive different addresses for different indices", () => {
      const descriptor = Descriptor.fromStringDetectType(derivableDescriptor);
      const result0 = getDescriptorAtIndex(descriptor, 0);
      const result1 = getDescriptorAtIndex(descriptor, 1);

      // Scripts should be different
      assert.notDeepStrictEqual(
        Buffer.from(result0.scriptPubkey()),
        Buffer.from(result1.scriptPubkey()),
      );
    });
  });

  describe("getDescriptorAtIndexCheckScript", () => {
    it("should return descriptor when script matches", () => {
      const descriptor = Descriptor.fromStringDetectType(definiteDescriptor);
      const script = Buffer.from(descriptor.scriptPubkey());

      const result = getDescriptorAtIndexCheckScript(descriptor, undefined, script);
      assert.ok(result instanceof Descriptor);
    });

    it("should throw when script does not match", () => {
      const descriptor = Descriptor.fromStringDetectType(definiteDescriptor);
      const wrongScript = Buffer.from([
        0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      ]);

      assert.throws(
        () => getDescriptorAtIndexCheckScript(descriptor, undefined, wrongScript),
        /Script mismatch/,
      );
    });

    it("should work with derivable descriptor at index", () => {
      const descriptor = Descriptor.fromStringDetectType(derivableDescriptor);
      const derived = descriptor.atDerivationIndex(5);
      const script = Buffer.from(derived.scriptPubkey());

      const result = getDescriptorAtIndexCheckScript(descriptor, 5, script);
      assert.ok(result instanceof Descriptor);
      assert.strictEqual(result.hasWildcard(), false);
    });
  });
});
