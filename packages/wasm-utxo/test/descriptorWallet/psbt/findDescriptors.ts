import * as assert from "assert";
import { Descriptor } from "../../../js/index.js";
import {
  findDescriptorForInput,
  findDescriptorForOutput,
  PsbtInput,
  PsbtOutput,
} from "../../../js/descriptorWallet/psbt/findDescriptors.js";
import { toDescriptorMap } from "../../../js/descriptorWallet/DescriptorMap.js";

describe("descriptorWallet/psbt/findDescriptors", () => {
  // Definite descriptors
  const wpkhDescriptor = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
  const wshDescriptor =
    "wsh(multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))";

  // Derivable descriptor
  const derivableDescriptor =
    "wpkh(xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5/0/*)";

  describe("findDescriptorForInput", () => {
    it("should find definite descriptor matching script", () => {
      const descriptor = Descriptor.fromStringDetectType(wpkhDescriptor);
      const script = descriptor.scriptPubkey();

      const descriptorMap = toDescriptorMap([{ name: "wpkh", value: wpkhDescriptor }]);

      const input: PsbtInput = {
        witnessUtxo: { script, value: 100000n },
      };

      const result = findDescriptorForInput(input, descriptorMap);

      assert.ok(result);
      assert.strictEqual(result.index, undefined);
      assert.ok(result.descriptor instanceof Descriptor);
    });

    it("should find derivable descriptor using bip32Derivation", () => {
      const descriptor = Descriptor.fromStringDetectType(derivableDescriptor);
      const derivedScript = descriptor.atDerivationIndex(5).scriptPubkey();

      const descriptorMap = toDescriptorMap([{ name: "derivable", value: derivableDescriptor }]);

      const input: PsbtInput = {
        witnessUtxo: { script: derivedScript, value: 100000n },
        bip32Derivation: [{ path: "m/0/5" }],
      };

      const result = findDescriptorForInput(input, descriptorMap);

      assert.ok(result);
      assert.strictEqual(result.index, 5);
    });

    it("should find derivable descriptor using tapBip32Derivation", () => {
      const descriptor = Descriptor.fromStringDetectType(derivableDescriptor);
      const derivedScript = descriptor.atDerivationIndex(10).scriptPubkey();

      const descriptorMap = toDescriptorMap([{ name: "derivable", value: derivableDescriptor }]);

      const input: PsbtInput = {
        witnessUtxo: { script: derivedScript, value: 100000n },
        tapBip32Derivation: [{ path: "m/0/10" }],
      };

      const result = findDescriptorForInput(input, descriptorMap);

      assert.ok(result);
      assert.strictEqual(result.index, 10);
    });

    it("should return undefined when no matching descriptor", () => {
      const descriptorMap = toDescriptorMap([{ name: "wpkh", value: wpkhDescriptor }]);

      // Use a different script that doesn't match
      const wshScript = Descriptor.fromStringDetectType(wshDescriptor).scriptPubkey();

      const input: PsbtInput = {
        witnessUtxo: { script: wshScript, value: 100000n },
      };

      const result = findDescriptorForInput(input, descriptorMap);

      assert.strictEqual(result, undefined);
    });

    it("should throw when witnessUtxo is missing", () => {
      const descriptorMap = toDescriptorMap([{ name: "wpkh", value: wpkhDescriptor }]);

      const input: PsbtInput = {};

      assert.throws(() => findDescriptorForInput(input, descriptorMap), /Missing script/);
    });

    it("should prefer definite descriptor over derivation", () => {
      const descriptor = Descriptor.fromStringDetectType(wpkhDescriptor);
      const script = descriptor.scriptPubkey();

      const descriptorMap = toDescriptorMap([
        { name: "wpkh", value: wpkhDescriptor },
        { name: "derivable", value: derivableDescriptor },
      ]);

      const input: PsbtInput = {
        witnessUtxo: { script, value: 100000n },
        bip32Derivation: [{ path: "m/0/0" }],
      };

      const result = findDescriptorForInput(input, descriptorMap);

      assert.ok(result);
      // Should find the definite descriptor (index undefined)
      assert.strictEqual(result.index, undefined);
    });
  });

  describe("findDescriptorForOutput", () => {
    it("should find definite descriptor for output", () => {
      const descriptor = Descriptor.fromStringDetectType(wpkhDescriptor);
      const script = descriptor.scriptPubkey();

      const descriptorMap = toDescriptorMap([{ name: "wpkh", value: wpkhDescriptor }]);

      const output: PsbtOutput = {};

      const result = findDescriptorForOutput(script, output, descriptorMap);

      assert.ok(result);
      assert.strictEqual(result.index, undefined);
    });

    it("should find derivable descriptor using bip32Derivation", () => {
      const descriptor = Descriptor.fromStringDetectType(derivableDescriptor);
      const script = descriptor.atDerivationIndex(3).scriptPubkey();

      const descriptorMap = toDescriptorMap([{ name: "derivable", value: derivableDescriptor }]);

      const output: PsbtOutput = {
        bip32Derivation: [{ path: "m/0/3" }],
      };

      const result = findDescriptorForOutput(script, output, descriptorMap);

      assert.ok(result);
      assert.strictEqual(result.index, 3);
    });

    it("should return undefined when no matching descriptor", () => {
      const descriptorMap = toDescriptorMap([{ name: "wpkh", value: wpkhDescriptor }]);

      const wshScript = Descriptor.fromStringDetectType(wshDescriptor).scriptPubkey();

      const output: PsbtOutput = {};

      const result = findDescriptorForOutput(wshScript, output, descriptorMap);

      assert.strictEqual(result, undefined);
    });
  });
});
