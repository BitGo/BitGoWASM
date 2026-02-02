import * as assert from "assert";
import { Descriptor, Psbt } from "../../js/index.js";
import {
  getInputVSizesForDescriptors,
  getChangeOutputVSizesForDescriptor,
  getVirtualSize,
  getVirtualSizeEstimateForPsbt,
} from "../../js/descriptorWallet/VirtualSize.js";
import { toDescriptorMap } from "../../js/descriptorWallet/DescriptorMap.js";

describe("descriptorWallet/VirtualSize", () => {
  // P2WPKH descriptor
  const wpkhDescriptor = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";

  // P2WSH 2-of-2 multisig descriptor
  const wshDescriptor =
    "wsh(multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))";

  describe("getInputVSizesForDescriptors", () => {
    it("should calculate input vsize for P2WPKH", () => {
      const descriptors = toDescriptorMap([{ name: "wpkh", value: wpkhDescriptor }]);

      const vsizes = getInputVSizesForDescriptors(descriptors);

      assert.ok("wpkh" in vsizes);
      // P2WPKH input is approximately 68 vbytes
      assert.ok(
        vsizes["wpkh"] > 60 && vsizes["wpkh"] < 80,
        `Expected P2WPKH vsize around 68, got ${vsizes["wpkh"]}`,
      );
    });

    it("should calculate input vsize for P2WSH", () => {
      const descriptors = toDescriptorMap([{ name: "wsh", value: wshDescriptor }]);

      const vsizes = getInputVSizesForDescriptors(descriptors);

      assert.ok("wsh" in vsizes);
      // P2WSH 2-of-2 multisig is larger than P2WPKH
      assert.ok(vsizes["wsh"] > 80, `Expected P2WSH vsize > 80, got ${vsizes["wsh"]}`);
    });

    it("should handle multiple descriptors", () => {
      const descriptors = toDescriptorMap([
        { name: "wpkh", value: wpkhDescriptor },
        { name: "wsh", value: wshDescriptor },
      ]);

      const vsizes = getInputVSizesForDescriptors(descriptors);

      assert.ok("wpkh" in vsizes);
      assert.ok("wsh" in vsizes);
    });
  });

  describe("getChangeOutputVSizesForDescriptor", () => {
    it("should return input and output vsize for P2WPKH", () => {
      const descriptor = Descriptor.fromStringDetectType(wpkhDescriptor);
      const sizes = getChangeOutputVSizesForDescriptor(descriptor);

      assert.ok(typeof sizes.inputVSize === "number");
      assert.ok(typeof sizes.outputVSize === "number");
      // P2WPKH output is 31 bytes (8 value + 1 + 22 scriptPubKey)
      assert.strictEqual(sizes.outputVSize, 22);
    });

    it("should return input and output vsize for P2WSH", () => {
      const descriptor = Descriptor.fromStringDetectType(wshDescriptor);
      const sizes = getChangeOutputVSizesForDescriptor(descriptor);

      // P2WSH output is 43 bytes (8 value + 1 + 34 scriptPubKey)
      assert.strictEqual(sizes.outputVSize, 34);
    });
  });

  describe("getVirtualSize", () => {
    it("should calculate vsize with Descriptor inputs", () => {
      const descriptor = Descriptor.fromStringDetectType(wpkhDescriptor);
      const script = descriptor.scriptPubkey();

      const tx = {
        inputs: [descriptor],
        outputs: [{ script }],
      };

      const vsize = getVirtualSize(tx);

      // Should be > 0 and reasonable
      assert.ok(vsize > 50 && vsize < 200, `Unexpected vsize: ${vsize}`);
    });

    it("should calculate vsize with descriptorName inputs", () => {
      const descriptors = toDescriptorMap([{ name: "wpkh", value: wpkhDescriptor }]);
      const descriptor = Descriptor.fromStringDetectType(wpkhDescriptor);
      const script = descriptor.scriptPubkey();

      const tx = {
        inputs: [{ descriptorName: "wpkh" }],
        outputs: [{ script }],
      };

      const vsize = getVirtualSize(tx, descriptors);

      assert.ok(vsize > 50 && vsize < 200, `Unexpected vsize: ${vsize}`);
    });

    it("should throw for descriptorName without descriptorMap", () => {
      const descriptor = Descriptor.fromStringDetectType(wpkhDescriptor);
      const script = descriptor.scriptPubkey();

      const tx = {
        inputs: [{ descriptorName: "wpkh" }],
        outputs: [{ script }],
      };

      // @ts-expect-error - testing error case with missing descriptorMap
      assert.throws(() => getVirtualSize(tx), /missing descriptorMap/);
    });
  });

  describe("getVirtualSizeEstimateForPsbt", () => {
    it("should estimate vsize for PSBT", () => {
      const descriptors = toDescriptorMap([{ name: "wpkh", value: wpkhDescriptor }]);

      // Create a minimal PSBT
      const psbt = new Psbt(2, 0);
      const descriptor = Descriptor.fromStringDetectType(wpkhDescriptor);
      const script = descriptor.scriptPubkey();

      // Add a dummy input
      psbt.addInput(
        "0000000000000000000000000000000000000000000000000000000000000000",
        0,
        100000n,
        script,
      );

      // Add a dummy output
      psbt.addOutput(script, 50000n);

      const vsize = getVirtualSizeEstimateForPsbt(psbt, descriptors);

      assert.ok(vsize > 0, "vsize should be positive");
      assert.ok(vsize < 500, `vsize seems too large: ${vsize}`);
    });
  });
});
