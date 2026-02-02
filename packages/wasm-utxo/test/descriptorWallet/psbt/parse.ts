import * as assert from "assert";
import { Descriptor, Psbt } from "../../../js/index.js";
import { toDescriptorMap } from "../../../js/descriptorWallet/DescriptorMap.js";
import { parse, parseFromBytes } from "../../../js/descriptorWallet/psbt/parse.js";

describe("descriptorWallet/psbt/parse", () => {
  // Test descriptors
  const wpkhDescriptor = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
  const derivableDescriptor =
    "wpkh(xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5/0/*)";

  describe("parse", () => {
    it("should parse a simple PSBT with one input and one output", () => {
      const descriptor = Descriptor.fromStringDetectType(wpkhDescriptor);
      const script = descriptor.scriptPubkey();

      // Create a simple PSBT
      const psbt = new Psbt(2, 0);
      psbt.addInput(
        "0000000000000000000000000000000000000000000000000000000000000001",
        0,
        100000n,
        script,
      );
      psbt.addOutput(script, 90000n);

      // Update with descriptor for proper bip32 derivation data
      psbt.updateInputWithDescriptor(0, descriptor);
      psbt.updateOutputWithDescriptor(0, descriptor);

      const descriptorMap = toDescriptorMap([{ name: "wpkh", value: wpkhDescriptor }]);

      const result = parse(psbt, descriptorMap, "btc");

      // Check inputs
      assert.strictEqual(result.inputs.length, 1);
      assert.strictEqual(result.inputs[0].value, 100000n);
      assert.ok(result.inputs[0].address.startsWith("bc1q"));
      assert.ok(result.inputs[0].scriptId);
      assert.strictEqual(result.inputs[0].scriptId.index, undefined); // definite descriptor
      // Verify descriptor is returned as a Descriptor instance
      assert.ok(result.inputs[0].scriptId.descriptor instanceof Descriptor);

      // Check outputs
      assert.strictEqual(result.outputs.length, 1);
      assert.strictEqual(result.outputs[0].value, 90000n);
      assert.ok(result.outputs[0].address?.startsWith("bc1q"));
      assert.ok(result.outputs[0].scriptId);
      // Verify descriptor is returned as a Descriptor instance
      assert.ok(result.outputs[0].scriptId.descriptor instanceof Descriptor);

      // Verify reference identity - descriptors should be the same object from the map
      const mapDescriptor = descriptorMap.get("wpkh");
      assert.strictEqual(
        result.inputs[0].scriptId.descriptor,
        mapDescriptor,
        "Input descriptor should be reference-identical to the one in the map",
      );
      assert.strictEqual(
        result.outputs[0].scriptId.descriptor,
        mapDescriptor,
        "Output descriptor should be reference-identical to the one in the map",
      );

      // Check calculated values
      assert.strictEqual(result.minerFee, 10000n);
      assert.strictEqual(result.spendAmount, 0n); // All outputs match descriptors
      assert.ok(result.virtualSize > 0);
    });

    it("should parse PSBT with derivable descriptor", () => {
      const descriptor = Descriptor.fromStringDetectType(derivableDescriptor);
      const derivedDescriptor = descriptor.atDerivationIndex(5);
      const script = derivedDescriptor.scriptPubkey();

      const psbt = new Psbt(2, 0);
      psbt.addInput(
        "0000000000000000000000000000000000000000000000000000000000000002",
        0,
        50000n,
        script,
      );
      psbt.addOutput(script, 40000n);

      // Update with descriptor
      psbt.updateInputWithDescriptor(0, derivedDescriptor);
      psbt.updateOutputWithDescriptor(0, derivedDescriptor);

      const descriptorMap = toDescriptorMap([{ name: "derivable", value: derivableDescriptor }]);

      const result = parse(psbt, descriptorMap, "btc");

      assert.strictEqual(result.inputs.length, 1);
      assert.strictEqual(result.inputs[0].value, 50000n);
      assert.strictEqual(result.inputs[0].scriptId.index, 5);

      assert.strictEqual(result.outputs.length, 1);
      assert.strictEqual(result.outputs[0].value, 40000n);

      // Verify reference identity for derivable descriptor
      const mapDescriptor = descriptorMap.get("derivable");
      assert.strictEqual(
        result.inputs[0].scriptId.descriptor,
        mapDescriptor,
        "Derivable descriptor should be reference-identical",
      );

      assert.strictEqual(result.minerFee, 10000n);
    });

    it("should calculate spendAmount for outputs without matching descriptors", () => {
      const descriptor = Descriptor.fromStringDetectType(wpkhDescriptor);
      const script = descriptor.scriptPubkey();

      // Create a different output script (external address) - P2WPKH with a different hash
      const externalScript = new Uint8Array([
        0x00,
        0x14, // OP_0 PUSH(20)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01, // random hash
      ]);

      const psbt = new Psbt(2, 0);
      psbt.addInput(
        "0000000000000000000000000000000000000000000000000000000000000003",
        0,
        100000n,
        script,
      );
      psbt.addOutput(externalScript, 60000n); // External output (spend)
      psbt.addOutput(script, 30000n); // Change output (matches descriptor)

      psbt.updateInputWithDescriptor(0, descriptor);
      psbt.updateOutputWithDescriptor(1, descriptor);

      const descriptorMap = toDescriptorMap([{ name: "wpkh", value: wpkhDescriptor }]);

      const result = parse(psbt, descriptorMap, "btc");

      assert.strictEqual(result.outputs.length, 2);
      assert.strictEqual(result.outputs[0].scriptId, undefined); // No matching descriptor
      assert.ok(result.outputs[1].scriptId); // Matches descriptor

      assert.strictEqual(result.spendAmount, 60000n);
      assert.strictEqual(result.minerFee, 10000n);
    });

    it("should work with testnet addresses", () => {
      const descriptor = Descriptor.fromStringDetectType(wpkhDescriptor);
      const script = descriptor.scriptPubkey();

      const psbt = new Psbt(2, 0);
      psbt.addInput(
        "0000000000000000000000000000000000000000000000000000000000000004",
        0,
        100000n,
        script,
      );
      psbt.addOutput(script, 90000n);

      psbt.updateInputWithDescriptor(0, descriptor);
      psbt.updateOutputWithDescriptor(0, descriptor);

      const descriptorMap = toDescriptorMap([{ name: "wpkh", value: wpkhDescriptor }]);

      const result = parse(psbt, descriptorMap, "tbtc");

      assert.ok(result.inputs[0].address.startsWith("tb1q"));
      assert.ok(result.outputs[0].address?.startsWith("tb1q"));
    });
  });

  describe("parseFromBytes", () => {
    it("should parse PSBT from serialized bytes", () => {
      const descriptor = Descriptor.fromStringDetectType(wpkhDescriptor);
      const script = descriptor.scriptPubkey();

      const psbt = new Psbt(2, 0);
      psbt.addInput(
        "0000000000000000000000000000000000000000000000000000000000000005",
        0,
        100000n,
        script,
      );
      psbt.addOutput(script, 90000n);

      psbt.updateInputWithDescriptor(0, descriptor);
      psbt.updateOutputWithDescriptor(0, descriptor);

      const psbtBytes = psbt.serialize();

      const descriptorMap = toDescriptorMap([{ name: "wpkh", value: wpkhDescriptor }]);

      const result = parseFromBytes(psbtBytes, descriptorMap, "btc");

      assert.strictEqual(result.inputs.length, 1);
      assert.strictEqual(result.outputs.length, 1);
      assert.strictEqual(result.minerFee, 10000n);
    });
  });
});
