import * as assert from "assert";
import { Descriptor } from "../../js/index.js";
import { toDescriptorMap } from "../../js/descriptorWallet/DescriptorMap.js";

describe("descriptorWallet/DescriptorMap", () => {
  const testDescriptor = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";

  describe("toDescriptorMap", () => {
    it("should create map from descriptor strings", () => {
      const map = toDescriptorMap([{ name: "external", value: testDescriptor }]);

      assert.strictEqual(map.size, 1);
      assert.ok(map.has("external"));
      const descriptor = map.get("external");
      assert.ok(descriptor instanceof Descriptor);
    });

    it("should create map from Descriptor instances", () => {
      const descriptor = Descriptor.fromStringDetectType(testDescriptor);
      const map = toDescriptorMap([{ name: "external", value: descriptor }]);

      assert.strictEqual(map.size, 1);
      assert.strictEqual(map.get("external"), descriptor);
    });

    it("should handle multiple descriptors", () => {
      const map = toDescriptorMap([
        { name: "external", value: testDescriptor },
        { name: "internal", value: testDescriptor },
      ]);

      assert.strictEqual(map.size, 2);
      assert.ok(map.has("external"));
      assert.ok(map.has("internal"));
    });

    it("should handle empty array", () => {
      const map = toDescriptorMap([]);
      assert.strictEqual(map.size, 0);
    });
  });
});
