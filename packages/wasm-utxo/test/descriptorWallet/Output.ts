import * as assert from "assert";
import {
  Output,
  MaxOutput,
  isMaxOutput,
  getMaxOutput,
  getOutputSum,
  getFixedOutputSum,
  toFixedOutputs,
} from "../../js/descriptorWallet/Output.js";

describe("descriptorWallet/Output", () => {
  describe("isMaxOutput", () => {
    it("should return true for max output", () => {
      const output: MaxOutput = { script: Buffer.from("test"), value: "max" };
      assert.strictEqual(isMaxOutput(output), true);
    });

    it("should return false for fixed output", () => {
      const output: Output = { script: Buffer.from("test"), value: 1000n };
      assert.strictEqual(isMaxOutput(output), false);
    });
  });

  describe("getMaxOutput", () => {
    it("should return undefined when no max output", () => {
      const outputs: Output[] = [
        { script: Buffer.from("a"), value: 100n },
        { script: Buffer.from("b"), value: 200n },
      ];
      assert.strictEqual(getMaxOutput(outputs), undefined);
    });

    it("should return the max output when present", () => {
      const maxOutput: MaxOutput = { script: Buffer.from("max"), value: "max" };
      const outputs: (Output | MaxOutput)[] = [
        { script: Buffer.from("a"), value: 100n },
        maxOutput,
      ];
      assert.strictEqual(getMaxOutput(outputs), maxOutput);
    });

    it("should throw when multiple max outputs", () => {
      const outputs: MaxOutput[] = [
        { script: Buffer.from("a"), value: "max" },
        { script: Buffer.from("b"), value: "max" },
      ];
      assert.throws(() => getMaxOutput(outputs), /Multiple max outputs/);
    });
  });

  describe("getOutputSum", () => {
    it("should sum output values", () => {
      const outputs: Output[] = [
        { script: Buffer.from("a"), value: 100n },
        { script: Buffer.from("b"), value: 200n },
        { script: Buffer.from("c"), value: 300n },
      ];
      assert.strictEqual(getOutputSum(outputs), 600n);
    });

    it("should return 0 for empty array", () => {
      assert.strictEqual(getOutputSum([]), 0n);
    });
  });

  describe("getFixedOutputSum", () => {
    it("should sum only fixed outputs, ignoring max", () => {
      const outputs: (Output | MaxOutput)[] = [
        { script: Buffer.from("a"), value: 100n },
        { script: Buffer.from("max"), value: "max" },
        { script: Buffer.from("b"), value: 200n },
      ];
      assert.strictEqual(getFixedOutputSum(outputs), 300n);
    });
  });

  describe("toFixedOutputs", () => {
    it("should replace max output with maxAmount", () => {
      const outputs: (Output | MaxOutput)[] = [
        { script: Buffer.from("a"), value: 100n },
        { script: Buffer.from("max"), value: "max" },
      ];
      const fixed = toFixedOutputs(outputs, { maxAmount: 500n });

      assert.strictEqual(fixed.length, 2);
      assert.strictEqual(fixed[0].value, 100n);
      assert.strictEqual(fixed[1].value, 500n);
    });

    it("should return same outputs when no max output", () => {
      const outputs: Output[] = [
        { script: Buffer.from("a"), value: 100n },
        { script: Buffer.from("b"), value: 200n },
      ];
      const fixed = toFixedOutputs(outputs, { maxAmount: 500n });

      assert.strictEqual(fixed.length, 2);
      assert.strictEqual(fixed[0].value, 100n);
      assert.strictEqual(fixed[1].value, 200n);
    });
  });
});
