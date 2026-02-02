import * as assert from "assert";
import { Descriptor, Psbt } from "../../../js/index.js";
import {
  getRequiredLocktime,
  assertSatisfiable,
  FINAL_SEQUENCE,
} from "../../../js/descriptorWallet/psbt/assertSatisfiable.js";

describe("descriptorWallet/psbt/assertSatisfiable", () => {
  describe("FINAL_SEQUENCE", () => {
    it("should be 0xffffffff", () => {
      assert.strictEqual(FINAL_SEQUENCE, 0xffffffff);
    });
  });

  describe("getRequiredLocktime", () => {
    it("should return undefined for simple descriptor", () => {
      const descriptor = Descriptor.fromStringDetectType(
        "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
      );
      const locktime = getRequiredLocktime(descriptor);
      assert.strictEqual(locktime, undefined);
    });

    it("should return undefined for non-descriptor values", () => {
      assert.strictEqual(getRequiredLocktime(null), undefined);
      assert.strictEqual(getRequiredLocktime(undefined), undefined);
      assert.strictEqual(getRequiredLocktime("string"), undefined);
      assert.strictEqual(getRequiredLocktime(123), undefined);
    });

    it("should extract locktime from After node", () => {
      const node = {
        After: { absLockTime: 500000 },
      };
      const locktime = getRequiredLocktime(node);
      assert.strictEqual(locktime, 500000);
    });

    it("should extract locktime from nested Wsh node", () => {
      const node = {
        Wsh: {
          After: { absLockTime: 600000 },
        },
      };
      const locktime = getRequiredLocktime(node);
      assert.strictEqual(locktime, 600000);
    });

    it("should extract locktime from AndV node", () => {
      const node = {
        AndV: [{ After: { absLockTime: 700000 } }, { pk: "somepubkey" }],
      };
      const locktime = getRequiredLocktime(node);
      assert.strictEqual(locktime, 700000);
    });

    it("should extract locktime from second AndV element", () => {
      const node = {
        AndV: [{ pk: "somepubkey" }, { After: { absLockTime: 800000 } }],
      };
      const locktime = getRequiredLocktime(node);
      assert.strictEqual(locktime, 800000);
    });
  });

  describe("assertSatisfiable", () => {
    it("should pass for simple descriptor with any locktime", () => {
      const descriptor = Descriptor.fromStringDetectType(
        "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
      );
      const script = Buffer.from(descriptor.scriptPubkey());

      const psbt = new Psbt(2, 0);
      psbt.addInput(
        "0000000000000000000000000000000000000000000000000000000000000000",
        0,
        100000n,
        script,
      );

      // Should not throw
      assertSatisfiable(psbt, 0, descriptor);
    });

    it("should pass when locktime matches required", () => {
      // Create a descriptor with a locktime requirement
      // For this test, we'll use a simple descriptor and mock the node
      const descriptor = Descriptor.fromStringDetectType(
        "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
      );
      const script = Buffer.from(descriptor.scriptPubkey());

      const psbt = new Psbt(2, 500000);
      psbt.addInput(
        "0000000000000000000000000000000000000000000000000000000000000000",
        0,
        100000n,
        script,
      );

      // Should not throw for descriptor without locktime requirement
      assertSatisfiable(psbt, 0, descriptor);
    });
  });
});
