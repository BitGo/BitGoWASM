import * as assert from "node:assert";

import { Descriptor, Psbt, testutils } from "../js/index.js";

describe("testutils.descriptor", () => {
  describe("getDefaultXPubs", () => {
    it("returns triple of xpub strings", () => {
      const xpubs = dt.getDefaultXPubs();
      assert.strictEqual(xpubs.length, 3);
      for (const xpub of xpubs) {
        assert.ok(xpub.startsWith("xpub"), `expected xpub, got ${xpub.slice(0, 10)}`);
      }
    });

    it("returns deterministic xpubs for same seed", () => {
      assert.deepStrictEqual(dt.getDefaultXPubs("foo"), dt.getDefaultXPubs("foo"));
    });

    it("returns different xpubs for different seeds", () => {
      const a = dt.getDefaultXPubs("a");
      const b = dt.getDefaultXPubs("b");
      assert.notDeepStrictEqual(a, b);
    });
  });

  describe("getUnspendableKey", () => {
    it("returns the BIP-341 NUMS point", () => {
      const key = dt.getUnspendableKey();
      assert.strictEqual(key.length, 64);
      assert.strictEqual(key, "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");
    });
  });

  describe("getDescriptor", () => {
    const templates: dt.DescriptorTemplate[] = [
      "Wsh2Of3",
      "Wsh2Of2",
      "Tr1Of3-NoKeyPath-Tree",
      "Tr1Of3-NoKeyPath-Tree-Plain",
      "Tr2Of3-NoKeyPath",
      "Wsh2Of3CltvDrop",
    ];

    for (const t of templates) {
      it(`creates valid descriptor for ${t}`, () => {
        const d = dt.getDescriptor(t);
        assert.ok(d instanceof Descriptor);
        const str = d.toString();
        assert.ok(str.length > 0, "descriptor string should not be empty");
      });
    }
  });

  describe("getDescriptorMap", () => {
    it("returns map with external and internal keys", () => {
      const map = dt.getDescriptorMap("Wsh2Of3");
      assert.ok(map.has("external"));
      assert.ok(map.has("internal"));
      assert.ok(map.get("external") instanceof Descriptor);
      assert.ok(map.get("internal") instanceof Descriptor);
      assert.notStrictEqual(map.get("external")?.toString(), map.get("internal")?.toString());
    });
  });

  describe("getPsbtParams", () => {
    it("returns locktime for Wsh2Of3CltvDrop", () => {
      assert.deepStrictEqual(dt.getPsbtParams("Wsh2Of3CltvDrop"), { locktime: 1 });
    });

    it("returns empty for Wsh2Of3", () => {
      assert.deepStrictEqual(dt.getPsbtParams("Wsh2Of3"), {});
    });
  });
});

describe("testutils.descriptor.mockPsbt", () => {
  describe("mockPsbtDefault", () => {
    it("creates a valid Psbt", () => {
      const psbt = dt.mockPsbtDefault();
      assert.ok(psbt instanceof Psbt);
      assert.strictEqual(psbt.inputCount(), 2);
      assert.strictEqual(psbt.outputCount(), 2);
    });
  });

  describe("mockPsbtDefaultWithDescriptorTemplate", () => {
    for (const t of ["Wsh2Of3", "Wsh2Of2", "Wsh2Of3CltvDrop"] as dt.DescriptorTemplate[]) {
      it(`creates valid Psbt for ${t}`, () => {
        const psbt = dt.mockPsbtDefaultWithDescriptorTemplate(t);
        assert.ok(psbt instanceof Psbt);
        assert.strictEqual(psbt.inputCount(), 2);
        assert.strictEqual(psbt.outputCount(), 2);
      });
    }
  });
});

describe("testutils.fixtures", () => {
  describe("jsonNormalize", () => {
    it("round-trips a simple object", () => {
      const obj = { a: 1, b: "hello", c: [1, 2, 3] };
      assert.deepStrictEqual(testutils.jsonNormalize(obj), obj);
    });

    it("strips undefined values", () => {
      const obj = { a: 1, b: undefined };
      assert.deepStrictEqual(testutils.jsonNormalize(obj), { a: 1 });
    });
  });

  describe("toPlainObject", () => {
    it("converts bigint to string", () => {
      assert.strictEqual(testutils.toPlainObject(BigInt(42)), "42");
    });

    it("converts Uint8Array to hex", () => {
      assert.strictEqual(
        testutils.toPlainObject(new Uint8Array([0xde, 0xad, 0xbe, 0xef])),
        "deadbeef",
      );
    });

    it("converts nested objects", () => {
      const obj = { a: BigInt(1), b: { c: new Uint8Array([0xff]) } };
      assert.deepStrictEqual(testutils.toPlainObject(obj), {
        a: "1",
        b: { c: "ff" },
      });
    });

    it("converts functions to undefined", () => {
      const obj = { a: 1, fn: () => {} };
      assert.deepStrictEqual(testutils.toPlainObject(obj), { a: 1, fn: undefined });
    });

    it("supports ignorePaths", () => {
      const obj = { a: 1, secret: "hidden", b: 2 };
      assert.deepStrictEqual(testutils.toPlainObject(obj, { ignorePaths: ["secret"] }), {
        a: 1,
        b: 2,
      });
    });

    it("supports apply transform", () => {
      const obj = { a: 1, b: 2 };
      assert.deepStrictEqual(
        testutils.toPlainObject(obj, {
          apply: (v) => (typeof v === "number" ? v * 10 : undefined),
        }),
        { a: 10, b: 20 },
      );
    });
  });
});
