import * as assert from "assert";
import { PatternMatcher, Pattern } from "../../js/descriptorWallet/parse/PatternMatcher.js";

describe("descriptorWallet/PatternMatcher", () => {
  const matcher = new PatternMatcher();

  describe("match", () => {
    it("should match exact strings", () => {
      const result = matcher.match("hello", "hello");
      assert.deepStrictEqual(result, {});
    });

    it("should not match different strings", () => {
      const result = matcher.match("hello", "world");
      assert.strictEqual(result, null);
    });

    it("should match exact numbers", () => {
      const result = matcher.match(42, 42);
      assert.deepStrictEqual(result, {});
    });

    it("should not match different numbers", () => {
      const result = matcher.match(42, 43);
      assert.strictEqual(result, null);
    });

    it("should capture variables", () => {
      const pattern: Pattern = { $var: "x" };
      const result = matcher.match("hello", pattern);
      assert.deepStrictEqual(result, { x: "hello" });
    });

    it("should capture complex values in variables", () => {
      const pattern: Pattern = { $var: "x" };
      const node = { foo: "bar", num: 42 };
      const result = matcher.match(node, pattern);
      assert.deepStrictEqual(result, { x: node });
    });

    it("should match arrays", () => {
      const node = [1, 2, 3];
      const pattern: Pattern = [1, 2, 3];
      const result = matcher.match(node, pattern);
      assert.deepStrictEqual(result, {});
    });

    it("should not match arrays of different lengths", () => {
      const node = [1, 2, 3];
      const pattern: Pattern = [1, 2];
      const result = matcher.match(node, pattern);
      assert.strictEqual(result, null);
    });

    it("should match arrays with variables", () => {
      const node = [1, 2, 3];
      const pattern: Pattern = [{ $var: "first" }, 2, { $var: "last" }];
      const result = matcher.match(node, pattern);
      assert.deepStrictEqual(result, { first: 1, last: 3 });
    });

    it("should match objects", () => {
      const node = { a: 1, b: 2 };
      const pattern: Pattern = { a: 1, b: 2 };
      const result = matcher.match(node, pattern);
      assert.deepStrictEqual(result, {});
    });

    it("should not match objects with different keys", () => {
      const node = { a: 1, b: 2 };
      const pattern: Pattern = { a: 1, c: 2 };
      const result = matcher.match(node, pattern);
      assert.strictEqual(result, null);
    });

    it("should match objects with variables", () => {
      const node = { a: 1, b: "hello" };
      const pattern: Pattern = { a: { $var: "num" }, b: { $var: "str" } };
      const result = matcher.match(node, pattern);
      assert.deepStrictEqual(result, { num: 1, str: "hello" });
    });

    it("should match nested structures", () => {
      const node = {
        outer: {
          inner: [1, 2, 3],
          value: "test",
        },
      };
      const pattern: Pattern = {
        outer: {
          inner: [{ $var: "first" }, 2, { $var: "last" }],
          value: { $var: "val" },
        },
      };
      const result = matcher.match(node, pattern);
      assert.deepStrictEqual(result, { first: 1, last: 3, val: "test" });
    });

    it("should require consistent variable values", () => {
      const node = { a: 1, b: 1 };
      const pattern: Pattern = { a: { $var: "x" }, b: { $var: "x" } };
      const result = matcher.match(node, pattern);
      assert.deepStrictEqual(result, { x: 1 });
    });

    it("should fail when variable values are inconsistent", () => {
      const node = { a: 1, b: 2 };
      const pattern: Pattern = { a: { $var: "x" }, b: { $var: "x" } };
      const result = matcher.match(node, pattern);
      assert.strictEqual(result, null);
    });

    it("should match descriptor-like structures", () => {
      // Example: matching a wsh(multi(...)) descriptor node
      const node = {
        Wsh: {
          Ms: {
            multi: [2, "key1", "key2", "key3"],
          },
        },
      };
      const pattern: Pattern = {
        Wsh: {
          Ms: {
            multi: { $var: "multiArgs" },
          },
        },
      };
      const result = matcher.match(node, pattern);
      assert.deepStrictEqual(result, { multiArgs: [2, "key1", "key2", "key3"] });
    });
  });
});
