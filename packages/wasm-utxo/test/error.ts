import * as assert from "assert";
import { Descriptor, isWasmUtxoError } from "../js/index.js";

describe("isWasmUtxoError", function () {
  describe("returns false for non-WasmUtxoError values", function () {
    it("plain Error without code", function () {
      assert.strictEqual(isWasmUtxoError(new Error("oops")), false);
    });

    it("null", function () {
      assert.strictEqual(isWasmUtxoError(null), false);
    });

    it("string", function () {
      assert.strictEqual(isWasmUtxoError("error string"), false);
    });

    it("plain object with code but not an Error instance", function () {
      assert.strictEqual(
        isWasmUtxoError({ message: "err", code: "WasmUtxoError.StringError" }),
        false,
      );
    });

    it("Error with non-string code", function () {
      const e = Object.assign(new Error("err"), { code: 42 });
      assert.strictEqual(isWasmUtxoError(e), false);
    });

    it("Error with string code but no wasm brand", function () {
      const e = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      assert.strictEqual(isWasmUtxoError(e), false);
    });
  });

  describe("for a WASM StringError", function () {
    let error: unknown;

    before(function () {
      try {
        // Invalid pk_type triggers WasmUtxoError::new("Invalid descriptor type") → StringError
        Descriptor.fromString("wsh(pk(abc))", "invalid_pk_type");
      } catch (e) {
        error = e;
      }
      assert.ok(error !== undefined, "expected an error to be thrown");
    });

    it("isWasmUtxoError returns true", function () {
      assert.ok(isWasmUtxoError(error));
    });

    it("code is WasmUtxoError.StringError", function () {
      assert.ok(isWasmUtxoError(error));
      assert.strictEqual(error.code, "WasmUtxoError.StringError");
    });

    it("is still an Error instance", function () {
      assert.ok(error instanceof Error);
    });
  });
});
