import assert from "node:assert";

import * as utxolib from "@bitgo/utxo-lib";

import { fixedScriptWallet } from "../../js/index.js";

const { ChainCode, chainCodes } = fixedScriptWallet;

describe("ChainCode", function () {
  describe("chainCodes array", function () {
    it("matches utxo-lib chainCodes", function () {
      assert.deepStrictEqual([...chainCodes], [...utxolib.bitgo.chainCodes]);
    });

    it("has expected values", function () {
      assert.deepStrictEqual([...chainCodes], [0, 1, 10, 11, 20, 21, 30, 31, 40, 41]);
    });
  });

  describe("ChainCode.is()", function () {
    it("returns true for valid chain codes", function () {
      for (const code of chainCodes) {
        assert.strictEqual(ChainCode.is(code), true, `Expected ${code} to be valid`);
      }
    });

    it("returns false for invalid chain codes", function () {
      const invalidValues = [-1, 2, 3, 5, 9, 12, 15, 19, 22, 25, 29, 32, 35, 39, 42, 50, 100];
      for (const value of invalidValues) {
        assert.strictEqual(ChainCode.is(value), false, `Expected ${value} to be invalid`);
      }
    });

    it("returns false for non-numbers", function () {
      const nonNumbers = [null, undefined, "0", "20", {}, [], true, false];
      for (const value of nonNumbers) {
        assert.strictEqual(
          ChainCode.is(value),
          false,
          `Expected ${JSON.stringify(value)} to be invalid`,
        );
      }
    });
  });

  describe("ChainCode.scope()", function () {
    it("returns correct scope for all chain codes", function () {
      const expectedScopes: Array<[number, "external" | "internal"]> = [
        [0, "external"],
        [1, "internal"],
        [10, "external"],
        [11, "internal"],
        [20, "external"],
        [21, "internal"],
        [30, "external"],
        [31, "internal"],
        [40, "external"],
        [41, "internal"],
      ];

      for (const [code, expectedScope] of expectedScopes) {
        if (!ChainCode.is(code)) throw new Error(`Invalid chain code: ${code}`);
        assert.strictEqual(
          ChainCode.scope(code),
          expectedScope,
          `Expected scope for ${code} to be ${expectedScope}`,
        );
      }
    });

    it("matches utxo-lib isExternalChainCode/isInternalChainCode", function () {
      for (const code of chainCodes) {
        const wasmScope = ChainCode.scope(code);
        const utxolibIsExternal = utxolib.bitgo.isExternalChainCode(code);
        const utxolibIsInternal = utxolib.bitgo.isInternalChainCode(code);

        if (wasmScope === "external") {
          assert.strictEqual(
            utxolibIsExternal,
            true,
            `Chain ${code}: expected utxolib to report external`,
          );
          assert.strictEqual(
            utxolibIsInternal,
            false,
            `Chain ${code}: expected utxolib to not report internal`,
          );
        } else {
          assert.strictEqual(
            utxolibIsExternal,
            false,
            `Chain ${code}: expected utxolib to not report external`,
          );
          assert.strictEqual(
            utxolibIsInternal,
            true,
            `Chain ${code}: expected utxolib to report internal`,
          );
        }
      }
    });
  });

  describe("ChainCode.scriptType()", function () {
    it("returns correct script type for all chain codes", function () {
      const expectedTypes: Array<[number, string]> = [
        [0, "p2sh"],
        [1, "p2sh"],
        [10, "p2shP2wsh"],
        [11, "p2shP2wsh"],
        [20, "p2wsh"],
        [21, "p2wsh"],
        [30, "p2trLegacy"],
        [31, "p2trLegacy"],
        [40, "p2trMusig2"],
        [41, "p2trMusig2"],
      ];

      for (const [code, expectedType] of expectedTypes) {
        if (!ChainCode.is(code)) throw new Error(`Invalid chain code: ${code}`);
        assert.strictEqual(
          ChainCode.scriptType(code),
          expectedType,
          `Expected scriptType for ${code} to be ${expectedType}`,
        );
      }
    });

    it("matches utxo-lib scriptTypeForChain", function () {
      for (const code of chainCodes) {
        const wasmType = ChainCode.scriptType(code);
        const utxolibType = utxolib.bitgo.scriptTypeForChain(code);

        // utxo-lib uses "p2tr" while wasm uses "p2trLegacy"
        const normalizedUtxolibType = utxolibType === "p2tr" ? "p2trLegacy" : utxolibType;

        assert.strictEqual(
          wasmType,
          normalizedUtxolibType,
          `Chain ${code}: expected scriptType ${normalizedUtxolibType}, got ${wasmType}`,
        );
      }
    });
  });

  describe("ChainCode.value()", function () {
    it("returns correct chain code for scriptType and scope combinations", function () {
      const testCases: Array<[string, "external" | "internal", number]> = [
        ["p2sh", "external", 0],
        ["p2sh", "internal", 1],
        ["p2shP2wsh", "external", 10],
        ["p2shP2wsh", "internal", 11],
        ["p2wsh", "external", 20],
        ["p2wsh", "internal", 21],
        ["p2trLegacy", "external", 30],
        ["p2trLegacy", "internal", 31],
        ["p2trMusig2", "external", 40],
        ["p2trMusig2", "internal", 41],
      ];

      for (const [scriptType, scope, expectedCode] of testCases) {
        const result = ChainCode.value(scriptType as fixedScriptWallet.OutputScriptType, scope);
        assert.strictEqual(
          result,
          expectedCode,
          `Expected value(${scriptType}, ${scope}) to be ${expectedCode}, got ${result}`,
        );
      }
    });

    it("throws for invalid script type", function () {
      assert.throws(
        () => ChainCode.value("invalid" as fixedScriptWallet.OutputScriptType, "external"),
        /Invalid scriptType/,
      );
    });
  });

  describe("round-trip conversions", function () {
    it("value() -> scope() and scriptType() round-trips correctly", function () {
      const scriptTypes: fixedScriptWallet.OutputScriptType[] = [
        "p2sh",
        "p2shP2wsh",
        "p2wsh",
        "p2trLegacy",
        "p2trMusig2",
      ];
      const scopes: fixedScriptWallet.Scope[] = ["external", "internal"];

      for (const scriptType of scriptTypes) {
        for (const scope of scopes) {
          const code = ChainCode.value(scriptType, scope);
          assert.strictEqual(ChainCode.scriptType(code), scriptType);
          assert.strictEqual(ChainCode.scope(code), scope);
        }
      }

      // legacy alias for p2trLegacy
      assert.strictEqual(ChainCode.value("p2tr", "external"), 30);
      assert.strictEqual(ChainCode.value("p2tr", "internal"), 31);
    });

    it("scriptType() and scope() -> value() round-trips correctly", function () {
      for (const code of chainCodes) {
        const scriptType = ChainCode.scriptType(code);
        const scope = ChainCode.scope(code);
        const roundTripped = ChainCode.value(scriptType, scope);
        assert.strictEqual(roundTripped, code);
      }
    });
  });

  describe("type narrowing with is()", function () {
    it("allows using narrowed value with other ChainCode methods", function () {
      const maybeChain: unknown = 20;

      if (ChainCode.is(maybeChain)) {
        // TypeScript should allow this without error
        const scope = ChainCode.scope(maybeChain);
        const scriptType = ChainCode.scriptType(maybeChain);

        assert.strictEqual(scope, "external");
        assert.strictEqual(scriptType, "p2wsh");
      } else {
        assert.fail("Expected 20 to be a valid ChainCode");
      }
    });
  });
});
