/**
 * Tests comparing wasm-utxo Dimensions against @bitgo/unspents Dimensions.
 *
 * ## Key Differences
 *
 * ### ECDSA Signature Size
 *
 * The main difference between the two implementations is how they handle ECDSA signature variance:
 *
 * - **@bitgo/unspents**: Uses a fixed 72-byte signature size for all ECDSA inputs.
 *   This is the most common size, but actual signatures can range from 71-73 bytes.
 *
 * - **wasm-utxo**: Tracks min/max weight bounds using:
 *   - min: 71-byte signatures (low-R, low-S)
 *   - max: 73-byte signatures (high-R, high-S)
 *
 * This means for ECDSA-based script types (p2sh, p2shP2wsh, p2wsh, p2shP2pk),
 * @bitgo/unspents returns a single value that falls between wasm-utxo's min and max.
 *
 * ### Discrepancy for p2sh
 *
 * For p2sh, the vSize range is larger than expected due to varint encoding:
 * - When scriptSig crosses 253 bytes, the varint length increases from 1 to 3 bytes
 * - With 71-byte sigs: scriptSig = 252 bytes (varint = 1 byte)
 * - With 73-byte sigs: scriptSig = 256 bytes (varint = 3 bytes)
 *
 * Observed values:
 * - wasm-utxo min (71-byte sigs): 293 vSize
 * - @bitgo/unspents (72-byte sigs, 3-byte varint): 298 vSize
 * - wasm-utxo max (73-byte sigs): 299 vSize
 *
 * Note: @bitgo/unspents uses OP_PUSHDATA2 (3 bytes) for the redeemScript push regardless
 * of actual size, while wasm-utxo uses the minimal encoding. This is why @bitgo/unspents
 * is close to wasm-utxo's max rather than in the middle.
 *
 * For segwit inputs (p2shP2wsh, p2wsh), the @bitgo/unspents value equals wasm-utxo's
 * max because witness data uses ceiling division differently than non-witness data.
 *
 * For Schnorr-based script types (p2tr, p2trMusig2), signatures are always 64 bytes,
 * so both implementations produce identical results.
 */

import assert from "node:assert";
import { Dimensions as WasmDimensions } from "../js/fixedScriptWallet/Dimensions.js";
import { Dimensions as UnspentsDimensions, VirtualSizes } from "@bitgo/unspents";

describe("Dimensions: wasm-utxo vs @bitgo/unspents compatibility", function () {
  describe("input vSize comparison", function () {
    /**
     * p2sh DISCREPANCY DOCUMENTATION:
     *
     * @bitgo/unspents uses a fixed 72-byte ECDSA signature size.
     * wasm-utxo tracks min (71) / max (73) bounds.
     *
     * For p2sh with 2-of-3 multisig (2 signatures):
     * - Signatures vary: 71, 72, or 73 bytes
     * - Additional variance from varint encoding (scriptSig crosses 253-byte boundary)
     *
     * Observed values:
     * - wasm-utxo min (71-byte sigs, 1-byte varint): 293 vSize
     * - @bitgo/unspents (72-byte sigs, 3-byte varint): 298 vSize
     * - wasm-utxo max (73-byte sigs, 3-byte varint): 299 vSize
     *
     * @bitgo/unspents uses OP_PUSHDATA2 (3 bytes) for the redeemScript push regardless
     * of actual scriptSig size, which is why it's close to wasm-utxo's max.
     */
    it("p2sh: @bitgo/unspents value is between wasm-utxo min and max", function () {
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2sh" });
      const unspentsDim = UnspentsDimensions.SingleInput.p2sh;

      const wasmMin = wasmDim.getInputVSize("min");
      const wasmMax = wasmDim.getInputVSize("max");
      const unspentsSize = unspentsDim.getInputsVSize();

      // Verify that wasm-utxo has variance (min < max)
      assert.ok(
        wasmMin < wasmMax,
        `p2sh should have ECDSA variance: min=${wasmMin}, max=${wasmMax}`,
      );

      // @bitgo/unspents (72-byte sig) should be between wasm-utxo min (71-byte) and max (73-byte)
      assert.ok(
        unspentsSize >= wasmMin && unspentsSize <= wasmMax,
        `@bitgo/unspents ${unspentsSize} should be between wasm-utxo min=${wasmMin} and max=${wasmMax}`,
      );

      // Document the specific values
      assert.strictEqual(wasmMin, 293, "p2sh wasm-utxo min vSize");
      assert.strictEqual(wasmMax, 299, "p2sh wasm-utxo max vSize");
      // Note: @bitgo/unspents uses 72-byte sigs but also uses 3-byte varint for scriptSig
      // (OP_PUSHDATA2 comment in inputWeights.ts), resulting in a higher vSize
      assert.strictEqual(unspentsSize, 298, "@bitgo/unspents p2sh vSize");
    });

    /**
     * p2shP2wsh DISCREPANCY:
     *
     * For segwit inputs, @bitgo/unspents equals wasm-utxo's max.
     * This is due to ceiling division in vSize calculation affecting segwit witness differently.
     */
    it("p2shP2wsh: @bitgo/unspents equals wasm-utxo max", function () {
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2shP2wsh" });
      const unspentsDim = UnspentsDimensions.SingleInput.p2shP2wsh;

      const wasmMin = wasmDim.getInputVSize("min");
      const wasmMax = wasmDim.getInputVSize("max");
      const unspentsSize = unspentsDim.getInputsVSize();

      // Verify that wasm-utxo has variance (min < max)
      assert.ok(
        wasmMin < wasmMax,
        `p2shP2wsh should have ECDSA variance: min=${wasmMin}, max=${wasmMax}`,
      );

      // Document: @bitgo/unspents equals wasm-utxo max for segwit inputs
      assert.strictEqual(
        unspentsSize,
        wasmMax,
        `p2shP2wsh: @bitgo/unspents ${unspentsSize} equals wasm-utxo max ${wasmMax}`,
      );
    });

    /**
     * p2wsh DISCREPANCY:
     *
     * Same as p2shP2wsh - @bitgo/unspents equals wasm-utxo's max for segwit.
     */
    it("p2wsh: @bitgo/unspents equals wasm-utxo max", function () {
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2wsh" });
      const unspentsDim = UnspentsDimensions.SingleInput.p2wsh;

      const wasmMin = wasmDim.getInputVSize("min");
      const wasmMax = wasmDim.getInputVSize("max");
      const unspentsSize = unspentsDim.getInputsVSize();

      // Verify that wasm-utxo has variance (min < max)
      assert.ok(
        wasmMin < wasmMax,
        `p2wsh should have ECDSA variance: min=${wasmMin}, max=${wasmMax}`,
      );

      // Document: @bitgo/unspents equals wasm-utxo max for segwit inputs
      assert.strictEqual(
        unspentsSize,
        wasmMax,
        `p2wsh: @bitgo/unspents ${unspentsSize} equals wasm-utxo max ${wasmMax}`,
      );
    });

    /**
     * p2shP2pk DISCREPANCY:
     *
     * Same pattern - @bitgo/unspents equals wasm-utxo's max.
     */
    it("p2shP2pk: @bitgo/unspents equals wasm-utxo max", function () {
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2shP2pk" });
      const unspentsDim = UnspentsDimensions.SingleInput.p2shP2pk;

      const wasmMin = wasmDim.getInputVSize("min");
      const wasmMax = wasmDim.getInputVSize("max");
      const unspentsSize = unspentsDim.getInputsVSize();

      // Verify that wasm-utxo has variance (min < max)
      assert.ok(
        wasmMin < wasmMax,
        `p2shP2pk should have ECDSA variance: min=${wasmMin}, max=${wasmMax}`,
      );

      // Document: @bitgo/unspents equals wasm-utxo max
      assert.strictEqual(
        unspentsSize,
        wasmMax,
        `p2shP2pk: @bitgo/unspents ${unspentsSize} equals wasm-utxo max ${wasmMax}`,
      );
    });

    /**
     * Schnorr-based inputs have fixed 64-byte signatures, so there's no variance.
     * Both implementations should produce identical results.
     */
    it("p2tr keypath: both implementations match exactly (Schnorr, no variance)", function () {
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2trMusig2KeyPath" });
      const unspentsDim = UnspentsDimensions.SingleInput.p2trKeypath;

      const wasmMin = wasmDim.getInputVSize("min");
      const wasmMax = wasmDim.getInputVSize("max");
      const unspentsSize = unspentsDim.getInputsVSize();

      // Schnorr has no variance
      assert.strictEqual(wasmMin, wasmMax, "Schnorr inputs should have no variance");

      // Both should match exactly
      assert.strictEqual(wasmMin, unspentsSize, "p2tr keypath vSize should match");
    });

    it("p2tr script path level 1: both implementations match exactly (Schnorr, no variance)", function () {
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2trLegacy" });
      const unspentsDim = UnspentsDimensions.SingleInput.p2trScriptPathLevel1;

      const wasmMin = wasmDim.getInputVSize("min");
      const wasmMax = wasmDim.getInputVSize("max");
      const unspentsSize = unspentsDim.getInputsVSize();

      // Schnorr has no variance
      assert.strictEqual(wasmMin, wasmMax, "Schnorr inputs should have no variance");

      // Both should match exactly
      assert.strictEqual(wasmMin, unspentsSize, "p2tr script path level 1 vSize should match");
    });

    it("p2tr script path level 2: both implementations match exactly (Schnorr, no variance)", function () {
      const wasmDim = WasmDimensions.fromInput({
        chain: 30,
        signPath: { signer: "user", cosigner: "backup" },
      });
      const unspentsDim = UnspentsDimensions.SingleInput.p2trScriptPathLevel2;

      const wasmMin = wasmDim.getInputVSize("min");
      const wasmMax = wasmDim.getInputVSize("max");
      const unspentsSize = unspentsDim.getInputsVSize();

      // Schnorr has no variance
      assert.strictEqual(wasmMin, wasmMax, "Schnorr inputs should have no variance");

      // Both should match exactly
      assert.strictEqual(wasmMin, unspentsSize, "p2tr script path level 2 vSize should match");
    });
  });

  describe("output vSize comparison", function () {
    it("p2sh output: both implementations match exactly", function () {
      const wasmDim = WasmDimensions.fromOutput({ scriptType: "p2sh" });
      const unspentsSize = VirtualSizes.txP2shOutputSize;

      assert.strictEqual(wasmDim.getOutputVSize(), unspentsSize, "p2sh output vSize should match");
    });

    it("p2wsh output: both implementations match exactly", function () {
      const wasmDim = WasmDimensions.fromOutput({ scriptType: "p2wsh" });
      const unspentsSize = VirtualSizes.txP2wshOutputSize;

      assert.strictEqual(wasmDim.getOutputVSize(), unspentsSize, "p2wsh output vSize should match");
    });

    it("p2tr output: both implementations match exactly", function () {
      const wasmDim = WasmDimensions.fromOutput({ scriptType: "p2trLegacy" });
      const unspentsSize = VirtualSizes.txP2trOutputSize;

      assert.strictEqual(wasmDim.getOutputVSize(), unspentsSize, "p2tr output vSize should match");
    });
  });

  describe("overhead vSize comparison", function () {
    it("non-segwit overhead: both implementations match", function () {
      // Non-segwit overhead is 10 bytes
      assert.strictEqual(VirtualSizes.txOverheadSize, 10);

      // wasm-utxo computes overhead as part of total weight
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2sh" });
      const totalVSize = wasmDim.getVSize("max");
      const inputVSize = wasmDim.getInputVSize("max");
      const wasmOverhead = totalVSize - inputVSize;

      assert.strictEqual(wasmOverhead, 10, "non-segwit overhead should be 10");
    });

    it("segwit overhead: both implementations match", function () {
      // Segwit overhead is 11 vSize
      assert.strictEqual(VirtualSizes.txSegOverheadVSize, 11);

      // wasm-utxo computes overhead as part of total weight
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2wsh" });
      const totalVSize = wasmDim.getVSize("max");
      const inputVSize = wasmDim.getInputVSize("max");
      const wasmOverhead = totalVSize - inputVSize;

      assert.strictEqual(wasmOverhead, 11, "segwit overhead should be 11");
    });
  });

  describe("combined transaction vSize comparison", function () {
    it("simple 1-input 1-output p2wsh transaction", function () {
      // wasm-utxo
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2wsh" }).plus(
        WasmDimensions.fromOutput({ scriptType: "p2wsh" }),
      );

      // @bitgo/unspents
      const unspentsDim = UnspentsDimensions.SingleInput.p2wsh.plus(
        UnspentsDimensions.SingleOutput.p2wsh,
      );

      const unspentsVSize = unspentsDim.getVSize();
      const wasmMin = wasmDim.getVSize("min");
      const wasmMax = wasmDim.getVSize("max");

      // @bitgo/unspents should be between or equal to wasm-utxo bounds
      assert.ok(
        wasmMin <= unspentsVSize && unspentsVSize <= wasmMax,
        `@bitgo/unspents ${unspentsVSize} should be between wasm-utxo min=${wasmMin} and max=${wasmMax}`,
      );
    });

    it("simple 1-input 1-output p2tr transaction (exact match)", function () {
      // wasm-utxo
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2trMusig2KeyPath" }).plus(
        WasmDimensions.fromOutput({ scriptType: "p2trMusig2" }),
      );

      // @bitgo/unspents
      const unspentsDim = UnspentsDimensions.SingleInput.p2trKeypath.plus(
        UnspentsDimensions.SingleOutput.p2tr,
      );

      // Should match exactly since Schnorr has no variance
      assert.strictEqual(wasmDim.getVSize("min"), unspentsDim.getVSize());
      assert.strictEqual(wasmDim.getVSize("max"), unspentsDim.getVSize());
    });

    it("mixed input transaction", function () {
      // Transaction with p2sh, p2wsh, and p2tr inputs
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2sh" })
        .plus(WasmDimensions.fromInput({ scriptType: "p2wsh" }))
        .plus(WasmDimensions.fromInput({ scriptType: "p2trMusig2KeyPath" }))
        .plus(WasmDimensions.fromOutput({ scriptType: "p2wsh" }));

      const unspentsDim = UnspentsDimensions.SingleInput.p2sh
        .plus(UnspentsDimensions.SingleInput.p2wsh)
        .plus(UnspentsDimensions.SingleInput.p2trKeypath)
        .plus(UnspentsDimensions.SingleOutput.p2wsh);

      // @bitgo/unspents should fall between wasm-utxo min and max
      const unspentsVSize = unspentsDim.getVSize();
      const wasmMin = wasmDim.getVSize("min");
      const wasmMax = wasmDim.getVSize("max");

      assert.ok(
        unspentsVSize >= wasmMin && unspentsVSize <= wasmMax,
        `@bitgo/unspents ${unspentsVSize} should be between wasm-utxo min=${wasmMin} and max=${wasmMax}`,
      );
    });
  });

  describe("input weight comparison (raw values)", function () {
    /**
     * Document the raw input weights for reference.
     * These tests verify the underlying weight calculations.
     */
    it("documents p2sh input weight calculation", function () {
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2sh" });

      // wasm-utxo computes weight as: 4 * base_size (for non-segwit)
      // For p2sh 2-of-3 multisig:
      // scriptSig = OP_0 + sig1 + sig2 + redeemScript
      //           = 1 + (1+sig) + (1+sig) + (2+105)
      //
      // With 71-byte sigs: 1 + 72 + 72 + 107 = 252 bytes
      // With 73-byte sigs: 1 + 74 + 74 + 107 = 256 bytes
      //
      // weight = 4 * (40 + varint + scriptSig)
      // min: 4 * (40 + 2 + 252) = 4 * 294 = 1176 (but actual is 1172)
      // max: 4 * (40 + 2 + 256) = 4 * 298 = 1192 (but actual is 1188)

      // Log actual values for documentation
      const minWeight = wasmDim.getInputWeight("min");
      const maxWeight = wasmDim.getInputWeight("max");

      // Verify ECDSA variance exists
      assert.ok(
        minWeight < maxWeight,
        `p2sh should have ECDSA variance: ${minWeight} < ${maxWeight}`,
      );

      // Document actual values
      // With 2 signatures and 2 byte variance each (71 vs 73), total variance = 2 * 2 * 4 = 16 weight units
      // But actual variance is 24 due to varint length change when scriptSig crosses 253 bytes
      assert.strictEqual(
        maxWeight - minWeight,
        24,
        "p2sh weight variance (includes varint boundary)",
      );
    });

    it("documents p2wsh input weight calculation", function () {
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2wsh" });

      // p2wsh has empty scriptSig, witness contains: OP_0 + sig1 + sig2 + witnessScript
      // Weight formula: 3 * base + (base + witness)
      // where base = 40 + 1 (empty scriptSig)

      const minWeight = wasmDim.getInputWeight("min");
      const maxWeight = wasmDim.getInputWeight("max");

      // Verify ECDSA variance exists
      assert.ok(
        minWeight < maxWeight,
        `p2wsh should have ECDSA variance: ${minWeight} < ${maxWeight}`,
      );

      // Document weight variance
      assert.strictEqual(maxWeight - minWeight, 4, "p2wsh weight variance should be 4");
    });

    it("documents p2tr keypath input weight calculation", function () {
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2trMusig2KeyPath" });

      // p2tr keypath has empty scriptSig, witness contains single 64-byte Schnorr signature
      // base_size = 40 + 1 = 41
      // witness = 1 (count) + 1 (length) + 64 (sig) = 66
      // weight = 3*41 + (41 + 66) = 123 + 107 = 230

      assert.strictEqual(wasmDim.getInputWeight("min"), 230, "p2tr keypath weight");
      assert.strictEqual(wasmDim.getInputWeight("max"), 230, "p2tr keypath weight (no variance)");

      // vSize = ceil(230 / 4) = 58
      assert.strictEqual(wasmDim.getInputVSize("min"), 58, "p2tr keypath vSize");
    });
  });

  describe("utxolibCompat option", function () {
    /**
     * When utxolibCompat: true is passed, the "max" values should match @bitgo/unspents exactly.
     * This is achieved by using 72-byte signatures instead of 73-byte for the max calculation.
     */
    it("p2sh with utxolibCompat: max matches @bitgo/unspents exactly", function () {
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2sh" }, { utxolibCompat: true });
      const unspentsDim = UnspentsDimensions.SingleInput.p2sh;

      const wasmMax = wasmDim.getInputVSize("max");
      const unspentsSize = unspentsDim.getInputsVSize();

      // With utxolibCompat, max should match @bitgo/unspents exactly
      assert.strictEqual(
        wasmMax,
        unspentsSize,
        `p2sh with utxolibCompat: max ${wasmMax} should equal @bitgo/unspents ${unspentsSize}`,
      );
    });

    it("p2shP2wsh with utxolibCompat: max matches @bitgo/unspents exactly", function () {
      const wasmDim = WasmDimensions.fromInput(
        { scriptType: "p2shP2wsh" },
        { utxolibCompat: true },
      );
      const unspentsDim = UnspentsDimensions.SingleInput.p2shP2wsh;

      const wasmMax = wasmDim.getInputVSize("max");
      const unspentsSize = unspentsDim.getInputsVSize();

      assert.strictEqual(
        wasmMax,
        unspentsSize,
        `p2shP2wsh with utxolibCompat: max ${wasmMax} should equal @bitgo/unspents ${unspentsSize}`,
      );
    });

    it("p2wsh with utxolibCompat: max matches @bitgo/unspents exactly", function () {
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2wsh" }, { utxolibCompat: true });
      const unspentsDim = UnspentsDimensions.SingleInput.p2wsh;

      const wasmMax = wasmDim.getInputVSize("max");
      const unspentsSize = unspentsDim.getInputsVSize();

      assert.strictEqual(
        wasmMax,
        unspentsSize,
        `p2wsh with utxolibCompat: max ${wasmMax} should equal @bitgo/unspents ${unspentsSize}`,
      );
    });

    it("p2shP2pk with utxolibCompat: max matches @bitgo/unspents exactly", function () {
      const wasmDim = WasmDimensions.fromInput({ scriptType: "p2shP2pk" }, { utxolibCompat: true });
      const unspentsDim = UnspentsDimensions.SingleInput.p2shP2pk;

      const wasmMax = wasmDim.getInputVSize("max");
      const unspentsSize = unspentsDim.getInputsVSize();

      assert.strictEqual(
        wasmMax,
        unspentsSize,
        `p2shP2pk with utxolibCompat: max ${wasmMax} should equal @bitgo/unspents ${unspentsSize}`,
      );
    });

    it("Schnorr inputs: utxolibCompat has no effect (already matches)", function () {
      // Schnorr signatures are always 64 bytes, so utxolibCompat has no effect
      const wasmDimDefault = WasmDimensions.fromInput({ scriptType: "p2trMusig2KeyPath" });
      const wasmDimCompat = WasmDimensions.fromInput(
        { scriptType: "p2trMusig2KeyPath" },
        { utxolibCompat: true },
      );
      const unspentsDim = UnspentsDimensions.SingleInput.p2trKeypath;

      assert.strictEqual(wasmDimDefault.getInputVSize("max"), wasmDimCompat.getInputVSize("max"));
      assert.strictEqual(wasmDimCompat.getInputVSize("max"), unspentsDim.getInputsVSize());
    });

    it("utxolibCompat with chain code parameter", function () {
      // Test that utxolibCompat works with chain-based input specification
      const wasmDim = WasmDimensions.fromInput({ chain: 10 }, { utxolibCompat: true }); // p2shP2wsh
      const unspentsDim = UnspentsDimensions.SingleInput.p2shP2wsh;

      assert.strictEqual(
        wasmDim.getInputVSize("max"),
        unspentsDim.getInputsVSize(),
        "chain-based p2shP2wsh with utxolibCompat should match @bitgo/unspents",
      );
    });

    it("all ECDSA input types: utxolibCompat max matches @bitgo/unspents", function () {
      const inputTypes: Array<{
        name: string;
        wasmScriptType: Parameters<typeof WasmDimensions.fromInput>[0];
        unspentsDim: typeof UnspentsDimensions.SingleInput.p2sh;
      }> = [
        {
          name: "p2sh",
          wasmScriptType: { scriptType: "p2sh" },
          unspentsDim: UnspentsDimensions.SingleInput.p2sh,
        },
        {
          name: "p2shP2wsh",
          wasmScriptType: { scriptType: "p2shP2wsh" },
          unspentsDim: UnspentsDimensions.SingleInput.p2shP2wsh,
        },
        {
          name: "p2wsh",
          wasmScriptType: { scriptType: "p2wsh" },
          unspentsDim: UnspentsDimensions.SingleInput.p2wsh,
        },
        {
          name: "p2shP2pk",
          wasmScriptType: { scriptType: "p2shP2pk" },
          unspentsDim: UnspentsDimensions.SingleInput.p2shP2pk,
        },
      ];

      for (const { name, wasmScriptType, unspentsDim } of inputTypes) {
        const wasmDim = WasmDimensions.fromInput(wasmScriptType, { utxolibCompat: true });
        const wasmMax = wasmDim.getInputVSize("max");
        const unspentsSize = unspentsDim.getInputsVSize();

        assert.strictEqual(
          wasmMax,
          unspentsSize,
          `${name} with utxolibCompat: max ${wasmMax} should equal @bitgo/unspents ${unspentsSize}`,
        );
      }
    });
  });

  describe("summary: wasm-utxo bounds contain @bitgo/unspents values", function () {
    /**
     * This test verifies the key property: wasm-utxo's [min, max] range
     * always contains @bitgo/unspents' single estimate.
     *
     * This is important for fee estimation:
     * - Use wasm-utxo min for optimistic estimates
     * - Use wasm-utxo max for conservative estimates
     * - @bitgo/unspents gives a reasonable middle-ground
     */
    it("all input types: @bitgo/unspents is within wasm-utxo bounds", function () {
      const inputTypes: Array<{
        name: string;
        wasmScriptType: Parameters<typeof WasmDimensions.fromInput>[0];
        unspentsDim: typeof UnspentsDimensions.SingleInput.p2sh;
      }> = [
        {
          name: "p2sh",
          wasmScriptType: { scriptType: "p2sh" },
          unspentsDim: UnspentsDimensions.SingleInput.p2sh,
        },
        {
          name: "p2shP2wsh",
          wasmScriptType: { scriptType: "p2shP2wsh" },
          unspentsDim: UnspentsDimensions.SingleInput.p2shP2wsh,
        },
        {
          name: "p2wsh",
          wasmScriptType: { scriptType: "p2wsh" },
          unspentsDim: UnspentsDimensions.SingleInput.p2wsh,
        },
        {
          name: "p2shP2pk",
          wasmScriptType: { scriptType: "p2shP2pk" },
          unspentsDim: UnspentsDimensions.SingleInput.p2shP2pk,
        },
        {
          name: "p2trKeypath",
          wasmScriptType: { scriptType: "p2trMusig2KeyPath" },
          unspentsDim: UnspentsDimensions.SingleInput.p2trKeypath,
        },
        {
          name: "p2trScriptPathL1",
          wasmScriptType: { scriptType: "p2trLegacy" },
          unspentsDim: UnspentsDimensions.SingleInput.p2trScriptPathLevel1,
        },
        {
          name: "p2trScriptPathL2",
          wasmScriptType: { chain: 30, signPath: { signer: "user", cosigner: "backup" } },
          unspentsDim: UnspentsDimensions.SingleInput.p2trScriptPathLevel2,
        },
      ];

      for (const { name, wasmScriptType, unspentsDim } of inputTypes) {
        const wasmDim = WasmDimensions.fromInput(wasmScriptType);
        const wasmMin = wasmDim.getInputVSize("min");
        const wasmMax = wasmDim.getInputVSize("max");
        const unspentsSize = unspentsDim.getInputsVSize();

        assert.ok(
          wasmMin <= unspentsSize && unspentsSize <= wasmMax,
          `${name}: @bitgo/unspents ${unspentsSize} should be within wasm-utxo bounds [${wasmMin}, ${wasmMax}]`,
        );
      }
    });
  });
});
