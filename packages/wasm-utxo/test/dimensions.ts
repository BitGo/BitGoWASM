import assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";
import { Dimensions, fixedScriptWallet } from "../js/index.js";
import { Transaction } from "../js/transaction.js";
import {
  loadPsbtFixture,
  getPsbtBuffer,
  type Fixture,
  type Output,
} from "./fixedScript/fixtureUtil.js";
import { getFixtureNetworks } from "./fixedScript/networkSupport.util.js";
import type { InputScriptType } from "../js/fixedScriptWallet/BitGoPsbt.js";

/**
 * Map fixture psbtInput type to InputScriptType
 */
function fixtureTypeToInputScriptType(fixtureType: string): InputScriptType | null {
  switch (fixtureType) {
    case "p2sh":
      return "p2sh";
    case "p2shP2wsh":
      return "p2shP2wsh";
    case "p2wsh":
      return "p2wsh";
    case "p2tr":
      return "p2trLegacy";
    case "p2trMusig2":
      // Script path spend (2-of-2 Schnorr in tapleaf)
      return "p2trMusig2ScriptPath";
    case "taprootKeyPathSpend":
      return "p2trMusig2KeyPath";
    case "p2shP2pk":
      return "p2shP2pk";
    default:
      return null;
  }
}

/**
 * Build Dimensions from fixture outputs
 */
function dimensionsFromOutputs(outputs: Output[]): Dimensions {
  let dim = Dimensions.empty();
  for (const output of outputs) {
    const script = Buffer.from(output.script, "hex");
    dim = dim.plus(Dimensions.fromOutput(script));
  }
  return dim;
}

describe("Dimensions", function () {
  describe("empty", function () {
    it("should return zero vSize for empty dimensions", function () {
      const dim = Dimensions.empty();
      assert.strictEqual(dim.getVSize(), 0);
      assert.strictEqual(dim.getVSize("min"), 0);
      assert.strictEqual(dim.getWeight(), 0);
      assert.strictEqual(dim.getWeight("min"), 0);
      assert.strictEqual(dim.hasSegwit, false);
    });
  });

  describe("fromInput", function () {
    it("should create dimensions for p2sh input", function () {
      const dim = Dimensions.fromInput({ chain: 0 });
      assert.strictEqual(dim.hasSegwit, false);
      // p2sh has ECDSA variance
      assert.ok(dim.getVSize("min") < dim.getVSize("max"));
    });

    it("should create dimensions for p2shP2wsh input", function () {
      const dim = Dimensions.fromInput({ chain: 10 });
      assert.strictEqual(dim.hasSegwit, true);
      // p2shP2wsh has ECDSA variance
      assert.ok(dim.getVSize("min") < dim.getVSize("max"));
    });

    it("should create dimensions for p2wsh input", function () {
      const dim = Dimensions.fromInput({ chain: 20 });
      assert.strictEqual(dim.hasSegwit, true);
      // p2wsh has ECDSA variance
      assert.ok(dim.getVSize("min") < dim.getVSize("max"));
    });

    it("should create dimensions for p2trLegacy input (user+bitgo)", function () {
      const dim = Dimensions.fromInput({ chain: 30 });
      assert.strictEqual(dim.hasSegwit, true);
      // Schnorr has no variance
      assert.strictEqual(dim.getVSize("min"), dim.getVSize("max"));
    });

    it("should create dimensions for p2trLegacy input (user+backup)", function () {
      const dim = Dimensions.fromInput({
        chain: 30,
        signPath: { signer: "user", cosigner: "backup" },
      });
      assert.strictEqual(dim.hasSegwit, true);
      // Level 2 should be larger than level 1
      const level1 = Dimensions.fromInput({ chain: 30 });
      assert.ok(dim.getVSize() > level1.getVSize());
    });

    it("should create dimensions for p2trMusig2 keypath (user+bitgo)", function () {
      const dim = Dimensions.fromInput({ chain: 40 });
      assert.strictEqual(dim.hasSegwit, true);
      // Schnorr has no variance
      assert.strictEqual(dim.getVSize("min"), dim.getVSize("max"));
    });

    it("should create dimensions for p2trMusig2 scriptpath (user+backup)", function () {
      const dim = Dimensions.fromInput({
        chain: 40,
        signPath: { signer: "user", cosigner: "backup" },
      });
      assert.strictEqual(dim.hasSegwit, true);
      // Script path should be larger than key path
      const keypath = Dimensions.fromInput({ chain: 40 });
      assert.ok(dim.getVSize() > keypath.getVSize());
    });

    it("should create dimensions for p2shP2pk input", function () {
      const dim = Dimensions.fromInput({ scriptType: "p2shP2pk" });
      assert.strictEqual(dim.hasSegwit, false);
      // p2shP2pk has ECDSA variance
      assert.ok(dim.getVSize("min") < dim.getVSize("max"));
    });

    it("should create same dimensions for scriptType and chain code", function () {
      const fromChain = Dimensions.fromInput({ chain: 10 });
      const fromType = Dimensions.fromInput({ scriptType: "p2shP2wsh" });
      assert.strictEqual(fromChain.getWeight("min"), fromType.getWeight("min"));
      assert.strictEqual(fromChain.getWeight("max"), fromType.getWeight("max"));
    });
  });

  describe("fromOutput", function () {
    it("should create dimensions for p2sh output (23 bytes)", function () {
      const script = Buffer.alloc(23);
      const dim = Dimensions.fromOutput(script);
      // Output weight = 4 * (8 + 1 + 23) = 128
      // Plus overhead (4 * 10 = 40) since there's content
      // Total = 168, vSize = 42
      assert.strictEqual(dim.getWeight(), 168);
      assert.strictEqual(dim.getVSize(), 42);
    });

    it("should create dimensions for p2wsh output (34 bytes)", function () {
      const script = Buffer.alloc(34);
      const dim = Dimensions.fromOutput(script);
      // Output weight = 4 * (8 + 1 + 34) = 172
      // Plus overhead (4 * 10 = 40) = 212
      assert.strictEqual(dim.getWeight(), 212);
      assert.strictEqual(dim.getVSize(), 53);
    });

    it("should create dimensions for p2tr output (34 bytes)", function () {
      const script = Buffer.alloc(34);
      const dim = Dimensions.fromOutput(script);
      // Output weight = 4 * (8 + 1 + 34) = 172
      // Plus overhead (4 * 10 = 40) = 212
      assert.strictEqual(dim.getWeight(), 212);
      assert.strictEqual(dim.getVSize(), 53);
    });

    it("should create dimensions from address string", function () {
      // p2wpkh address -> 22 byte script
      const dim = Dimensions.fromOutput("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "btc");
      // Output weight = 4 * (8 + 1 + 22) = 124
      // Plus overhead (4 * 10 = 40) = 164
      assert.strictEqual(dim.getWeight(), 164);
      assert.strictEqual(dim.getVSize(), 41);
    });

    it("should throw when address is provided without network", function () {
      assert.throws(() => {
        // String matches { length: number } but implementation detects string and throws
        Dimensions.fromOutput("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
      }, /network is required/);
    });

    it("should create dimensions from script length only", function () {
      // Compare with actual script
      const script = Buffer.alloc(23);
      const fromScript = Dimensions.fromOutput(script);
      const fromLength = Dimensions.fromOutput({ length: 23 });

      assert.strictEqual(fromLength.getWeight(), fromScript.getWeight());
      assert.strictEqual(fromLength.getVSize(), fromScript.getVSize());
      assert.strictEqual(fromLength.getOutputWeight(), fromScript.getOutputWeight());
    });

    it("should calculate correct weight for different script lengths", function () {
      // p2pkh: 25 bytes -> weight = 4 * (8 + 1 + 25) = 136
      const p2pkh = Dimensions.fromOutput({ length: 25 });
      assert.strictEqual(p2pkh.getOutputWeight(), 136);

      // p2wpkh: 22 bytes -> weight = 4 * (8 + 1 + 22) = 124
      const p2wpkh = Dimensions.fromOutput({ length: 22 });
      assert.strictEqual(p2wpkh.getOutputWeight(), 124);

      // p2tr: 34 bytes -> weight = 4 * (8 + 1 + 34) = 172
      const p2tr = Dimensions.fromOutput({ length: 34 });
      assert.strictEqual(p2tr.getOutputWeight(), 172);
    });

    it("should create dimensions from script type", function () {
      // p2sh/p2shP2wsh: 23 bytes -> weight = 4 * (8 + 1 + 23) = 128
      const p2sh = Dimensions.fromOutput({ scriptType: "p2sh" });
      assert.strictEqual(p2sh.getOutputWeight(), 128);

      const p2shP2wsh = Dimensions.fromOutput({ scriptType: "p2shP2wsh" });
      assert.strictEqual(p2shP2wsh.getOutputWeight(), 128);

      // p2wsh: 34 bytes -> weight = 4 * (8 + 1 + 34) = 172
      const p2wsh = Dimensions.fromOutput({ scriptType: "p2wsh" });
      assert.strictEqual(p2wsh.getOutputWeight(), 172);

      // p2tr/p2trLegacy: 34 bytes -> weight = 4 * (8 + 1 + 34) = 172
      const p2tr = Dimensions.fromOutput({ scriptType: "p2tr" });
      assert.strictEqual(p2tr.getOutputWeight(), 172);

      const p2trLegacy = Dimensions.fromOutput({ scriptType: "p2trLegacy" });
      assert.strictEqual(p2trLegacy.getOutputWeight(), 172);

      // p2trMusig2: 34 bytes -> weight = 4 * (8 + 1 + 34) = 172
      const p2trMusig2 = Dimensions.fromOutput({ scriptType: "p2trMusig2" });
      assert.strictEqual(p2trMusig2.getOutputWeight(), 172);
    });

    it("scriptType should match equivalent length", function () {
      // p2sh = 23 bytes
      assert.strictEqual(
        Dimensions.fromOutput({ scriptType: "p2sh" }).getOutputWeight(),
        Dimensions.fromOutput({ length: 23 }).getOutputWeight(),
      );

      // p2wsh = 34 bytes
      assert.strictEqual(
        Dimensions.fromOutput({ scriptType: "p2wsh" }).getOutputWeight(),
        Dimensions.fromOutput({ length: 34 }).getOutputWeight(),
      );
    });
  });

  describe("plus", function () {
    it("should combine dimensions", function () {
      const input = Dimensions.fromInput({ chain: 10 });
      const output = Dimensions.fromOutput(Buffer.alloc(23));
      const combined = input.plus(output);

      // When combining, overhead is only counted once (not doubled)
      // The combined weight should be greater than either individual weight
      assert.ok(combined.getWeight("min") > input.getWeight("min"));
      assert.ok(combined.getWeight("max") > output.getWeight("max"));
      assert.strictEqual(combined.hasSegwit, true);

      // Combined should have segwit overhead (44) not non-segwit (40)
      // since input is segwit
      const empty = Dimensions.empty();
      const combinedViaEmpty = empty.plus(input).plus(output);
      assert.strictEqual(combined.getWeight("min"), combinedViaEmpty.getWeight("min"));
    });

    it("should preserve segwit flag from either operand", function () {
      const segwit = Dimensions.fromInput({ chain: 20 });
      const nonSegwit = Dimensions.fromInput({ chain: 0 });

      assert.strictEqual(segwit.plus(nonSegwit).hasSegwit, true);
      assert.strictEqual(nonSegwit.plus(segwit).hasSegwit, true);
    });
  });

  describe("times", function () {
    it("should multiply dimensions by a scalar", function () {
      const input = Dimensions.fromInput({ chain: 10 });
      const doubled = input.times(2);

      assert.strictEqual(doubled.getInputWeight("min"), input.getInputWeight("min") * 2);
      assert.strictEqual(doubled.getInputWeight("max"), input.getInputWeight("max") * 2);
      assert.strictEqual(doubled.hasSegwit, input.hasSegwit);
    });

    it("should return zero for times(0)", function () {
      const input = Dimensions.fromInput({ chain: 10 });
      const zeroed = input.times(0);

      assert.strictEqual(zeroed.getInputWeight(), 0);
      assert.strictEqual(zeroed.getOutputWeight(), 0);
    });

    it("should multiply outputs", function () {
      const output = Dimensions.fromOutput(Buffer.alloc(34));
      const tripled = output.times(3);

      assert.strictEqual(tripled.getOutputWeight(), output.getOutputWeight() * 3);
    });

    it("times(1) should return equivalent dimensions", function () {
      const dim = Dimensions.fromInput({ chain: 20 }).plus(Dimensions.fromOutput(Buffer.alloc(23)));
      const same = dim.times(1);

      assert.strictEqual(same.getInputWeight("min"), dim.getInputWeight("min"));
      assert.strictEqual(same.getInputWeight("max"), dim.getInputWeight("max"));
      assert.strictEqual(same.getOutputWeight(), dim.getOutputWeight());
    });
  });

  describe("getInputWeight and getInputVSize", function () {
    it("should return input weight only (no overhead)", function () {
      const input = Dimensions.fromInput({ chain: 10 });
      const inputWeight = input.getInputWeight();

      // Input weight should be less than total weight (which includes overhead)
      assert.ok(inputWeight < input.getWeight());
      assert.ok(inputWeight > 0);
    });

    it("should return min/max input weights for ECDSA inputs", function () {
      const input = Dimensions.fromInput({ chain: 10 });

      // p2shP2wsh has ECDSA variance
      assert.ok(input.getInputWeight("min") < input.getInputWeight("max"));
      assert.ok(input.getInputVSize("min") < input.getInputVSize("max"));
    });

    it("should return equal min/max for Schnorr inputs", function () {
      const input = Dimensions.fromInput({ chain: 40 });

      // p2trMusig2 keypath has no variance
      assert.strictEqual(input.getInputWeight("min"), input.getInputWeight("max"));
      assert.strictEqual(input.getInputVSize("min"), input.getInputVSize("max"));
    });

    it("getInputVSize should be ceiling of weight/4", function () {
      const input = Dimensions.fromInput({ chain: 20 });

      assert.strictEqual(input.getInputVSize("min"), Math.ceil(input.getInputWeight("min") / 4));
      assert.strictEqual(input.getInputVSize("max"), Math.ceil(input.getInputWeight("max") / 4));
    });

    it("should return zero for output-only dimensions", function () {
      const output = Dimensions.fromOutput(Buffer.alloc(34));

      assert.strictEqual(output.getInputWeight(), 0);
      assert.strictEqual(output.getInputVSize(), 0);
    });
  });

  describe("getOutputWeight and getOutputVSize", function () {
    it("should return output weight only (no overhead)", function () {
      const output = Dimensions.fromOutput(Buffer.alloc(23));
      const outputWeight = output.getOutputWeight();

      // Output weight = 4 * (8 + 1 + 23) = 128
      assert.strictEqual(outputWeight, 128);
    });

    it("getOutputVSize should be ceiling of weight/4", function () {
      const output = Dimensions.fromOutput(Buffer.alloc(23));

      assert.strictEqual(output.getOutputVSize(), Math.ceil(output.getOutputWeight() / 4));
      // 128 / 4 = 32
      assert.strictEqual(output.getOutputVSize(), 32);
    });

    it("should return zero for input-only dimensions", function () {
      const input = Dimensions.fromInput({ chain: 10 });

      assert.strictEqual(input.getOutputWeight(), 0);
      assert.strictEqual(input.getOutputVSize(), 0);
    });

    it("should combine correctly with plus", function () {
      const input = Dimensions.fromInput({ chain: 10 });
      const output = Dimensions.fromOutput(Buffer.alloc(34));
      const combined = input.plus(output);

      assert.strictEqual(combined.getInputWeight(), input.getInputWeight());
      assert.strictEqual(combined.getOutputWeight(), output.getOutputWeight());
    });
  });

  describe("integration tests with fixtures", function () {
    // Zcash has additional transaction overhead (version group, expiry height, etc.)
    // that we don't account for in Dimensions - skip it for now
    const networksToTest = getFixtureNetworks().filter((n) => n !== utxolib.networks.zcash);

    networksToTest.forEach((network) => {
      const networkName = utxolib.getNetworkName(network);

      describe(`${networkName}`, function () {
        let fixture: Fixture;

        before(function () {
          fixture = loadPsbtFixture(networkName, "fullsigned");
        });

        it("actual vSize is within estimated min/max bounds", function () {
          if (!fixture.extractedTransaction) {
            this.skip();
            return;
          }

          // Build dimensions from fixture inputs
          let dim = Dimensions.empty();

          for (const psbtInput of fixture.psbtInputs) {
            const scriptType = fixtureTypeToInputScriptType(psbtInput.type);
            if (scriptType === null) {
              throw new Error(`Unknown input type: ${psbtInput.type}`);
            }
            dim = dim.plus(Dimensions.fromInput({ scriptType }));
          }

          // Add outputs
          dim = dim.plus(dimensionsFromOutputs(fixture.outputs));

          // Get actual vSize from extracted transaction
          const txBytes = Buffer.from(fixture.extractedTransaction, "hex");
          const actualVSize = Transaction.fromBytes(txBytes).getVSize();

          // Get estimated bounds
          const minVSize = dim.getVSize("min");
          const maxVSize = dim.getVSize("max");

          // Actual should be within bounds
          assert.ok(actualVSize >= minVSize, `actual ${actualVSize} < min ${minVSize}`);
          assert.ok(actualVSize <= maxVSize, `actual ${actualVSize} > max ${maxVSize}`);
        });
      });
    });
  });

  describe("manual construction test", function () {
    it("builds correct dimensions for bitcoin fixture", function () {
      const fixture = loadPsbtFixture("bitcoin", "fullsigned");
      if (!fixture.extractedTransaction) {
        return;
      }

      // Build dimensions based on fixture input types:
      // 0: p2sh, 1: p2shP2wsh, 2: p2wsh, 3: p2tr (script),
      // 4: p2trMusig2 (script path), 5: p2trMusig2 (keypath), 6: p2shP2pk
      let dim = Dimensions.empty()
        .plus(Dimensions.fromInput({ chain: 0 })) // p2sh
        .plus(Dimensions.fromInput({ chain: 11 })) // p2shP2wsh
        .plus(Dimensions.fromInput({ chain: 21 })) // p2wsh
        .plus(Dimensions.fromInput({ chain: 31 })) // p2tr script path level 1
        .plus(
          Dimensions.fromInput({
            chain: 41,
            signPath: { signer: "user", cosigner: "backup" },
          }),
        ) // p2trMusig2 script path
        .plus(Dimensions.fromInput({ chain: 41 })) // p2trMusig2 keypath
        .plus(Dimensions.fromInput({ scriptType: "p2shP2pk" })); // replay protection

      // Add outputs
      dim = dim.plus(dimensionsFromOutputs(fixture.outputs));

      // Build dimensions using scriptType
      let dimFromTypes = Dimensions.empty()
        .plus(Dimensions.fromInput({ scriptType: "p2sh" }))
        .plus(Dimensions.fromInput({ scriptType: "p2shP2wsh" }))
        .plus(Dimensions.fromInput({ scriptType: "p2wsh" }))
        .plus(Dimensions.fromInput({ scriptType: "p2trLegacy" }))
        .plus(Dimensions.fromInput({ scriptType: "p2trMusig2ScriptPath" }))
        .plus(Dimensions.fromInput({ scriptType: "p2trMusig2KeyPath" }))
        .plus(Dimensions.fromInput({ scriptType: "p2shP2pk" }));

      dimFromTypes = dimFromTypes.plus(dimensionsFromOutputs(fixture.outputs));

      // Both methods should produce same weights
      assert.strictEqual(dim.getWeight("min"), dimFromTypes.getWeight("min"));
      assert.strictEqual(dim.getWeight("max"), dimFromTypes.getWeight("max"));

      // Get actual vSize
      const txBytes = Buffer.from(fixture.extractedTransaction, "hex");
      const actualVSize = Transaction.fromBytes(txBytes).getVSize();

      // Should be within bounds
      assert.ok(
        actualVSize >= dim.getVSize("min"),
        `actual ${actualVSize} < min ${dim.getVSize("min")}`,
      );
      assert.ok(
        actualVSize <= dim.getVSize("max"),
        `actual ${actualVSize} > max ${dim.getVSize("max")}`,
      );
    });
  });

  describe("fromPsbt", function () {
    // Zcash has additional transaction overhead that we don't account for
    const networksToTest = getFixtureNetworks().filter((n) => n !== utxolib.networks.zcash);

    networksToTest.forEach((network) => {
      const networkName = utxolib.getNetworkName(network);

      describe(`${networkName}`, function () {
        it("actual vSize is within fromPsbt estimated bounds", function () {
          const fixture = loadPsbtFixture(networkName, "fullsigned");
          if (!fixture.extractedTransaction) {
            this.skip();
            return;
          }

          // Load PSBT and compute dimensions directly
          const psbt = fixedScriptWallet.BitGoPsbt.fromBytes(getPsbtBuffer(fixture), networkName);
          const dim = Dimensions.fromPsbt(psbt);

          // Get actual vSize from extracted transaction
          const txBytes = Buffer.from(fixture.extractedTransaction, "hex");
          const actualVSize = Transaction.fromBytes(txBytes).getVSize();

          // Get estimated bounds
          const minVSize = dim.getVSize("min");
          const maxVSize = dim.getVSize("max");

          // Actual should be within bounds
          assert.ok(actualVSize >= minVSize, `actual ${actualVSize} < min ${minVSize}`);
          assert.ok(actualVSize <= maxVSize, `actual ${actualVSize} > max ${maxVSize}`);
        });
      });
    });
  });
});
