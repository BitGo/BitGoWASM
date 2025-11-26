import assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";
import { fixedScriptWallet } from "../../js/index.js";
import { BitGoPsbt, InputScriptType } from "../../js/fixedScriptWallet/index.js";
import type { RootWalletKeys } from "../../js/fixedScriptWallet/RootWalletKeys.js";
import type { ECPair } from "../../js/index.js";
import {
  loadPsbtFixture,
  loadWalletKeysFromFixture,
  getPsbtBuffer,
  loadReplayProtectionKeyFromFixture,
  type Fixture,
} from "./fixtureUtil.js";

function getExpectedInputScriptType(fixtureScriptType: string): InputScriptType {
  // Map fixture types to InputScriptType values
  // Based on the Rust mapping in src/fixed_script_wallet/test_utils/fixtures.rs
  switch (fixtureScriptType) {
    case "p2shP2pk":
    case "p2sh":
    case "p2shP2wsh":
    case "p2wsh":
      return fixtureScriptType;
    case "p2tr":
      return "p2trLegacy";
    case "p2trMusig2":
      return "p2trMusig2ScriptPath";
    case "taprootKeyPathSpend":
      return "p2trMusig2KeyPath";
    default:
      throw new Error(`Unknown fixture script type: ${fixtureScriptType}`);
  }
}

function getOtherWalletKeys(): utxolib.bitgo.RootWalletKeys {
  const otherWalletKeys = utxolib.testutil.getKeyTriple("too many secrets");
  return new utxolib.bitgo.RootWalletKeys(otherWalletKeys);
}

describe("parseTransactionWithWalletKeys", function () {
  const supportedNetworks = utxolib.getNetworkList().filter((network) => {
    return (
      utxolib.isMainnet(network) &&
      network !== utxolib.networks.bitcoincash &&
      network !== utxolib.networks.bitcoingold &&
      network !== utxolib.networks.bitcoinsv &&
      network !== utxolib.networks.ecash &&
      network !== utxolib.networks.zcash
    );
  });

  supportedNetworks.forEach((network) => {
    const networkName = utxolib.getNetworkName(network);

    describe(`network: ${networkName}`, function () {
      let fullsignedPsbtBytes: Buffer;
      let bitgoPsbt: BitGoPsbt;
      let rootWalletKeys: RootWalletKeys;
      let replayProtectionKey: ECPair;
      let fixture: Fixture;

      before(function () {
        fixture = loadPsbtFixture(networkName, "fullsigned");
        fullsignedPsbtBytes = getPsbtBuffer(fixture);
        bitgoPsbt = fixedScriptWallet.BitGoPsbt.fromBytes(fullsignedPsbtBytes, networkName);
        rootWalletKeys = loadWalletKeysFromFixture(fixture);
        replayProtectionKey = loadReplayProtectionKeyFromFixture(fixture);
      });

      it("should have matching unsigned transaction ID", function () {
        const unsignedTxid = bitgoPsbt.unsignedTxid();
        const expectedUnsignedTxid = utxolib.bitgo
          .createPsbtFromBuffer(fullsignedPsbtBytes, network)
          .getUnsignedTx()
          .getId();
        assert.strictEqual(unsignedTxid, expectedUnsignedTxid);
      });

      it("should parse transaction and identify internal/external outputs", function () {
        const parsed = bitgoPsbt.parseTransactionWithWalletKeys(rootWalletKeys, {
          publicKeys: [replayProtectionKey],
        });

        // Verify all inputs have addresses and values
        parsed.inputs.forEach((input, i) => {
          assert.ok(input.address, `Input ${i} should have an address`);
          assert.ok(typeof input.value === "bigint", `Input ${i} value should be bigint`);
          assert.ok(input.value > 0n, `Input ${i} value should be > 0`);
        });

        // Validate outputs
        assert.ok(parsed.outputs.length > 0, "Should have at least one output");

        // Count internal outputs (scriptId is defined and not null)
        const internalOutputs = parsed.outputs.filter((o) => o.scriptId);

        // Count external outputs (scriptId is null or undefined)
        const externalOutputs = parsed.outputs.filter((o) => o.scriptId === null);

        assert.ok(externalOutputs.every((o) => o.address || o.script));
        const nonAddressOutputs = externalOutputs.filter((o) => o.address === null);
        assert.strictEqual(nonAddressOutputs.length, 1);
        const [opReturnOutput] = nonAddressOutputs;
        const expectedOpReturn = utxolib.payments.embed({
          data: [Buffer.from("setec astronomy")],
        }).output;
        assert.strictEqual(
          Buffer.from(opReturnOutput.script).toString("hex"),
          expectedOpReturn.toString("hex"),
        );

        // Fixtures now have 3 external outputs
        assert.ok(internalOutputs.length > 0, "Should have internal outputs (have scriptId)");
        assert.strictEqual(
          externalOutputs.length,
          3,
          "Should have 3 external outputs in test fixture",
        );

        // Verify all outputs have proper structure
        parsed.outputs.forEach((output, i) => {
          assert.ok(output.script instanceof Uint8Array, `Output ${i} script should be Uint8Array`);
          assert.ok(typeof output.value === "bigint", `Output ${i} value should be bigint`);
          assert.ok(output.value > 0n, `Output ${i} value should be > 0`);
          // Address is optional for non-standard scripts
        });

        // Verify spend amount (should be > 0 since there are external outputs)
        assert.strictEqual(parsed.spendAmount, 900n * 3n);

        // Verify miner fee calculation
        const totalInputValue = parsed.inputs.reduce((sum, i) => sum + i.value, 0n);
        const totalOutputValue = parsed.outputs.reduce((sum, o) => sum + o.value, 0n);
        assert.strictEqual(
          parsed.minerFee,
          totalInputValue - totalOutputValue,
          "Miner fee should equal inputs minus outputs",
        );
        assert.ok(parsed.minerFee > 0n, "Miner fee should be > 0");

        // Verify virtual size
        assert.ok(typeof parsed.virtualSize === "number", "Virtual size should be a number");
        assert.ok(parsed.virtualSize > 0, "Virtual size should be > 0");
      });

      it("should parse inputs with correct scriptType", function () {
        const parsed = bitgoPsbt.parseTransactionWithWalletKeys(rootWalletKeys, {
          publicKeys: [replayProtectionKey],
        });

        // Verify all inputs have scriptType matching fixture
        parsed.inputs.forEach((input, i) => {
          const fixtureInput = fixture.psbtInputs[i];
          const expectedScriptType = getExpectedInputScriptType(fixtureInput.type);
          assert.strictEqual(
            input.scriptType,
            expectedScriptType,
            `Input ${i} scriptType should be ${expectedScriptType}, got ${input.scriptType}`,
          );
        });
      });

      it("should fail to parse with other wallet keys", function () {
        assert.throws(
          () => {
            bitgoPsbt.parseTransactionWithWalletKeys(getOtherWalletKeys(), {
              publicKeys: [replayProtectionKey],
            });
          },
          (error: Error) => {
            return error.message.includes(
              "Failed to parse transaction: Input 0: wallet validation failed",
            );
          },
        );
      });

      it("should recognize output for other wallet keys", function () {
        const parsedOutputs = bitgoPsbt.parseOutputsWithWalletKeys(getOtherWalletKeys());

        // Should return an array of parsed outputs
        assert.ok(Array.isArray(parsedOutputs), "Should return an array");
        assert.ok(parsedOutputs.length > 0, "Should have at least one output");

        // Verify all outputs have proper structure
        parsedOutputs.forEach((output, i) => {
          assert.ok(output.script instanceof Uint8Array, `Output ${i} script should be Uint8Array`);
          assert.ok(typeof output.value === "bigint", `Output ${i} value should be bigint`);
          assert.ok(output.value > 0n, `Output ${i} value should be > 0`);
          // Address can be null for non-standard scripts
          assert.ok(
            typeof output.address === "string" || output.address === null,
            `Output ${i} address should be string or null`,
          );
          // scriptId can be null for external outputs
          assert.ok(
            output.scriptId === null ||
              (typeof output.scriptId === "object" &&
                typeof output.scriptId.chain === "number" &&
                typeof output.scriptId.index === "number"),
            `Output ${i} scriptId should be null or an object with chain and index`,
          );
        });

        // Compare with the original wallet keys to verify we get different results
        const originalParsedOutputs = bitgoPsbt.parseOutputsWithWalletKeys(rootWalletKeys);

        // Should have the same number of outputs
        assert.strictEqual(
          parsedOutputs.length,
          originalParsedOutputs.length,
          "Should parse the same number of outputs",
        );

        // Find outputs that belong to the other wallet keys (scriptId !== null)
        const otherWalletOutputs = parsedOutputs.filter((o) => o.scriptId !== null);

        // Should have exactly one output for the other wallet keys
        assert.strictEqual(
          otherWalletOutputs.length,
          1,
          "Should have exactly one output belonging to the other wallet keys",
        );

        // Verify that this output is marked as external (scriptId === null) under regular wallet keys
        const otherWalletOutputIndex = parsedOutputs.findIndex((o) => o.scriptId !== null);
        const sameOutputWithRegularKeys = originalParsedOutputs[otherWalletOutputIndex];

        assert.strictEqual(
          sameOutputWithRegularKeys.scriptId,
          null,
          "The output belonging to other wallet keys should be marked as external (scriptId === null) when parsed with regular wallet keys",
        );
      });
    });
  });

  describe("error handling", function () {
    it("should throw error for invalid PSBT bytes", function () {
      const invalidBytes = new Uint8Array([0x00, 0x01, 0x02]);
      assert.throws(
        () => {
          fixedScriptWallet.BitGoPsbt.fromBytes(invalidBytes, "bitcoin");
        },
        (error: Error) => {
          return error.message.includes("Failed to deserialize PSBT");
        },
        "Should throw error for invalid PSBT bytes",
      );
    });
  });
});
