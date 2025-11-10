import assert from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import * as utxolib from "@bitgo/utxo-lib";
import { fixedScriptWallet } from "../../js";

type Triple<T> = [T, T, T];

/**
 * Load a PSBT fixture from JSON file and return the PSBT bytes
 */
function loadPsbtFixture(network: string): Buffer {
  const fixturePath = path.join(
    __dirname,
    "..",
    "fixtures",
    "fixed-script",
    `psbt-lite.${network}.fullsigned.json`,
  );
  const fixtureContent = fs.readFileSync(fixturePath, "utf-8");
  const fixture = JSON.parse(fixtureContent) as { psbtBase64: string; walletKeys: string[] };
  return Buffer.from(fixture.psbtBase64, "base64");
}

/**
 * Load wallet keys from fixture
 */
function loadWalletKeysFromFixture(network: string): utxolib.bitgo.RootWalletKeys {
  const fixturePath = path.join(
    __dirname,
    "..",
    "fixtures",
    "fixed-script",
    `psbt-lite.${network}.fullsigned.json`,
  );
  const fixtureContent = fs.readFileSync(fixturePath, "utf-8");
  const fixture = JSON.parse(fixtureContent) as { walletKeys: string[] };

  // Parse xprvs and convert to xpubs
  const xpubs = fixture.walletKeys.map((xprv) => {
    const key = utxolib.bip32.fromBase58(xprv);
    return key.neutered();
  });

  return new utxolib.bitgo.RootWalletKeys(xpubs as Triple<utxolib.BIP32Interface>);
}

describe("parseTransactionWithWalletKeys", function () {
  // Replay protection script that matches Rust tests
  const replayProtectionScript = Buffer.from(
    "a91420b37094d82a513451ff0ccd9db23aba05bc5ef387",
    "hex",
  );

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

  function hasReplayProtection(network: utxolib.Network): boolean {
    const mainnet = utxolib.getMainnet(network);
    return mainnet === utxolib.networks.bitcoincash;
  }

  supportedNetworks.forEach((network) => {
    const networkName = utxolib.getNetworkName(network);

    describe(`network: ${networkName}`, function () {
      it("should parse transaction and identify internal/external outputs", function () {
        // Load PSBT from fixture
        const psbtBytes = loadPsbtFixture(networkName);
        const rootWalletKeys = loadWalletKeysFromFixture(networkName);

        // Parse with WASM
        const bitgoPsbt = fixedScriptWallet.BitGoPsbt.fromBytes(psbtBytes, networkName);
        const parsed = bitgoPsbt.parseTransactionWithWalletKeys(rootWalletKeys, {
          outputScripts: [replayProtectionScript],
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
