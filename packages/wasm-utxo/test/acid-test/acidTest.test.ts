import { describe, it } from "mocha";
import * as assert from "assert";
import { AcidTest, signStages, txFormats } from "../../js/testutils/AcidTest.js";
import { BitGoPsbt } from "../../js/fixedScriptWallet/BitGoPsbt.js";
import { coinNames, isMainnet } from "../../js/coinName.js";

describe("AcidTest", function () {
  describe("Basic Creation", function () {
    it("should create AcidTest with default config for btc", function () {
      const test = AcidTest.withConfig("btc", "unsigned", "psbt");

      assert.strictEqual(test.network, "btc");
      assert.strictEqual(test.signStage, "unsigned");
      assert.strictEqual(test.txFormat, "psbt");
      assert.ok(test.rootWalletKeys);
      assert.ok(test.otherWalletKeys);
      assert.ok(test.inputs.length > 0);
      assert.ok(test.outputs.length > 0);
    });

    it("should have correct name format", function () {
      const test = AcidTest.withConfig("btc", "halfsigned", "psbt-lite");
      assert.strictEqual(test.name, "btc halfsigned psbt-lite");
    });

    it("should filter inputs by network support", function () {
      // Bitcoin supports all script types (6 by default, excludes p2trMusig2ScriptPath)
      const btcTest = AcidTest.withConfig("btc", "unsigned", "psbt");
      assert.ok(
        btcTest.inputs.length >= 6,
        "Bitcoin should have all input types (except p2trMusig2ScriptPath)",
      );

      // Dogecoin only supports p2sh (legacy)
      const dogeTest = AcidTest.withConfig("doge", "unsigned", "psbt");
      const dogeInputTypes = dogeTest.inputs.map((i) => i.scriptType);
      assert.ok(dogeInputTypes.includes("p2sh"), "Doge should have p2sh");
      assert.ok(dogeInputTypes.includes("p2shP2pk"), "Doge should have p2shP2pk");
      assert.ok(!dogeInputTypes.includes("p2wsh"), "Doge should not have p2wsh");
      assert.ok(!dogeInputTypes.includes("p2trLegacy"), "Doge should not have taproot");
    });

    it("should filter outputs by network support", function () {
      // Litecoin supports segwit but not taproot
      const ltcTest = AcidTest.withConfig("ltc", "unsigned", "psbt");
      const ltcOutputTypes = ltcTest.outputs
        .filter((o) => "scriptType" in o)
        .map((o) => ("scriptType" in o ? o.scriptType : null));

      assert.ok(ltcOutputTypes.includes("p2sh"), "Litecoin should have p2sh");
      assert.ok(ltcOutputTypes.includes("p2wsh"), "Litecoin should have p2wsh");
      assert.ok(!ltcOutputTypes.includes("p2trLegacy"), "Litecoin should not have taproot");
    });

    it("should always include OP_RETURN, external, and other wallet outputs", function () {
      const test = AcidTest.withConfig("btc", "unsigned", "psbt");

      // Check for OP_RETURN
      const hasOpReturn = test.outputs.some((o) => "opReturn" in o);
      assert.ok(hasOpReturn, "Should have OP_RETURN output");

      // Check for external output (walletKeys: null)
      const hasExternal = test.outputs.some((o) => o.walletKeys === null);
      assert.ok(hasExternal, "Should have external output");

      // Check for other wallet output
      const hasOtherWallet = test.outputs.some(
        (o) => o.walletKeys && o.walletKeys !== test.rootWalletKeys,
      );
      assert.ok(hasOtherWallet, "Should have other wallet output");
    });

    it("should use deterministic input amounts", function () {
      const test = AcidTest.withConfig("btc", "unsigned", "psbt");

      // Check that amounts are deterministic and increasing
      for (let i = 0; i < test.inputs.length; i++) {
        const expectedAmount = BigInt(10000 + i * 10000);
        assert.strictEqual(
          test.inputs[i].value,
          expectedAmount,
          `Input ${i} should have value ${expectedAmount}`,
        );
      }
    });
  });

  describe("PSBT Creation", function () {
    it("should create unsigned PSBT", function () {
      const test = AcidTest.withConfig("btc", "unsigned", "psbt");
      const psbt = test.createPsbt();

      assert.ok(psbt);

      // Verify no signatures present
      const rpKey = test.getReplayProtectionKey();
      const replayProtection = { publicKeys: [rpKey.publicKey] };
      const parsed = psbt.parseTransactionWithWalletKeys(test.rootWalletKeys, replayProtection);
      const user = test.rootWalletKeys.userKey();
      const backup = test.rootWalletKeys.backupKey();
      const bitgo = test.rootWalletKeys.bitgoKey();

      for (let i = 0; i < parsed.inputs.length; i++) {
        assert.strictEqual(
          psbt.verifySignature(i, user),
          false,
          `Input ${i} should not have user signature`,
        );
        assert.strictEqual(
          psbt.verifySignature(i, backup),
          false,
          `Input ${i} should not have backup signature`,
        );
        assert.strictEqual(
          psbt.verifySignature(i, bitgo),
          false,
          `Input ${i} should not have bitgo signature`,
        );
      }
    });

    it("should create halfsigned PSBT", function () {
      const test = AcidTest.withConfig("btc", "halfsigned", "psbt");
      const psbt = test.createPsbt();

      assert.ok(psbt);

      // Verify one signature per input (user only)
      const rpKey = test.getReplayProtectionKey();
      const replayProtection = { publicKeys: [rpKey.publicKey] };
      const parsed = psbt.parseTransactionWithWalletKeys(test.rootWalletKeys, replayProtection);
      const user = test.rootWalletKeys.userKey();
      const backup = test.rootWalletKeys.backupKey();
      const bitgo = test.rootWalletKeys.bitgoKey();

      for (let i = 0; i < parsed.inputs.length; i++) {
        // Check if this is a replay protection input
        const isReplayProtection = parsed.inputs[i].scriptType === "p2shP2pk";

        if (isReplayProtection) {
          // Replay protection inputs are signed with user private key
          // but verification needs the public key (ECPair), not BIP32 with derivation
          assert.strictEqual(
            psbt.verifySignature(i, user.publicKey),
            true,
            `Input ${i} (replay protection) should have user signature`,
          );
        } else {
          // Regular inputs should have user signature only
          assert.strictEqual(
            psbt.verifySignature(i, user),
            true,
            `Input ${i} should have user signature`,
          );
          assert.strictEqual(
            psbt.verifySignature(i, backup),
            false,
            `Input ${i} should not have backup signature`,
          );
          assert.strictEqual(
            psbt.verifySignature(i, bitgo),
            false,
            `Input ${i} should not have bitgo signature`,
          );
        }
      }
    });

    it("should create fullsigned PSBT", function () {
      const test = AcidTest.withConfig("btc", "fullsigned", "psbt");
      const psbt = test.createPsbt();

      assert.ok(psbt);

      // Verify two signatures per input (user + bitgo or user + backup)
      const rpKey = test.getReplayProtectionKey();
      const replayProtection = { publicKeys: [rpKey.publicKey] };
      const parsed = psbt.parseTransactionWithWalletKeys(test.rootWalletKeys, replayProtection);
      const user = test.rootWalletKeys.userKey();
      const backup = test.rootWalletKeys.backupKey();
      const bitgo = test.rootWalletKeys.bitgoKey();

      for (let i = 0; i < parsed.inputs.length; i++) {
        // Use the original input spec to determine expected signing behavior
        const inputSpec = test.inputs[i];
        const isReplayProtection = inputSpec.scriptType === "p2shP2pk";
        const isMusig2ScriptPath = inputSpec.scriptType === "p2trMusig2ScriptPath";

        if (isReplayProtection) {
          // Replay protection inputs are signed with user private key
          // but verification needs the public key (ECPair), not BIP32 with derivation
          assert.strictEqual(
            psbt.verifySignature(i, user.publicKey),
            true,
            `Input ${i} (replay protection) should have user signature`,
          );
        } else {
          // Regular inputs should have user signature
          assert.strictEqual(
            psbt.verifySignature(i, user),
            true,
            `Input ${i} should have user signature`,
          );

          // p2trMusig2ScriptPath uses user + backup, others use user + bitgo
          if (isMusig2ScriptPath) {
            assert.strictEqual(
              psbt.verifySignature(i, backup),
              true,
              `Input ${i} (p2trMusig2ScriptPath) should have backup signature`,
            );
            assert.strictEqual(
              psbt.verifySignature(i, bitgo),
              false,
              `Input ${i} (p2trMusig2ScriptPath) should not have bitgo signature`,
            );
          } else {
            assert.strictEqual(
              psbt.verifySignature(i, bitgo),
              true,
              `Input ${i} should have bitgo signature`,
            );
            assert.strictEqual(
              psbt.verifySignature(i, backup),
              false,
              `Input ${i} should not have backup signature`,
            );
          }
        }
      }
    });

    it("should serialize and deserialize PSBT", function () {
      const test = AcidTest.withConfig("btc", "unsigned", "psbt");
      const psbt = test.createPsbt();

      const bytes = psbt.serialize();
      assert.ok(bytes);
      assert.ok(bytes.length > 0);

      // Deserialize and check it works
      const psbt2 = BitGoPsbt.fromBytes(bytes, test.network);
      assert.ok(psbt2);
    });
  });

  describe("Suite Generation", function () {
    it("should generate suite for all networks/stages/formats", function () {
      const suite = AcidTest.forAllNetworksSignStagesTxFormats({
        includeP2trMusig2ScriptPath: true,
      });

      assert.ok(suite.length > 0);

      // Should have entries for each mainnet (except bsv) × 3 sign stages × 2 formats
      const mainnetCoins = coinNames.filter((coin) => isMainnet(coin) && coin !== "bsv");
      const expectedCount = mainnetCoins.length * signStages.length * txFormats.length;

      assert.strictEqual(
        suite.length,
        expectedCount,
        `Should have ${expectedCount} test cases (${mainnetCoins.length} networks × ${signStages.length} stages × ${txFormats.length} formats)`,
      );
    });

    it("should not include bitcoinsv in suite", function () {
      const suite = AcidTest.forAllNetworksSignStagesTxFormats({
        includeP2trMusig2ScriptPath: true,
      });
      const hasBsv = suite.some((test) => test.network === "bsv");
      assert.ok(!hasBsv, "Suite should not include bitcoinsv");
    });

    it("should include all sign stages", function () {
      const suite = AcidTest.forAllNetworksSignStagesTxFormats({
        includeP2trMusig2ScriptPath: true,
      });

      signStages.forEach((stage) => {
        const hasStage = suite.some((test) => test.signStage === stage);
        assert.ok(hasStage, `Suite should include ${stage}`);
      });
    });

    it("should include all tx formats", function () {
      const suite = AcidTest.forAllNetworksSignStagesTxFormats({
        includeP2trMusig2ScriptPath: true,
      });

      txFormats.forEach((format) => {
        const hasFormat = suite.some((test) => test.txFormat === format);
        assert.ok(hasFormat, `Suite should include ${format}`);
      });
    });
  });

  describe("Config Options", function () {
    it("should exclude p2trMusig2ScriptPath by default", function () {
      const test = AcidTest.withConfig("btc", "unsigned", "psbt");

      const hasScriptPath = test.inputs.some((i) => i.scriptType === "p2trMusig2ScriptPath");
      assert.ok(!hasScriptPath, "Should not include p2trMusig2ScriptPath by default");
    });

    it("should include p2trMusig2ScriptPath when configured", function () {
      const test = AcidTest.withConfig("btc", "unsigned", "psbt", {
        includeP2trMusig2ScriptPath: true,
      });

      const hasScriptPath = test.inputs.some((i) => i.scriptType === "p2trMusig2ScriptPath");
      assert.ok(hasScriptPath, "Should include p2trMusig2ScriptPath when configured");
    });
  });

  describe("Replay Protection", function () {
    it("should include p2shP2pk input", function () {
      const test = AcidTest.withConfig("btc", "unsigned", "psbt");

      const hasReplayProtection = test.inputs.some((i) => i.scriptType === "p2shP2pk");
      assert.ok(hasReplayProtection, "Should include p2shP2pk replay protection input");
    });

    it("should provide replay protection key", function () {
      const test = AcidTest.withConfig("btc", "unsigned", "psbt");
      const key = test.getReplayProtectionKey();

      assert.ok(key);
      assert.ok(key.publicKey);
      assert.ok(key.publicKey.length === 33 || key.publicKey.length === 65);
    });
  });

  describe("Network-Specific Tests", function () {
    it("should create valid PSBT for Bitcoin", function () {
      const test = AcidTest.withConfig("btc", "unsigned", "psbt");
      const psbt = test.createPsbt();
      assert.ok(psbt);
    });

    it("should create valid PSBT for Litecoin", function () {
      const test = AcidTest.withConfig("ltc", "unsigned", "psbt");
      const psbt = test.createPsbt();
      assert.ok(psbt);
    });

    it("should create valid PSBT for Dogecoin", function () {
      const test = AcidTest.withConfig("doge", "unsigned", "psbt");
      const psbt = test.createPsbt();
      assert.ok(psbt);
    });

    it("should create valid PSBT for Zcash", function () {
      const test = AcidTest.withConfig("zec", "unsigned", "psbt");
      const psbt = test.createPsbt();
      assert.ok(psbt);
    });
  });
});
