import assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";
import { fixedScriptWallet } from "../../js/index.js";
import {
  BitGoPsbt,
  ZcashBitGoPsbt,
  type InputScriptType,
  type SignPath,
} from "../../js/fixedScriptWallet/index.js";
import type { RootWalletKeys } from "../../js/fixedScriptWallet/RootWalletKeys.js";
import {
  loadPsbtFixture,
  loadWalletKeysFromFixture,
  loadReplayProtectionKeyFromFixture,
  getPsbtBuffer,
  type Fixture,
} from "./fixtureUtil.js";
import { getFixtureNetworks } from "./networkSupport.util.js";

// Zcash Sapling consensus branch ID for test fixtures
const ZCASH_SAPLING_BRANCH_ID = 0x76b809bb;

/**
 * Infer signPath from scriptType (matches Rust logic)
 */
function getSignPathFromScriptType(scriptType: InputScriptType): SignPath | undefined {
  switch (scriptType) {
    case "p2trLegacy":
      return { signer: "user", cosigner: "bitgo" };
    case "p2trMusig2ScriptPath":
      return { signer: "user", cosigner: "backup" };
    case "p2trMusig2KeyPath":
      return { signer: "user", cosigner: "bitgo" };
    default:
      return undefined;
  }
}

/**
 * Get "other wallet keys" for testing outputs from different wallet
 * Uses the same seed as utxo-lib tests: "too many secrets"
 */
function getOtherWalletKeys(): RootWalletKeys {
  const otherWalletKeys = utxolib.testutil.getKeyTriple("too many secrets");
  const neuteredKeys = otherWalletKeys.map((key) => key.neutered()) as [
    utxolib.BIP32Interface,
    utxolib.BIP32Interface,
    utxolib.BIP32Interface,
  ];
  return fixedScriptWallet.RootWalletKeys.from({
    triple: neuteredKeys,
    derivationPrefixes: ["0/0", "0/0", "0/0"],
  });
}

/**
 * Reverse a hex string by bytes (for txid conversion)
 * Bitcoin txids in fixtures are in internal byte order (reversed)
 */
function reverseHex(hex: string): string {
  return Buffer.from(hex, "hex").reverse().toString("hex");
}

describe("PSBT reconstruction", function () {
  getFixtureNetworks().forEach((network) => {
    const networkName = utxolib.getNetworkName(network);

    describe(`network: ${networkName}`, function () {
      let fixture: Fixture;
      let originalPsbt: BitGoPsbt;
      let rootWalletKeys: RootWalletKeys;
      let otherWalletKeys: RootWalletKeys;

      before(function () {
        fixture = loadPsbtFixture(networkName, "unsigned");
        originalPsbt = fixedScriptWallet.BitGoPsbt.fromBytes(getPsbtBuffer(fixture), networkName);
        rootWalletKeys = loadWalletKeysFromFixture(fixture);
        otherWalletKeys = getOtherWalletKeys();
      });

      it("should reconstruct PSBT from parsed data with matching unsigned txid", function () {
        // Parse the original PSBT to get inputs/outputs
        const replayProtectionKey = loadReplayProtectionKeyFromFixture(fixture);
        const parsedTx = originalPsbt.parseTransactionWithWalletKeys(rootWalletKeys, {
          publicKeys: [replayProtectionKey],
        });

        // Parse outputs with other wallet keys to detect outputs from different wallet
        const parsedOutputsOther = originalPsbt.parseOutputsWithWalletKeys(otherWalletKeys);

        // Create empty PSBT with same version/locktime
        let reconstructed: BitGoPsbt;
        if (networkName === "zcash" || networkName === "zcashTest") {
          const zcashPsbt = ZcashBitGoPsbt.fromBytes(getPsbtBuffer(fixture), networkName);
          reconstructed = ZcashBitGoPsbt.createEmptyWithConsensusBranchId(
            networkName,
            rootWalletKeys,
            {
              consensusBranchId: ZCASH_SAPLING_BRANCH_ID,
              version: zcashPsbt.version,
              lockTime: zcashPsbt.lockTime,
              versionGroupId: zcashPsbt.versionGroupId,
              expiryHeight: zcashPsbt.expiryHeight,
            },
          );
        } else {
          reconstructed = BitGoPsbt.createEmpty(networkName, rootWalletKeys, {
            version: originalPsbt.version,
            lockTime: originalPsbt.lockTime,
          });
        }

        // Add inputs
        for (let i = 0; i < parsedTx.inputs.length; i++) {
          const parsedInput = parsedTx.inputs[i];
          const fixtureInput = fixture.inputs[i];

          // Convert fixture txid (internal byte order) to display order
          const txid = reverseHex(fixtureInput.hash);

          if (parsedInput.scriptId !== null) {
            // Wallet input - use addWalletInput
            const signPath = getSignPathFromScriptType(parsedInput.scriptType);

            reconstructed.addWalletInput(
              {
                txid,
                vout: fixtureInput.index,
                value: parsedInput.value,
                sequence: parsedInput.sequence,
              },
              rootWalletKeys,
              { scriptId: parsedInput.scriptId, signPath },
            );
          } else {
            // Replay protection input - use the underived user key
            assert.strictEqual(
              parsedInput.scriptType,
              "p2shP2pk",
              `Non-wallet input ${i} should be p2shP2pk`,
            );

            reconstructed.addReplayProtectionInput(
              {
                txid,
                vout: fixtureInput.index,
                value: parsedInput.value,
                sequence: parsedInput.sequence,
              },
              replayProtectionKey,
            );
          }
        }

        // Add outputs
        for (let i = 0; i < parsedTx.outputs.length; i++) {
          const parsedOutput = parsedTx.outputs[i];
          const parsedOutputOther = parsedOutputsOther[i];

          if (parsedOutput.scriptId !== null) {
            // Output belongs to main wallet
            reconstructed.addWalletOutput(rootWalletKeys, {
              chain: parsedOutput.scriptId.chain,
              index: parsedOutput.scriptId.index,
              value: parsedOutput.value,
            });
          } else if (parsedOutputOther.scriptId !== null) {
            // Output belongs to other wallet (from seed "too many secrets")
            reconstructed.addWalletOutput(otherWalletKeys, {
              chain: parsedOutputOther.scriptId.chain,
              index: parsedOutputOther.scriptId.index,
              value: parsedOutputOther.value,
            });
          } else {
            // External output - use addOutput
            reconstructed.addOutput({
              script: parsedOutput.script,
              value: parsedOutput.value,
            });
          }
        }

        // Compare unsigned txids
        assert.strictEqual(
          reconstructed.unsignedTxid(),
          originalPsbt.unsignedTxid(),
          "Reconstructed PSBT should have same unsigned txid as original",
        );
      });

      it("should have correct version and lockTime getters", function () {
        // Version and lockTime should be numbers
        assert.strictEqual(typeof originalPsbt.version, "number", "version should be a number");
        assert.strictEqual(typeof originalPsbt.lockTime, "number", "lockTime should be a number");
        // Version depends on network: Zcash uses version 4 (Sapling) or 5 (NU5), others use 1 or 2
        if (network === utxolib.networks.zcash) {
          assert.ok(
            originalPsbt.version === 4 || originalPsbt.version === 5,
            `Zcash version should be 4 or 5, got ${originalPsbt.version}`,
          );
        } else {
          assert.ok(
            originalPsbt.version === 1 || originalPsbt.version === 2,
            `version should be 1 or 2, got ${originalPsbt.version}`,
          );
        }
        // LockTime is typically 0 for these fixtures
        assert.strictEqual(originalPsbt.lockTime, 0, "lockTime should be 0 for unsigned fixtures");
      });

      it("should include sequence in parsed inputs", function () {
        const replayProtectionKey = loadReplayProtectionKeyFromFixture(fixture);
        const parsedTx = originalPsbt.parseTransactionWithWalletKeys(rootWalletKeys, {
          publicKeys: [replayProtectionKey],
        });

        // Verify all inputs have sequence field
        parsedTx.inputs.forEach((input, i) => {
          assert.ok(
            typeof input.sequence === "number",
            `Input ${i} sequence should be a number, got ${typeof input.sequence}`,
          );
          // Compare with fixture
          assert.strictEqual(
            input.sequence,
            fixture.inputs[i].sequence,
            `Input ${i} sequence should match fixture`,
          );
        });
      });

      it("should create equivalent PSBTs using block height vs explicit branch ID (Zcash only)", function () {
        // Skip for non-Zcash networks
        if (networkName !== "zcash" && networkName !== "zcashTest") {
          this.skip();
        }

        const replayProtectionKey = loadReplayProtectionKeyFromFixture(fixture);
        const parsedTx = originalPsbt.parseTransactionWithWalletKeys(rootWalletKeys, {
          publicKeys: [replayProtectionKey],
        });
        const parsedOutputsOther = originalPsbt.parseOutputsWithWalletKeys(otherWalletKeys);

        // Get Zcash-specific parameters from original PSBT
        const zcashPsbt = ZcashBitGoPsbt.fromBytes(getPsbtBuffer(fixture), networkName);

        // Sapling activation heights: mainnet=419200, testnet=280000
        const saplingHeight = networkName === "zcash" ? 419200 : 280000;

        // Create PSBT using explicit branch ID (advanced approach)
        const psbtWithBranchId = ZcashBitGoPsbt.createEmptyWithConsensusBranchId(
          networkName,
          rootWalletKeys,
          {
            consensusBranchId: ZCASH_SAPLING_BRANCH_ID,
            version: zcashPsbt.version,
            lockTime: zcashPsbt.lockTime,
            versionGroupId: zcashPsbt.versionGroupId,
            expiryHeight: zcashPsbt.expiryHeight,
          },
        );

        // Create PSBT using block height (preferred approach)
        const psbtWithHeight = ZcashBitGoPsbt.createEmpty(networkName, rootWalletKeys, {
          blockHeight: saplingHeight,
          version: zcashPsbt.version,
          lockTime: zcashPsbt.lockTime,
          versionGroupId: zcashPsbt.versionGroupId,
          expiryHeight: zcashPsbt.expiryHeight,
        });

        // Add the same inputs and outputs to both PSBTs
        for (let i = 0; i < parsedTx.inputs.length; i++) {
          const parsedInput = parsedTx.inputs[i];
          const fixtureInput = fixture.inputs[i];
          const txid = reverseHex(fixtureInput.hash);

          if (parsedInput.scriptId !== null) {
            const signPath = getSignPathFromScriptType(parsedInput.scriptType);
            const inputOptions = {
              txid,
              vout: fixtureInput.index,
              value: parsedInput.value,
              sequence: parsedInput.sequence,
            };
            const walletOptions = { scriptId: parsedInput.scriptId, signPath };

            psbtWithBranchId.addWalletInput(inputOptions, rootWalletKeys, walletOptions);
            psbtWithHeight.addWalletInput(inputOptions, rootWalletKeys, walletOptions);
          } else {
            const inputOptions = {
              txid,
              vout: fixtureInput.index,
              value: parsedInput.value,
              sequence: parsedInput.sequence,
            };

            psbtWithBranchId.addReplayProtectionInput(inputOptions, replayProtectionKey);
            psbtWithHeight.addReplayProtectionInput(inputOptions, replayProtectionKey);
          }
        }

        for (let i = 0; i < parsedTx.outputs.length; i++) {
          const parsedOutput = parsedTx.outputs[i];
          const parsedOutputOther = parsedOutputsOther[i];

          if (parsedOutput.scriptId !== null) {
            const outputOptions = {
              chain: parsedOutput.scriptId.chain,
              index: parsedOutput.scriptId.index,
              value: parsedOutput.value,
            };
            psbtWithBranchId.addWalletOutput(rootWalletKeys, outputOptions);
            psbtWithHeight.addWalletOutput(rootWalletKeys, outputOptions);
          } else if (parsedOutputOther.scriptId !== null) {
            const outputOptions = {
              chain: parsedOutputOther.scriptId.chain,
              index: parsedOutputOther.scriptId.index,
              value: parsedOutputOther.value,
            };
            psbtWithBranchId.addWalletOutput(otherWalletKeys, outputOptions);
            psbtWithHeight.addWalletOutput(otherWalletKeys, outputOptions);
          } else {
            const outputOptions = {
              script: parsedOutput.script,
              value: parsedOutput.value,
            };
            psbtWithBranchId.addOutput(outputOptions);
            psbtWithHeight.addOutput(outputOptions);
          }
        }

        // Verify both PSBTs produce the same unsigned txid
        assert.strictEqual(
          psbtWithHeight.unsignedTxid(),
          psbtWithBranchId.unsignedTxid(),
          "PSBT created with block height should have same unsigned txid as one created with explicit branch ID",
        );

        // Verify both PSBTs serialize to the same bytes
        const serializedWithBranchId = psbtWithBranchId.serialize();
        const serializedWithHeight = psbtWithHeight.serialize();
        assert.ok(
          Buffer.from(serializedWithBranchId).equals(Buffer.from(serializedWithHeight)),
          "PSBTs should serialize to identical bytes",
        );
      });

      it("should extract transaction with valid getId() after finalization", function () {
        // Load fullsigned fixture for this network
        const fullsignedFixture = loadPsbtFixture(networkName, "fullsigned");
        const psbt = fixedScriptWallet.BitGoPsbt.fromBytes(
          getPsbtBuffer(fullsignedFixture),
          networkName,
        );

        // Finalize and extract
        psbt.finalizeAllInputs();
        const extractedTx = psbt.extractTransaction();

        // Verify getId() returns a valid 64-character hex txid
        const txid = extractedTx.getId();
        assert.strictEqual(txid.length, 64, "txid should be 64 characters");
        assert.match(txid, /^[0-9a-f]{64}$/, "txid should be lowercase hex");

        // Verify unsignedTxid() also returns valid format
        const unsignedTxid = psbt.unsignedTxid();
        assert.strictEqual(unsignedTxid.length, 64, "unsignedTxid should be 64 characters");
        assert.match(unsignedTxid, /^[0-9a-f]{64}$/, "unsignedTxid should be lowercase hex");
      });
    });
  });
});
