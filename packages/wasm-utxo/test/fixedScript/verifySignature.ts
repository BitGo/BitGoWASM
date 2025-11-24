import assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";
import { fixedScriptWallet } from "../../js/index.js";
import { BitGoPsbt } from "../../js/fixedScriptWallet.js";
import {
  loadPsbtFixture,
  loadWalletKeysFromFixture,
  getPsbtBuffer,
  type Fixture,
} from "./fixtureUtil.js";

type SignatureStage = "unsigned" | "halfsigned" | "fullsigned";

type ExpectedSignatures =
  | { hasReplayProtectionSignature: boolean }
  | { user: boolean; backup: boolean; bitgo: boolean };

/**
 * Get expected signature state for an input based on type and signing stage
 * @param inputType - The type of input (e.g., "p2shP2pk", "p2trMusig2")
 * @param signatureStage - The signing stage (unsigned, halfsigned, fullsigned)
 * @returns Expected signature state for replay protection OR multi-key signatures
 */
function getExpectedSignatures(
  inputType: string,
  signatureStage: SignatureStage,
): ExpectedSignatures {
  // p2shP2pk inputs use replay protection signature verification
  if (inputType === "p2shP2pk") {
    return {
      hasReplayProtectionSignature:
        signatureStage === "halfsigned" || signatureStage === "fullsigned",
    };
  }

  switch (signatureStage) {
    case "unsigned":
      return { user: false, backup: false, bitgo: false };
    case "halfsigned":
      // User signs first
      return { user: true, backup: false, bitgo: false };
    case "fullsigned":
      // p2trMusig2 uses user + backup for 2-of-2 MuSig2
      if (inputType === "p2trMusig2") {
        return { user: true, backup: true, bitgo: false };
      }
      // Regular multisig uses user + bitgo
      return { user: true, backup: false, bitgo: true };
    default:
      throw new Error(`Unknown signature stage: ${String(signatureStage)}`);
  }
}

/**
 * Verify signature state for a specific input in a PSBT
 * @param bitgoPsbt - The PSBT to verify
 * @param rootWalletKeys - Wallet keys for verification
 * @param inputIndex - The input index to verify
 * @param inputType - The type of input (for replay protection handling)
 * @param expectedSignatures - Expected signature state for each key or replay protection
 */
function verifyInputSignatures(
  bitgoPsbt: BitGoPsbt,
  rootWalletKeys: utxolib.bitgo.RootWalletKeys,
  inputIndex: number,
  expectedSignatures: ExpectedSignatures,
): void {
  // Handle replay protection inputs (P2shP2pk)
  if ("hasReplayProtectionSignature" in expectedSignatures) {
    const replayProtectionScript = Buffer.from(
      "a91420b37094d82a513451ff0ccd9db23aba05bc5ef387",
      "hex",
    );
    const hasReplaySig = bitgoPsbt.verifyReplayProtectionSignature(inputIndex, {
      outputScripts: [replayProtectionScript],
    });
    assert.strictEqual(
      hasReplaySig,
      expectedSignatures.hasReplayProtectionSignature,
      `Input ${inputIndex} replay protection signature mismatch`,
    );
    return;
  }

  // Handle standard multisig inputs
  const xpubs = rootWalletKeys.triple;

  const hasUserSig = bitgoPsbt.verifySignature(inputIndex, xpubs[0].toBase58());
  const hasBackupSig = bitgoPsbt.verifySignature(inputIndex, xpubs[1].toBase58());
  const hasBitGoSig = bitgoPsbt.verifySignature(inputIndex, xpubs[2].toBase58());

  assert.strictEqual(
    hasUserSig,
    expectedSignatures.user,
    `Input ${inputIndex} user key signature mismatch`,
  );
  assert.strictEqual(
    hasBackupSig,
    expectedSignatures.backup,
    `Input ${inputIndex} backup key signature mismatch`,
  );
  assert.strictEqual(
    hasBitGoSig,
    expectedSignatures.bitgo,
    `Input ${inputIndex} BitGo key signature mismatch`,
  );
}

describe("verifySignature", function () {
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
      let rootWalletKeys: utxolib.bitgo.RootWalletKeys;
      let unsignedFixture: Fixture;
      let halfsignedFixture: Fixture;
      let fullsignedFixture: Fixture;
      let unsignedBitgoPsbt: BitGoPsbt;
      let halfsignedBitgoPsbt: BitGoPsbt;
      let fullsignedBitgoPsbt: BitGoPsbt;

      before(function () {
        rootWalletKeys = loadWalletKeysFromFixture(networkName);
        unsignedFixture = loadPsbtFixture(networkName, "unsigned");
        halfsignedFixture = loadPsbtFixture(networkName, "halfsigned");
        fullsignedFixture = loadPsbtFixture(networkName, "fullsigned");
        unsignedBitgoPsbt = fixedScriptWallet.BitGoPsbt.fromBytes(
          getPsbtBuffer(unsignedFixture),
          networkName,
        );
        halfsignedBitgoPsbt = fixedScriptWallet.BitGoPsbt.fromBytes(
          getPsbtBuffer(halfsignedFixture),
          networkName,
        );
        fullsignedBitgoPsbt = fixedScriptWallet.BitGoPsbt.fromBytes(
          getPsbtBuffer(fullsignedFixture),
          networkName,
        );
      });

      describe("unsigned PSBT", function () {
        it("should return false for unsigned inputs", function () {
          // Verify all xpubs return false for all inputs
          unsignedFixture.psbtInputs.forEach((input, index) => {
            verifyInputSignatures(
              unsignedBitgoPsbt,
              rootWalletKeys,
              index,
              getExpectedSignatures(input.type, "unsigned"),
            );
          });
        });
      });

      describe("half-signed PSBT", function () {
        it("should return true for signed xpubs and false for unsigned", function () {
          halfsignedFixture.psbtInputs.forEach((input, index) => {
            verifyInputSignatures(
              halfsignedBitgoPsbt,
              rootWalletKeys,
              index,
              getExpectedSignatures(input.type, "halfsigned"),
            );
          });
        });
      });

      describe("fully signed PSBT", function () {
        it("should have 2 signatures (2-of-3 multisig)", function () {
          // In fullsigned fixtures, verify 2 signatures exist per multisig input
          fullsignedFixture.psbtInputs.forEach((input, index) => {
            verifyInputSignatures(
              fullsignedBitgoPsbt,
              rootWalletKeys,
              index,
              getExpectedSignatures(input.type, "fullsigned"),
            );
          });
        });
      });

      describe("error handling", function () {
        it("should throw error for out of bounds input index", function () {
          const xpubs = rootWalletKeys.triple;

          assert.throws(
            () => {
              fullsignedBitgoPsbt.verifySignature(999, xpubs[0].toBase58());
            },
            (error: Error) => {
              return error.message.includes("Input index 999 out of bounds");
            },
            "Should throw error for out of bounds input index",
          );
        });

        it("should throw error for invalid xpub", function () {
          assert.throws(
            () => {
              fullsignedBitgoPsbt.verifySignature(0, "invalid-xpub");
            },
            (error: Error) => {
              return error.message.includes("Invalid xpub");
            },
            "Should throw error for invalid xpub",
          );
        });

        it("should return false for xpub not in derivation path", function () {
          // Create a different xpub that's not in the wallet
          // Use a proper 32-byte seed (256 bits)
          const differentSeed = Buffer.alloc(32, 0xaa); // 32 bytes filled with 0xaa
          const differentKey = utxolib.bip32.fromSeed(differentSeed, network);
          const differentXpub = differentKey.neutered();

          const result = fullsignedBitgoPsbt.verifySignature(0, differentXpub.toBase58());
          assert.strictEqual(
            result,
            false,
            "Should return false for xpub not in PSBT derivation paths",
          );
        });
      });
    });
  });
});
