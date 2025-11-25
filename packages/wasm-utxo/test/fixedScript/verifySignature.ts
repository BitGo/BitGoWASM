import assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";
import { fixedScriptWallet, BIP32, ECPair } from "../../js/index.js";
import { BitGoPsbt, RootWalletKeys, ParsedTransaction } from "../../js/fixedScriptWallet/index.js";
import {
  loadPsbtFixture,
  loadWalletKeysFromFixture,
  getPsbtBuffer,
  type Fixture,
  loadReplayProtectionKeyFromFixture,
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
  parsed: ParsedTransaction,
  rootWalletKeys: RootWalletKeys,
  replayProtectionKey: ECPair,
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

  if (parsed.inputs[inputIndex].scriptType === "p2shP2pk") {
    const hasReplaySig = bitgoPsbt.verifySignature(inputIndex, replayProtectionKey);
    assert.ok(
      "hasReplayProtectionSignature" in expectedSignatures,
      "Expected hasReplayProtectionSignature to be present",
    );
    assert.strictEqual(
      hasReplaySig,
      expectedSignatures.hasReplayProtectionSignature,
      `Input ${inputIndex} replay protection signature mismatch`,
    );
    return;
  }

  // Handle standard multisig inputs
  const hasUserSig = bitgoPsbt.verifySignature(inputIndex, rootWalletKeys.userKey());
  const hasBackupSig = bitgoPsbt.verifySignature(inputIndex, rootWalletKeys.backupKey());
  const hasBitGoSig = bitgoPsbt.verifySignature(inputIndex, rootWalletKeys.bitgoKey());

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
      let rootWalletKeys: RootWalletKeys;
      let replayProtectionKey: ECPair;
      let unsignedFixture: Fixture;
      let halfsignedFixture: Fixture;
      let fullsignedFixture: Fixture;
      let unsignedBitgoPsbt: BitGoPsbt;
      let halfsignedBitgoPsbt: BitGoPsbt;
      let fullsignedBitgoPsbt: BitGoPsbt;
      let replayProtectionScript: Uint8Array;

      before(function () {
        unsignedFixture = loadPsbtFixture(networkName, "unsigned");
        halfsignedFixture = loadPsbtFixture(networkName, "halfsigned");
        fullsignedFixture = loadPsbtFixture(networkName, "fullsigned");
        rootWalletKeys = loadWalletKeysFromFixture(fullsignedFixture);
        replayProtectionKey = loadReplayProtectionKeyFromFixture(fullsignedFixture);
        replayProtectionScript = Buffer.from(
          "a91420b37094d82a513451ff0ccd9db23aba05bc5ef387",
          "hex",
        );
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
          const parsed = unsignedBitgoPsbt.parseTransactionWithWalletKeys(rootWalletKeys, {
            outputScripts: [replayProtectionScript],
          });
          // Verify all xpubs return false for all inputs
          unsignedFixture.psbtInputs.forEach((input, index) => {
            verifyInputSignatures(
              unsignedBitgoPsbt,
              parsed,
              rootWalletKeys,
              replayProtectionKey,
              index,
              getExpectedSignatures(input.type, "unsigned"),
            );
          });
        });
      });

      describe("half-signed PSBT", function () {
        it("should return true for signed xpubs and false for unsigned", function () {
          const parsed = halfsignedBitgoPsbt.parseTransactionWithWalletKeys(rootWalletKeys, {
            outputScripts: [replayProtectionScript],
          });
          halfsignedFixture.psbtInputs.forEach((input, index) => {
            verifyInputSignatures(
              halfsignedBitgoPsbt,
              parsed,
              rootWalletKeys,
              replayProtectionKey,
              index,
              getExpectedSignatures(input.type, "halfsigned"),
            );
          });
        });
      });

      describe("fully signed PSBT", function () {
        it("should have 2 signatures (2-of-3 multisig)", function () {
          // In fullsigned fixtures, verify 2 signatures exist per multisig input
          const parsed = fullsignedBitgoPsbt.parseTransactionWithWalletKeys(rootWalletKeys, {
            outputScripts: [replayProtectionScript],
          });
          fullsignedFixture.psbtInputs.forEach((input, index) => {
            verifyInputSignatures(
              fullsignedBitgoPsbt,
              parsed,
              rootWalletKeys,
              replayProtectionKey,
              index,
              getExpectedSignatures(input.type, "fullsigned"),
            );
          });
        });
      });

      describe("error handling", function () {
        it("should throw error for out of bounds input index", function () {
          assert.throws(
            () => {
              fullsignedBitgoPsbt.verifySignature(999, rootWalletKeys.userKey());
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
              return error.message.includes("Invalid");
            },
            "Should throw error for invalid xpub",
          );
        });

        it("should return false for xpub not in derivation path", function () {
          // Create a different xpub that's not in the wallet
          // Use a proper 32-byte seed (256 bits)
          const differentSeed = Buffer.alloc(32, 0xaa); // 32 bytes filled with 0xaa
          const differentKey = BIP32.fromSeed(differentSeed);
          const differentXpub = differentKey.neutered();

          const result = fullsignedBitgoPsbt.verifySignature(0, differentXpub);
          assert.strictEqual(
            result,
            false,
            "Should return false for xpub not in PSBT derivation paths",
          );
        });

        it("should verify signature with raw public key (Uint8Array)", function () {
          // Verify that xpub-based verification works
          const userKey = rootWalletKeys.userKey();
          const hasXpubSig = fullsignedBitgoPsbt.verifySignature(0, userKey);

          // This test specifically checks that raw public key verification works
          // We test the underlying WASM API by ensuring both xpub and raw pubkey
          // calls reach the correct methods

          // Use a random public key that's not in the PSBT to test the API works
          const randomSeed = Buffer.alloc(32, 0xcc);
          const randomKey = BIP32.fromSeed(randomSeed);
          const randomPubkey = randomKey.publicKey;

          // This should return false (no signature for this key)
          const result = fullsignedBitgoPsbt.verifySignature(0, randomPubkey);
          assert.strictEqual(result, false, "Should return false for public key not in PSBT");

          // Verify the xpub check still works (regression test)
          assert.strictEqual(hasXpubSig, true, "Should still verify with xpub");
        });

        it("should return false for raw public key with no signature", function () {
          // Create a random public key that's not in the PSBT
          const randomSeed = Buffer.alloc(32, 0xbb);
          const randomKey = BIP32.fromSeed(randomSeed);
          const randomPubkey = randomKey.publicKey;

          const result = fullsignedBitgoPsbt.verifySignature(0, randomPubkey);
          assert.strictEqual(
            result,
            false,
            "Should return false for public key not in PSBT signatures",
          );
        });

        it("should throw error for invalid key length", function () {
          const invalidKey = Buffer.alloc(31); // Invalid length (should be 32 for private key or 33 for public key)

          assert.throws(
            () => {
              fullsignedBitgoPsbt.verifySignature(0, invalidKey);
            },
            (error: Error) => {
              return error.message.includes("Invalid key length");
            },
            "Should throw error for invalid key length",
          );
        });
      });
    });
  });
});
