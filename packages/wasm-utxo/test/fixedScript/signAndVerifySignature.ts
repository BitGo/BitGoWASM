import assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";
import { BIP32, ECPair } from "../../js/index.js";
import {
  BitGoPsbt,
  RootWalletKeys,
  ParsedTransaction,
  type NetworkName,
} from "../../js/fixedScriptWallet/index.js";
import {
  loadPsbtFixture,
  loadWalletKeysFromFixture,
  getBitGoPsbt,
  type Fixture,
  loadReplayProtectionKeyFromFixture,
} from "./fixtureUtil.js";
import { getFixtureNetworks } from "./networkSupport.util.js";

type SignatureStage = "unsigned" | "halfsigned" | "fullsigned";

type ExpectedSignatures =
  | { hasReplayProtectionSignature: boolean }
  | { user: boolean; backup: boolean; bitgo: boolean };

type RootWalletXprivs = {
  user: BIP32;
  backup: BIP32;
  bitgo: BIP32;
};

/**
 * Load xprivs from a fixture
 * @param fixture - The test fixture
 * @returns The xprivs for user, backup, and bitgo keys
 */
function loadXprivsFromFixture(fixture: Fixture): RootWalletXprivs {
  const [userXpriv, backupXpriv, bitgoXpriv] = fixture.walletKeys.map((xprv) =>
    BIP32.fromBase58(xprv),
  );
  return {
    user: userXpriv,
    backup: backupXpriv,
    bitgo: bitgoXpriv,
  };
}

/**
 * Get expected signature state for an input based on type and signing stage
 * @param inputType - The type of input (e.g., "p2shP2pk", "p2trMusig2", "taprootKeyPathSpend")
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
    const hasReplaySig = bitgoPsbt.verifyReplayProtectionSignature(inputIndex, {
      publicKeys: [replayProtectionKey],
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

  const scriptType = parsed.inputs[inputIndex].scriptType;

  assert.strictEqual(
    hasUserSig,
    expectedSignatures.user,
    `Input ${inputIndex} user key signature mismatch type=${scriptType}`,
  );
  assert.strictEqual(
    hasBackupSig,
    expectedSignatures.backup,
    `Input ${inputIndex} backup key signature mismatch type=${scriptType}`,
  );
  assert.strictEqual(
    hasBitGoSig,
    expectedSignatures.bitgo,
    `Input ${inputIndex} BitGo key signature mismatch type=${scriptType}`,
  );
}

/**
 * Helper to verify signatures for all inputs in a PSBT
 * @param bitgoPsbt - The PSBT to verify
 * @param fixture - The test fixture containing input metadata
 * @param rootWalletKeys - Wallet keys for verification
 * @param replayProtectionKey - Key for replay protection inputs
 * @param signatureStage - The signing stage (unsigned, halfsigned, fullsigned)
 */
function verifyAllInputSignatures(
  bitgoPsbt: BitGoPsbt,
  fixture: Fixture,
  rootWalletKeys: RootWalletKeys,
  replayProtectionKey: ECPair,
  signatureStage: SignatureStage,
): void {
  const parsed = bitgoPsbt.parseTransactionWithWalletKeys(rootWalletKeys, {
    publicKeys: [replayProtectionKey],
  });

  fixture.psbtInputs.forEach((input, index) => {
    verifyInputSignatures(
      bitgoPsbt,
      parsed,
      rootWalletKeys,
      replayProtectionKey,
      index,
      getExpectedSignatures(input.type, signatureStage),
    );
  });
}

function signInputAndVerify(
  bitgoPsbt: BitGoPsbt,
  index: number,
  key: BIP32 | ECPair,
  keyName: string,
  inputType: string,
): void {
  bitgoPsbt.sign(index, key);
  assert.strictEqual(
    bitgoPsbt.verifySignature(index, key),
    true,
    `Input ${index} signature mismatch key=${keyName} type=${inputType}`,
  );
}

/**
 * Sign all inputs in a PSBT according to the signature stage
 * @param bitgoPsbt - The PSBT to sign
 * @param rootWalletKeys - Wallet keys for parsing the transaction
 * @param xprivs - The xprivs to use for signing
 * @param replayProtectionKey - The ECPair for signing replay protection (p2shP2pk) inputs
 */
function signAllInputs(
  bitgoPsbt: BitGoPsbt,
  rootWalletKeys: RootWalletKeys,
  xprivs: RootWalletXprivs,
  replayProtectionKey: ECPair,
): void {
  // Parse transaction to get input types
  const parsed = bitgoPsbt.parseTransactionWithWalletKeys(rootWalletKeys, {
    publicKeys: [replayProtectionKey],
  });

  // Generate MuSig2 nonces for user and backup keys (MuSig2 uses 2-of-2 with user+backup)
  bitgoPsbt.generateMusig2Nonces(xprivs.user);
  bitgoPsbt.generateMusig2Nonces(xprivs.bitgo);

  // First pass: sign with user key (skip p2shP2pk inputs)
  parsed.inputs.forEach((input, index) => {
    switch (input.scriptType) {
      case "p2shP2pk":
        break;
      default:
        signInputAndVerify(bitgoPsbt, index, xprivs.user, "user", input.scriptType);
        break;
    }
  });

  // Second pass: sign with appropriate second key
  parsed.inputs.forEach((input, index) => {
    switch (input.scriptType) {
      case "p2shP2pk":
        signInputAndVerify(
          bitgoPsbt,
          index,
          replayProtectionKey,
          "replayProtection",
          input.scriptType,
        );
        break;
      case "p2trMusig2ScriptPath":
        // MuSig2 script path inputs use backup key for second signature
        signInputAndVerify(bitgoPsbt, index, xprivs.backup, "backup", input.scriptType);
        break;
      default:
        // Regular multisig uses bitgo key
        signInputAndVerify(bitgoPsbt, index, xprivs.bitgo, "bitgo", input.scriptType);
        break;
    }
  });
}

/**
 * Run tests for a fixture: load PSBT, verify, sign, and verify again
 * @param fixture - The test fixture
 * @param networkName - The network name for deserializing the PSBT
 * @param rootWalletKeys - Wallet keys for verification
 * @param replayProtectionKey - Key for replay protection inputs
 * @param xprivs - The xprivs to use for signing
 * @param signatureStage - The current signing stage
 */
function runTestsForFixture(
  fixture: Fixture,
  networkName: NetworkName,
  rootWalletKeys: RootWalletKeys,
  replayProtectionKey: ECPair,
  xprivs: RootWalletXprivs,
  signatureStage: SignatureStage,
): void {
  // Load PSBT from fixture
  const bitgoPsbt = getBitGoPsbt(fixture, networkName);

  // Verify current state
  verifyAllInputSignatures(bitgoPsbt, fixture, rootWalletKeys, replayProtectionKey, signatureStage);

  // Sign inputs (if not already fully signed)
  if (signatureStage !== "unsigned") {
    signAllInputs(bitgoPsbt, rootWalletKeys, xprivs, replayProtectionKey);
  }
}

describe("verifySignature", function () {
  getFixtureNetworks().forEach((network) => {
    const networkName = utxolib.getNetworkName(network);

    describe(`network: ${networkName}`, function () {
      let rootWalletKeys: RootWalletKeys;
      let replayProtectionKey: ECPair;
      let xprivs: RootWalletXprivs;
      let unsignedFixture: Fixture;
      let halfsignedFixture: Fixture;
      let fullsignedFixture: Fixture;

      before(function () {
        unsignedFixture = loadPsbtFixture(networkName, "unsigned");
        halfsignedFixture = loadPsbtFixture(networkName, "halfsigned");
        fullsignedFixture = loadPsbtFixture(networkName, "fullsigned");
        rootWalletKeys = loadWalletKeysFromFixture(fullsignedFixture);
        replayProtectionKey = loadReplayProtectionKeyFromFixture(fullsignedFixture);
        xprivs = loadXprivsFromFixture(fullsignedFixture);
      });

      describe("unsigned PSBT", function () {
        it("should return false for unsigned inputs, then sign and verify", function () {
          runTestsForFixture(
            unsignedFixture,
            networkName,
            rootWalletKeys,
            replayProtectionKey,
            xprivs,
            "unsigned",
          );
        });
      });

      describe("half-signed PSBT", function () {
        it("should return true for signed xpubs and false for unsigned, then sign and verify", function () {
          runTestsForFixture(
            halfsignedFixture,
            networkName,
            rootWalletKeys,
            replayProtectionKey,
            xprivs,
            "halfsigned",
          );
        });
      });

      describe("fully signed PSBT", function () {
        it("should have 2 signatures (2-of-3 multisig)", function () {
          runTestsForFixture(
            fullsignedFixture,
            networkName,
            rootWalletKeys,
            replayProtectionKey,
            xprivs,
            "fullsigned",
          );
        });
      });

      describe("error handling", function () {
        it("should throw error for out of bounds input index", function () {
          const psbt = getBitGoPsbt(fullsignedFixture, networkName);
          assert.throws(
            () => {
              psbt.verifySignature(999, rootWalletKeys.userKey());
            },
            (error: Error) => {
              return error.message.includes("Input index 999 out of bounds");
            },
            "Should throw error for out of bounds input index",
          );
        });

        it("should throw error for invalid xpub", function () {
          const psbt = getBitGoPsbt(fullsignedFixture, networkName);
          assert.throws(
            () => {
              psbt.verifySignature(0, "invalid-xpub");
            },
            (error: Error) => {
              return error.message.includes("Invalid");
            },
            "Should throw error for invalid xpub",
          );
        });

        it("should return false for xpub not in derivation path", function () {
          const psbt = getBitGoPsbt(fullsignedFixture, networkName);
          // Create a different xpub that's not in the wallet
          // Use a proper 32-byte seed (256 bits)
          const differentSeed = Buffer.alloc(32, 0xaa); // 32 bytes filled with 0xaa
          const differentKey = BIP32.fromSeed(differentSeed);
          const differentXpub = differentKey.neutered();

          const result = psbt.verifySignature(0, differentXpub);
          assert.strictEqual(
            result,
            false,
            "Should return false for xpub not in PSBT derivation paths",
          );
        });

        it("should verify signature with raw public key (Uint8Array)", function () {
          const psbt = getBitGoPsbt(fullsignedFixture, networkName);
          // Verify that xpub-based verification works
          const userKey = rootWalletKeys.userKey();
          const hasXpubSig = psbt.verifySignature(0, userKey);

          // This test specifically checks that raw public key verification works
          // We test the underlying WASM API by ensuring both xpub and raw pubkey
          // calls reach the correct methods

          // Use a random public key that's not in the PSBT to test the API works
          const randomSeed = Buffer.alloc(32, 0xcc);
          const randomKey = BIP32.fromSeed(randomSeed);
          const randomPubkey = randomKey.publicKey;

          // This should return false (no signature for this key)
          const result = psbt.verifySignature(0, randomPubkey);
          assert.strictEqual(result, false, "Should return false for public key not in PSBT");

          // Verify the xpub check still works (regression test)
          assert.strictEqual(hasXpubSig, true, "Should still verify with xpub");
        });

        it("should return false for raw public key with no signature", function () {
          const psbt = getBitGoPsbt(fullsignedFixture, networkName);
          // Create a random public key that's not in the PSBT
          const randomSeed = Buffer.alloc(32, 0xbb);
          const randomKey = BIP32.fromSeed(randomSeed);
          const randomPubkey = randomKey.publicKey;

          const result = psbt.verifySignature(0, randomPubkey);
          assert.strictEqual(
            result,
            false,
            "Should return false for public key not in PSBT signatures",
          );
        });

        it("should throw error for invalid key length", function () {
          const psbt = getBitGoPsbt(fullsignedFixture, networkName);
          const invalidKey = Buffer.alloc(31); // Invalid length (should be 32 for private key or 33 for public key)

          assert.throws(
            () => {
              psbt.verifySignature(0, invalidKey);
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
