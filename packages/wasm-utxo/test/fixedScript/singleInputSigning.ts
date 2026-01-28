/**
 * Tests for single-input signing behavior
 *
 * Verifies that signInput() truly only signs the specified input and
 * does not add signatures to other inputs.
 */

import assert from "node:assert";
import { BIP32 } from "../../js/bip32.js";
import { BitGoPsbt, RootWalletKeys } from "../../js/fixedScriptWallet/index.js";
import type { BIP32Interface } from "../../js/bip32.js";
import type { IWalletKeys } from "../../js/fixedScriptWallet/RootWalletKeys.js";
import type { NetworkName } from "../../js/fixedScriptWallet/BitGoPsbt.js";

type Triple<T> = [T, T, T];

function createTestWalletKeys(): { keys: RootWalletKeys; xprivs: Triple<BIP32> } {
  const seeds = [
    Buffer.alloc(32, 0x01), // user
    Buffer.alloc(32, 0x02), // backup
    Buffer.alloc(32, 0x03), // bitgo
  ];

  const xprivs = seeds.map((seed) => BIP32.fromSeed(seed)) as Triple<BIP32>;
  const xpubs = xprivs.map((k) => k.neutered()) as unknown as Triple<BIP32Interface>;

  const walletKeysLike: IWalletKeys = {
    triple: xpubs,
    derivationPrefixes: ["0/0", "0/0", "0/0"],
  };

  return {
    keys: RootWalletKeys.from(walletKeysLike),
    xprivs,
  };
}

type SignPath = { signer: "user" | "backup" | "bitgo"; cosigner: "user" | "backup" | "bitgo" };

function createPsbtWithInputs(
  inputCount: number,
  chain: number,
  walletKeys: RootWalletKeys,
  signPath?: SignPath,
): BitGoPsbt {
  const network: NetworkName = "bitcoin";

  const psbt = BitGoPsbt.createEmpty(network, walletKeys, {
    version: 2,
    lockTime: 0,
  });

  for (let i = 0; i < inputCount; i++) {
    const txidBytes = Buffer.alloc(32);
    txidBytes.writeUInt32BE(i, 0);
    const txid = txidBytes.toString("hex");

    const walletOptions: { scriptId: { chain: number; index: number }; signPath?: SignPath } = {
      scriptId: { chain, index: i },
    };

    // p2tr and p2trMusig2 require signPath
    if (signPath) {
      walletOptions.signPath = signPath;
    }

    psbt.addWalletInput(
      {
        txid,
        vout: 0,
        value: BigInt(100000),
        sequence: 0xfffffffe,
      },
      walletKeys,
      walletOptions,
    );
  }

  // Add output
  psbt.addWalletOutput(walletKeys, {
    chain: chain + 1,
    index: 0,
    value: BigInt(inputCount * 100000 - 10000),
  });

  return psbt;
}

/**
 * Count signatures on a specific input by checking each key
 */
function countInputSignatures(psbt: BitGoPsbt, inputIndex: number, xprivs: Triple<BIP32>): number {
  let count = 0;
  for (const xpriv of xprivs) {
    if (psbt.verifySignature(inputIndex, xpriv.neutered())) {
      count++;
    }
  }
  return count;
}

/**
 * Check if any input other than the specified one has signatures from any key
 */
function hasSignaturesOnOtherInputs(
  psbt: BitGoPsbt,
  inputCount: number,
  excludeIndex: number,
  xprivs: Triple<BIP32>,
): boolean {
  for (let i = 0; i < inputCount; i++) {
    if (i === excludeIndex) continue;

    for (const xpriv of xprivs) {
      if (psbt.verifySignature(i, xpriv.neutered())) {
        return true;
      }
    }
  }

  return false;
}

describe("Single-input signing", function () {
  let walletKeys: RootWalletKeys;
  let xprivs: Triple<BIP32>;

  before(function () {
    const testKeys = createTestWalletKeys();
    walletKeys = testKeys.keys;
    xprivs = testKeys.xprivs;
  });

  describe("p2sh (ECDSA)", function () {
    it("should sign only the specified input, not others", function () {
      const psbt = createPsbtWithInputs(5, 0, walletKeys); // chain 0 = p2sh

      // Sign only input 2 with user key
      psbt.signInput(2, xprivs[0]);

      // Verify input 2 has a signature from user
      assert.strictEqual(
        psbt.verifySignature(2, xprivs[0].neutered()),
        true,
        "Input 2 should have user signature",
      );

      // Verify no other inputs have signatures
      assert.strictEqual(
        hasSignaturesOnOtherInputs(psbt, 5, 2, xprivs),
        false,
        "Other inputs should not have signatures",
      );
    });

    it("should allow signing different inputs with different keys", function () {
      const psbt = createPsbtWithInputs(5, 0, walletKeys);

      // Sign input 1 with user key
      psbt.signInput(1, xprivs[0]);

      // Sign input 3 with bitgo key
      psbt.signInput(3, xprivs[2]);

      // Verify input 1 has user's signature only
      assert.strictEqual(
        psbt.verifySignature(1, xprivs[0].neutered()),
        true,
        "Input 1 should have user sig",
      );
      assert.strictEqual(
        psbt.verifySignature(1, xprivs[2].neutered()),
        false,
        "Input 1 should not have bitgo sig",
      );

      // Verify input 3 has bitgo's signature only
      assert.strictEqual(
        psbt.verifySignature(3, xprivs[2].neutered()),
        true,
        "Input 3 should have bitgo sig",
      );
      assert.strictEqual(
        psbt.verifySignature(3, xprivs[0].neutered()),
        false,
        "Input 3 should not have user sig",
      );

      // Verify inputs 0, 2, 4 have no signatures
      assert.strictEqual(countInputSignatures(psbt, 0, xprivs), 0, "Input 0 should have no sigs");
      assert.strictEqual(countInputSignatures(psbt, 2, xprivs), 0, "Input 2 should have no sigs");
      assert.strictEqual(countInputSignatures(psbt, 4, xprivs), 0, "Input 4 should have no sigs");
    });

    it("should allow completing a single input with both signers", function () {
      const psbt = createPsbtWithInputs(5, 0, walletKeys);

      // Sign input 2 with user key
      psbt.signInput(2, xprivs[0]);

      // Sign input 2 with bitgo key
      psbt.signInput(2, xprivs[2]);

      // Verify input 2 has 2 signatures (user + bitgo)
      assert.strictEqual(
        countInputSignatures(psbt, 2, xprivs),
        2,
        "Input 2 should have 2 signatures",
      );

      // Verify no other inputs have signatures
      assert.strictEqual(
        hasSignaturesOnOtherInputs(psbt, 5, 2, xprivs),
        false,
        "Other inputs should not have signatures",
      );
    });
  });

  describe("p2wsh (SegWit ECDSA)", function () {
    it("should sign only the specified input, not others", function () {
      const psbt = createPsbtWithInputs(5, 20, walletKeys); // chain 20 = p2wsh

      // Sign only input 0 with user key
      psbt.signInput(0, xprivs[0]);

      // Verify input 0 has a signature
      assert.strictEqual(
        psbt.verifySignature(0, xprivs[0].neutered()),
        true,
        "Input 0 should have signature",
      );

      // Verify no other inputs have signatures
      assert.strictEqual(
        hasSignaturesOnOtherInputs(psbt, 5, 0, xprivs),
        false,
        "Other inputs should not have signatures",
      );
    });
  });

  describe("p2trMusig2KeyPath (MuSig2)", function () {
    it("should sign only the specified input, not others", function () {
      // chain 40 = p2trMusig2, requires signPath with signer and cosigner
      const psbt = createPsbtWithInputs(5, 40, walletKeys, { signer: "user", cosigner: "bitgo" });

      // Generate nonces for all inputs (required for MuSig2)
      psbt.generateMusig2Nonces(xprivs[0]);
      psbt.generateMusig2Nonces(xprivs[2]);

      // Sign only input 1 with user key
      psbt.signInput(1, xprivs[0]);

      // Verify input 1 has a partial signature from user
      assert.strictEqual(
        psbt.verifySignature(1, xprivs[0].neutered()),
        true,
        "Input 1 should have user signature",
      );

      // Verify no other inputs have signatures
      assert.strictEqual(
        hasSignaturesOnOtherInputs(psbt, 5, 1, xprivs),
        false,
        "Other inputs should not have signatures",
      );
    });

    it("should allow completing a single input with both signers", function () {
      const psbt = createPsbtWithInputs(5, 40, walletKeys, { signer: "user", cosigner: "bitgo" });

      // Generate nonces
      psbt.generateMusig2Nonces(xprivs[0]);
      psbt.generateMusig2Nonces(xprivs[2]);

      // Sign input 3 with user key
      psbt.signInput(3, xprivs[0]);

      // Sign input 3 with bitgo key
      psbt.signInput(3, xprivs[2]);

      // Verify input 3 has 2 partial signatures
      assert.strictEqual(
        countInputSignatures(psbt, 3, xprivs),
        2,
        "Input 3 should have 2 signatures",
      );

      // Verify no other inputs have signatures
      assert.strictEqual(
        hasSignaturesOnOtherInputs(psbt, 5, 3, xprivs),
        false,
        "Other inputs should not have signatures",
      );
    });
  });

  describe("bulk vs single-input comparison", function () {
    it("bulk sign should sign all inputs, single-input should sign one", function () {
      // Create two identical PSBTs
      const psbtBulk = createPsbtWithInputs(5, 0, walletKeys);
      const psbtSingle = createPsbtWithInputs(5, 0, walletKeys);

      // Bulk sign all inputs
      const bulkSigned = psbtBulk.sign(xprivs[0]);
      assert.strictEqual(bulkSigned.length, 5, "Bulk sign should sign all 5 inputs");

      // Verify all inputs have signatures
      for (let i = 0; i < 5; i++) {
        assert.strictEqual(
          psbtBulk.verifySignature(i, xprivs[0].neutered()),
          true,
          `Bulk: Input ${i} should have signature`,
        );
      }

      // Single-input sign only input 2
      psbtSingle.signInput(2, xprivs[0]);

      // Verify only input 2 has a signature
      assert.strictEqual(
        psbtSingle.verifySignature(2, xprivs[0].neutered()),
        true,
        "Single: Input 2 should have signature",
      );
      assert.strictEqual(
        hasSignaturesOnOtherInputs(psbtSingle, 5, 2, xprivs),
        false,
        "Single: Other inputs should not have signatures",
      );
    });
  });
});
