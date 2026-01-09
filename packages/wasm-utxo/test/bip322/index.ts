import assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";
import { bip322, fixedScriptWallet, BIP32 } from "../../js/index.js";
import type { Triple } from "../../js/triple.js";

/**
 * Create test wallet keys from a seed string
 */
function createTestWalletKeys(seed: string): {
  xpubs: Triple<string>;
  xprivs: Triple<string>;
} {
  const keys = utxolib.testutil.getKeyTriple(seed);

  const xpubs: Triple<string> = [
    keys[0].neutered().toBase58(),
    keys[1].neutered().toBase58(),
    keys[2].neutered().toBase58(),
  ];

  const xprivs: Triple<string> = [keys[0].toBase58(), keys[1].toBase58(), keys[2].toBase58()];

  return { xpubs, xprivs };
}

describe("BIP-0322", function () {
  describe("addBip322Input", function () {
    const { xpubs } = createTestWalletKeys("bip322_test");
    const walletKeys = fixedScriptWallet.RootWalletKeys.from(xpubs);

    it("should add a valid BIP-0322 input for p2shP2wsh", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const inputIndex = bip322.addBip322Input(psbt, {
        message: "Hello, BitGo!",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });

      assert.strictEqual(inputIndex, 0, "First input should have index 0");
      assert.strictEqual(psbt.version, 0, "BIP-0322 PSBTs must have version 0");
      assert.strictEqual(psbt.lockTime, 0, "BIP-0322 PSBTs must have lockTime 0");
    });

    it("should add a valid BIP-0322 input for p2wsh", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const inputIndex = bip322.addBip322Input(psbt, {
        message: "Test p2wsh",
        scriptId: { chain: 20, index: 5 },
        rootWalletKeys: walletKeys,
      });

      assert.strictEqual(inputIndex, 0);
      assert.strictEqual(psbt.version, 0);
    });

    it("should add multiple BIP-0322 inputs", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const idx0 = bip322.addBip322Input(psbt, {
        message: "Message 1",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });
      const idx1 = bip322.addBip322Input(psbt, {
        message: "Message 2",
        scriptId: { chain: 10, index: 1 },
        rootWalletKeys: walletKeys,
      });
      const idx2 = bip322.addBip322Input(psbt, {
        message: "Message 3",
        scriptId: { chain: 20, index: 0 },
        rootWalletKeys: walletKeys,
      });

      assert.strictEqual(idx0, 0);
      assert.strictEqual(idx1, 1);
      assert.strictEqual(idx2, 2);
      assert.strictEqual(psbt.version, 0);
    });

    it("should throw for non-version-0 PSBT", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 2 });

      assert.throws(() => {
        bip322.addBip322Input(psbt, {
          message: "Test",
          scriptId: { chain: 10, index: 0 },
          rootWalletKeys: walletKeys,
        });
      }, /BIP-0322 PSBT must have version 0/);
    });
  });

  describe("sign and verify per-input", function () {
    const { xpubs, xprivs } = createTestWalletKeys("bip322_sign_test");
    const walletKeys = fixedScriptWallet.RootWalletKeys.from(xpubs);

    it("should sign and verify a p2shP2wsh message", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const inputIndex = bip322.addBip322Input(psbt, {
        message: "Proof of control",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });

      // Sign with user and bitgo keys (2-of-3)
      const userXpriv = BIP32.fromBase58(xprivs[0]);
      const bitgoXpriv = BIP32.fromBase58(xprivs[2]);

      psbt.sign(inputIndex, userXpriv);
      psbt.sign(inputIndex, bitgoXpriv);

      // Verify the input and check signers
      const signers = bip322.verifyBip322PsbtInput(psbt, inputIndex, {
        message: "Proof of control",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });
      assert.deepStrictEqual(signers, ["user", "bitgo"]);
    });

    it("should sign and verify a p2wsh message", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const inputIndex = bip322.addBip322Input(psbt, {
        message: "P2WSH proof",
        scriptId: { chain: 20, index: 3 },
        rootWalletKeys: walletKeys,
      });

      // Sign with user and bitgo keys
      const userXpriv = BIP32.fromBase58(xprivs[0]);
      const bitgoXpriv = BIP32.fromBase58(xprivs[2]);

      psbt.sign(inputIndex, userXpriv);
      psbt.sign(inputIndex, bitgoXpriv);

      // Verify and check signers
      const signers = bip322.verifyBip322PsbtInput(psbt, inputIndex, {
        message: "P2WSH proof",
        scriptId: { chain: 20, index: 3 },
        rootWalletKeys: walletKeys,
      });
      assert.deepStrictEqual(signers, ["user", "bitgo"]);
    });

    it("should sign with backup key and return correct signer", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const inputIndex = bip322.addBip322Input(psbt, {
        message: "Backup key test",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });

      // Sign with user and backup keys
      const userXpriv = BIP32.fromBase58(xprivs[0]);
      const backupXpriv = BIP32.fromBase58(xprivs[1]);

      psbt.sign(inputIndex, userXpriv);
      psbt.sign(inputIndex, backupXpriv);

      // Verify and check signers
      const signers = bip322.verifyBip322PsbtInput(psbt, inputIndex, {
        message: "Backup key test",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });
      assert.deepStrictEqual(signers, ["user", "backup"]);
    });

    it("should sign and verify multiple inputs", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const idx0 = bip322.addBip322Input(psbt, {
        message: "Message 1",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });
      const idx1 = bip322.addBip322Input(psbt, {
        message: "Message 2",
        scriptId: { chain: 20, index: 5 },
        rootWalletKeys: walletKeys,
      });

      const userXpriv = BIP32.fromBase58(xprivs[0]);
      const bitgoXpriv = BIP32.fromBase58(xprivs[2]);

      // Sign both inputs
      psbt.sign(idx0, userXpriv);
      psbt.sign(idx0, bitgoXpriv);
      psbt.sign(idx1, userXpriv);
      psbt.sign(idx1, bitgoXpriv);

      // Verify each input individually and check signers
      const signers0 = bip322.verifyBip322PsbtInput(psbt, idx0, {
        message: "Message 1",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });
      const signers1 = bip322.verifyBip322PsbtInput(psbt, idx1, {
        message: "Message 2",
        scriptId: { chain: 20, index: 5 },
        rootWalletKeys: walletKeys,
      });
      assert.deepStrictEqual(signers0, ["user", "bitgo"]);
      assert.deepStrictEqual(signers1, ["user", "bitgo"]);
    });

    it("should fail verification with wrong message", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const inputIndex = bip322.addBip322Input(psbt, {
        message: "Original message",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });

      const userXpriv = BIP32.fromBase58(xprivs[0]);
      const bitgoXpriv = BIP32.fromBase58(xprivs[2]);
      psbt.sign(inputIndex, userXpriv);
      psbt.sign(inputIndex, bitgoXpriv);

      // Verify with wrong message should fail
      assert.throws(() => {
        bip322.verifyBip322PsbtInput(psbt, inputIndex, {
          message: "Different message",
          scriptId: { chain: 10, index: 0 },
          rootWalletKeys: walletKeys,
        });
      }, /wrong to_spend txid/);
    });

    it("should fail verification with wrong scriptId", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const inputIndex = bip322.addBip322Input(psbt, {
        message: "Test message",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });

      const userXpriv = BIP32.fromBase58(xprivs[0]);
      const bitgoXpriv = BIP32.fromBase58(xprivs[2]);
      psbt.sign(inputIndex, userXpriv);
      psbt.sign(inputIndex, bitgoXpriv);

      // Verify with wrong scriptId should fail
      assert.throws(() => {
        bip322.verifyBip322PsbtInput(psbt, inputIndex, {
          message: "Test message",
          scriptId: { chain: 10, index: 1 },
          rootWalletKeys: walletKeys,
        });
      }, /wrong to_spend txid/);
    });

    it("should fail verification with unsigned input", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const inputIndex = bip322.addBip322Input(psbt, {
        message: "Unsigned",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });

      // Verify should fail because no valid signatures from wallet keys
      assert.throws(() => {
        bip322.verifyBip322PsbtInput(psbt, inputIndex, {
          message: "Unsigned",
          scriptId: { chain: 10, index: 0 },
          rootWalletKeys: walletKeys,
        });
      }, /no valid signatures/);
    });

    it("should fail verification with out-of-bounds input index", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      bip322.addBip322Input(psbt, {
        message: "Test",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });

      assert.throws(() => {
        bip322.verifyBip322PsbtInput(psbt, 5, {
          message: "Test",
          scriptId: { chain: 10, index: 0 },
          rootWalletKeys: walletKeys,
        });
      }, /out of bounds/);
    });
  });

  describe("custom tag", function () {
    const { xpubs, xprivs } = createTestWalletKeys("bip322_tag_test");
    const walletKeys = fixedScriptWallet.RootWalletKeys.from(xpubs);

    it("should use custom tag in input creation and verification", function () {
      const customTag = "MyApp-signed-message";
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const inputIndex = bip322.addBip322Input(psbt, {
        message: "Custom tag test",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
        tag: customTag,
      });

      // Sign
      const userXpriv = BIP32.fromBase58(xprivs[0]);
      const bitgoXpriv = BIP32.fromBase58(xprivs[2]);
      psbt.sign(inputIndex, userXpriv);
      psbt.sign(inputIndex, bitgoXpriv);

      // Verify with same tag should work
      const signers = bip322.verifyBip322PsbtInput(psbt, inputIndex, {
        message: "Custom tag test",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
        tag: customTag,
      });
      assert.deepStrictEqual(signers, ["user", "bitgo"]);

      // Verify with default tag should fail
      assert.throws(() => {
        bip322.verifyBip322PsbtInput(psbt, inputIndex, {
          message: "Custom tag test",
          scriptId: { chain: 10, index: 0 },
          rootWalletKeys: walletKeys,
        });
      }, /wrong to_spend txid/);
    });
  });

  describe("verify with pubkeys", function () {
    const { xpubs, xprivs } = createTestWalletKeys("bip322_pubkeys_test");
    const walletKeys = fixedScriptWallet.RootWalletKeys.from(xpubs);

    /**
     * Get derived pubkeys for a given chain and index
     */
    function getDerivedPubkeys(chain: number, index: number): [string, string, string] {
      const keys = utxolib.testutil.getKeyTriple("bip322_pubkeys_test");
      const derivedKeys = keys.map((k) =>
        k.derivePath(`m/0/0/${chain}/${index}`).publicKey.toString("hex"),
      ) as [string, string, string];
      return derivedKeys;
    }

    it("should verify p2shP2wsh with pubkeys and return signer indices", function () {
      const chain = 10;
      const idx = 0;
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const inputIndex = bip322.addBip322Input(psbt, {
        message: "Verify with pubkeys",
        scriptId: { chain, index: idx },
        rootWalletKeys: walletKeys,
      });

      // Sign with user and bitgo keys
      const userXpriv = BIP32.fromBase58(xprivs[0]);
      const bitgoXpriv = BIP32.fromBase58(xprivs[2]);
      psbt.sign(inputIndex, userXpriv);
      psbt.sign(inputIndex, bitgoXpriv);

      // Get derived pubkeys for the same chain/index
      const pubkeys = getDerivedPubkeys(chain, idx);

      // Verify with pubkeys
      const signerIndices = bip322.verifyBip322PsbtInputWithPubkeys(psbt, inputIndex, {
        message: "Verify with pubkeys",
        pubkeys,
        scriptType: "p2shP2wsh",
      });

      // Should return indices 0 and 2 (user and bitgo)
      assert.deepStrictEqual(signerIndices, [0, 2]);
    });

    it("should verify p2wsh with pubkeys and return signer indices", function () {
      const chain = 20;
      const idx = 3;
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const inputIndex = bip322.addBip322Input(psbt, {
        message: "P2WSH with pubkeys",
        scriptId: { chain, index: idx },
        rootWalletKeys: walletKeys,
      });

      // Sign with user and backup keys
      const userXpriv = BIP32.fromBase58(xprivs[0]);
      const backupXpriv = BIP32.fromBase58(xprivs[1]);
      psbt.sign(inputIndex, userXpriv);
      psbt.sign(inputIndex, backupXpriv);

      // Get derived pubkeys
      const pubkeys = getDerivedPubkeys(chain, idx);

      // Verify with pubkeys
      const signerIndices = bip322.verifyBip322PsbtInputWithPubkeys(psbt, inputIndex, {
        message: "P2WSH with pubkeys",
        pubkeys,
        scriptType: "p2wsh",
      });

      // Should return indices 0 and 1 (user and backup)
      assert.deepStrictEqual(signerIndices, [0, 1]);
    });

    it("should fail verification with wrong pubkeys", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      const inputIndex = bip322.addBip322Input(psbt, {
        message: "Wrong pubkeys test",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });

      // Sign
      const userXpriv = BIP32.fromBase58(xprivs[0]);
      const bitgoXpriv = BIP32.fromBase58(xprivs[2]);
      psbt.sign(inputIndex, userXpriv);
      psbt.sign(inputIndex, bitgoXpriv);

      // Use pubkeys from a different derivation path
      const wrongPubkeys = getDerivedPubkeys(10, 999);

      // Should fail because pubkeys don't match the signed input
      assert.throws(() => {
        bip322.verifyBip322PsbtInputWithPubkeys(psbt, inputIndex, {
          message: "Wrong pubkeys test",
          pubkeys: wrongPubkeys,
          scriptType: "p2shP2wsh",
        });
      }, /wrong to_spend txid/);
    });

    it("should fail verification with wrong script type", function () {
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("testnet", walletKeys, { version: 0 });

      // Create p2shP2wsh input (chain 10)
      const inputIndex = bip322.addBip322Input(psbt, {
        message: "Script type test",
        scriptId: { chain: 10, index: 0 },
        rootWalletKeys: walletKeys,
      });

      // Sign
      const userXpriv = BIP32.fromBase58(xprivs[0]);
      const bitgoXpriv = BIP32.fromBase58(xprivs[2]);
      psbt.sign(inputIndex, userXpriv);
      psbt.sign(inputIndex, bitgoXpriv);

      const pubkeys = getDerivedPubkeys(10, 0);

      // Verify with wrong script type (p2wsh instead of p2shP2wsh)
      assert.throws(() => {
        bip322.verifyBip322PsbtInputWithPubkeys(psbt, inputIndex, {
          message: "Script type test",
          pubkeys,
          scriptType: "p2wsh", // Wrong! Should be p2shP2wsh
        });
      }, /wrong to_spend txid/);
    });
  });
});
