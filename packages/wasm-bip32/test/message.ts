import * as assert from "assert";
import { ECPair } from "../js/ecpair.js";

describe("Message Signing", () => {
  const testPrivateKey = new Uint8Array(
    Buffer.from("1111111111111111111111111111111111111111111111111111111111111111", "hex"),
  );

  describe("Raw ECDSA signing", () => {
    it("should sign a 32-byte message hash", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const messageHash = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        messageHash[i] = i;
      }

      const signature = key.sign(messageHash);

      assert.ok(signature instanceof Uint8Array);
      assert.strictEqual(signature.length, 64); // r (32) + s (32)
    });

    it("should verify a valid signature", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const messageHash = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        messageHash[i] = i;
      }

      const signature = key.sign(messageHash);
      const isValid = key.verify(messageHash, signature);

      assert.strictEqual(isValid, true);
    });

    it("should reject invalid signature", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const messageHash = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        messageHash[i] = i;
      }

      // Create an invalid signature
      const invalidSignature = new Uint8Array(64);
      const isValid = key.verify(messageHash, invalidSignature);

      assert.strictEqual(isValid, false);
    });

    it("should reject signature for different message", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const messageHash1 = new Uint8Array(32);
      const messageHash2 = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        messageHash1[i] = i;
        messageHash2[i] = i + 1;
      }

      const signature = key.sign(messageHash1);
      const isValid = key.verify(messageHash2, signature);

      assert.strictEqual(isValid, false);
    });

    it("should verify signature with public key only", () => {
      const privateKey = ECPair.fromPrivateKey(testPrivateKey);
      const publicKey = ECPair.fromPublicKey(privateKey.publicKey);

      const messageHash = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        messageHash[i] = i;
      }

      const signature = privateKey.sign(messageHash);
      const isValid = publicKey.verify(messageHash, signature);

      assert.strictEqual(isValid, true);
    });

    it("should fail to sign with public key only", () => {
      const privateKey = ECPair.fromPrivateKey(testPrivateKey);
      const publicKey = ECPair.fromPublicKey(privateKey.publicKey);

      const messageHash = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        messageHash[i] = i;
      }

      assert.throws(() => {
        publicKey.sign(messageHash);
      });
    });

    it("should reject message hash of wrong length", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);

      assert.throws(() => {
        key.sign(new Uint8Array(31));
      });

      assert.throws(() => {
        key.sign(new Uint8Array(33));
      });
    });
  });

  describe("Bitcoin message signing (BIP-137)", () => {
    it("should sign a message", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const message = "Hello, Bitcoin!";

      const signature = key.signMessage(message);

      assert.ok(signature instanceof Uint8Array);
      // 1-byte header + 64-byte signature
      assert.strictEqual(signature.length, 65);
    });

    it("should verify a valid message signature", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const message = "Hello, Bitcoin!";

      const signature = key.signMessage(message);
      const isValid = key.verifyMessage(message, signature);

      assert.strictEqual(isValid, true);
    });

    it("should reject signature for different message", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);

      const signature = key.signMessage("Hello, Bitcoin!");
      const isValid = key.verifyMessage("Different message", signature);

      assert.strictEqual(isValid, false);
    });

    it("should verify message signature with public key", () => {
      const privateKey = ECPair.fromPrivateKey(testPrivateKey);
      const publicKey = ECPair.fromPublicKey(privateKey.publicKey);

      const message = "Hello, Bitcoin!";
      const signature = privateKey.signMessage(message);
      const isValid = publicKey.verifyMessage(message, signature);

      assert.strictEqual(isValid, true);
    });

    it("should fail to sign message with public key only", () => {
      const privateKey = ECPair.fromPrivateKey(testPrivateKey);
      const publicKey = ECPair.fromPublicKey(privateKey.publicKey);

      assert.throws(() => {
        publicKey.signMessage("Hello, Bitcoin!");
      });
    });

    it("should produce consistent signatures", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const message = "Test message";

      // Sign the same message twice
      const sig1 = key.signMessage(message);
      const sig2 = key.signMessage(message);

      // Both signatures should be valid
      assert.strictEqual(key.verifyMessage(message, sig1), true);
      assert.strictEqual(key.verifyMessage(message, sig2), true);
    });

    it("should handle empty message", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const message = "";

      const signature = key.signMessage(message);
      const isValid = key.verifyMessage(message, signature);

      assert.strictEqual(isValid, true);
    });

    it("should handle long message", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const message = "A".repeat(1000);

      const signature = key.signMessage(message);
      const isValid = key.verifyMessage(message, signature);

      assert.strictEqual(isValid, true);
    });

    it("should handle unicode message", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const message = "Hello, 世界! 🚀";

      const signature = key.signMessage(message);
      const isValid = key.verifyMessage(message, signature);

      assert.strictEqual(isValid, true);
    });
  });
});
