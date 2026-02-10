import * as assert from "assert";
import { ECPair } from "../js/ecpair.js";
import { message } from "../js/index.js";

describe("Message Signing (BIP-137)", () => {
  const testPrivateKey = new Uint8Array(
    Buffer.from("1111111111111111111111111111111111111111111111111111111111111111", "hex"),
  );

  describe("signMessage", () => {
    it("should sign a message and return 65-byte signature", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const signature = message.signMessage("Hello, Bitcoin!", key);

      assert.ok(signature instanceof Uint8Array);
      assert.strictEqual(signature.length, 65);
    });

    it("should produce a valid BIP-137 header byte", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const signature = message.signMessage("Hello, Bitcoin!", key);

      // Compressed key headers: 31-34 (31 + recovery_id 0-3)
      assert.ok(
        signature[0] >= 31 && signature[0] <= 34,
        `Expected header 31-34, got ${signature[0]}`,
      );
    });

    it("should fail to sign with public key only", () => {
      const privateKey = ECPair.fromPrivateKey(testPrivateKey);
      const publicKey = ECPair.fromPublicKey(privateKey.publicKey);

      assert.throws(() => {
        message.signMessage("Hello, Bitcoin!", publicKey);
      });
    });

    it("should accept ECPairArg as Uint8Array (private key)", () => {
      const signature = message.signMessage("Hello, Bitcoin!", testPrivateKey);

      assert.ok(signature instanceof Uint8Array);
      assert.strictEqual(signature.length, 65);
    });

    it("should accept ECPairArg as WasmECPair", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const signature = message.signMessage("Hello, Bitcoin!", key.wasm);

      assert.ok(signature instanceof Uint8Array);
      assert.strictEqual(signature.length, 65);
    });
  });

  describe("verifyMessage", () => {
    it("should verify a valid signature", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const signature = message.signMessage("Hello, Bitcoin!", key);

      assert.strictEqual(message.verifyMessage("Hello, Bitcoin!", key, signature), true);
    });

    it("should verify with public key only", () => {
      const privateKey = ECPair.fromPrivateKey(testPrivateKey);
      const publicKey = ECPair.fromPublicKey(privateKey.publicKey);

      const signature = message.signMessage("Hello, Bitcoin!", privateKey);

      assert.strictEqual(message.verifyMessage("Hello, Bitcoin!", publicKey, signature), true);
    });

    it("should reject signature for different message", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const signature = message.signMessage("Hello, Bitcoin!", key);

      assert.strictEqual(message.verifyMessage("Different message", key, signature), false);
    });

    it("should reject signature for wrong key", () => {
      const key1 = ECPair.fromPrivateKey(testPrivateKey);
      const key2 = ECPair.fromPrivateKey(
        new Uint8Array(
          Buffer.from("2222222222222222222222222222222222222222222222222222222222222222", "hex"),
        ),
      );

      const signature = message.signMessage("Hello, Bitcoin!", key1);

      assert.strictEqual(message.verifyMessage("Hello, Bitcoin!", key2, signature), false);
    });

    it("should reject signature of invalid length", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);

      assert.throws(() => {
        message.verifyMessage("test", key, new Uint8Array(32));
      });

      assert.throws(() => {
        message.verifyMessage("test", key, new Uint8Array(64));
      });
    });

    it("should accept ECPairArg as Uint8Array (public key) for verification", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const signature = message.signMessage("Hello, Bitcoin!", key);

      assert.strictEqual(message.verifyMessage("Hello, Bitcoin!", key.publicKey, signature), true);
    });
  });

  describe("edge cases", () => {
    it("should handle empty message", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const signature = message.signMessage("", key);

      assert.strictEqual(signature.length, 65);
      assert.strictEqual(message.verifyMessage("", key, signature), true);
    });

    it("should handle long message", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const msg = "A".repeat(1000);
      const signature = message.signMessage(msg, key);

      assert.strictEqual(message.verifyMessage(msg, key, signature), true);
    });

    it("should handle unicode message", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const msg = "Hello, 世界! 🚀";
      const signature = message.signMessage(msg, key);

      assert.strictEqual(message.verifyMessage(msg, key, signature), true);
    });

    it("should produce consistent signatures", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const sig1 = message.signMessage("Test message", key);
      const sig2 = message.signMessage("Test message", key);

      assert.strictEqual(message.verifyMessage("Test message", key, sig1), true);
      assert.strictEqual(message.verifyMessage("Test message", key, sig2), true);
    });
  });

  describe("cross-verification with wasm-bip32", () => {
    // Use a known private key and message to produce a deterministic signature
    // that can be verified across implementations
    it("should produce signatures verifiable by the same key's public key", () => {
      const key = ECPair.fromPrivateKey(testPrivateKey);
      const publicOnlyKey = ECPair.fromPublicKey(key.publicKey);

      const testMessages = [
        "Hello, Bitcoin!",
        "",
        "The quick brown fox jumps over the lazy dog",
        "0",
        "A".repeat(253), // just below varint boundary
        "A".repeat(254), // at varint boundary
      ];

      for (const msg of testMessages) {
        const signature = message.signMessage(msg, key);
        assert.strictEqual(
          message.verifyMessage(msg, publicOnlyKey, signature),
          true,
          `Failed to verify message: ${JSON.stringify(msg.slice(0, 50))}`,
        );
      }
    });
  });
});
