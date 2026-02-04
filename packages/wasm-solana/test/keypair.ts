import * as assert from "assert";
import { Keypair } from "../dist/cjs/js/keypair.js";

describe("Keypair", () => {
  const testSecretKey = new Uint8Array(32).fill(1);

  it("should generate a random keypair", () => {
    const keypair = Keypair.generate();
    assert.strictEqual(keypair.publicKey.length, 32);
    assert.strictEqual(keypair.secretKey.length, 32);
    assert.ok(keypair.getAddress().length > 30, "Address should be base58");
  });

  it("should create keypair from secret key", () => {
    const keypair = Keypair.fromSecretKey(testSecretKey);

    assert.strictEqual(keypair.publicKey.length, 32);
    assert.deepStrictEqual(keypair.secretKey, testSecretKey);
  });

  it("should create keypair from 64-byte Solana secret key", () => {
    const keypair1 = Keypair.fromSecretKey(testSecretKey);

    // Create 64-byte Solana format (secret + public)
    const solanaSecretKey = new Uint8Array(64);
    solanaSecretKey.set(testSecretKey, 0);
    solanaSecretKey.set(keypair1.publicKey, 32);

    const keypair2 = Keypair.fromSolanaSecretKey(solanaSecretKey);

    assert.strictEqual(keypair2.getAddress(), keypair1.getAddress());
  });

  it("should reject invalid secret key lengths", () => {
    assert.throws(() => Keypair.fromSecretKey(new Uint8Array(31)), /32 bytes/);
    assert.throws(() => Keypair.fromSecretKey(new Uint8Array(33)), /32 bytes/);
  });

  it("should reject invalid Solana secret key lengths", () => {
    assert.throws(() => Keypair.fromSolanaSecretKey(new Uint8Array(63)), /64 bytes/);
    assert.throws(() => Keypair.fromSolanaSecretKey(new Uint8Array(65)), /64 bytes/);
  });
});
