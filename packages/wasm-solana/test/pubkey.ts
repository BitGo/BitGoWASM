import * as assert from "assert";
import { Pubkey } from "../js/pubkey.js";
import { Keypair } from "../js/keypair.js";

describe("Pubkey", () => {
  const testAddress = "11111111111111111111111111111111";
  const testBytes = new Uint8Array(32).fill(0);
  const testSecretKey = new Uint8Array(32).fill(1);

  it("should create Pubkey from base58 and bytes", () => {
    const pubkey1 = Pubkey.fromBase58(testAddress);
    const pubkey2 = Pubkey.fromBytes(testBytes);

    assert.strictEqual(pubkey1.toBase58(), testAddress);
    assert.strictEqual(pubkey2.toBase58(), testAddress);
  });

  it("should roundtrip base58 -> bytes -> base58", () => {
    const keypair = Keypair.fromSecretKey(testSecretKey);
    const pubkey = Pubkey.fromBase58(keypair.getAddress());

    assert.strictEqual(pubkey.toBase58(), keypair.getAddress());
    assert.deepStrictEqual(pubkey.toBytes(), keypair.publicKey);
  });

  it("should compare pubkeys for equality", () => {
    const pubkey1 = Pubkey.fromBase58(testAddress);
    const pubkey2 = Pubkey.fromBase58(testAddress);

    assert.ok(pubkey1.equals(pubkey2));
  });

  it("should reject invalid inputs", () => {
    assert.throws(() => Pubkey.fromBase58("invalid!@#$"), /Invalid base58/);
    assert.throws(() => Pubkey.fromBytes(new Uint8Array(31)), /expected 32 bytes/);
  });

  it("isOnCurve should return true for keypair addresses", () => {
    const keypair = Keypair.fromSecretKey(testSecretKey);
    const pubkey = Pubkey.fromBytes(keypair.publicKey);

    assert.strictEqual(pubkey.isOnCurve(), true);
  });
});
