import * as assert from "assert";
import { Transaction } from "../js/transaction.js";

// Fixtures from BitGoJS sdk-coin-ton/test/resources/ton.ts
const signedSendTransaction = {
  tx: "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==",
  txId: "tuyOkyFUMv_neV_FeNBH24Nd4cML2jUgDP4zjGkuOFI=",
  signable: "k4XUmjB65j3klMXCXdh5Vs3bJZzo3NSfnXK8NIYFayI=",
};

const v3CompatibleSignedSendTransaction = {
  txBounceable:
    "te6cckEBAgEAqAAB34gB6PRRbBG9U/w5zruVAiyjjtuAoJQrbKx6iNEFbGT4q1oHBW0S6HI3Mqn+qZUL6E/GLQEBfdhXuswqDfR0WMiOFLIpITCTcMwZNRZL6yKqMb7Zfzi/A8YXdkVVgxgakEPAaU1NGLtH0CDAAAAAGBwBAGZiAGcJlmF0UvErDsi5Rs21SP70rP1K36wtjBImqtbV96EuHMS0AAAAAAAAAAAAAAAAAAAiW72E",
  txIdBounceable: "4i1GCyN5IkQQ-vESvNl4Wp1ejp7LfazRlNWzUbtGwSA=",
  bounceableSignable: "lOEOTzPXnPotTTHi7xgivFNUHH+xUgq/nKpaP/bK+Xo=",
};

describe("Transaction", () => {
  it("should deserialize a V4R2 transaction from base64", () => {
    const tx = Transaction.fromBase64(signedSendTransaction.tx);
    assert.ok(tx.seqno > 0);
    assert.ok(tx.expireTime > 0);
    assert.strictEqual(tx.walletVersion, "V4R2");
    assert.ok(tx.isSigned);
  });

  it("should deserialize a V3R2 transaction from base64", () => {
    const tx = Transaction.fromBase64(v3CompatibleSignedSendTransaction.txBounceable);
    assert.ok(tx.seqno > 0);
    assert.strictEqual(tx.walletVersion, "V3R2");
    assert.ok(tx.isSigned);
  });

  it("should deserialize from raw bytes", () => {
    const bytes = Uint8Array.from(Buffer.from(signedSendTransaction.tx, "base64"));
    const tx = Transaction.fromBytes(bytes);
    assert.ok(tx.seqno > 0);
    assert.strictEqual(tx.walletVersion, "V4R2");
  });

  it("should return the correct transaction ID", () => {
    const tx = Transaction.fromBase64(signedSendTransaction.tx);
    assert.strictEqual(tx.id, signedSendTransaction.txId);
  });

  it("should return the correct V3R2 transaction ID", () => {
    const tx = Transaction.fromBase64(v3CompatibleSignedSendTransaction.txBounceable);
    assert.strictEqual(tx.id, v3CompatibleSignedSendTransaction.txIdBounceable);
  });

  it("should return the correct signable payload", () => {
    const tx = Transaction.fromBase64(signedSendTransaction.tx);
    const payload = tx.signablePayload();
    const expected = Buffer.from(signedSendTransaction.signable, "base64");

    assert.ok(payload instanceof Uint8Array);
    assert.strictEqual(payload.length, 32);
    assert.deepStrictEqual(Buffer.from(payload), expected);
  });

  it("should return the correct V3R2 signable payload", () => {
    const tx = Transaction.fromBase64(v3CompatibleSignedSendTransaction.txBounceable);
    const payload = tx.signablePayload();
    const expected = Buffer.from(v3CompatibleSignedSendTransaction.bounceableSignable, "base64");

    assert.deepStrictEqual(Buffer.from(payload), expected);
  });

  it("should roundtrip through serialization", () => {
    const tx1 = Transaction.fromBase64(signedSendTransaction.tx);
    const broadcastBase64 = tx1.toBroadcastFormat();
    const tx2 = Transaction.fromBase64(broadcastBase64);

    assert.strictEqual(tx1.seqno, tx2.seqno);
    assert.strictEqual(tx1.expireTime, tx2.expireTime);
    assert.strictEqual(tx1.walletId, tx2.walletId);
    assert.strictEqual(tx1.id, tx2.id);
  });

  it("toBroadcastFormat should return base64 string", () => {
    const tx = Transaction.fromBase64(signedSendTransaction.tx);
    const broadcast = tx.toBroadcastFormat();
    assert.strictEqual(typeof broadcast, "string");
    // Should be valid base64
    assert.doesNotThrow(() => Buffer.from(broadcast, "base64"));
  });

  it("toBytes should return Uint8Array", () => {
    const tx = Transaction.fromBase64(signedSendTransaction.tx);
    const bytes = tx.toBytes();
    assert.ok(bytes instanceof Uint8Array);
    assert.ok(bytes.length > 0);
  });

  it("should reject invalid base64", () => {
    assert.throws(() => Transaction.fromBase64("not-valid-boc"));
  });

  it("should reject invalid bytes", () => {
    assert.throws(() => Transaction.fromBytes(new Uint8Array([0, 1, 2, 3])));
  });
});
