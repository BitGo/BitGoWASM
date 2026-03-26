/**
 * Transaction tests: deserialization, signing, serialization, round-trip.
 */
import * as assert from "assert";
import { Transaction } from "../js/transaction.js";

function base64ToBytes(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

describe("Transaction", () => {
  // From BitGoJS sdk-coin-ton test/resources/ton.ts
  const SIGNED_SEND_TX =
    "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==";

  // From BitGoJS: signedSendTransaction.signable
  const EXPECTED_SIGNABLE_B64 = "k4XUmjB65j3klMXCXdh5Vs3bJZzo3NSfnXK8NIYFayI=";

  describe("fromBase64", () => {
    it("should deserialize a signed send transaction", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      assert.ok(tx);
    });

    it("should throw on invalid base64", () => {
      assert.throws(() => Transaction.fromBase64("not-valid-boc!!!"));
    });
  });

  describe("fromBytes", () => {
    it("should deserialize from raw bytes", () => {
      const bytes = base64ToBytes(SIGNED_SEND_TX);
      const tx = Transaction.fromBytes(bytes);
      assert.ok(tx);
    });
  });

  describe("fromHex", () => {
    it("should deserialize from hex-encoded BOC", () => {
      const bytes = base64ToBytes(SIGNED_SEND_TX);
      const hex = Buffer.from(bytes).toString("hex");
      const tx = Transaction.fromHex(hex);
      assert.ok(tx);

      // Should produce the same signable payload as fromBase64
      const txB64 = Transaction.fromBase64(SIGNED_SEND_TX);
      assert.deepStrictEqual(tx.signablePayload(), txB64.signablePayload());
    });

    it("should throw on invalid hex", () => {
      assert.throws(() => Transaction.fromHex("not_valid_hex!!!"));
    });
  });

  describe("signablePayload", () => {
    it("should return 32 bytes matching the BitGoJS fixture", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      const payload = tx.signablePayload();
      assert.strictEqual(payload.length, 32);

      const expected = base64ToBytes(EXPECTED_SIGNABLE_B64);
      assert.deepStrictEqual(payload, expected);
    });
  });

  describe("addSignature", () => {
    it("should accept a 64-byte signature", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      const sig = new Uint8Array(64).fill(0xab);
      tx.addSignature(sig);
      // After signing, tx should have an ID
      assert.ok(tx.id);
    });

    it("should reject non-64-byte signatures", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      assert.throws(() => tx.addSignature(new Uint8Array(32)));
      assert.throws(() => tx.addSignature(new Uint8Array(128)));
    });
  });

  describe("id", () => {
    it("should return a string for signed transactions", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      assert.ok(tx.id);
      assert.strictEqual(typeof tx.id, "string");
    });

    it("should return undefined for unsigned transactions", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      tx.addSignature(new Uint8Array(64)); // all zeros
      assert.strictEqual(tx.id, undefined);
    });
  });

  describe("toBytes / toBroadcastFormat", () => {
    it("should serialize to bytes", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      const bytes = tx.toBytes();
      assert.ok(bytes.length > 0);
    });

    it("should serialize to base64 broadcast format", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      const broadcast = tx.toBroadcastFormat();
      assert.strictEqual(typeof broadcast, "string");
      // Should be valid base64
      const decoded = Buffer.from(broadcast, "base64");
      assert.ok(decoded.length > 0);
    });
  });

  describe("round-trip", () => {
    it("should round-trip through bytes", () => {
      const tx1 = Transaction.fromBase64(SIGNED_SEND_TX);
      const bytes = tx1.toBytes();
      const tx2 = Transaction.fromBytes(bytes);

      // Both should produce the same signable payload
      assert.deepStrictEqual(tx1.signablePayload(), tx2.signablePayload());
    });

    it("should round-trip through base64 broadcast format", () => {
      const tx1 = Transaction.fromBase64(SIGNED_SEND_TX);
      const broadcast = tx1.toBroadcastFormat();
      const tx2 = Transaction.fromBase64(broadcast);

      assert.deepStrictEqual(tx1.signablePayload(), tx2.signablePayload());
    });
  });
});
