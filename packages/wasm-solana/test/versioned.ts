import * as assert from "assert";
import { VersionedTransaction, isVersionedTransaction } from "../js/versioned.js";

describe("VersionedTransaction", () => {
  // Legacy transaction (same as transaction.ts test)
  const LEGACY_TX_BASE64 =
    "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDFVMqpim7tqEi2XL8R6KKkP0DYJvY3eiRXLlL1P9EjYgXKQC+k0FKnqyC4AZGJR7OhJXfpPP3NHOhS8t/6G7bLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/1c7Oaj3RbyLIjU0/ZPpsmVfVUWAzc8g36fK5g6A0JoBAgIAAQwCAAAAoIYBAAAAAAA=";

  describe("isVersionedTransaction", () => {
    it("should return false for legacy transaction", () => {
      const bytes = Buffer.from(LEGACY_TX_BASE64, "base64");
      assert.strictEqual(isVersionedTransaction(bytes), false);
    });
  });

  describe("legacy transaction parsing", () => {
    it("should parse legacy transaction as versioned", () => {
      const tx = VersionedTransaction.fromBase64(LEGACY_TX_BASE64);

      assert.strictEqual(tx.isVersioned, false);
      assert.ok(tx.feePayer);
      assert.ok(tx.recentBlockhash);
    });

    it("should have empty address lookup tables for legacy", () => {
      const tx = VersionedTransaction.fromBase64(LEGACY_TX_BASE64);
      const alts = tx.addressLookupTables();

      assert.strictEqual(alts.length, 0);
    });

    it("should have static account keys", () => {
      const tx = VersionedTransaction.fromBase64(LEGACY_TX_BASE64);
      const keys = tx.staticAccountKeys();

      assert.ok(Array.isArray(keys));
      assert.ok(keys.length > 0);
      // First key should be fee payer
      assert.strictEqual(keys[0], tx.feePayer);
    });

    it("should get instructions", () => {
      const tx = VersionedTransaction.fromBase64(LEGACY_TX_BASE64);
      const instructions = tx.instructions();

      assert.ok(Array.isArray(instructions));
      assert.ok(instructions.length > 0);

      const instr = instructions[0];
      assert.ok(instr.programId);
      assert.ok(Array.isArray(instr.accounts));
      assert.ok(instr.data instanceof Uint8Array);
    });

    it("should get signable payload", () => {
      const tx = VersionedTransaction.fromBase64(LEGACY_TX_BASE64);
      const payload = tx.signablePayload();

      assert.ok(payload instanceof Uint8Array);
      assert.ok(payload.length > 0);
    });

    it("should roundtrip", () => {
      const tx = VersionedTransaction.fromBase64(LEGACY_TX_BASE64);
      const bytes = tx.toBytes();

      const tx2 = VersionedTransaction.fromBytes(bytes);
      assert.strictEqual(tx.isVersioned, tx2.isVersioned);
      assert.strictEqual(tx.feePayer, tx2.feePayer);
      assert.strictEqual(tx.recentBlockhash, tx2.recentBlockhash);
    });

    it("should add signature", () => {
      const tx = VersionedTransaction.fromBase64(LEGACY_TX_BASE64);
      const feePayer = tx.feePayer;

      const signature = new Uint8Array(64).fill(42);
      tx.addSignature(feePayer, signature);

      const sigs = tx.signatures;
      assert.strictEqual(sigs.length, 1);
      assert.deepStrictEqual(sigs[0], signature);
    });
  });

  describe("base64 serialization", () => {
    it("should roundtrip base64", () => {
      const tx = VersionedTransaction.fromBase64(LEGACY_TX_BASE64);
      const base64 = tx.toBase64();

      const tx2 = VersionedTransaction.fromBase64(base64);
      assert.strictEqual(tx.feePayer, tx2.feePayer);
    });
  });

  describe("id getter", () => {
    it("should return UNSIGNED for unsigned transaction", () => {
      const bytes = Buffer.from(LEGACY_TX_BASE64, "base64");
      const tx = VersionedTransaction.fromBytes(bytes);
      // The test transaction has an all-zeros signature (unsigned)
      assert.strictEqual(tx.id, "UNSIGNED");
    });

    it("should return base58 signature after signing", () => {
      const bytes = Buffer.from(LEGACY_TX_BASE64, "base64");
      const tx = VersionedTransaction.fromBytes(bytes);
      const feePayer = tx.feePayer;

      // Add a non-zero signature
      const signature = new Uint8Array(64);
      for (let i = 0; i < 64; i++) signature[i] = i + 1;
      tx.addSignature(feePayer, signature);

      // ID should now be a base58-encoded string of the signature
      const id = tx.id;
      assert.notStrictEqual(id, "UNSIGNED");
      assert.ok(id.length > 20); // base58 encoded 64 bytes should be ~80+ chars
    });
  });
});
