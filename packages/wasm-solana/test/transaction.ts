import * as assert from "assert";
import { Transaction } from "../js/transaction.js";

describe("Transaction", () => {
  // Test transaction from @solana/web3.js - a simple SOL transfer
  // This is a real transaction serialized with Transaction.serialize()
  const TEST_TX_BASE64 =
    "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDFVMqpim7tqEi2XL8R6KKkP0DYJvY3eiRXLlL1P9EjYgXKQC+k0FKnqyC4AZGJR7OhJXfpPP3NHOhS8t/6G7bLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/1c7Oaj3RbyLIjU0/ZPpsmVfVUWAzc8g36fK5g6A0JoBAgIAAQwCAAAAoIYBAAAAAAA=";

  it("should deserialize transaction from base64", () => {
    const tx = Transaction.fromBase64(TEST_TX_BASE64);

    assert.ok(tx.numSignatures > 0);
    assert.ok(tx.numInstructions > 0);
  });

  it("should get fee payer", () => {
    const tx = Transaction.fromBase64(TEST_TX_BASE64);
    const feePayer = tx.feePayer;

    assert.ok(feePayer);
    // Fee payer should be a valid base58 Solana address
    assert.ok(feePayer.length >= 32 && feePayer.length <= 44);
  });

  it("should get recent blockhash", () => {
    const tx = Transaction.fromBase64(TEST_TX_BASE64);
    const blockhash = tx.recentBlockhash;

    // Blockhash should be a valid base58 string
    assert.ok(blockhash.length >= 32 && blockhash.length <= 44);
  });

  it("should get account keys", () => {
    const tx = Transaction.fromBase64(TEST_TX_BASE64);
    const keys = tx.accountKeys();

    assert.ok(Array.isArray(keys));
    assert.ok(keys.length >= 1);
    // First key should be the fee payer
    assert.strictEqual(keys[0], tx.feePayer);
  });

  it("should roundtrip base64", () => {
    const tx = Transaction.fromBase64(TEST_TX_BASE64);
    const serialized = tx.toBase64();

    const tx2 = Transaction.fromBase64(serialized);
    assert.strictEqual(tx.numSignatures, tx2.numSignatures);
    assert.strictEqual(tx.numInstructions, tx2.numInstructions);
    assert.strictEqual(tx.recentBlockhash, tx2.recentBlockhash);
  });

  it("should get signable payload", () => {
    const tx = Transaction.fromBase64(TEST_TX_BASE64);
    const payload = tx.signablePayload();

    assert.ok(payload instanceof Uint8Array);
    assert.ok(payload.length > 0);
  });

  it("should get signatures", () => {
    const tx = Transaction.fromBase64(TEST_TX_BASE64);

    // Get signature as base58
    const sig0 = tx.signatureAt(0);
    assert.ok(sig0);

    // Get signature as bytes
    const sigBytes0 = tx.signatureBytesAt(0);
    assert.ok(sigBytes0);
    assert.strictEqual(sigBytes0.length, 64);

    // Out of bounds should return null
    assert.strictEqual(tx.signatureAt(999), null);
    assert.strictEqual(tx.signatureBytesAt(999), null);
  });

  it("should reject invalid base64", () => {
    assert.throws(() => Transaction.fromBase64("not valid base64!!!"), /Invalid base64/);
  });

  it("should reject invalid transaction bytes", () => {
    const invalidBytes = new Uint8Array([0, 1, 2, 3]);
    assert.throws(() => Transaction.fromBytes(invalidBytes), /deserialize/);
  });

  it("should get instructions", () => {
    const tx = Transaction.fromBase64(TEST_TX_BASE64);
    const instructions = tx.instructions();

    assert.ok(Array.isArray(instructions));
    assert.strictEqual(instructions.length, tx.numInstructions);
    assert.ok(instructions.length > 0);

    // Check first instruction structure
    const instr = instructions[0];
    assert.ok(typeof instr.programId === "string");
    assert.ok(Array.isArray(instr.accounts));
    assert.ok(instr.data instanceof Uint8Array);
  });

  it("should get instruction at index", () => {
    const tx = Transaction.fromBase64(TEST_TX_BASE64);
    const instr = tx.instructionAt(0);

    assert.ok(instr);
    assert.ok(typeof instr.programId === "string");
    assert.ok(Array.isArray(instr.accounts));
    assert.ok(instr.data instanceof Uint8Array);

    // Out of bounds should return null
    assert.strictEqual(tx.instructionAt(999), null);
  });

  it("should get instruction accounts with signer/writable flags", () => {
    const tx = Transaction.fromBase64(TEST_TX_BASE64);
    const instr = tx.instructionAt(0);

    assert.ok(instr);
    assert.ok(instr.accounts.length > 0);

    // Check account structure
    const account = instr.accounts[0];
    assert.ok(typeof account.pubkey === "string");
    assert.ok(typeof account.isSigner === "boolean");
    assert.ok(typeof account.isWritable === "boolean");
  });

  it("should have System Program as program ID for SOL transfer", () => {
    const tx = Transaction.fromBase64(TEST_TX_BASE64);
    const instr = tx.instructionAt(0);

    assert.ok(instr);
    // System program ID is 11111111111111111111111111111111
    assert.strictEqual(instr.programId, "11111111111111111111111111111111");
  });
});
