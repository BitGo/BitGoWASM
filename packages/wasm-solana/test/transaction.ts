import * as assert from "assert";
import { Transaction } from "../js/transaction.js";

// Helper to decode base64 in tests
function base64ToBytes(base64: string): Uint8Array {
  const binary = Buffer.from(base64, "base64");
  return new Uint8Array(binary);
}

describe("Transaction", () => {
  // Test transaction from @solana/web3.js - a simple SOL transfer
  // This is a real transaction serialized with Transaction.serialize()
  const TEST_TX_BASE64 =
    "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDFVMqpim7tqEi2XL8R6KKkP0DYJvY3eiRXLlL1P9EjYgXKQC+k0FKnqyC4AZGJR7OhJXfpPP3NHOhS8t/6G7bLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/1c7Oaj3RbyLIjU0/ZPpsmVfVUWAzc8g36fK5g6A0JoBAgIAAQwCAAAAoIYBAAAAAAA=";

  const TEST_TX_BYTES = base64ToBytes(TEST_TX_BASE64);

  it("should deserialize transaction from bytes", () => {
    const tx = Transaction.fromBytes(TEST_TX_BYTES);

    assert.ok(tx.numSignatures > 0);
    assert.ok(tx.instructions().length > 0);
  });

  it("should get fee payer", () => {
    const tx = Transaction.fromBytes(TEST_TX_BYTES);
    const feePayer = tx.feePayer;

    assert.ok(feePayer);
    // Fee payer should be a valid base58 Solana address
    assert.ok(feePayer.length >= 32 && feePayer.length <= 44);
  });

  it("should get recent blockhash", () => {
    const tx = Transaction.fromBytes(TEST_TX_BYTES);
    const blockhash = tx.recentBlockhash;

    // Blockhash should be a valid base58 string
    assert.ok(blockhash.length >= 32 && blockhash.length <= 44);
  });

  it("should get account keys", () => {
    const tx = Transaction.fromBytes(TEST_TX_BYTES);
    const keys = tx.accountKeys();

    assert.ok(Array.isArray(keys));
    assert.ok(keys.length >= 1);
    // First key should be the fee payer
    assert.strictEqual(keys[0].toBase58(), tx.feePayer);
  });

  it("should roundtrip bytes", () => {
    const tx = Transaction.fromBytes(TEST_TX_BYTES);
    const serialized = tx.toBytes();

    const tx2 = Transaction.fromBytes(serialized);
    assert.strictEqual(tx.numSignatures, tx2.numSignatures);
    assert.strictEqual(tx.instructions().length, tx2.instructions().length);
    assert.strictEqual(tx.recentBlockhash, tx2.recentBlockhash);
  });

  it("should get signable payload", () => {
    const tx = Transaction.fromBytes(TEST_TX_BYTES);
    const payload = tx.signablePayload();

    assert.ok(payload instanceof Uint8Array);
    assert.ok(payload.length > 0);
  });

  it("should get signatures as bytes", () => {
    const tx = Transaction.fromBytes(TEST_TX_BYTES);
    const sigs = tx.signatures();

    assert.ok(Array.isArray(sigs));
    assert.strictEqual(sigs.length, tx.numSignatures);

    // Each signature should be 64 bytes
    for (const sig of sigs) {
      assert.ok(sig instanceof Uint8Array);
      assert.strictEqual(sig.length, 64);
    }
  });

  it("should reject invalid transaction bytes", () => {
    const invalidBytes = new Uint8Array([0, 1, 2, 3]);
    assert.throws(() => Transaction.fromBytes(invalidBytes), /deserialize/);
  });

  it("should get instructions", () => {
    const tx = Transaction.fromBytes(TEST_TX_BYTES);
    const instructions = tx.instructions();

    assert.ok(Array.isArray(instructions));
    assert.ok(instructions.length > 0);

    // Check first instruction structure
    const instr = instructions[0];
    assert.ok(typeof instr.programId === "string");
    assert.ok(Array.isArray(instr.accounts));
    assert.ok(instr.data instanceof Uint8Array);
  });

  it("should get instruction accounts with signer/writable flags", () => {
    const tx = Transaction.fromBytes(TEST_TX_BYTES);
    const instructions = tx.instructions();

    assert.ok(instructions.length > 0);
    const instr = instructions[0];
    assert.ok(instr.accounts.length > 0);

    // Check account structure
    const account = instr.accounts[0];
    assert.ok(typeof account.pubkey === "string");
    assert.ok(typeof account.isSigner === "boolean");
    assert.ok(typeof account.isWritable === "boolean");
  });

  it("should have System Program as program ID for SOL transfer", () => {
    const tx = Transaction.fromBytes(TEST_TX_BYTES);
    const instructions = tx.instructions();

    assert.ok(instructions.length > 0);
    const instr = instructions[0];
    // System program ID is 11111111111111111111111111111111
    assert.strictEqual(instr.programId, "11111111111111111111111111111111");
  });
});
