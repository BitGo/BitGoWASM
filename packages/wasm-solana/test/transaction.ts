import * as assert from "assert";
import { Transaction } from "../js/transaction.js";
import { VersionedTransaction } from "../js/versioned.js";

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
    assert.ok(tx.instructions.length > 0);
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
    assert.strictEqual(tx.instructions.length, tx2.instructions.length);
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
    const sigs = tx.signatures;

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
    const instructions = tx.instructions;

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
    const instructions = tx.instructions;

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
    const instructions = tx.instructions;

    assert.ok(instructions.length > 0);
    const instr = instructions[0];
    // System program ID is 11111111111111111111111111111111
    assert.strictEqual(instr.programId, "11111111111111111111111111111111");
  });

  describe("id getter", () => {
    it("should return undefined for unsigned transaction", () => {
      const tx = Transaction.fromBytes(TEST_TX_BYTES);
      // The test transaction has an all-zeros signature (unsigned)
      assert.strictEqual(tx.id, undefined);
    });

    it("should return base58 signature after signing", () => {
      const tx = Transaction.fromBytes(TEST_TX_BYTES);
      const feePayer = tx.feePayer;

      // Add a non-zero signature
      const signature = new Uint8Array(64);
      for (let i = 0; i < 64; i++) signature[i] = i + 1;
      tx.addSignature(feePayer, signature);

      // ID should now be a base58-encoded string of the signature
      const id = tx.id;
      assert.notStrictEqual(id, undefined);
      assert.ok(id && id.length > 20); // base58 encoded 64 bytes should be ~80+ chars
    });
  });

  describe("signerIndex", () => {
    it("should return signer index for fee payer", () => {
      const tx = Transaction.fromBytes(TEST_TX_BYTES);
      const feePayer = tx.feePayer;

      const idx = tx.signerIndex(feePayer);
      assert.strictEqual(idx, 0); // Fee payer is always at index 0
    });

    it("should return null for non-signer pubkey", () => {
      const tx = Transaction.fromBytes(TEST_TX_BYTES);

      // System program is not a signer
      const idx = tx.signerIndex("11111111111111111111111111111111");
      assert.strictEqual(idx, null);
    });
  });

  describe("addSignature", () => {
    it("should add signature for valid signer", () => {
      const tx = Transaction.fromBytes(TEST_TX_BYTES);
      const feePayer = tx.feePayer;

      // Create a dummy 64-byte signature
      const signature = new Uint8Array(64).fill(42);

      // Add the signature
      tx.addSignature(feePayer, signature);

      // Verify the signature was added
      const sigs = tx.signatures;
      assert.strictEqual(sigs.length, 1);
      assert.deepStrictEqual(sigs[0], signature);
    });

    it("should throw for invalid signature length", () => {
      const tx = Transaction.fromBytes(TEST_TX_BYTES);
      const feePayer = tx.feePayer;

      // Try to add a signature with wrong length
      const badSignature = new Uint8Array(32);
      assert.throws(() => tx.addSignature(feePayer, badSignature), /Invalid signature length/);
    });

    it("should throw for non-signer pubkey", () => {
      const tx = Transaction.fromBytes(TEST_TX_BYTES);
      const signature = new Uint8Array(64);

      // Try to add signature for non-signer (System program)
      assert.throws(
        () => tx.addSignature("11111111111111111111111111111111", signature),
        /unknown signer:/,
      );
    });

    it("should roundtrip after adding signature", () => {
      const tx = Transaction.fromBytes(TEST_TX_BYTES);
      const feePayer = tx.feePayer;

      // Add a signature
      const signature = new Uint8Array(64);
      for (let i = 0; i < 64; i++) signature[i] = i;
      tx.addSignature(feePayer, signature);

      // Serialize and deserialize
      const bytes = tx.toBytes();
      const tx2 = Transaction.fromBytes(bytes);

      // Verify signature is preserved
      const sigs = tx2.signatures;
      assert.deepStrictEqual(sigs[0], signature);
    });
  });

  describe("VersionedTransaction.fromVersionedData", () => {
    it("should build versioned transaction from raw MessageV0 data", () => {
      // Create minimal versioned transaction data
      // Fee payer is first account
      const feePayer = "2gCzKgSETrQ74HZfisZUENTLyNhV6cAgV77xDMhxmHg2";
      const data = {
        staticAccountKeys: [
          feePayer,
          "11111111111111111111111111111111", // system program
        ],
        addressLookupTables: [],
        versionedInstructions: [
          {
            programIdIndex: 1,
            accountKeyIndexes: [0],
            data: "3Bxs4ThwQbE4vyj", // base58 encoded transfer instruction data
          },
        ],
        messageHeader: {
          numRequiredSignatures: 1,
          numReadonlySignedAccounts: 0,
          numReadonlyUnsignedAccounts: 1,
        },
        recentBlockhash: "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi",
      };

      const tx = VersionedTransaction.fromVersionedData(data);

      // Verify basic properties
      assert.ok(tx.feePayer); // Fee payer exists
      assert.strictEqual(tx.recentBlockhash, data.recentBlockhash);
      assert.strictEqual(tx.numSignatures, 1);
      assert.ok(tx.numInstructions > 0);
      // Fee payer should be the first static account key (index 0)
      assert.strictEqual(tx.feePayer, feePayer);
    });

    it("should roundtrip versioned transaction", () => {
      const data = {
        staticAccountKeys: [
          "2gCzKgSETrQ74HZfisZUENTLyNhV6cAgV77xDMhxmHg2",
          "11111111111111111111111111111111",
        ],
        addressLookupTables: [],
        versionedInstructions: [
          {
            programIdIndex: 1,
            accountKeyIndexes: [0],
            data: "3Bxs4ThwQbE4vyj",
          },
        ],
        messageHeader: {
          numRequiredSignatures: 1,
          numReadonlySignedAccounts: 0,
          numReadonlyUnsignedAccounts: 1,
        },
        recentBlockhash: "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi",
      };

      const tx = VersionedTransaction.fromVersionedData(data);
      const bytes = tx.toBytes();

      // Deserialize and verify using VersionedTransaction
      const tx2 = VersionedTransaction.fromBytes(bytes);
      assert.strictEqual(tx2.feePayer, tx.feePayer);
      assert.strictEqual(tx2.recentBlockhash, tx.recentBlockhash);
    });

    it("should build versioned transaction with ALTs (Jupiter-like)", () => {
      // This is extracted from a real Jupiter swap versioned transaction
      // which uses Address Lookup Tables
      const data = {
        staticAccountKeys: [
          "35aKHPPJqb7qVNAaUb8DQLRC3Njp5RJZJSQM3v2PZhM7",
          "ESuE8KSzSHBRCtgDwauL7vCR2ohxrWXf8rw75vVbNFvL",
          "DWkKDVpGEVeABT4xh4SoBJzzxhSZxBuK7fWAD5LiMBui",
          "4fxWJ1umh7bWbMrhrPaJcdV3EYjwm2kqPVKWHq7JcNXb",
          "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
          "11111111111111111111111111111111",
          "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
          "D8cy77BBepLMngZx6ZukaTff5hCt1HrWyKk3Hnd9oitf",
          "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
          "ComputeBudget111111111111111111111111111111",
          "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",
          "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1",
          "srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX",
        ],
        addressLookupTables: [
          {
            accountKey: "2immgwYNHBbyVQKVGCEkgWpi53bLwWNRMB5G2nbgYV17",
            writableIndexes: [0, 16, 21, 23, 34, 45],
            readonlyIndexes: [1, 4, 22, 24, 37, 53, 61, 65],
          },
          {
            accountKey: "6i9zbbghVBpHm6A8DqqBDDnJZ9zRLcqZVTdNkQyTpGjC",
            writableIndexes: [2, 3],
            readonlyIndexes: [5, 6, 7],
          },
        ],
        versionedInstructions: [
          {
            programIdIndex: 9,
            accountKeyIndexes: [],
            data: "3DdGGhkhJbjm",
          },
          {
            programIdIndex: 9,
            accountKeyIndexes: [],
            data: "Fj2Eoy",
          },
          {
            programIdIndex: 6,
            accountKeyIndexes: [7, 0, 5, 4, 10, 11, 12, 1, 2, 3, 8],
            data: "2gCNTm5Pp1JgJmCK3KqDm",
          },
        ],
        messageHeader: {
          numRequiredSignatures: 1,
          numReadonlySignedAccounts: 0,
          numReadonlyUnsignedAccounts: 5,
        },
        recentBlockhash: "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi",
      };

      const tx = VersionedTransaction.fromVersionedData(data);

      // Verify basic properties
      assert.ok(tx.feePayer);
      assert.strictEqual(tx.feePayer, data.staticAccountKeys[0]);
      assert.strictEqual(tx.recentBlockhash, data.recentBlockhash);
      assert.strictEqual(tx.numSignatures, 1);
      assert.strictEqual(tx.numInstructions, 3);

      // Verify we can serialize and it's a valid versioned transaction
      const bytes = tx.toBytes();
      assert.ok(bytes.length > 0);

      // Verify we can parse it back
      const tx2 = VersionedTransaction.fromBytes(bytes);
      assert.strictEqual(tx2.feePayer, tx.feePayer);
      assert.strictEqual(tx2.recentBlockhash, tx.recentBlockhash);
    });
  });
});
