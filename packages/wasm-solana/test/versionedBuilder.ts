/**
 * Tests for buildFromVersionedData - versioned transaction building
 * from pre-compiled MessageV0 data (for WalletConnect/Jupiter).
 */

import * as assert from "assert";
import { VersionedTransaction } from "../js/versioned.js";
import { buildFromVersionedData } from "../js/builder.js";

describe("buildFromVersionedData", () => {
  const feePayer = "2gCzKgSETrQ74HZfisZUENTLyNhV6cAgV77xDMhxmHg2";
  const blockhash = "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi";

  it("should build versioned transaction from raw MessageV0 data", () => {
    const data = {
      staticAccountKeys: [feePayer, "11111111111111111111111111111111"],
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
      recentBlockhash: blockhash,
    };

    const tx = buildFromVersionedData(data);

    assert.ok(tx instanceof VersionedTransaction);
    assert.ok(tx.feePayer);
    assert.strictEqual(tx.feePayer, feePayer);
    assert.strictEqual(tx.recentBlockhash, blockhash);
    assert.strictEqual(tx.numSignatures, 1);
    assert.ok(tx.numInstructions > 0);
  });

  it("should roundtrip versioned transaction", () => {
    const data = {
      staticAccountKeys: [feePayer, "11111111111111111111111111111111"],
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
      recentBlockhash: blockhash,
    };

    const tx = buildFromVersionedData(data);
    const bytes = tx.toBytes();

    // Deserialize and verify
    const tx2 = VersionedTransaction.fromBytes(bytes);
    assert.strictEqual(tx2.feePayer, tx.feePayer);
    assert.strictEqual(tx2.recentBlockhash, tx.recentBlockhash);
  });

  it("should build versioned transaction with ALTs (Jupiter-like)", () => {
    // Simulates a Jupiter swap transaction with Address Lookup Tables
    const data = {
      staticAccountKeys: [
        "35aKHPPJqb7qVNAaUb8DQLRC3Njp5RJZJSQM3v2PZhM7",
        "ESuE8KSzSHBRCtgDwauL7vCR2ohxrWXf8rw75vVbNFvL",
        "DWkKDVpGEVeABT4xh4SoBJzzxhSZxBuK7fWAD5LiMBui",
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "11111111111111111111111111111111",
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
        "ComputeBudget111111111111111111111111111111",
      ],
      addressLookupTables: [
        {
          accountKey: "2immgwYNHBbyVQKVGCEkgWpi53bLwWNRMB5G2nbgYV17",
          writableIndexes: [0, 16, 21],
          readonlyIndexes: [1, 4, 22],
        },
      ],
      versionedInstructions: [
        {
          programIdIndex: 6,
          accountKeyIndexes: [],
          data: "3DdGGhkhJbjm", // SetComputeUnitLimit
        },
        {
          programIdIndex: 6,
          accountKeyIndexes: [],
          data: "Fj2Eoy", // SetComputeUnitPrice
        },
        {
          programIdIndex: 5,
          accountKeyIndexes: [0, 1, 2, 3, 4],
          data: "2gCNTm5Pp1JgJmCK3KqDm", // Jupiter route
        },
      ],
      messageHeader: {
        numRequiredSignatures: 1,
        numReadonlySignedAccounts: 0,
        numReadonlyUnsignedAccounts: 3,
      },
      recentBlockhash: blockhash,
    };

    const tx = buildFromVersionedData(data);

    assert.ok(tx.feePayer);
    assert.strictEqual(tx.feePayer, data.staticAccountKeys[0]);
    assert.strictEqual(tx.recentBlockhash, blockhash);
    assert.strictEqual(tx.numSignatures, 1);
    assert.strictEqual(tx.numInstructions, 3);

    // Verify it serializes correctly
    const bytes = tx.toBytes();
    assert.ok(bytes.length > 0);

    // Verify it can be parsed back
    const tx2 = VersionedTransaction.fromBytes(bytes);
    assert.strictEqual(tx2.feePayer, tx.feePayer);
    assert.strictEqual(tx2.recentBlockhash, tx.recentBlockhash);
    assert.ok(tx2.isVersioned);
  });

  it("should add signature to versioned transaction", () => {
    const data = {
      staticAccountKeys: [feePayer, "11111111111111111111111111111111"],
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
      recentBlockhash: blockhash,
    };

    const tx = buildFromVersionedData(data);

    // Initially unsigned
    assert.strictEqual(tx.id, "UNSIGNED");

    // Add signature
    const signature = new Uint8Array(64);
    for (let i = 0; i < 64; i++) signature[i] = i + 1;
    tx.addSignature(feePayer, signature);

    // Now signed
    assert.notStrictEqual(tx.id, "UNSIGNED");
    assert.ok(tx.id.length > 20);
  });
});
