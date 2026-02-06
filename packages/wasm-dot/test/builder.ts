import * as assert from "assert";
import { buildTransaction, type TransactionIntent, type BuildContext } from "../js/index.js";
import { westendMetadataRpc } from "./resources/westend.js";

describe("buildTransaction", () => {
  // Test addresses (Substrate generic format, prefix 42)
  const SENDER = "5EGoFA95omzemRssELLDjVenNZ68aXyUeqtKQScXSEBvVJkr";
  const RECIPIENT = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";

  // Westend testnet material (with metadata)
  const WESTEND_MATERIAL = {
    genesisHash: "0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e",
    chainName: "Westend",
    specName: "westend",
    specVersion: 9420,
    txVersion: 16,
    metadataHex: westendMetadataRpc,
  };

  // Reference block (use genesis for testing)
  const REFERENCE_BLOCK = "0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e";

  // Common context for tests
  const testContext = (nonce: number = 0): BuildContext => ({
    sender: SENDER,
    nonce,
    material: WESTEND_MATERIAL,
    validity: { firstValid: 1000, maxDuration: 2400 },
    referenceBlock: REFERENCE_BLOCK,
  });

  describe("transfer", () => {
    it("should build a DOT transfer transaction", () => {
      const intent: TransactionIntent = {
        type: "transfer",
        to: RECIPIENT,
        amount: "1000000000000",
      };

      const tx = buildTransaction(intent, testContext(0));
      assert.ok(tx);
      assert.strictEqual(tx.nonce, 0);
    });

    it("should build a transfer with BigInt amount", () => {
      const intent: TransactionIntent = {
        type: "transfer",
        to: RECIPIENT,
        amount: 1000000000000n,
      };

      const tx = buildTransaction(intent, testContext(5));
      assert.ok(tx);
      assert.strictEqual(tx.nonce, 5);
    });

    it("should build transferAll", () => {
      const intent: TransactionIntent = {
        type: "transferAll",
        to: RECIPIENT,
        keepAlive: false,
      };

      const tx = buildTransaction(intent, testContext(1));
      assert.ok(tx);
    });
  });

  describe("staking operations", () => {
    it("should build a stake (bond) transaction", () => {
      const intent: TransactionIntent = {
        type: "stake",
        amount: "10000000000000",
        payee: { type: "stash" },
      };

      const tx = buildTransaction(intent, testContext(0));
      assert.ok(tx);
    });

    it("should build an unstake (unbond) transaction", () => {
      const intent: TransactionIntent = {
        type: "unstake",
        amount: "5000000000000",
      };

      const tx = buildTransaction(intent, testContext(1));
      assert.ok(tx);
    });

    it("should build a chill transaction", () => {
      const intent: TransactionIntent = { type: "chill" };

      const tx = buildTransaction(intent, testContext(2));
      assert.ok(tx);
    });

    it("should build a withdrawUnbonded transaction", () => {
      const intent: TransactionIntent = {
        type: "withdrawUnbonded",
        slashingSpans: 0,
      };

      const tx = buildTransaction(intent, testContext(3));
      assert.ok(tx);
    });
  });

  describe("batch operations", () => {
    it("should build a batched transaction with transfer + stake", () => {
      const intent: TransactionIntent = {
        type: "batch",
        calls: [
          { type: "transfer", to: RECIPIENT, amount: "1000000000000" },
          { type: "stake", amount: "5000000000000", payee: { type: "staked" } },
        ],
        atomic: true,
      };

      const tx = buildTransaction(intent, testContext(10));
      assert.ok(tx);
    });

    it("should build non-atomic batch", () => {
      const intent: TransactionIntent = {
        type: "batch",
        calls: [{ type: "transfer", to: RECIPIENT, amount: "1000000000000" }, { type: "chill" }],
        atomic: false,
      };

      const tx = buildTransaction(intent, testContext(0));
      assert.ok(tx);
    });

    it("should encode batch calls correctly - inner calls match standalone encoding", () => {
      // Build a standalone transfer
      const transferIntent: TransactionIntent = {
        type: "transfer",
        to: RECIPIENT,
        amount: "1000000000000",
      };
      const standaloneTx = buildTransaction(transferIntent, testContext(0));
      const standaloneCallData = standaloneTx.callDataHex.replace("0x", "");

      // Build a batch with the same transfer
      const batchIntent: TransactionIntent = {
        type: "batch",
        calls: [transferIntent],
        atomic: true,
      };
      const batchTx = buildTransaction(batchIntent, testContext(0));
      const batchCallData = batchTx.callDataHex.replace("0x", "");

      // Batch structure: [pallet_idx][call_idx][compact_len][call1...]
      // The inner call should appear in the batch call data after the header
      assert.ok(
        batchCallData.includes(standaloneCallData),
        `Batch call data should contain the standalone call data.\nBatch: ${batchCallData}\nStandalone: ${standaloneCallData}`,
      );

      // Verify batch has correct length prefix (1 call = 0x04 in compact encoding)
      // Format: pallet(1) + method(1) + compact_len + calls
      // For single call batch, compact(1) = 0x04
      const compactLen = batchCallData.slice(4, 6); // bytes 2-3 (after pallet+method)
      assert.strictEqual(compactLen, "04", "Compact length for 1 call should be 0x04");

      // Verify the call appears right after the header
      const callsStart = batchCallData.slice(6); // after pallet + method + compact_len
      assert.strictEqual(
        callsStart,
        standaloneCallData,
        "Call data should match exactly after batch header",
      );
    });

    it("should encode batch with 2 calls correctly", () => {
      // Build standalone calls
      const transfer: TransactionIntent = {
        type: "transfer",
        to: RECIPIENT,
        amount: "1000000000000",
      };
      const chill: TransactionIntent = { type: "chill" };

      const transferTx = buildTransaction(transfer, testContext(0));
      const chillTx = buildTransaction(chill, testContext(0));

      // Build batch
      const batchIntent: TransactionIntent = {
        type: "batch",
        calls: [transfer, chill],
        atomic: false,
      };
      const batchTx = buildTransaction(batchIntent, testContext(0));
      const batchCallData = batchTx.callDataHex.replace("0x", "");

      // Verify compact length = 0x08 (2 calls)
      const compactLen = batchCallData.slice(4, 6);
      assert.strictEqual(compactLen, "08", "Compact length for 2 calls should be 0x08");

      // Verify both calls are in the batch
      assert.ok(
        batchCallData.includes(transferTx.callDataHex.replace("0x", "")),
        "Batch should contain transfer call",
      );
      assert.ok(
        batchCallData.includes(chillTx.callDataHex.replace("0x", "")),
        "Batch should contain chill call",
      );
    });
  });

  describe("proxy operations", () => {
    it("should build addProxy transaction", () => {
      const intent: TransactionIntent = {
        type: "addProxy",
        delegate: RECIPIENT,
        proxyType: "Any",
        delay: 0,
      };

      const tx = buildTransaction(intent, testContext(0));
      assert.ok(tx);
    });

    it("should build removeProxy transaction", () => {
      const intent: TransactionIntent = {
        type: "removeProxy",
        delegate: RECIPIENT,
        proxyType: "Staking",
        delay: 0,
      };

      const tx = buildTransaction(intent, testContext(1));
      assert.ok(tx);
    });
  });
});
