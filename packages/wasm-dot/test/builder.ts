import * as assert from "assert";
import { buildTransaction, type TransactionIntent, type BuildContext } from "../js/index.js";
import { getWestendMetadata } from "./resources/westend.js";

/** Convert Uint8Array to hex string (no 0x prefix) */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

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
    metadata: getWestendMetadata(),
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

  describe("payment", () => {
    it("should build a payment transaction (transferKeepAlive)", () => {
      const intent: TransactionIntent = {
        type: "payment",
        to: RECIPIENT,
        amount: 1000000000000n,
      };

      const tx = buildTransaction(intent, testContext(0));
      assert.ok(tx);
      assert.strictEqual(tx.nonce, 0);
    });

    it("should build a payment with custom nonce", () => {
      const intent: TransactionIntent = {
        type: "payment",
        to: RECIPIENT,
        amount: 1000000000000n,
      };

      const tx = buildTransaction(intent, testContext(5));
      assert.ok(tx);
      assert.strictEqual(tx.nonce, 5);
    });

    it("should build a payment with keepAlive=false (transferAllowDeath)", () => {
      const intent: TransactionIntent = {
        type: "payment",
        to: RECIPIENT,
        amount: 1000000000000n,
        keepAlive: false,
      };

      const tx = buildTransaction(intent, testContext(0));
      assert.ok(tx);
    });
  });

  describe("consolidate", () => {
    it("should build a consolidate transaction (transferAll)", () => {
      const intent: TransactionIntent = {
        type: "consolidate",
        to: RECIPIENT,
      };

      const tx = buildTransaction(intent, testContext(1));
      assert.ok(tx);
    });

    it("should build consolidate with keepAlive=false", () => {
      const intent: TransactionIntent = {
        type: "consolidate",
        to: RECIPIENT,
        keepAlive: false,
      };

      const tx = buildTransaction(intent, testContext(0));
      assert.ok(tx);
    });
  });

  describe("staking", () => {
    it("should build a stake top-up (bondExtra)", () => {
      const intent: TransactionIntent = {
        type: "stake",
        amount: 10000000000000n,
      };

      const tx = buildTransaction(intent, testContext(0));
      assert.ok(tx);
    });

    it("should build a new stake with proxy (batchAll: bond + addProxy)", () => {
      const intent: TransactionIntent = {
        type: "stake",
        amount: 10000000000000n,
        payee: { type: "stash" },
        proxyAddress: RECIPIENT,
      };

      const tx = buildTransaction(intent, testContext(0));
      assert.ok(tx);
      // Should be a batchAll since it produces bond + addProxy
      const callData = toHex(tx.callData);
      // Utility.batch_all pallet index varies by runtime, but compact length should be 0x08 (2 calls)
      assert.ok(callData.length > 10, "Batch call data should be non-trivial");
    });

    it("should build a partial unstake (unbond)", () => {
      const intent: TransactionIntent = {
        type: "unstake",
        amount: 5000000000000n,
      };

      const tx = buildTransaction(intent, testContext(1));
      assert.ok(tx);
    });

    it("should build a full unstake with proxy (batchAll: removeProxy + chill + unbond)", () => {
      const intent: TransactionIntent = {
        type: "unstake",
        amount: 5000000000000n,
        stopStaking: true,
        proxyAddress: RECIPIENT,
      };

      const tx = buildTransaction(intent, testContext(2));
      assert.ok(tx);
      // Should be a batchAll with 3 calls
      const callData = toHex(tx.callData);
      assert.ok(callData.length > 20, "Full unstake batch should be non-trivial");
    });
  });

  describe("claim", () => {
    it("should build a claim transaction (withdrawUnbonded)", () => {
      const intent: TransactionIntent = {
        type: "claim",
      };

      const tx = buildTransaction(intent, testContext(3));
      assert.ok(tx);
    });

    it("should build a claim with custom slashingSpans", () => {
      const intent: TransactionIntent = {
        type: "claim",
        slashingSpans: 5,
      };

      const tx = buildTransaction(intent, testContext(0));
      assert.ok(tx);
    });
  });

  describe("fillNonce", () => {
    it("should build a fillNonce transaction (zero self-transfer)", () => {
      const intent: TransactionIntent = {
        type: "fillNonce",
      };

      const tx = buildTransaction(intent, testContext(42));
      assert.ok(tx);
      assert.strictEqual(tx.nonce, 42);
    });
  });

  describe("batch composition", () => {
    it("new stake call data should differ from top-up (bond+addProxy vs bondExtra)", () => {
      const topUp: TransactionIntent = {
        type: "stake",
        amount: 10000000000000n,
      };
      const newStake: TransactionIntent = {
        type: "stake",
        amount: 10000000000000n,
        proxyAddress: RECIPIENT,
      };

      const topUpTx = buildTransaction(topUp, testContext(0));
      const newStakeTx = buildTransaction(newStake, testContext(0));

      // They should produce different call data (bondExtra vs batchAll(bond, addProxy))
      assert.notStrictEqual(
        toHex(topUpTx.callData),
        toHex(newStakeTx.callData),
        "Top-up and new stake should produce different call data",
      );
    });

    it("partial unstake call data should differ from full unstake", () => {
      const partial: TransactionIntent = {
        type: "unstake",
        amount: 5000000000000n,
      };
      const full: TransactionIntent = {
        type: "unstake",
        amount: 5000000000000n,
        stopStaking: true,
        proxyAddress: RECIPIENT,
      };

      const partialTx = buildTransaction(partial, testContext(0));
      const fullTx = buildTransaction(full, testContext(0));

      assert.notStrictEqual(
        toHex(partialTx.callData),
        toHex(fullTx.callData),
        "Partial and full unstake should produce different call data",
      );

      // Full unstake should have larger call data (3 calls vs 1)
      assert.ok(
        fullTx.callData.length > partialTx.callData.length,
        "Full unstake (3 calls) should be larger than partial (1 call)",
      );
    });
  });
});
