import * as assert from "assert";
import {
  buildTransaction,
  parseTransaction,
  explainTransaction,
  TransactionType,
  type TransactionIntent,
  type BuildContext,
} from "../js/index.js";
import { westendMetadataRpc } from "./resources/westend.js";

describe("explainTransaction", () => {
  const SENDER = "5EGoFA95omzemRssELLDjVenNZ68aXyUeqtKQScXSEBvVJkr";
  const RECIPIENT = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";

  const WESTEND_MATERIAL = {
    genesisHash: "0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e",
    chainName: "Westend",
    specName: "westend",
    specVersion: 9420,
    txVersion: 16,
    metadata: westendMetadataRpc,
  };

  const REFERENCE_BLOCK = "0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e";

  const testContext = (nonce: number = 0): BuildContext => ({
    sender: SENDER,
    nonce,
    material: WESTEND_MATERIAL,
    validity: { firstValid: 1000, maxDuration: 2400 },
    referenceBlock: REFERENCE_BLOCK,
  });

  const FIRST_VALID = 1000;

  const parseContext = {
    material: WESTEND_MATERIAL,
    referenceBlock: REFERENCE_BLOCK,
    blockNumber: FIRST_VALID,
  };

  /** Build a transaction, then explain it (round-trip) */
  function buildAndExplain(intent: TransactionIntent, nonce = 0) {
    const tx = buildTransaction(intent, testContext(nonce));
    return explainTransaction(tx.toHex(), { context: parseContext });
  }

  describe("transfers", () => {
    it("should explain a transfer as Send", () => {
      const explained = buildAndExplain({
        type: "transfer",
        to: RECIPIENT,
        amount: 1000000000000n,
      });

      assert.strictEqual(explained.type, TransactionType.Send);
      assert.strictEqual(explained.outputs.length, 1);
      assert.strictEqual(explained.outputs[0].amount, "1000000000000");
      assert.strictEqual(explained.outputAmount, "1000000000000");
      assert.strictEqual(explained.method.pallet, "balances");
    });

    it("should explain transferAll as Send with ALL amount", () => {
      const explained = buildAndExplain({
        type: "transferAll",
        to: RECIPIENT,
        keepAlive: false,
      });

      assert.strictEqual(explained.type, TransactionType.Send);
      assert.strictEqual(explained.outputs.length, 1);
      assert.strictEqual(explained.outputs[0].amount, "ALL");
      // ALL outputs don't contribute to outputAmount
      assert.strictEqual(explained.outputAmount, "0");
    });
  });

  describe("staking", () => {
    it("should explain bond as StakingActivate", () => {
      const explained = buildAndExplain({
        type: "stake",
        amount: 10000000000000n,
        payee: { type: "stash" },
      });

      assert.strictEqual(explained.type, TransactionType.StakingActivate);
      assert.strictEqual(explained.outputs.length, 1);
      assert.strictEqual(explained.outputs[0].address, "STAKING");
      assert.strictEqual(explained.outputs[0].amount, "10000000000000");
      assert.strictEqual(explained.method.args.payee, "Stash");
    });

    it("should explain unbond as StakingUnlock", () => {
      const explained = buildAndExplain({
        type: "unstake",
        amount: 5000000000000n,
      });

      assert.strictEqual(explained.type, TransactionType.StakingUnlock);
      assert.strictEqual(explained.outputs.length, 1);
      assert.strictEqual(explained.outputs[0].address, "STAKING");
      assert.strictEqual(explained.outputs[0].amount, "5000000000000");
    });

    it("should explain withdrawUnbonded as StakingWithdraw", () => {
      const explained = buildAndExplain({
        type: "withdrawUnbonded",
        slashingSpans: 0,
      });

      assert.strictEqual(explained.type, TransactionType.StakingWithdraw);
      assert.strictEqual(explained.outputs.length, 0);
      assert.strictEqual(explained.method.args.numSlashingSpans, 0);
    });

    it("should explain chill as StakingUnvote", () => {
      const explained = buildAndExplain({ type: "chill" });

      assert.strictEqual(explained.type, TransactionType.StakingUnvote);
      assert.strictEqual(explained.outputs.length, 0);
    });
  });

  describe("proxy", () => {
    it("should explain addProxy as AddressInitialization", () => {
      const explained = buildAndExplain({
        type: "addProxy",
        delegate: RECIPIENT,
        proxyType: "Any",
        delay: 0,
      });

      assert.strictEqual(explained.type, TransactionType.AddressInitialization);
      assert.strictEqual(explained.outputs.length, 0);
      assert.strictEqual(explained.method.args.proxy_type, "Any");
      assert.strictEqual(explained.method.args.delay, 0);
    });

    it("should explain removeProxy as AddressInitialization", () => {
      // Use "Any" (index 0) — consistent across all chains.
      // Note: proxy type indices differ between chains (e.g., "Staking" is index 3
      // on Polkadot but index 2 on Westend), so the parser's hardcoded mapping
      // may not match the builder's metadata-based encoding for non-zero types.
      const explained = buildAndExplain({
        type: "removeProxy",
        delegate: RECIPIENT,
        proxyType: "Any",
        delay: 0,
      });

      assert.strictEqual(explained.type, TransactionType.AddressInitialization);
      assert.strictEqual(explained.method.args.proxy_type, "Any");
    });
  });

  describe("batch", () => {
    it("should explain batch as Batch type", () => {
      const explained = buildAndExplain({
        type: "batch",
        calls: [{ type: "transfer", to: RECIPIENT, amount: 1000000000000n }, { type: "chill" }],
        atomic: true,
      });

      assert.strictEqual(explained.type, TransactionType.Batch);
      assert.strictEqual(explained.method.pallet, "utility");
      // Batch should extract outputs from inner calls
      assert.strictEqual(explained.outputs.length, 1);
      assert.strictEqual(explained.outputs[0].amount, "1000000000000");
    });

    it("should extract outputs from multiple batch calls", () => {
      const explained = buildAndExplain({
        type: "batch",
        calls: [
          { type: "transfer", to: RECIPIENT, amount: 1000000000000n },
          { type: "stake", amount: 5000000000000n, payee: { type: "staked" } },
        ],
        atomic: false,
      });

      assert.strictEqual(explained.type, TransactionType.Batch);
      assert.strictEqual(explained.outputs.length, 2);
      assert.strictEqual(explained.outputs[0].amount, "1000000000000");
      assert.strictEqual(explained.outputs[1].address, "STAKING");
      assert.strictEqual(explained.outputs[1].amount, "5000000000000");
      assert.strictEqual(explained.outputAmount, "6000000000000");
    });
  });

  describe("unsigned transactions", () => {
    it("should handle unsigned transaction (no sender, no id)", () => {
      const intent: TransactionIntent = {
        type: "transfer",
        to: RECIPIENT,
        amount: 1000000000000n,
      };

      const tx = buildTransaction(intent, testContext(0));
      // Parse without signing → unsigned
      const explained = explainTransaction(tx.toHex(), { context: parseContext });

      assert.strictEqual(explained.isSigned, false);
      assert.strictEqual(explained.id, undefined);
      // Unsigned tx has no sender
      assert.strictEqual(explained.sender, undefined);
      assert.strictEqual(explained.inputs.length, 0);
    });
  });

  describe("metadata", () => {
    it("should populate tip and era", () => {
      const explained = buildAndExplain({
        type: "transfer",
        to: RECIPIENT,
        amount: 1000000000000n,
      });

      assert.strictEqual(explained.tip, "0");
      assert.strictEqual(explained.nonce, 0);
      assert.strictEqual(explained.era.type, "mortal");
    });

    it("should pass through context fields (material + referenceBlock + blockNumber)", () => {
      const explained = buildAndExplain({
        type: "transfer",
        to: RECIPIENT,
        amount: 1000000000000n,
      });

      // From material
      assert.strictEqual(explained.genesisHash, WESTEND_MATERIAL.genesisHash);
      assert.strictEqual(explained.specVersion, WESTEND_MATERIAL.specVersion);
      assert.strictEqual(explained.transactionVersion, WESTEND_MATERIAL.txVersion);
      assert.strictEqual(explained.chainName, WESTEND_MATERIAL.chainName);
      // From context
      assert.strictEqual(explained.referenceBlock, REFERENCE_BLOCK);
      assert.strictEqual(explained.blockNumber, FIRST_VALID);
    });

    it("should omit context fields when no context is provided", () => {
      const tx = buildTransaction(
        { type: "transfer", to: RECIPIENT, amount: 1000000000000n },
        testContext(0),
      );
      const explained = explainTransaction(tx.toHex(), {});

      assert.strictEqual(explained.genesisHash, undefined);
      assert.strictEqual(explained.specVersion, undefined);
      assert.strictEqual(explained.referenceBlock, undefined);
      assert.strictEqual(explained.blockNumber, undefined);
    });
  });

  describe("parseTransaction → .parse() pattern", () => {
    it("should return a DotTransaction with .parse() method", () => {
      const builtTx = buildTransaction(
        { type: "transfer", to: RECIPIENT, amount: 1000000000000n },
        testContext(0),
      );

      // parseTransaction returns a DotTransaction (not plain data)
      const tx = parseTransaction(builtTx.toHex(), parseContext);
      assert.ok(tx.signablePayload, "should have signablePayload method");
      assert.ok(tx.addSignature, "should have addSignature method");
      assert.ok(tx.parse, "should have parse method");

      // .parse() returns decoded method data
      const parsed = tx.parse();
      assert.strictEqual(parsed.method.pallet, "balances");
      assert.strictEqual(parsed.method.name, "transferKeepAlive");
      assert.strictEqual(parsed.nonce, 0);
      assert.strictEqual(parsed.isSigned, false);
    });

    it("should preserve context from buildTransaction for .parse()", () => {
      // buildTransaction stores context — .parse() should work without extra args
      const tx = buildTransaction(
        { type: "stake", amount: 10000000000000n, payee: { type: "stash" } },
        testContext(5),
      );

      const parsed = tx.parse();
      assert.strictEqual(parsed.method.pallet, "staking");
      assert.strictEqual(parsed.method.name, "bond");
      assert.strictEqual(parsed.nonce, 5);
    });

    it("should roundtrip: build → toHex → parseTransaction → .parse()", () => {
      const tx = buildTransaction(
        {
          type: "batch",
          calls: [{ type: "transfer", to: RECIPIENT, amount: 1000000000000n }, { type: "chill" }],
          atomic: true,
        },
        testContext(0),
      );

      // Roundtrip through hex
      const hex = tx.toHex();
      const parsed = parseTransaction(hex, parseContext);
      const data = parsed.parse();

      assert.strictEqual(data.method.pallet, "utility");
      assert.strictEqual(data.method.name, "batchAll");
    });
  });
});
