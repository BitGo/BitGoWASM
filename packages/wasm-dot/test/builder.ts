import * as assert from "assert";
import {
  buildTransaction,
  encodeSs58,
  parseTransaction,
  type TransactionIntent,
  type BuildContext,
} from "../js/index.js";
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

  describe("SS58 address domains", () => {
    const pubkey = new Uint8Array(32).fill(7);
    const addresses = new Map(
      ([0, 2, 42] as const).map((prefix) => [prefix, encodeSs58(pubkey, prefix)] as const),
    );
    const address = (prefix: number): string => addresses.get(prefix)!;

    // Reuse Westend runtime metadata to isolate address-domain handling.
    // The chainName controls the trusted prefix, not the metadata contents.
    const context = (chainName: string, prefix: number): BuildContext => ({
      ...testContext(),
      sender: address(prefix),
      material: { ...WESTEND_MATERIAL, chainName },
    });

    const destinations = (to: string, proxy: string): [string, TransactionIntent][] => [
      ["payment", { type: "payment", to, amount: 1n }],
      ["consolidate", { type: "consolidate", to }],
      [
        "account payee",
        {
          type: "stake",
          amount: 1n,
          proxyAddress: proxy,
          payee: { type: "account", address: to },
        },
      ],
      ["add proxy", { type: "stake", amount: 1n, proxyAddress: to }],
      ["remove proxy", { type: "unstake", amount: 1n, stopStaking: true, proxyAddress: to }],
    ];

    for (const [chainName, expected, wrong] of [
      ["Polkadot", 0, 2],
      ["Kusama", 2, 0],
    ] as const) {
      for (const [name, intent] of destinations(address(wrong), address(expected))) {
        it(`${chainName} rejects ${name} from prefix ${wrong} before creating a payload`, () => {
          assert.throws(
            () => buildTransaction(intent, context(chainName, expected)),
            { code: "WrongNetwork", actualPrefix: wrong, expectedPrefix: expected },
          );
        });
      }

      it(`${chainName} rejects generic destinations unless allowed`, () => {
        assert.throws(
          () =>
            buildTransaction(
              { type: "payment", to: address(42), amount: 1n },
              context(chainName, expected),
            ),
          /Wrong SS58 network/,
        );
      });

      for (const [name, intent] of destinations(address(expected), address(expected))) {
        it(`${chainName} parses ${name} in the approved domain`, () => {
          const ctx = context(chainName, expected);
          const tx = buildTransaction(intent, ctx);
          const args = parseTransaction(tx, { material: ctx.material }).method.args;
          const calls = args.calls as { args: Record<string, unknown> }[] | undefined;
          const actual =
            name === "account payee"
              ? calls?.[0].args.payee
              : name === "add proxy"
                ? calls?.[1].args.delegate
                : name === "remove proxy"
                  ? calls?.[0].args.delegate
                  : args.dest;
          assert.strictEqual(actual, address(expected));
        });
      }
    }

    it("accepts explicit generic inputs but parses the canonical chain address", () => {
      const ctx = context("Polkadot", 0);
      ctx.material.ss58AddressPolicy = { prefix: 0, allowGeneric: true };
      const tx = buildTransaction({ type: "payment", to: address(42), amount: 1n }, ctx);
      assert.strictEqual(
        parseTransaction(tx, { material: ctx.material }).method.args.dest,
        address(0),
      );
    });

    it("keeps generic-chain inputs in the approved domain", () => {
      const ctx = context("Westend", 42);
      const tx = buildTransaction({ type: "consolidate", to: address(42) }, ctx);
      assert.strictEqual(
        parseTransaction(tx, { material: ctx.material }).method.args.dest,
        address(42),
      );
    });

    it("requires an explicit format for unmapped chains", () => {
      const ctx = context("Custom chain", 42);
      const intent: TransactionIntent = { type: "payment", to: address(42), amount: 1n };
      assert.throws(() => buildTransaction(intent, ctx), /SS58 prefix required/);
      ctx.material.ss58AddressPolicy = { prefix: 42 };
      const tx = buildTransaction(intent, ctx);
      assert.strictEqual(
        parseTransaction(tx, { material: ctx.material }).method.args.dest,
        address(42),
      );
    });

    it("rejects an incorrect known-chain policy and an out-of-range prefix", () => {
      const ctx = context("Polkadot", 0);
      const intent: TransactionIntent = { type: "payment", to: address(0), amount: 1n };
      ctx.material.ss58AddressPolicy = { prefix: 2 };
      assert.throws(() => buildTransaction(intent, ctx), /conflicts with chain Polkadot/);
      ctx.material = {
        ...ctx.material,
        chainName: "Custom chain",
        ss58AddressPolicy: { prefix: 16384 },
      };
      assert.throws(() => buildTransaction(intent, ctx), /Invalid SS58 prefix/);
    });

    it("rejects malformed destination and wrong-domain fillNonce sender", () => {
      const ctx = context("Polkadot", 0);
      assert.throws(
        () => buildTransaction({ type: "payment", to: "invalid!", amount: 1n }, ctx),
        /Invalid address/,
      );
      ctx.sender = address(2);
      assert.throws(
        () => buildTransaction({ type: "fillNonce" }, ctx),
        /Wrong SS58 network: prefix 2/,
      );
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
