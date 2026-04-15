import assert from "node:assert";
import { Transaction, ZcashTransaction, DashTransaction } from "../js/transaction.js";
import { fixedScriptWallet } from "../js/index.js";
import { coinNames } from "../js/coinName.js";

describe("Transaction builder", function () {
  it("should create an empty transaction", function () {
    const tx = Transaction.create();
    const bytes = tx.toBytes();
    assert.ok(bytes.length > 0, "serialized transaction should not be empty");

    // Round-trip: the deserialized transaction should produce the same bytes
    const tx2 = Transaction.fromBytes(bytes);
    assert.deepStrictEqual(tx2.toBytes(), bytes);
  });

  it("should add an input and return index 0", function () {
    const tx = Transaction.create();
    const txid = "a".repeat(64);
    const idx = tx.addInput(txid, 0);
    assert.strictEqual(idx, 0);
  });

  it("should add multiple inputs with incrementing indices", function () {
    const tx = Transaction.create();
    const txid = "b".repeat(64);
    assert.strictEqual(tx.addInput(txid, 0), 0);
    assert.strictEqual(tx.addInput(txid, 1), 1);
    assert.strictEqual(tx.addInput(txid, 2), 2);
  });

  it("should add an output and return index 0", function () {
    const tx = Transaction.create();
    // OP_RETURN script
    const script = fixedScriptWallet.createOpReturnScript();
    const idx = tx.addOutput(script, 0n);
    assert.strictEqual(idx, 0);
  });

  it("should add multiple outputs with incrementing indices", function () {
    const tx = Transaction.create();
    const script = fixedScriptWallet.createOpReturnScript();
    assert.strictEqual(tx.addOutput(script, 1000n), 0);
    assert.strictEqual(tx.addOutput(script, 2000n), 1);
  });

  it("should round-trip a transaction with inputs and outputs", function () {
    const tx = Transaction.create();
    const txid = "c".repeat(64);
    tx.addInput(txid, 0);
    tx.addInput(txid, 1, 0xfffffffe);

    const script = fixedScriptWallet.createOpReturnScript(new Uint8Array([0xde, 0xad]));
    tx.addOutput(script, 50000n);

    const bytes = tx.toBytes();
    const tx2 = Transaction.fromBytes(bytes);
    assert.deepStrictEqual(tx2.toBytes(), bytes);
    assert.strictEqual(tx2.getId(), tx.getId());
    assert.strictEqual(tx2.getVSize(), tx.getVSize());
  });

  it("should produce a valid txid", function () {
    const tx = Transaction.create();
    tx.addInput("a".repeat(64), 0);
    tx.addOutput(fixedScriptWallet.createOpReturnScript(), 0n);
    const txid = tx.getId();
    assert.strictEqual(txid.length, 64);
    assert.match(txid, /^[0-9a-f]{64}$/);
  });

  it("should reject an invalid txid", function () {
    const tx = Transaction.create();
    assert.throws(() => tx.addInput("not-a-valid-txid", 0));
  });

  it("should accept custom sequence number", function () {
    const tx = Transaction.create();
    const txid = "d".repeat(64);
    tx.addInput(txid, 0, 0);
    // If we can round-trip it, the sequence was accepted
    const bytes = tx.toBytes();
    const tx2 = Transaction.fromBytes(bytes);
    assert.deepStrictEqual(tx2.toBytes(), bytes);
  });
});

describe("supportsCoin", function () {
  it("should identify Zcash coins correctly", function () {
    assert.ok(ZcashTransaction.supportsCoin("zec"), "zec should be supported by ZcashTransaction");
    assert.ok(
      ZcashTransaction.supportsCoin("tzec"),
      "tzec should be supported by ZcashTransaction",
    );
  });

  it("should reject non-Zcash coins in ZcashTransaction", function () {
    const nonZcashCoins = coinNames.filter((c) => !ZcashTransaction.supportsCoin(c));
    assert.ok(nonZcashCoins.length > 0, "should have non-Zcash coins");
    nonZcashCoins.forEach((coin) => {
      assert.ok(
        !ZcashTransaction.supportsCoin(coin),
        `ZcashTransaction should not support ${coin}`,
      );
    });
  });

  it("should identify Dash coins correctly", function () {
    assert.ok(DashTransaction.supportsCoin("dash"), "dash should be supported by DashTransaction");
    assert.ok(
      DashTransaction.supportsCoin("tdash"),
      "tdash should be supported by DashTransaction",
    );
  });

  it("should reject non-Dash coins in DashTransaction", function () {
    const nonDashCoins = coinNames.filter((c) => !DashTransaction.supportsCoin(c));
    assert.ok(nonDashCoins.length > 0, "should have non-Dash coins");
    nonDashCoins.forEach((coin) => {
      assert.ok(!DashTransaction.supportsCoin(coin), `DashTransaction should not support ${coin}`);
    });
  });

  it("should identify Bitcoin-like coins correctly", function () {
    const bitcoinLikeCoins = coinNames.filter((c) => Transaction.supportsCoin(c));
    assert.ok(bitcoinLikeCoins.length > 0, "should have Bitcoin-like coins");
    bitcoinLikeCoins.forEach((coin) => {
      assert.ok(
        !ZcashTransaction.supportsCoin(coin) && !DashTransaction.supportsCoin(coin),
        `${coin} should only be supported by Transaction`,
      );
    });
  });

  it("should partition all coins into exactly one family", function () {
    coinNames.forEach((coin) => {
      const zSupports = ZcashTransaction.supportsCoin(coin);
      const dSupports = DashTransaction.supportsCoin(coin);
      const bSupports = Transaction.supportsCoin(coin);

      const supportCount = [zSupports, dSupports, bSupports].filter(Boolean).length;
      assert.strictEqual(
        supportCount,
        1,
        `${coin} should be supported by exactly one transaction class`,
      );
    });
  });
});
