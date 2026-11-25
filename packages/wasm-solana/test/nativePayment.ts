import * as assert from "assert";
import { createRequire } from "node:module";
import { parseTransaction } from "../js/parser.js";
import { Transaction } from "../js/transaction.js";

const value: unknown = createRequire(import.meta.url)("./fixtures/native-payment.json");
function isRecord(input: unknown): input is Record<string, unknown> {
  return typeof input === "object" && input !== null && !Array.isArray(input);
}
if (!isRecord(value)) {
  throw new TypeError("invalid reference fixture");
}
const fixture: Record<string, unknown> = value;

function text(key: string): string {
  if (!(key in fixture) || typeof fixture[key] !== "string") {
    throw new TypeError(`invalid fixture field ${key}`);
  }
  return fixture[key];
}

const bytes = Buffer.from(text("transactionBase64"), "base64");

describe("legacy native payment reference", () => {
  it("preserves message, signer slots, roles, nonce and transfer order", () => {
    const tx = Transaction.fromBytes(bytes);
    assert.deepStrictEqual(Buffer.from(tx.toBytes()), bytes);
    assert.deepStrictEqual(
      Buffer.from(tx.signablePayload()),
      Buffer.from(text("messageBase64"), "base64"),
    );
    assert.strictEqual(tx.feePayer, text("source"));
    assert.strictEqual(tx.recentBlockhash, text("blockhash"));
    assert.strictEqual(tx.signerIndex(text("source")), 0);
    assert.strictEqual(tx.signerIndex(text("nonceAuthority")), 1);
    assert.deepStrictEqual(tx.signatures[0], new Uint8Array(64));
    assert.deepStrictEqual(tx.signatures[1], new Uint8Array(64).fill(9));

    const nonceAccounts = tx.instructions[0].accounts;
    assert.deepStrictEqual(
      nonceAccounts.map((account) => [account.pubkey, account.isSigner, account.isWritable]),
      [
        [text("nonceAccount"), false, true],
        ["SysvarRecentB1ockHashes11111111111111111111", false, false],
        [text("nonceAuthority"), true, false],
      ],
    );
    const parsed = parseTransaction(tx);
    assert.deepStrictEqual(
      parsed.instructionsData.map((item) => item.type),
      ["NonceAdvance", "SetComputeUnitLimit", "Memo", "Transfer", "Transfer"],
    );
    assert.deepStrictEqual(parsed.durableNonce, {
      walletNonceAddress: text("nonceAccount"),
      authWalletAddress: text("nonceAuthority"),
    });
    const transfers = parsed.instructionsData.slice(3);
    assert.deepStrictEqual(
      transfers,
      [123456789n, 0n].map((amount) => ({
        type: "Transfer",
        fromAddress: text("source"),
        toAddress: text("destination"),
        amount,
      })),
    );
  });

  it("rejects truncation, trailing bytes, invalid signature count and oversized packets", () => {
    assert.throws(() => Transaction.fromBytes(bytes.subarray(0, bytes.length - 1)));
    assert.throws(() => Transaction.fromBytes(Buffer.concat([bytes, Buffer.from([0])])));
    assert.throws(() => Transaction.fromBytes(new Uint8Array(1233)));
    assert.throws(() => Transaction.fromBytes(Uint8Array.of(255, 255, 3)));
    const mismatchedSlots = Buffer.from(bytes);
    mismatchedSlots[1 + 2 * 64] = 3;
    assert.throws(() => Transaction.fromBytes(mismatchedSlots));
  });

  it("preserves native amounts beyond the JavaScript safe integer range", () => {
    const data = Buffer.from([2, 0, 0, 0, 21, 205, 91, 7, 0, 0, 0, 0]);
    const offset = bytes.indexOf(data);
    assert.ok(offset > 0);
    const altered = Buffer.from(bytes);
    const amount = (1n << 60n) + 7n;
    altered.writeBigUInt64LE(amount, offset + 4);
    const transfer = parseTransaction(Transaction.fromBytes(altered)).instructionsData[3];
    assert.strictEqual(transfer.type, "Transfer");
    if (transfer.type !== "Transfer") throw new Error("expected transfer");
    assert.strictEqual(transfer.amount, amount);
  });

  it("keeps noncanonical transfer data unknown and preserves its account roles", () => {
    const data = Buffer.from([2, 0, 0, 0, 21, 205, 91, 7, 0, 0, 0, 0]);
    const offset = bytes.indexOf(data);
    assert.ok(offset > 0);
    assert.strictEqual(bytes[offset - 1], data.length);
    const altered = Buffer.concat([
      bytes.subarray(0, offset - 1),
      Buffer.from([data.length + 1]),
      data,
      Buffer.from([42]),
      bytes.subarray(offset + data.length),
    ]);
    const parsed = parseTransaction(Transaction.fromBytes(altered));
    const instruction = parsed.instructionsData[3];
    assert.strictEqual(instruction.type, "Unknown");
    if (instruction.type !== "Unknown") throw new Error("expected unknown instruction");
    assert.deepStrictEqual(
      instruction.accounts.map((account) => [account.pubkey, account.isSigner, account.isWritable]),
      [
        [text("source"), true, true],
        [text("destination"), false, true],
      ],
    );
    assert.strictEqual(
      instruction.data,
      Buffer.concat([data, Buffer.from([42])]).toString("base64"),
    );
  });
});
