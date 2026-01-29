import * as assert from "assert";
import { parseTransaction } from "../js/parser.js";

// Helper to decode base64 in tests
function base64ToBytes(base64: string): Uint8Array {
  const binary = Buffer.from(base64, "base64");
  return new Uint8Array(binary);
}

describe("parseTransaction", () => {
  // Test transaction from @solana/web3.js - a simple SOL transfer (100000 lamports)
  const TEST_TX_BASE64 =
    "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDFVMqpim7tqEi2XL8R6KKkP0DYJvY3eiRXLlL1P9EjYgXKQC+k0FKnqyC4AZGJR7OhJXfpPP3NHOhS8t/6G7bLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/1c7Oaj3RbyLIjU0/ZPpsmVfVUWAzc8g36fK5g6A0JoBAgIAAQwCAAAAoIYBAAAAAAA=";

  const TEST_TX_BYTES = base64ToBytes(TEST_TX_BASE64);

  it("should parse a SOL transfer transaction", () => {
    const parsed = parseTransaction(TEST_TX_BYTES);

    // Check basic structure
    assert.ok(parsed.feePayer);
    assert.ok(parsed.nonce);
    assert.strictEqual(parsed.numSignatures, 1);
    assert.ok(parsed.instructionsData.length > 0);
    assert.ok(parsed.accountKeys.length > 0);
  });

  it("should decode SOL transfer instruction correctly", () => {
    const parsed = parseTransaction(TEST_TX_BYTES);

    assert.strictEqual(parsed.instructionsData.length, 1);
    const instr = parsed.instructionsData[0];

    // Should be a Transfer instruction
    assert.strictEqual(instr.type, "Transfer");

    // Type guard to access Transfer-specific fields
    if (instr.type === "Transfer") {
      assert.ok(instr.fromAddress);
      assert.ok(instr.toAddress);
      // Amount should be 100000 lamports (from test tx)
      assert.strictEqual(instr.amount, 100000n);
    }
  });

  it("should include fee payer as first account key", () => {
    const parsed = parseTransaction(TEST_TX_BYTES);

    assert.strictEqual(parsed.feePayer, parsed.accountKeys[0]);
  });

  it("should reject invalid bytes", () => {
    const invalidBytes = new Uint8Array([0, 1, 2, 3]);
    assert.throws(() => parseTransaction(invalidBytes));
  });

  it("should set durableNonce for nonce transactions", () => {
    // This is a regular (non-nonce) transaction, so durableNonce should be undefined
    const parsed = parseTransaction(TEST_TX_BYTES);
    assert.strictEqual(parsed.durableNonce, undefined);
  });

  describe("instruction type discrimination", () => {
    it("should have type field on all instructions", () => {
      const parsed = parseTransaction(TEST_TX_BYTES);

      for (const instr of parsed.instructionsData) {
        assert.ok("type" in instr, "Instruction should have type field");
        assert.strictEqual(typeof instr.type, "string");
      }
    });

    it("Transfer instruction should have correct fields", () => {
      const parsed = parseTransaction(TEST_TX_BYTES);
      const transfer = parsed.instructionsData[0];

      if (transfer.type === "Transfer") {
        assert.ok("fromAddress" in transfer);
        assert.ok("toAddress" in transfer);
        assert.ok("amount" in transfer);
      }
    });
  });
});

describe("StakingAuthorize parsing", () => {
  it("should parse CLI-generated StakingAuthorize transaction that web3.js cannot decode", () => {
    // This is a raw CLI-generated Stake Authorize transaction that web3.js fails to decode
    // but WASM can parse correctly
    const STAKING_AUTHORIZE_RAW_MSG_TXN =
      "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAwQJSN/yAiroYbrh33Xw+MKSGtu8m4Hx4sqwncAXz/he+b84neq4+YPEcZolDyLtQRwrgvHDZaDkTO1AFV+8JECpZViONvuJhgX6ijN1ogXXktMlrW9LsGh17WRMFiwbX9DjtnKIrK5VJ/5vhQidfy2H5id17M7MCqU8z9fuL/G26kb+iZNTXfchXIJtP9yKrACRJunT7w9bkgs7KLnfQO4e/QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABqHYF5E3VCqYNDe9/ip6slV/U1yKeHIraKSdwAAAAAAGp9UXGMd0yShWY5hpHV62i164o5tLbVxzVVshAAAAAAan1RcZLFaO4IqEX3PSl4jPA1wxRbIas0TYBi6pQAAAHv54hjZyXUu92IV/PX26I8zpgfXc5S/zZXMURlOUSjQCBQMECAAEBAAAAAYFBAcCAQMICgAAAAEAAAA=";

    const bytes = Buffer.from(STAKING_AUTHORIZE_RAW_MSG_TXN, "base64");
    const parsed = parseTransaction(bytes);

    // Should have NonceAdvance + StakingAuthorize
    assert.strictEqual(parsed.instructionsData.length, 2);
    assert.strictEqual(parsed.instructionsData[0].type, "NonceAdvance");
    assert.strictEqual(parsed.instructionsData[1].type, "StakingAuthorize");

    // Verify the StakingAuthorize has correct fields
    const authorizeInstr = parsed.instructionsData[1] as {
      type: string;
      stakingAddress: string;
      authorizeType: string;
    };
    assert.strictEqual(
      authorizeInstr.stakingAddress,
      "J8cECxcT6Q6H4fcQCvd4LbhmmSjsHL63kpJtrUcrF74Q",
    );
    assert.strictEqual(authorizeInstr.authorizeType, "Withdrawer");
  });
});
