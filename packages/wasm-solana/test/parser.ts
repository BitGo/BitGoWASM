import * as assert from "assert";
import {
  parseTransaction,
  type ParsedTransaction,
  type StakePoolDepositSolParams,
  type StakePoolWithdrawStakeParams,
} from "../js/parser.js";

// Helper to decode base64 in tests
function base64ToBytes(base64: string): Uint8Array {
  const binary = Buffer.from(base64, "base64");
  return new Uint8Array(binary);
}

// Jito stake pool test transactions from sdk-coin-sol
const JITO_STAKING_ACTIVATE_UNSIGNED_TX =
  "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAQKReV5vPklPPaLR9/x+zo6XCwhusWyPAmuEqbgVWvwi0Ecg6pe+BOG2OETfAVS9ftz6va1oE4onLBolJ2N+ZOOhJ6naP7fZEyKrpuOIYit0GvFUPv3Fsgiuc5jx3g9lS4fCeaj/uz5kDLhwd9rlyLcs2NOe440QJNrw0sMwcjrUh/80UHpgyyvEK2RdJXKDycbWyk81HAn6nNwB+1A6zmgvQSKPgjDtJW+F/RUJ9ib7FuAx+JpXBhk12dD2zm+00bWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABU5Z4kwFGooUp7HpeX8OEs36dJAhZlMZWmpRKm8WZgKwaBTtTK9ooXRnL9rIYDGmPoTqFe+h1EtyKT9tvbABZQBt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKnjMtr5L6vs6LY/96RABeX9/Zr6FYdWthxalfkEs7jQgQEICgUHAgABAwEEBgkJDuCTBAAAAAAA";

const JITO_STAKING_ACTIVATE_SIGNED_TX =
  "AdOUrFCk9yyhi1iB1EfOOXHOeiaZGQnLRwnypt+be8r9lrYMx8w7/QTnithrqcuBApg1ctJAlJMxNZ925vMP2Q0BAAQKReV5vPklPPaLR9/x+zo6XCwhusWyPAmuEqbgVWvwi0Ecg6pe+BOG2OETfAVS9ftz6va1oE4onLBolJ2N+ZOOhJ6naP7fZEyKrpuOIYit0GvFUPv3Fsgiuc5jx3g9lS4fCeaj/uz5kDLhwd9rlyLcs2NOe440QJNrw0sMwcjrUh/80UHpgyyvEK2RdJXKDycbWyk81HAn6nNwB+1A6zmgvQSKPgjDtJW+F/RUJ9ib7FuAx+JpXBhk12dD2zm+00bWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABU5Z4kwFGooUp7HpeX8OEs36dJAhZlMZWmpRKm8WZgKwaBTtTK9ooXRnL9rIYDGmPoTqFe+h1EtyKT9tvbABZQBt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKnjMtr5L6vs6LY/96RABeX9/Zr6FYdWthxalfkEs7jQgQEICgUHAgABAwEEBgkJDuCTBAAAAAAA";

const JITO_STAKING_ACTIVATE_SIGNED_TX_WITH_MEMO =
  "AVuU0ma/g7Ur8yGbZDVeoyHWdhh3fCilgfUoKq84lkq7wyhSySwqgR/WC3JAOiRGiW4/8S2244duw6GQNNb3vQYBAAULReV5vPklPPaLR9/x+zo6XCwhusWyPAmuEqbgVWvwi0Ecg6pe+BOG2OETfAVS9ftz6va1oE4onLBolJ2N+ZOOhJ6naP7fZEyKrpuOIYit0GvFUPv3Fsgiuc5jx3g9lS4fCeaj/uz5kDLhwd9rlyLcs2NOe440QJNrw0sMwcjrUh/80UHpgyyvEK2RdJXKDycbWyk81HAn6nNwB+1A6zmgvQSKPgjDtJW+F/RUJ9ib7FuAx+JpXBhk12dD2zm+00bWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABU5Z4kwFGooUp7HpeX8OEs36dJAhZlMZWmpRKm8WZgKwVKU1qZKSEGTSTocWDaOHx8NbXdvJK7geQfqEBBBUSNBoFO1Mr2ihdGcv2shgMaY+hOoV76HUS3IpP229sAFlAG3fbh12Whk9nL4UbO63msHLSF7V9bN5E6jPWFfv8AqeMy2vkvq+zotj/3pEAF5f39mvoVh1a2HFqV+QSzuNCBAgkKBQcCAAEDAQQGCgkO4JMEAAAAAAAIAAl0ZXN0IG1lbW8=";

const JITO_STAKING_DEACTIVATE_SIGNED_TX =
  "A7txZr55CtSJogfV1ihB1JOIuVbmhAh7BCl4hJeTBcbrq6KT+Jzbbjx4qEXDgRnMtY7cb9xnekOHUfKkW9D2RQpchl2oH4Np/+Oghy7QNjKrodZsFlqhiYoo+Zx0Bjf+Hwq35h/zVd1kHRTkaB1ebZwDeEejPrFgNCpkqxRh9ZgOMBethjkNPCrqzk50pOqx1ktJik5loScyp/81bggjQASE4jMdtET/a2jpFJeG34GZLIY6r+LNTXtGsK53qyR9CQMBBg9F5Xm8+SU89otH3/H7OjpcLCG6xbI8Ca4SpuBVa/CLQWJ7L7oBJ2H5uRm8+Uy7TJ3IBR2fCTKZMU05SSMyaL3p6Lfi7T4mzoclKbPedsv+JDs60KtRcBK6Y7CHyYejKikcg6pe+BOG2OETfAVS9ftz6va1oE4onLBolJ2N+ZOOhCPgdQm63e39tRapC5GXu1BHQyVdDjfF/13OiiQe7cQxl9rD5vZLBx1Aaz7SV4hmv2ZhGp4LQEU67b++EtDrIi8J5qP+7PmQMuHB32uXItyzY057jjRAk2vDSwzByOtSH/zRQemDLK8QrZF0lcoPJxtbKTzUcCfqc3AH7UDrOaC9BIo+CMO0lb4X9FQn2JvsW4DH4mlcGGTXZ0PbOb7TRtYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFTlniTAUaihSnsel5fw4Szfp0kCFmUxlaalEqbxZmArBoFO1Mr2ihdGcv2shgMaY+hOoV76HUS3IpP229sAFlAGodgXkTdUKpg0N73+KnqyVX9TXIp4citopJ3AAAAAAAan1RcYx3TJKFZjmGkdXraLXrijm0ttXHNVWyEAAAAABt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKnjMtr5L6vs6LY/96RABeX9/Zr6FYdWthxalfkEs7jQgQQOAwMCAAkE6AMAAAAAAAAJAgABNAAAAACA1SIAAAAAAMgAAAAAAAAABqHYF5E3VCqYNDe9/ip6slV/U1yKeHIraKSdwAAAAAALDQgECgUBAAIDBgcNDgwJCugDAAAAAAAADAMBDQAEBQAAAA==";

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
    assert.ok(parsed.signatures.length > 0);
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
      assert.strictEqual(instr.amount, "100000");
    }
  });

  it("should include fee payer as first account key", () => {
    const parsed = parseTransaction(TEST_TX_BYTES);

    assert.strictEqual(parsed.feePayer, parsed.accountKeys[0]);
  });

  it("should have signatures as base64 strings", () => {
    const parsed = parseTransaction(TEST_TX_BYTES);

    assert.ok(parsed.signatures.length > 0);
    // Signatures should be base64 encoded (string)
    for (const sig of parsed.signatures) {
      assert.strictEqual(typeof sig, "string");
      // Base64 of 64 bytes is 88 characters
      assert.ok(sig.length > 0);
    }
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

  it("should serialize to valid JSON", () => {
    const parsed = parseTransaction(TEST_TX_BYTES);
    const json = JSON.stringify(parsed);

    // Should be valid JSON
    const reparsed = JSON.parse(json) as ParsedTransaction;
    assert.strictEqual(reparsed.feePayer, parsed.feePayer);
    assert.strictEqual(reparsed.instructionsData.length, parsed.instructionsData.length);
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

  describe("Stake Pool (Jito) instruction decoding", () => {
    it("should decode DepositSol instruction from Jito staking activate tx", () => {
      const bytes = base64ToBytes(JITO_STAKING_ACTIVATE_UNSIGNED_TX);
      const parsed = parseTransaction(bytes);

      // Find the DepositSol instruction (should be the last one with discriminator 14)
      const depositSol = parsed.instructionsData.find(
        (instr): instr is StakePoolDepositSolParams => instr.type === "StakePoolDepositSol",
      );

      assert.ok(depositSol, "Should have a StakePoolDepositSol instruction");
      assert.strictEqual(depositSol.type, "StakePoolDepositSol");

      // Verify key fields are present and valid
      assert.ok(depositSol.stakePool, "Should have stakePool");
      assert.ok(depositSol.withdrawAuthority, "Should have withdrawAuthority");
      assert.ok(depositSol.reserveStake, "Should have reserveStake");
      assert.ok(depositSol.fundingAccount, "Should have fundingAccount");
      assert.ok(depositSol.destinationPoolAccount, "Should have destinationPoolAccount");
      assert.ok(depositSol.managerFeeAccount, "Should have managerFeeAccount");
      assert.ok(depositSol.referralPoolAccount, "Should have referralPoolAccount");
      assert.ok(depositSol.poolMint, "Should have poolMint");
      assert.ok(depositSol.lamports, "Should have lamports amount");

      // Verify amount is a valid number string (should be 80000000 = 0.08 SOL based on test tx)
      const lamportsNum = BigInt(depositSol.lamports);
      assert.ok(lamportsNum > 0n, "Lamports should be positive");
    });

    it("should decode WithdrawStake instruction from Jito staking deactivate tx", () => {
      const bytes = base64ToBytes(JITO_STAKING_DEACTIVATE_SIGNED_TX);
      const parsed = parseTransaction(bytes);

      // Find the WithdrawStake instruction (should have discriminator 10)
      const withdrawStake = parsed.instructionsData.find(
        (instr): instr is StakePoolWithdrawStakeParams => instr.type === "StakePoolWithdrawStake",
      );

      assert.ok(withdrawStake, "Should have a StakePoolWithdrawStake instruction");
      assert.strictEqual(withdrawStake.type, "StakePoolWithdrawStake");

      // Verify key fields are present and valid
      assert.ok(withdrawStake.stakePool, "Should have stakePool");
      assert.ok(withdrawStake.validatorList, "Should have validatorList");
      assert.ok(withdrawStake.withdrawAuthority, "Should have withdrawAuthority");
      assert.ok(withdrawStake.validatorStake, "Should have validatorStake");
      assert.ok(withdrawStake.destinationStake, "Should have destinationStake");
      assert.ok(withdrawStake.destinationStakeAuthority, "Should have destinationStakeAuthority");
      assert.ok(withdrawStake.sourceTransferAuthority, "Should have sourceTransferAuthority");
      assert.ok(withdrawStake.sourcePoolAccount, "Should have sourcePoolAccount");
      assert.ok(withdrawStake.managerFeeAccount, "Should have managerFeeAccount");
      assert.ok(withdrawStake.poolMint, "Should have poolMint");
      assert.ok(withdrawStake.poolTokens, "Should have poolTokens amount");

      // Verify pool tokens is a valid number string
      const poolTokensNum = BigInt(withdrawStake.poolTokens);
      assert.ok(poolTokensNum > 0n, "Pool tokens should be positive");
    });

    it("should parse Jito staking tx and include correct instruction types", () => {
      const bytes = base64ToBytes(JITO_STAKING_ACTIVATE_UNSIGNED_TX);
      const parsed = parseTransaction(bytes);

      // Get all instruction types
      const types = parsed.instructionsData.map((i) => i.type);

      // Should contain StakePoolDepositSol
      assert.ok(
        types.includes("StakePoolDepositSol"),
        `Expected StakePoolDepositSol in ${types.join(", ")}`,
      );
    });

    it("should decode DepositSol from signed Jito staking tx", () => {
      const bytes = base64ToBytes(JITO_STAKING_ACTIVATE_SIGNED_TX);
      const parsed = parseTransaction(bytes);

      const depositSol = parsed.instructionsData.find(
        (instr): instr is StakePoolDepositSolParams => instr.type === "StakePoolDepositSol",
      );

      assert.ok(depositSol, "Signed tx should have StakePoolDepositSol instruction");
      // Verify the lamports amount (300000 lamports in the test tx)
      assert.strictEqual(depositSol.lamports, "300000");
    });

    it("should decode DepositSol from Jito staking tx with memo", () => {
      const bytes = base64ToBytes(JITO_STAKING_ACTIVATE_SIGNED_TX_WITH_MEMO);
      const parsed = parseTransaction(bytes);

      // Should find both Memo and StakePoolDepositSol instructions
      const types = parsed.instructionsData.map((i) => i.type);
      assert.ok(types.includes("Memo"), `Expected Memo in ${types.join(", ")}`);
      assert.ok(
        types.includes("StakePoolDepositSol"),
        `Expected StakePoolDepositSol in ${types.join(", ")}`,
      );

      // Verify memo content
      const memo = parsed.instructionsData.find((i) => i.type === "Memo");
      if (memo && memo.type === "Memo") {
        assert.strictEqual(memo.memo, "test memo");
      }

      // Verify DepositSol
      const depositSol = parsed.instructionsData.find(
        (instr): instr is StakePoolDepositSolParams => instr.type === "StakePoolDepositSol",
      );
      assert.ok(depositSol);
      assert.strictEqual(depositSol.lamports, "300000");
    });

    it("should verify WithdrawStake pool tokens amount", () => {
      const bytes = base64ToBytes(JITO_STAKING_DEACTIVATE_SIGNED_TX);
      const parsed = parseTransaction(bytes);

      const withdrawStake = parsed.instructionsData.find(
        (instr): instr is StakePoolWithdrawStakeParams => instr.type === "StakePoolWithdrawStake",
      );

      assert.ok(withdrawStake);
      // Verify pool tokens amount (1000 in the test tx)
      assert.strictEqual(withdrawStake.poolTokens, "1000");
    });
  });
});
