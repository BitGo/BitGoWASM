/**
 * Compatibility tests using BitGoJS test fixtures.
 *
 * These tests verify that our parseTransaction output matches
 * what BitGoJS's Transaction.toJson() produces.
 */
import * as assert from "assert";
import { parseTransactionData as parseTransaction } from "../js/parser.js";

// Helper to decode base64 in tests
function base64ToBytes(base64: string): Uint8Array {
  const binary = Buffer.from(base64, "base64");
  return new Uint8Array(binary);
}

describe("BitGoJS Compatibility", () => {
  describe("Transfer with memo and durable nonce", () => {
    // From BitGoJS: test/resources/sol.ts - TRANSFER_UNSIGNED_TX_WITH_MEMO_AND_DURABLE_NONCE
    const TX_BASE64 =
      "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAMGReV5vPklPPaLR9/x+zo6XCwhusWyPAmuEqbgVWvwi0Fv+hKJ+pxZaLwHGEyk2Svp5PfAC5ZEi/wYI1tPTHHhbqkYG1L37ZDq6w2tS3G+tFODYWdhMXF+kwlYEF+3o4nVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFSlNamSkhBk0k6HFg2jh8fDW13bySu4HkH6hAQQVEjQan1RcZLFaO4IqEX3PSl4jPA1wxRbIas0TYBi6pQAAA4zLa+S+r7Oi2P/ekQAXl/f2a+hWHVrYcWpX5BLO40IEDAwMBBQAEBAAAAAMCAAIMAgAAAOCTBAAAAAAABAAJdGVzdCBtZW1v";

    // Expected values from BitGoJS test/unit/transaction.ts lines 33-60
    // Note: WASM returns all instructions including NonceAdvance; BitGoJS may filter it for its own use
    const EXPECTED = {
      feePayer: "5hr5fisPi6DXNuuRpm5XUbzpiEnmdyxXuBDTwzwZj5Pe",
      nonce: "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi",
      numSignatures: 1, // header.num_required_signatures
      durableNonce: {
        walletNonceAddress: "8Y7RM6JfcX4ASSNBkrkrmSbRu431YVi9Y3oLFnzC2dCh",
        authWalletAddress: "5hr5fisPi6DXNuuRpm5XUbzpiEnmdyxXuBDTwzwZj5Pe",
      },
      // instructionsData includes all instructions including NonceAdvance
      instructionsData: [
        {
          type: "NonceAdvance",
          walletNonceAddress: "8Y7RM6JfcX4ASSNBkrkrmSbRu431YVi9Y3oLFnzC2dCh",
          authWalletAddress: "5hr5fisPi6DXNuuRpm5XUbzpiEnmdyxXuBDTwzwZj5Pe",
        },
        {
          type: "Transfer",
          fromAddress: "5hr5fisPi6DXNuuRpm5XUbzpiEnmdyxXuBDTwzwZj5Pe",
          toAddress: "CP5Dpaa42RtJmMuKqCQsLwma5Yh3knuvKsYDFX85F41S",
          amount: 300000n,
        },
        {
          type: "Memo",
          memo: "test memo",
        },
      ],
    };

    it("should parse feePayer correctly", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);
      assert.strictEqual(parsed.feePayer, EXPECTED.feePayer);
    });

    it("should parse nonce correctly", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);
      assert.strictEqual(parsed.nonce, EXPECTED.nonce);
    });

    it("should parse numSignatures correctly", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);
      assert.strictEqual(parsed.numSignatures, EXPECTED.numSignatures);
    });

    it("should detect durable nonce transaction", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);
      assert.ok(parsed.durableNonce, "Should detect durable nonce");
      assert.strictEqual(
        parsed.durableNonce.walletNonceAddress,
        EXPECTED.durableNonce.walletNonceAddress,
      );
      assert.strictEqual(
        parsed.durableNonce.authWalletAddress,
        EXPECTED.durableNonce.authWalletAddress,
      );
    });

    it("should have NonceAdvance in both instructionsData and durableNonce", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);
      // WASM returns all instructions including NonceAdvance
      const nonceAdvance = parsed.instructionsData.find((i) => i.type === "NonceAdvance");
      assert.ok(nonceAdvance, "NonceAdvance should be in instructionsData");
      assert.ok(parsed.durableNonce, "durableNonce should also be populated");
      // Verify the data matches
      if (nonceAdvance && nonceAdvance.type === "NonceAdvance" && parsed.durableNonce) {
        assert.strictEqual(nonceAdvance.walletNonceAddress, parsed.durableNonce.walletNonceAddress);
        assert.strictEqual(nonceAdvance.authWalletAddress, parsed.durableNonce.authWalletAddress);
      }
    });

    it("should parse Transfer instruction correctly", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);
      // Transfer is at index 1 (after NonceAdvance)
      const instr = parsed.instructionsData[1];

      assert.strictEqual(instr.type, "Transfer");
      if (instr.type === "Transfer") {
        const expectedTransfer = EXPECTED.instructionsData[1];
        if (expectedTransfer.type === "Transfer") {
          assert.strictEqual(instr.fromAddress, expectedTransfer.fromAddress);
          assert.strictEqual(instr.toAddress, expectedTransfer.toAddress);
          assert.strictEqual(instr.amount, expectedTransfer.amount);
        }
      }
    });

    it("should parse Memo instruction correctly", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);
      // Memo is at index 2 (after NonceAdvance and Transfer)
      const instr = parsed.instructionsData[2];

      assert.strictEqual(instr.type, "Memo");
      if (instr.type === "Memo") {
        const expectedMemo = EXPECTED.instructionsData[2];
        if (expectedMemo.type === "Memo") {
          assert.strictEqual(instr.memo, expectedMemo.memo);
        }
      }
    });

    it("should have correct number of instructions", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);
      // 3 instructions: NonceAdvance + Transfer + Memo
      assert.strictEqual(parsed.instructionsData.length, 3);
    });
  });

  describe("Multi transfer transaction", () => {
    // From BitGoJS: test/resources/sol.ts - MULTI_TRANSFER_SIGNED
    const TX_BASE64 =
      "ARbBf3TOkZIuuO2ziM3aACNNdYKDcumvwrylryRXRabSipz6t4VY0ccLsH7v9v8o/k9TVaToi9eAKBR0C0NRzgYBAAMLReV5vPklPPaLR9/x+zo6XCwhusWyPAmuEqbgVWvwi0FLR9EoOL6wqR8uLpnq0nwpNHchcLqBetRGhm70JDF+8kze2o1mtPDaZbuLoBDbpF4Ym6uNOoiXV4Z/XzIP2qDiVfSSHY6HxxiRep+SggDoFZcJjEpbyDbmNXstOeVFqelv+hKJ+pxZaLwHGEyk2Svp5PfAC5ZEi/wYI1tPTHHhbqOP64stlmOImTCUdTdWfXmX4VEgLlAxGjAYzAqkGvGpqRgbUvftkOrrDa1Lcb60U4NhZ2ExcX6TCVgQX7ejidWvmf90gv+iLyF+MaUVKbB3PxFvBm0rWUtT2LJWOlSvUwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABUpTWpkpIQZNJOhxYNo4fHw1td28kruB5B+oQEEFRI0Gp9UXGSxWjuCKhF9z0peIzwNcMUWyGrNE2AYuqUAAAOMy2vkvq+zotj/3pEAF5f39mvoVh1a2HFqV+QSzuNCBCAgDBAoABAQAAAAIAgAGDAIAAADgkwQAAAAAAAgCAAIMAgAAAOCTBAAAAAAACAIABQwCAAAA4JMEAAAAAAAIAgAHDAIAAADgkwQAAAAAAAgCAAEMAgAAAOCTBAAAAAAACAIAAwwCAAAA4JMEAAAAAAAJAAl0ZXN0IG1lbW8=";

    // Expected values from BitGoJS test/unit/transaction.ts lines 63-141
    const EXPECTED_FEE_PAYER = "5hr5fisPi6DXNuuRpm5XUbzpiEnmdyxXuBDTwzwZj5Pe";
    const EXPECTED_NONCE = "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi";
    const EXPECTED_TRANSFER_RECIPIENTS = [
      "CP5Dpaa42RtJmMuKqCQsLwma5Yh3knuvKsYDFX85F41S",
      "6B55XMiaS6tUZw5Tt3G1RaXAqdrvN38yXVDJmWvKLkiM",
      "C1UjpxcXNBpp1UyvYsuNBNZ5Da1G1i49g3yTvC23Ny7e",
      "CpUYXh9xXoWfkBVaBQRZ8nAgDbT16GZeQdqveeBS1hmk",
      "64s6NjmEokdhicHEd432X5Ut2EDfDmVqdvGh4rASn1gd",
      "6nXxL2jMSdkgfHm13Twvn1gzRAPdrWnWLfu89PJL3Aqe",
    ];

    it("should parse multi-transfer with correct structure", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);

      assert.strictEqual(parsed.feePayer, EXPECTED_FEE_PAYER);
      assert.strictEqual(parsed.nonce, EXPECTED_NONCE);
      // NonceAdvance + 6 Transfers + 1 Memo = 8 instructions
      assert.strictEqual(parsed.instructionsData.length, 8);
      assert.ok(parsed.durableNonce, "Should have durableNonce");
      assert.strictEqual(parsed.instructionsData[0].type, "NonceAdvance");
    });

    it("should parse all transfer recipients correctly", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);

      // Transfers are at indices 1-6 (index 0 is NonceAdvance)
      const transfers = parsed.instructionsData.slice(1, 7);
      assert.strictEqual(transfers.length, 6);

      for (let i = 0; i < transfers.length; i++) {
        const transfer = transfers[i];
        assert.strictEqual(transfer.type, "Transfer", `Instruction ${i + 1} should be Transfer`);
        if (transfer.type === "Transfer") {
          assert.strictEqual(transfer.toAddress, EXPECTED_TRANSFER_RECIPIENTS[i]);
          assert.strictEqual(transfer.amount, 300000n);
          assert.strictEqual(transfer.fromAddress, EXPECTED_FEE_PAYER);
        }
      }
    });

    it("should have memo as last instruction", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);
      const lastInstr = parsed.instructionsData[parsed.instructionsData.length - 1];

      assert.strictEqual(lastInstr.type, "Memo");
      if (lastInstr.type === "Memo") {
        assert.strictEqual(lastInstr.memo, "test memo");
      }
    });
  });

  describe("Staking activate transaction", () => {
    // From BitGoJS: test/resources/sol.ts - STAKING_ACTIVATE_SIGNED_TX
    const TX_BASE64 =
      "AgqGWxEJnQ6oPZd9ysQx+RoWZiNC5caG1vZfCKihyobmUMA/mj7tUVV3j02GUl25Cm7letLefgUz9WB+kXAe4ABUzgW/NnG7GeZGxTVAsEWxGK93sc/cNVFODjkf97ap2bugoN48UG3jBA0JvcNa35xPVrJVdB8VW8dWe/jfxSgMAgAHCUXlebz5JTz2i0ff8fs6OlwsIbrFsjwJrhKm4FVr8ItBYnsvugEnYfm5Gbz5TLtMncgFHZ8JMpkxTTlJIzJovekAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALH5eXiaHEfRPEjYei8nFxDrf5MmCVEXMWKQvWwp2vXZBqHYF5E3VCqYNDe9/ip6slV/U1yKeHIraKSdwAAAAAAGodgXpQIFC2gHkebObbiOHltxUPYfxnkKTrTRAAAAAAan1RcYx3TJKFZjmGkdXraLXrijm0ttXHNVWyEAAAAABqfVFxksXFEhjMlMPUrxf1ja7gibof1E49vZigAAAAAGp9UXGTWE0P7tm7NDHRMga+VEKBtXuFZsxTdf9AAAAOMy2vkvq+zotj/3pEAF5f39mvoVh1a2HFqV+QSzuNCBAwICAAE0AAAAAOCTBAAAAAAAyAAAAAAAAAAGodgXkTdUKpg0N73+KnqyVX9TXIp4citopJ3AAAAAAAQCAQd0AAAAAEXlebz5JTz2i0ff8fs6OlwsIbrFsjwJrhKm4FVr8ItBReV5vPklPPaLR9/x+zo6XCwhusWyPAmuEqbgVWvwi0EAAAAAAAAAAAAAAAAAAAAAReV5vPklPPaLR9/x+zo6XCwhusWyPAmuEqbgVWvwi0EEBgEDBggFAAQCAAAA";

    it("should parse staking transaction structure", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);

      assert.strictEqual(parsed.feePayer, "5hr5fisPi6DXNuuRpm5XUbzpiEnmdyxXuBDTwzwZj5Pe");
      assert.ok(parsed.instructionsData.length >= 1, "Should have instructions");

      // Check that we can identify system and stake program instructions
      const types = parsed.instructionsData.map((i) => i.type);
      assert.ok(
        types.includes("CreateAccount") ||
          types.includes("StakingActivate") ||
          types.includes("StakingDelegate"),
        `Should have staking-related instructions, got: ${types.join(", ")}`,
      );
    });
  });

  describe("Token transfer transaction", () => {
    // From BitGoJS: test/resources/sol.ts - TOKEN_TRANSFER_SIGNED_TX_WITH_MEMO_AND_DURABLE_NONCE
    const TX_BASE64 =
      "AV6dvFclQvoTuCoia6uKVEUuUnV6Vzuzoyrbn9r/hvlDupmR6Y+zRtKCyIoAu7Yn4SDswSP5ihpsRl+sla53rQABAAYKAGymKVqOJEQemBHH67uu8ISJV4rtwTejLrjw7VSeW6dv+hKJ+pxZaLwHGEyk2Svp5PfAC5ZEi/wYI1tPTHHhbpXS8VwMObd6fTnfCKrnxvwQ5LFhipVbiG+aiTNM1eFsqRgbUvftkOrrDa1Lcb60U4NhZ2ExcX6TCVgQX7ejidUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMGRm/lIRcy/+ytunLDm+e8jOW7xfcSayxDmzpAAAAA0QOJ+87lKPIIYR3MxzSzEJJUDLK41Y0QDy6qLO202l4FSlNamSkhBk0k6HFg2jh8fDW13bySu4HkH6hAQQVEjQan1RcZLFaO4IqEX3PSl4jPA1wxRbIas0TYBi6pQAAABt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKnjMtr5L6vs6LY/96RABeX9/Zr6FYdWthxalfkEs7jQgQQEAwEIAAQEAAAABQAJA4CWmAAAAAAACQQCBgMACgzgkwQAAAAAAAkHAAl0ZXN0IG1lbW8=";

    it("should parse token transfer transaction", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);

      // Should have 4 instructions: NonceAdvance, SetPriorityFee, TokenTransfer, Memo
      assert.strictEqual(parsed.instructionsData.length, 4);
      assert.ok(parsed.durableNonce, "Should have durableNonce");

      const types = parsed.instructionsData.map((i) => i.type);
      assert.strictEqual(types[0], "NonceAdvance", "First should be NonceAdvance");
      assert.strictEqual(types[1], "SetPriorityFee", "Second should be SetPriorityFee");
      assert.strictEqual(types[2], "TokenTransfer", "Third should be TokenTransfer");
      assert.strictEqual(types[3], "Memo", "Fourth should be Memo");

      // Check token transfer details
      const tokenTransfer = parsed.instructionsData[2];
      if (tokenTransfer.type === "TokenTransfer") {
        assert.strictEqual(tokenTransfer.amount, 300000n);
      }
    });
  });

  describe("Simple unsigned transfer", () => {
    // From BitGoJS: test/resources/sol.ts - RAW_TX_UNSIGNED
    const TX_BASE64 =
      "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAIF1NAQCUWYPPTiKY7R/E6KZUKc6Cfr4EUtPm/5/SxQojC7/8v6bBS5ivQMOPXcf/+IbTe8TTN0fjWV33cOwFlm7v5/ZxIQXcf05+tDimmyGgnt1z0tG4opHSR2L2GlM6FGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGp9UXGSxWjuCKhF9z0peIzwNcMUWyGrNE2AYuqUAAAOghhIq8A3U5dDmSv3/3VTX6V+0obalzpFvB2Pemp8/uAgMDAgQABAQAAAADAgABDAIAAACghgEAAAAAAA==";

    it("should parse basic unsigned transfer", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);

      // This is a durable nonce transaction: NonceAdvance + Transfer
      assert.strictEqual(parsed.instructionsData.length, 2);
      assert.strictEqual(parsed.instructionsData[0].type, "NonceAdvance");
      assert.strictEqual(parsed.instructionsData[1].type, "Transfer");
      assert.ok(parsed.durableNonce, "Should have durableNonce");

      if (parsed.instructionsData[1].type === "Transfer") {
        // 100000 lamports = 0x186a0
        assert.strictEqual(parsed.instructionsData[1].amount, 100000n);
      }
    });
  });

  describe("Jito liquid staking transaction", () => {
    // From BitGoJS: test/resources/sol.ts - JITO_STAKING_ACTIVATE_SIGNED_TX
    // This is a Jito DepositSol instruction (discriminator 14) - deposits SOL into the Jito stake pool
    const TX_BASE64 =
      "AdOUrFCk9yyhi1iB1EfOOXHOeiaZGQnLRwnypt+be8r9lrYMx8w7/QTnithrqcuBApg1ctJAlJMxNZ925vMP2Q0BAAQKReV5vPklPPaLR9/x+zo6XCwhusWyPAmuEqbgVWvwi0Ecg6pe+BOG2OETfAVS9ftz6va1oE4onLBolJ2N+ZOOhJ6naP7fZEyKrpuOIYit0GvFUPv3Fsgiuc5jx3g9lS4fCeaj/uz5kDLhwd9rlyLcs2NOe440QJNrw0sMwcjrUh/80UHpgyyvEK2RdJXKDycbWyk81HAn6nNwB+1A6zmgvQSKPgjDtJW+F/RUJ9ib7FuAx+JpXBhk12dD2zm+00bWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABU5Z4kwFGooUp7HpeX8OEs36dJAhZlMZWmpRKm8WZgKwaBTtTK9ooXRnL9rIYDGmPoTqFe+h1EtyKT9tvbABZQBt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKnjMtr5L6vs6LY/96RABeX9/Zr6FYdWthxalfkEs7jQgQEICgUHAgABAwEEBgkJDuCTBAAAAAAA";

    it("should parse Jito DepositSol instruction", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);

      // Find the StakePoolDepositSol instruction
      const depositSolInstr = parsed.instructionsData.find((i) => i.type === "StakePoolDepositSol");
      assert.ok(depositSolInstr, "Should have StakePoolDepositSol instruction");

      if (depositSolInstr && depositSolInstr.type === "StakePoolDepositSol") {
        // Amount should be 300000 lamports (0x493e0 in little endian: e0 93 04 00 00 00 00 00)
        assert.strictEqual(depositSolInstr.lamports, 300000n);
        // Stake pool should be the Jito stake pool program
        assert.ok(depositSolInstr.stakePool, "Should have stakePool");
        assert.ok(depositSolInstr.fundingAccount, "Should have fundingAccount");
        assert.ok(depositSolInstr.destinationPoolAccount, "Should have destinationPoolAccount");
        assert.ok(depositSolInstr.poolMint, "Should have poolMint");
      }
    });

    it("should have correct fee payer for Jito transaction", () => {
      const bytes = base64ToBytes(TX_BASE64);
      const parsed = parseTransaction(bytes);

      // Fee payer from BitGoJS tests
      assert.strictEqual(parsed.feePayer, "5hr5fisPi6DXNuuRpm5XUbzpiEnmdyxXuBDTwzwZj5Pe");
    });
  });
});
