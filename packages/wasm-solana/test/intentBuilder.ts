/**
 * Tests for intent-based transaction building.
 *
 * These tests verify that buildFromIntent correctly builds transactions
 * from BitGo intent objects.
 */

/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-argument */

import assert from "assert";
import { buildFromIntent, Transaction, parseTransaction } from "../dist/cjs/js/index.js";

describe("buildFromIntent", function () {
  // Common test params
  const feePayer = "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB";
  const blockhash = "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4";

  describe("payment intent", function () {
    it("should build a simple payment transaction", function () {
      const intent = {
        intentType: "payment",
        recipients: [
          {
            address: { address: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH" },
            amount: { value: 1000000n },
          },
        ],
      };

      const result = buildFromIntent(intent, {
        feePayer,
        nonce: { type: "blockhash", value: blockhash },
      });

      assert(result.transaction instanceof Transaction, "Should return Transaction object");
      assert(Array.isArray(result.generatedKeypairs), "Should return generatedKeypairs array");
      assert.equal(result.generatedKeypairs.length, 0, "Payment should not generate keypairs");
    });

    it("should build a multi-recipient payment", function () {
      const intent = {
        intentType: "payment",
        recipients: [
          {
            address: { address: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH" },
            amount: { value: 1000000n },
          },
          {
            address: { address: "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN" },
            amount: { value: 2000000n },
          },
        ],
      };

      const result = buildFromIntent(intent, {
        feePayer,
        nonce: { type: "blockhash", value: blockhash },
      });

      // Parse to verify
      const parsed = parseTransaction(result.transaction.toBytes());

      // Should have 2 Transfer instructions
      const transfers = parsed.instructionsData.filter((i: any) => i.type === "Transfer");
      assert.equal(transfers.length, 2, "Should have 2 transfer instructions");
    });

    it("should include memo when provided", function () {
      const intent = {
        intentType: "payment",
        recipients: [
          {
            address: { address: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH" },
            amount: { value: 1000000n },
          },
        ],
        memo: "Test payment memo",
      };

      const result = buildFromIntent(intent, {
        feePayer,
        nonce: { type: "blockhash", value: blockhash },
      });

      // Parse to verify
      const parsed = parseTransaction(result.transaction.toBytes());

      // Should have Memo instruction
      const memos = parsed.instructionsData.filter((i: any) => i.type === "Memo");
      assert.equal(memos.length, 1, "Should have 1 memo instruction");
      assert.equal((memos[0] as any).memo, "Test payment memo", "Memo should match");
    });
  });

  describe("stake intent (native)", function () {
    it("should build a native stake transaction", function () {
      const intent = {
        intentType: "stake",
        validatorAddress: "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN",
        amount: { value: 1000000000n },
      };

      const result = buildFromIntent(intent, {
        feePayer,
        nonce: { type: "blockhash", value: blockhash },
      });

      assert(result.transaction instanceof Transaction, "Should return Transaction object");
      assert.equal(result.generatedKeypairs.length, 1, "Should generate 1 keypair");
      assert.equal(result.generatedKeypairs[0].purpose, "stakeAccount", "Should be stakeAccount");
      assert(result.generatedKeypairs[0].address, "Should have address");
      assert(result.generatedKeypairs[0].secretKey, "Should have secretKey");
    });

    it("should produce valid stake instructions", function () {
      const intent = {
        intentType: "stake",
        validatorAddress: "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN",
        amount: { value: 1000000000n },
      };

      const result = buildFromIntent(intent, {
        feePayer,
        nonce: { type: "blockhash", value: blockhash },
      });

      // Parse to verify
      const parsed = parseTransaction(result.transaction.toBytes());

      // Native staking should have 3 instructions: CreateAccount, StakeInitialize, StakeDelegate
      assert(parsed.instructionsData.length >= 3, "Should have at least 3 instructions");

      const createAccount = parsed.instructionsData.find((i: any) => i.type === "CreateAccount");
      assert(createAccount, "Should have CreateAccount instruction");

      const stakeInit = parsed.instructionsData.find((i: any) => i.type === "StakeInitialize");
      assert(stakeInit, "Should have StakeInitialize instruction");

      const stakeDelegate = parsed.instructionsData.find((i: any) => i.type === "StakingDelegate");
      assert(stakeDelegate, "Should have StakingDelegate instruction");
    });
  });

  describe("deactivate intent", function () {
    it("should build a deactivate transaction with single address", function () {
      const intent = {
        intentType: "deactivate",
        stakingAddress: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH",
      };

      const result = buildFromIntent(intent, {
        feePayer,
        nonce: { type: "blockhash", value: blockhash },
      });

      assert(result.transaction instanceof Transaction, "Should return Transaction object");
      assert.equal(result.generatedKeypairs.length, 0, "Should not generate keypairs");

      // Verify instruction
      const parsed = parseTransaction(result.transaction.toBytes());

      const deactivate = parsed.instructionsData.find((i: any) => i.type === "StakingDeactivate");
      assert(deactivate, "Should have StakingDeactivate instruction");
    });

    it("should build a deactivate transaction with multiple addresses", function () {
      const intent = {
        intentType: "deactivate",
        stakingAddresses: [
          "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH",
          "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN",
        ],
      };

      const result = buildFromIntent(intent, {
        feePayer,
        nonce: { type: "blockhash", value: blockhash },
      });

      // Verify instructions
      const parsed = parseTransaction(result.transaction.toBytes());

      const deactivates = parsed.instructionsData.filter(
        (i: any) => i.type === "StakingDeactivate",
      );
      assert.equal(deactivates.length, 2, "Should have 2 StakingDeactivate instructions");
    });
  });

  describe("claim intent", function () {
    it("should build a claim (withdraw) transaction", function () {
      const intent = {
        intentType: "claim",
        stakingAddress: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH",
        amount: { value: 1000000000n },
      };

      const result = buildFromIntent(intent, {
        feePayer,
        nonce: { type: "blockhash", value: blockhash },
      });

      assert(result.transaction instanceof Transaction, "Should return Transaction object");
      assert.equal(result.generatedKeypairs.length, 0, "Should not generate keypairs");

      // Verify instruction
      const parsed = parseTransaction(result.transaction.toBytes());

      const withdraw = parsed.instructionsData.find((i: any) => i.type === "StakingWithdraw");
      assert(withdraw, "Should have StakingWithdraw instruction");
    });
  });

  describe("delegate intent", function () {
    it("should build a delegate transaction", function () {
      const intent = {
        intentType: "delegate",
        validatorAddress: "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN",
        stakingAddress: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH",
      };

      const result = buildFromIntent(intent, {
        feePayer,
        nonce: { type: "blockhash", value: blockhash },
      });

      assert(result.transaction instanceof Transaction, "Should return Transaction object");
      assert.equal(result.generatedKeypairs.length, 0, "Should not generate keypairs");

      // Verify instruction - delegate is a StakingDelegate instruction
      const parsed = parseTransaction(result.transaction.toBytes());

      const delegate = parsed.instructionsData.find((i: any) => i.type === "StakingDelegate");
      assert(delegate, "Should have StakingDelegate instruction");
    });
  });

  describe("enableToken intent", function () {
    it("should build an enableToken transaction", function () {
      const intent = {
        intentType: "enableToken",
        tokenAddress: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", // USDC mint
        recipientAddress: feePayer,
      };

      const result = buildFromIntent(intent, {
        feePayer,
        nonce: { type: "blockhash", value: blockhash },
      });

      assert(result.transaction instanceof Transaction, "Should return Transaction object");
      assert.equal(result.generatedKeypairs.length, 0, "Should not generate keypairs");

      // Verify instruction
      const parsed = parseTransaction(result.transaction.toBytes());

      const createAta = parsed.instructionsData.find(
        (i: any) => i.type === "CreateAssociatedTokenAccount",
      );
      assert(createAta, "Should have CreateAssociatedTokenAccount instruction");
    });
  });

  describe("closeAssociatedTokenAccount intent", function () {
    it("should build a closeAssociatedTokenAccount transaction", function () {
      const intent = {
        intentType: "closeAssociatedTokenAccount",
        tokenAccountAddress: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH",
      };

      const result = buildFromIntent(intent, {
        feePayer,
        nonce: { type: "blockhash", value: blockhash },
      });

      assert(result.transaction instanceof Transaction, "Should return Transaction object");
      assert.equal(result.generatedKeypairs.length, 0, "Should not generate keypairs");

      // Verify instruction
      const parsed = parseTransaction(result.transaction.toBytes());

      const closeAta = parsed.instructionsData.find(
        (i: any) => i.type === "CloseAssociatedTokenAccount",
      );
      assert(closeAta, "Should have CloseAssociatedTokenAccount instruction");
    });
  });

  describe("consolidate intent", function () {
    it("should build a consolidate transaction (transfer from child to root)", function () {
      const childAddress = "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN";
      const rootAddress = feePayer;
      const intent = {
        intentType: "consolidate",
        receiveAddress: childAddress, // The child address to consolidate FROM
        recipients: [
          {
            address: { address: rootAddress }, // Transfer TO root
            amount: { value: 50000000n }, // 0.05 SOL
          },
        ],
      };

      const result = buildFromIntent(intent, {
        feePayer, // Fee payer is root address
        nonce: { type: "blockhash", value: blockhash },
      });

      assert(result.transaction instanceof Transaction, "Should return Transaction object");
      assert.equal(result.generatedKeypairs.length, 0, "Should not generate keypairs");

      // Verify instruction
      const parsed = parseTransaction(result.transaction.toBytes());

      // Should have a Transfer instruction where the sender is the child address
      const transfer = parsed.instructionsData.find((i: any) => i.type === "Transfer");
      assert(transfer, "Should have Transfer instruction");
      // The transfer should be FROM the child address (receiveAddress), not the fee payer
      assert.equal((transfer as any).fromAddress, childAddress, "Sender should be child address");
      assert.equal((transfer as any).toAddress, rootAddress, "Recipient should be root address");
    });

    it("should build a multi-recipient consolidate (SOL + tokens)", function () {
      const childAddress = "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN";
      const intent = {
        intentType: "consolidate",
        receiveAddress: childAddress,
        recipients: [
          {
            address: { address: feePayer },
            amount: { value: 50000000n },
          },
          {
            address: { address: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH" }, // Token ATA
            amount: { value: 1000000n },
          },
        ],
      };

      const result = buildFromIntent(intent, {
        feePayer,
        nonce: { type: "blockhash", value: blockhash },
      });

      const parsed = parseTransaction(result.transaction.toBytes());

      // Should have 2 Transfer instructions
      const transfers = parsed.instructionsData.filter((i: any) => i.type === "Transfer");
      assert.equal(transfers.length, 2, "Should have 2 transfer instructions");
    });
  });

  describe("durable nonce", function () {
    it("should prepend nonce advance for durable nonce", function () {
      const intent = {
        intentType: "payment",
        recipients: [
          {
            address: { address: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH" },
            amount: { value: 1000000n },
          },
        ],
      };

      const nonceAddress = "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN";
      const nonceAuthority = "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB";

      const result = buildFromIntent(intent, {
        feePayer,
        nonce: {
          type: "durable",
          address: nonceAddress,
          authority: nonceAuthority,
          value: blockhash,
        },
      });

      // Verify instructions
      const parsed = parseTransaction(result.transaction.toBytes());

      // First instruction should be NonceAdvance
      assert.equal(
        parsed.instructionsData[0].type,
        "NonceAdvance",
        "First instruction should be NonceAdvance",
      );
    });
  });

  describe("error handling", function () {
    it("should reject invalid intent type", function () {
      const intent = {
        intentType: "invalidType",
      };

      assert.throws(() => {
        buildFromIntent(intent, {
          feePayer,
          nonce: { type: "blockhash", value: blockhash },
        });
      }, /Unsupported intent type/);
    });

    it("should reject missing intentType", function () {
      const intent = {
        recipients: [],
      };

      assert.throws(() => {
        buildFromIntent(intent as any, {
          feePayer,
          nonce: { type: "blockhash", value: blockhash },
        });
      }, /Missing intentType/);
    });

    it("should reject invalid feePayer", function () {
      const intent = {
        intentType: "payment",
        recipients: [
          {
            address: { address: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH" },
            amount: { value: 1000000n },
          },
        ],
      };

      assert.throws(() => {
        buildFromIntent(intent, {
          feePayer: "invalid-address",
          nonce: { type: "blockhash", value: blockhash },
        });
      }, /Invalid feePayer/);
    });
  });
});
