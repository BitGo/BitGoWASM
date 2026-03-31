import { strict as assert } from "assert";
import {
  buildTransaction,
  parseTransaction,
  TonStakingType,
  TonTransactionType,
} from "../js/index.js";
import type { BuildContext, TonIntent } from "../js/index.js";

const TEST_SENDER = "EQBkD52LACNxGgaoAxm5Nhs0SN6gg8hNaceNYifev88Y7qoZ";
const TEST_VALIDATOR = "EQDr9Sq482A6ikIUh5mUUjJaBUUJBrye13CJiDB-R31_lwIq";
const TEST_RECIPIENT = "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG";
const TEST_JETTON = "UQACn6WjuRU-_ZJToT7Aswd4BnLO3vuCEZH4LUQoQNiMc3SE";

function makeContext(overrides: Partial<BuildContext> = {}): BuildContext {
  return {
    sender: TEST_SENDER,
    seqno: 0,
    expireTime: 1234567890n,
    walletVersion: 4,
    ...overrides,
  };
}

describe("Builder", () => {
  describe("payment (native)", () => {
    it("should build and parse a native transfer", () => {
      const intent: TonIntent = {
        type: "payment",
        to: TEST_RECIPIENT,
        amount: 10_000_000n,
      };

      const tx = buildTransaction(intent, makeContext());
      const parsed = parseTransaction(tx);

      assert.equal(parsed.transactionType, "Transfer");
      assert.equal(parsed.sendActions.length, 1);
      assert.equal(parsed.sendActions[0].amount, 10_000_000n);
    });

    it("should build a transfer with memo", () => {
      const intent: TonIntent = {
        type: "payment",
        to: TEST_RECIPIENT,
        amount: 10_000_000n,
        memo: "test memo",
      };

      const tx = buildTransaction(intent, makeContext());
      const parsed = parseTransaction(tx);

      assert.equal(parsed.transactionType, "Transfer");
      assert.equal(parsed.sendActions[0].memo, "test memo");
    });
  });

  describe("payment (token)", () => {
    it("should build and parse a token transfer", () => {
      const intent: TonIntent = {
        type: "tokenPayment",
        to: TEST_RECIPIENT,
        amount: 1_000_000_000n,
        jettonAddress: TEST_JETTON,
      };

      const tx = buildTransaction(intent, makeContext());
      const parsed = parseTransaction(tx);

      assert.equal(parsed.transactionType, "TokenTransfer");
      assert.ok(parsed.sendActions[0].jettonTransfer);
      assert.equal(parsed.sendActions[0].jettonTransfer?.amount, 1_000_000_000n);
    });
  });

  describe("fillNonce", () => {
    it("should build a native fill nonce (self-send 1 nanoTON)", () => {
      const intent: TonIntent = {
        type: "fillNonce",
      };

      const tx = buildTransaction(intent, makeContext());
      const parsed = parseTransaction(tx);

      assert.equal(parsed.transactionType, "Transfer");
      assert.equal(parsed.sendActions[0].amount, 1n);
    });

    it("should build a token fill nonce", () => {
      const intent: TonIntent = {
        type: "fillNonce",
        isToken: true,
        jettonAddress: TEST_JETTON,
      };

      const tx = buildTransaction(intent, makeContext());
      const parsed = parseTransaction(tx);

      assert.equal(parsed.transactionType, "TokenTransfer");
    });
  });

  describe("consolidate", () => {
    it("should build a native consolidate", () => {
      const intent: TonIntent = {
        type: "consolidate",
      };

      const tx = buildTransaction(intent, makeContext());
      const parsed = parseTransaction(tx);

      assert.equal(parsed.transactionType, "Transfer");
    });

    it("should reject consolidate for wallet version 1", () => {
      const intent: TonIntent = {
        type: "consolidate",
      };

      assert.throws(() => {
        buildTransaction(intent, makeContext({ walletVersion: 1 }));
      });
    });
  });

  describe("delegate", () => {
    it("should build TonWhales deposit", () => {
      const intent: TonIntent = {
        type: "delegate",
        amount: 10_000_000_000n,
        validatorAddress: TEST_VALIDATOR,
        stakingType: "TonWhales",
      };

      const tx = buildTransaction(intent, makeContext());
      const parsed = parseTransaction(tx);

      assert.equal(parsed.transactionType, "WhalesDeposit");
    });

    it("should build SingleNominator delegate", () => {
      const intent: TonIntent = {
        type: "delegate",
        amount: 10_000_000_000n,
        validatorAddress: TEST_VALIDATOR,
        stakingType: "SingleNominator",
      };

      const tx = buildTransaction(intent, makeContext());
      const parsed = parseTransaction(tx);

      // SingleNominator delegate is just a plain transfer
      assert.equal(parsed.transactionType, "Transfer");
    });

    it("should build MultiNominator delegate", () => {
      const intent: TonIntent = {
        type: "delegate",
        amount: 10_000_000_000n,
        validatorAddress: TEST_VALIDATOR,
        stakingType: "MultiNominator",
      };

      const tx = buildTransaction(intent, makeContext());
      const parsed = parseTransaction(tx);

      // MultiNominator delegate has memo 'd'
      assert.equal(parsed.transactionType, "Transfer");
      assert.equal(parsed.sendActions[0].memo, "d");
    });
  });

  describe("undelegate", () => {
    it("should build TonWhales withdraw", () => {
      const intent: TonIntent = {
        type: "undelegate",
        amount: 10_000_000_000n,
        validatorAddress: TEST_VALIDATOR,
        stakingType: "TonWhales",
      };

      const tx = buildTransaction(intent, makeContext());
      const parsed = parseTransaction(tx);

      assert.equal(parsed.transactionType, "WhalesWithdraw");
    });

    it("should build TonWhales full withdraw (amount=0)", () => {
      const intent: TonIntent = {
        type: "undelegate",
        amount: 0n,
        validatorAddress: TEST_VALIDATOR,
        stakingType: "TonWhales",
      };

      const tx = buildTransaction(intent, makeContext());
      const parsed = parseTransaction(tx);

      assert.equal(parsed.transactionType, "WhalesWithdraw");
    });

    it("should build SingleNominator withdraw", () => {
      const intent: TonIntent = {
        type: "undelegate",
        amount: 123_400_000n,
        validatorAddress: TEST_VALIDATOR,
        stakingType: "SingleNominator",
      };

      const tx = buildTransaction(intent, makeContext());
      const parsed = parseTransaction(tx);

      assert.equal(parsed.transactionType, "SingleNominatorWithdraw");
    });

    it("should build MultiNominator withdraw", () => {
      const intent: TonIntent = {
        type: "undelegate",
        validatorAddress: TEST_VALIDATOR,
        stakingType: "MultiNominator",
      };

      const tx = buildTransaction(intent, makeContext());
      const parsed = parseTransaction(tx);

      // MultiNominator withdraw has memo 'w'
      assert.equal(parsed.transactionType, "Transfer");
      assert.equal(parsed.sendActions[0].memo, "w");
    });
  });

  describe("as const values", () => {
    it("TonStakingType should contain all staking types", () => {
      assert.ok(TonStakingType.includes("TonWhales"));
      assert.ok(TonStakingType.includes("SingleNominator"));
      assert.ok(TonStakingType.includes("MultiNominator"));
      assert.equal(TonStakingType.length, 3);
    });

    it("TonTransactionType should contain all transaction types", () => {
      assert.ok(TonTransactionType.includes("Transfer"));
      assert.ok(TonTransactionType.includes("TokenTransfer"));
      assert.ok(TonTransactionType.includes("WhalesDeposit"));
      assert.equal(TonTransactionType.length, 8);
    });
  });
});
