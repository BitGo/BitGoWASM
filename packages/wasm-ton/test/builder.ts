import { strict as assert } from "node:assert";
import { describe, it } from "mocha";
import { buildTransaction, parseTransaction, Transaction, TonStakingType } from "../js/index.js";
import type { BuildContext, TonTransactionIntent } from "../js/builder.js";

// =============================================================================
// Test helpers
// =============================================================================

const testAddress = "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e";
const testJettonAddress = "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG";

function baseContext(overrides: Partial<BuildContext> = {}): BuildContext {
  return {
    senderAddress: testAddress,
    seqno: 10,
    expireTime: 1700000000,
    ...overrides,
  };
}

// =============================================================================
// Payment (native)
// =============================================================================

describe("buildTransaction", () => {
  describe("payment (native)", () => {
    it("should build a native payment and round-trip parse", () => {
      const tx = buildTransaction(
        {
          intentType: "payment",
          recipients: [{ address: testAddress, amount: 1_000_000_000n }],
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.type, "Send");
      assert.equal(parsed.outputs.length, 1);
      assert.equal(parsed.outputAmount, 1_000_000_000n);
      assert.equal(parsed.seqno, 10);
    });

    it("should preserve memo in round-trip", () => {
      const tx = buildTransaction(
        {
          intentType: "payment",
          recipients: [{ address: testAddress, amount: 500_000_000n }],
          memo: "hello ton",
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.type, "Send");
      assert.equal(parsed.memo, "hello ton");
      assert.equal(parsed.outputAmount, 500_000_000n);
    });

    it("should accept string amounts", () => {
      const tx = buildTransaction(
        {
          intentType: "payment",
          recipients: [{ address: testAddress, amount: "2000000000" }],
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.outputAmount, 2_000_000_000n);
    });

    it("should accept number amounts", () => {
      const tx = buildTransaction(
        {
          intentType: "payment",
          recipients: [{ address: testAddress, amount: 3000000 }],
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.outputAmount, 3_000_000n);
    });
  });

  // ===========================================================================
  // Payment (token/jetton)
  // ===========================================================================

  describe("payment (token)", () => {
    it("should build a jetton transfer and round-trip parse", () => {
      const tx = buildTransaction(
        {
          intentType: "payment",
          recipients: [{ address: testAddress, amount: 5000n }],
          isToken: true,
          senderJettonAddress: testJettonAddress,
          tonAmount: 100_000_000n,
          forwardTonAmount: 1n,
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.type, "SendToken");
      assert.equal(parsed.jettonAmount, 5000n);
      assert.ok(parsed.jettonDestination !== undefined);
      assert.equal(parsed.forwardTonAmount, 1n);
    });

    it("should build token payment with memo", () => {
      const tx = buildTransaction(
        {
          intentType: "payment",
          recipients: [{ address: testAddress, amount: 100n }],
          memo: "jetton testing",
          isToken: true,
          senderJettonAddress: testJettonAddress,
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.type, "SendToken");
      assert.equal(parsed.memo, "jetton testing");
    });
  });

  // ===========================================================================
  // FillNonce
  // ===========================================================================

  describe("fillNonce", () => {
    it("should build a native fill nonce (self-send of 0)", () => {
      const tx = buildTransaction({ intentType: "fillNonce" }, baseContext());

      const parsed = parseTransaction(tx);
      assert.equal(parsed.type, "Send");
      assert.equal(parsed.outputAmount, 0n);
    });

    it("should build a token fill nonce", () => {
      const tx = buildTransaction(
        {
          intentType: "fillNonce",
          isToken: true,
          senderJettonAddress: testJettonAddress,
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.type, "SendToken");
      assert.equal(parsed.jettonAmount, 0n);
    });
  });

  // ===========================================================================
  // Consolidate
  // ===========================================================================

  describe("consolidate", () => {
    it("should build native consolidation with carry-all send mode", () => {
      const tx = buildTransaction(
        {
          intentType: "consolidate",
          recipients: [{ address: testAddress, amount: 5_000_000_000n }],
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.type, "Send");
      assert.equal(parsed.sendMode, 128); // carry all remaining balance
    });

    it("should build token consolidation", () => {
      const tx = buildTransaction(
        {
          intentType: "consolidate",
          recipients: [{ address: testAddress, amount: 10000n }],
          isToken: true,
          senderJettonAddress: testJettonAddress,
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.type, "SendToken");
    });
  });

  // ===========================================================================
  // Delegate (staking deposit)
  // ===========================================================================

  describe("delegate", () => {
    it("should build TonWhales deposit with correct opcode", () => {
      const tx = buildTransaction(
        {
          intentType: "delegate",
          stakingType: TonStakingType.TonWhales,
          validatorAddress: testAddress,
          amount: 10_000_000_000n,
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.type, "TonWhalesDeposit");
      assert.equal(parsed.outputAmount, 10_000_000_000n);
      assert.equal(parsed.bounceable, true);
    });

    it("should build SingleNominator deposit as bounceable transfer", () => {
      const tx = buildTransaction(
        {
          intentType: "delegate",
          stakingType: TonStakingType.SingleNominator,
          validatorAddress: testAddress,
          amount: 5_000_000_000n,
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.type, "Send");
      assert.equal(parsed.bounceable, true);
    });

    it("should build MultiNominator deposit with memo='d'", () => {
      const tx = buildTransaction(
        {
          intentType: "delegate",
          stakingType: TonStakingType.MultiNominator,
          validatorAddress: testAddress,
          amount: 5_000_000_000n,
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.memo, "d");
      assert.equal(parsed.bounceable, true);
    });
  });

  // ===========================================================================
  // Undelegate (staking withdrawal)
  // ===========================================================================

  describe("undelegate", () => {
    it("should build TonWhales withdrawal with correct opcode", () => {
      const tx = buildTransaction(
        {
          intentType: "undelegate",
          stakingType: TonStakingType.TonWhales,
          validatorAddress: testAddress,
          amount: 1_000_000_000n,
          withdrawalAmount: 5_000_000_000n,
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.type, "TonWhalesWithdrawal");
      assert.equal(parsed.bounceable, true);
    });

    it("should build SingleNominator withdrawal with correct opcode", () => {
      const tx = buildTransaction(
        {
          intentType: "undelegate",
          stakingType: TonStakingType.SingleNominator,
          validatorAddress: testAddress,
          amount: 1_000_000_000n,
          withdrawalAmount: 10_000_000_000n,
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.type, "SingleNominatorWithdraw");
    });

    it("should build MultiNominator withdrawal with memo='w'", () => {
      const tx = buildTransaction(
        {
          intentType: "undelegate",
          stakingType: TonStakingType.MultiNominator,
          validatorAddress: testAddress,
          amount: 1_000_000_000n,
        },
        baseContext(),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.memo, "w");
      assert.equal(parsed.bounceable, true);
    });
  });

  // ===========================================================================
  // StateInit (seqno == 0)
  // ===========================================================================

  describe("stateInit", () => {
    it("should include StateInit when seqno == 0", () => {
      const tx = buildTransaction(
        {
          intentType: "payment",
          recipients: [{ address: testAddress, amount: 1_000_000n }],
        },
        baseContext({
          seqno: 0,
          publicKey: "a26a1e5a8acab8c52e1bb9dd0e5cb8eee0ba403a7b5f3e1ec8c1cd0c1e1a3b2d",
        }),
      );

      assert.equal(tx.hasStateInit, true);
      assert.equal(tx.seqno, 0);
    });
  });

  // ===========================================================================
  // Vesting wallet ID
  // ===========================================================================

  describe("vesting", () => {
    it("should use walletId=268 for vesting contracts", () => {
      const tx = buildTransaction(
        {
          intentType: "delegate",
          stakingType: TonStakingType.TonWhales,
          validatorAddress: testAddress,
          amount: 10_000_000_000n,
        },
        baseContext({ isVestingContract: true }),
      );

      const parsed = parseTransaction(tx);
      assert.equal(parsed.walletId, 268);
    });
  });

  // ===========================================================================
  // Sign + broadcast roundtrip
  // ===========================================================================

  describe("sign and broadcast roundtrip", () => {
    it("should build, sign, serialize, and re-parse", () => {
      const tx = buildTransaction(
        {
          intentType: "payment",
          recipients: [{ address: testAddress, amount: 1_000_000_000n }],
          memo: "roundtrip",
        },
        baseContext(),
      );

      // Get signable payload
      const payload = tx.signablePayload();
      assert.equal(payload.length, 32);

      // Simulate signing
      const fakeSig = new Uint8Array(64).fill(42);
      tx.addSignature(fakeSig);

      // Serialize and re-parse
      const broadcast = tx.toBroadcastFormat();
      const tx2 = Transaction.fromBytes(Buffer.from(broadcast, "base64"));
      assert.equal(tx2.seqno, 10);

      const parsed = parseTransaction(tx2);
      assert.equal(parsed.memo, "roundtrip");
      assert.equal(parsed.outputAmount, 1_000_000_000n);
    });
  });

  // ===========================================================================
  // Error cases
  // ===========================================================================

  describe("error cases", () => {
    it("should throw for empty recipients", () => {
      assert.throws(() =>
        buildTransaction(
          {
            intentType: "payment",
            recipients: [],
          },
          baseContext(),
        ),
      );
    });

    it("should throw for token payment without jetton address", () => {
      assert.throws(() =>
        buildTransaction(
          {
            intentType: "payment",
            recipients: [{ address: testAddress, amount: 100n }],
            isToken: true,
            senderJettonAddress: undefined as unknown as string,
          },
          baseContext(),
        ),
      );
    });

    it("should throw for seqno=0 without publicKey", () => {
      assert.throws(() =>
        buildTransaction(
          {
            intentType: "payment",
            recipients: [{ address: testAddress, amount: 100n }],
          },
          baseContext({ seqno: 0 }),
        ),
      );
    });
  });
});
