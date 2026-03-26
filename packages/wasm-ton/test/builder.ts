import { strict as assert } from "assert";
import {
  buildTransaction,
  parseTransaction,
  Transaction,
  TonIntentType,
  TonStakingType,
  TonTransactionType,
  encodeAddress,
} from "../dist/cjs/js/index.js";

// Deterministic test keys
const TEST_PUBKEY = new Uint8Array(32).fill(1);
const TEST_PUBKEY_HEX = "01".repeat(32);

// Derive sender address from test pubkey
const SENDER_ADDRESS = encodeAddress(TEST_PUBKEY, { bounceable: false });

// Derive a recipient address from a different pubkey
const RECIPIENT_PUBKEY = new Uint8Array(32).fill(2);
const RECIPIENT_ADDRESS = encodeAddress(RECIPIENT_PUBKEY, { bounceable: false });

// Jetton wallet address (different key)
const JETTON_PUBKEY = new Uint8Array(32).fill(3);
const JETTON_ADDRESS = encodeAddress(JETTON_PUBKEY, { bounceable: true });

const EXPIRE_AT = 1700000000;

describe("buildTransaction", () => {
  describe("Payment (native)", () => {
    it("should build a native transfer", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Payment,
        recipients: [{ address: RECIPIENT_ADDRESS, amount: 1_000_000_000n }],
        sender: SENDER_ADDRESS,
        seqno: 1,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.transactionType, TonTransactionType.Send);
      assert.equal(parsed.amount, 1_000_000_000n);
      assert.equal(parsed.seqno, 1);
      assert.equal(parsed.isSigned, false);
    });

    it("should build a native transfer with memo", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Payment,
        recipients: [{ address: RECIPIENT_ADDRESS, amount: 500_000_000n }],
        memo: "test memo",
        sender: SENDER_ADDRESS,
        seqno: 2,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.transactionType, TonTransactionType.Send);
      assert.equal(parsed.amount, 500_000_000n);
      assert.equal(parsed.memo, "test memo");
    });

    it("should build a bounceable transfer", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Payment,
        recipients: [{ address: RECIPIENT_ADDRESS, amount: 100_000_000n }],
        bounceable: true,
        sender: SENDER_ADDRESS,
        seqno: 3,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.bounceable, true);
    });
  });

  describe("Payment (jetton)", () => {
    it("should build a jetton transfer", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Payment,
        recipients: [{ address: RECIPIENT_ADDRESS, amount: 5_000_000n }],
        memo: "jetton transfer",
        sender: SENDER_ADDRESS,
        seqno: 10,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
        senderJettonAddress: JETTON_ADDRESS,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.transactionType, TonTransactionType.SendToken);
      assert.equal(parsed.seqno, 10);
      assert.equal(parsed.bounceable, true);
    });
  });

  describe("FillNonce", () => {
    it("should build a native fill nonce (self-send)", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.FillNonce,
        address: SENDER_ADDRESS,
        seqno: 5,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.transactionType, TonTransactionType.Send);
      assert.equal(parsed.amount, 0n);
      assert.equal(parsed.seqno, 5);
    });

    it("should build a token fill nonce", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.FillNonce,
        address: SENDER_ADDRESS,
        seqno: 6,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
        senderJettonAddress: JETTON_ADDRESS,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.transactionType, TonTransactionType.SendToken);
      assert.equal(parsed.seqno, 6);
    });
  });

  describe("Consolidate", () => {
    it("should build a native consolidation", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Consolidate,
        recipients: [{ address: RECIPIENT_ADDRESS, amount: 2_000_000_000n }],
        sender: SENDER_ADDRESS,
        seqno: 3,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.seqno, 3);
      // Consolidation uses mode 128 (send all)
      assert.equal(parsed.sendMode, 128);
    });

    it("should build a token consolidation", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Consolidate,
        recipients: [{ address: RECIPIENT_ADDRESS, amount: 1_000_000n }],
        sender: SENDER_ADDRESS,
        seqno: 4,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
        senderJettonAddress: JETTON_ADDRESS,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.transactionType, TonTransactionType.SendToken);
      assert.equal(parsed.seqno, 4);
    });
  });

  describe("Delegate", () => {
    it("should build a TON Whales deposit", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Delegate,
        validatorAddress: RECIPIENT_ADDRESS,
        amount: 5_000_000_000n,
        stakingType: TonStakingType.TonWhales,
        sender: SENDER_ADDRESS,
        seqno: 10,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.transactionType, TonTransactionType.TonWhalesDeposit);
      assert.equal(parsed.seqno, 10);
      assert.equal(parsed.bounceable, true);
    });

    it("should build a TON Whales vesting deposit", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Delegate,
        validatorAddress: RECIPIENT_ADDRESS,
        amount: 5_000_000_000n,
        stakingType: TonStakingType.TonWhales,
        sender: SENDER_ADDRESS,
        seqno: 30,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
        isVesting: true,
        subWalletId: 268,
      });

      // Vesting transactions produce a valid signable payload
      const payload = tx.signablePayload();
      assert.equal(payload.length, 32);

      // Can serialize to bytes
      const bytes = tx.toBytes();
      assert.ok(bytes.length > 0);

      // Can sign
      const fakeSig = new Uint8Array(64).fill(0xab);
      tx.addSignature(fakeSig);
      assert.notEqual(tx.id, undefined);
    });

    it("should build a Single Nominator delegation (plain transfer)", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Delegate,
        validatorAddress: RECIPIENT_ADDRESS,
        amount: 3_000_000_000n,
        stakingType: TonStakingType.SingleNominator,
        sender: SENDER_ADDRESS,
        seqno: 11,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.transactionType, TonTransactionType.Send);
      assert.equal(parsed.bounceable, true);
      assert.equal(parsed.amount, 3_000_000_000n);
    });

    it("should build a Multi Nominator delegation (memo 'd')", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Delegate,
        validatorAddress: RECIPIENT_ADDRESS,
        amount: 4_000_000_000n,
        stakingType: TonStakingType.MultiNominator,
        sender: SENDER_ADDRESS,
        seqno: 12,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.memo, "d");
      assert.equal(parsed.bounceable, true);
    });
  });

  describe("Undelegate", () => {
    it("should build a TON Whales withdrawal", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Undelegate,
        validatorAddress: RECIPIENT_ADDRESS,
        amount: 1_000_000_000n,
        withdrawalAmount: 5_000_000_000n,
        stakingType: TonStakingType.TonWhales,
        sender: SENDER_ADDRESS,
        seqno: 20,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.transactionType, TonTransactionType.TonWhalesWithdrawal);
      assert.equal(parsed.seqno, 20);
    });

    it("should build a TON Whales vesting withdrawal", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Undelegate,
        validatorAddress: RECIPIENT_ADDRESS,
        amount: 1_000_000_000n,
        stakingType: TonStakingType.TonWhales,
        sender: SENDER_ADDRESS,
        seqno: 31,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
        isVesting: true,
        subWalletId: 268,
      });

      const payload = tx.signablePayload();
      assert.equal(payload.length, 32);

      const bytes = tx.toBytes();
      assert.ok(bytes.length > 0);
    });

    it("should build a Single Nominator withdrawal", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Undelegate,
        validatorAddress: RECIPIENT_ADDRESS,
        amount: 1_000_000_000n,
        withdrawalAmount: 3_000_000_000n,
        stakingType: TonStakingType.SingleNominator,
        sender: SENDER_ADDRESS,
        seqno: 21,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.transactionType, TonTransactionType.SingleNominatorWithdraw);
      assert.equal(parsed.seqno, 21);
    });

    it("should build a Multi Nominator withdrawal (memo 'w')", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Undelegate,
        validatorAddress: RECIPIENT_ADDRESS,
        amount: 2_000_000_000n,
        stakingType: TonStakingType.MultiNominator,
        sender: SENDER_ADDRESS,
        seqno: 22,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      const parsed = parseTransaction(tx);
      assert.equal(parsed.memo, "w");
      assert.equal(parsed.bounceable, true);
    });
  });

  describe("round-trip (build -> serialize -> deserialize -> parse)", () => {
    it("should round-trip a native payment", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Payment,
        recipients: [{ address: RECIPIENT_ADDRESS, amount: 750_000_000n }],
        memo: "roundtrip test",
        sender: SENDER_ADDRESS,
        seqno: 99,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      const bytes = tx.toBytes();
      const tx2 = Transaction.fromBytes(bytes);
      const parsed = parseTransaction(tx2);

      assert.equal(parsed.seqno, 99);
      assert.equal(parsed.amount, 750_000_000n);
      assert.equal(parsed.memo, "roundtrip test");
    });

    it("should round-trip a base64 broadcast format", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Payment,
        recipients: [{ address: RECIPIENT_ADDRESS, amount: 100_000_000n }],
        sender: SENDER_ADDRESS,
        seqno: 42,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      const b64 = tx.toBroadcastFormat();
      const tx2 = Transaction.fromBase64(b64);
      const parsed = parseTransaction(tx2);

      assert.equal(parsed.seqno, 42);
      assert.equal(parsed.amount, 100_000_000n);
    });
  });

  describe("signing flow", () => {
    it("should be unsigned initially, allow signing, then have an ID", () => {
      const tx = buildTransaction({
        intentType: TonIntentType.Payment,
        recipients: [{ address: RECIPIENT_ADDRESS, amount: 1_000_000n }],
        sender: SENDER_ADDRESS,
        seqno: 1,
        expireAt: EXPIRE_AT,
        publicKey: TEST_PUBKEY_HEX,
      });

      // Unsigned: no ID
      assert.equal(tx.id, undefined);

      // Get signable payload
      const payload = tx.signablePayload();
      assert.equal(payload.length, 32);

      // Add a fake signature
      const fakeSig = new Uint8Array(64).fill(0xab);
      tx.addSignature(fakeSig);

      // Now has an ID
      assert.notEqual(tx.id, undefined);
      assert.equal(typeof tx.id, "string");
    });
  });
});
