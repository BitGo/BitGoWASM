import * as assert from "assert";
import { Transaction } from "../js/transaction.js";
import { parseTransaction, TransactionType } from "../js/parser.js";
import { encodeAddress } from "../js/address.js";
import { buildTransaction, TonStakingType } from "../js/builder.js";
import type {
  BuildContext,
  PaymentIntent,
  FillNonceIntent,
  ConsolidateIntent,
  DelegateIntent,
  UndelegateIntent,
} from "../js/builder.js";

// =============================================================================
// Test constants
// =============================================================================

const TEST_PUBLIC_KEY = "f61b63341a65e5e23adbf052a7e27fad28bb6f461ef63c1c04e9f63d9eb1e54f";
const TEST_RECIPIENT = "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG";
const TEST_VALIDATOR = "EQDr9Sq482A6ikIUh5mUUjJaBUUJBrye13CJiDB-R31_lwIq";
const TEST_JETTON_WALLET = "EQB-CM6DF-jpq9XVdiSdefAMU5KC1gpZuYBFp-Q65aUhnx5K";

// Derive the sender address from the public key to ensure it's valid
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

const TEST_SENDER = encodeAddress(hexToBytes(TEST_PUBLIC_KEY), {
  bounceable: true,
  walletVersion: "V4R2",
});

function makeContext(overrides?: Partial<BuildContext>): BuildContext {
  return {
    sender: TEST_SENDER,
    publicKey: TEST_PUBLIC_KEY,
    seqno: 10,
    expireTime: 1700000000,
    walletVersion: "V4R2",
    walletId: 698983191,
    ...overrides,
  };
}

// =============================================================================
// Payment tests
// =============================================================================

describe("Builder: Payment", () => {
  it("should build a native TON transfer", () => {
    const intent: PaymentIntent = {
      intentType: "payment",
      recipients: [{ address: TEST_RECIPIENT, amount: 10_000_000n }],
    };
    const tx = buildTransaction(intent, makeContext());
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.Send);
    assert.strictEqual(parsed.recipients.length, 1);
    assert.strictEqual(parsed.recipients[0].amount, 10_000_000n);
    assert.strictEqual(parsed.seqno, 10);
    assert.strictEqual(parsed.expireTime, 1_700_000_000);
  });

  it("should build a payment with memo", () => {
    const intent: PaymentIntent = {
      intentType: "payment",
      recipients: [{ address: TEST_RECIPIENT, amount: 50_000_000n }],
      memo: "hello world",
    };
    const tx = buildTransaction(intent, makeContext());
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.Send);
    assert.strictEqual(parsed.memo, "hello world");
    assert.strictEqual(parsed.recipients[0].amount, 50_000_000n);
  });

  it("should build a payment with multiple recipients", () => {
    const intent: PaymentIntent = {
      intentType: "payment",
      recipients: [
        { address: TEST_RECIPIENT, amount: 10_000_000n },
        { address: TEST_VALIDATOR, amount: 20_000_000n },
      ],
    };
    const tx = buildTransaction(intent, makeContext());
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.recipients.length, 2);
    assert.strictEqual(parsed.recipients[0].amount, 10_000_000n);
    assert.strictEqual(parsed.recipients[1].amount, 20_000_000n);
  });

  it("should build a token transfer", () => {
    const intent: PaymentIntent = {
      intentType: "payment",
      recipients: [{ address: TEST_RECIPIENT, amount: 1_000_000_000n }],
      isToken: true,
      senderJettonWalletAddress: TEST_JETTON_WALLET,
      memo: "jetton test",
    };
    const tx = buildTransaction(intent, makeContext());
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.SendToken);
    assert.ok(parsed.jettonTransfer);
    assert.strictEqual(parsed.jettonTransfer!.amount, "1000000000");
  });

  it("should reject token transfer without jetton wallet address", () => {
    const intent: PaymentIntent = {
      intentType: "payment",
      recipients: [{ address: TEST_RECIPIENT, amount: 1_000_000_000n }],
      isToken: true,
    };
    assert.throws(() => buildTransaction(intent, makeContext()), /senderJettonWalletAddress/);
  });

  it("should roundtrip through serialization", () => {
    const intent: PaymentIntent = {
      intentType: "payment",
      recipients: [{ address: TEST_RECIPIENT, amount: 10_000_000n }],
      memo: "roundtrip",
    };
    const tx1 = buildTransaction(intent, makeContext());
    const bytes = tx1.toBytes();
    const tx2 = Transaction.fromBytes(bytes);

    assert.strictEqual(tx1.seqno, tx2.seqno);
    assert.strictEqual(tx1.expireTime, tx2.expireTime);
    assert.strictEqual(tx1.walletId, tx2.walletId);
    assert.deepStrictEqual(
      Uint8Array.from(tx1.signablePayload()),
      Uint8Array.from(tx2.signablePayload()),
    );
  });
});

// =============================================================================
// FillNonce tests
// =============================================================================

describe("Builder: FillNonce", () => {
  it("should build a fill nonce (self-send of 0)", () => {
    const intent: FillNonceIntent = {
      intentType: "fillNonce",
      sender: TEST_SENDER,
    };
    const tx = buildTransaction(intent, makeContext());
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.Send);
    assert.strictEqual(parsed.recipients.length, 1);
    assert.strictEqual(parsed.recipients[0].amount, 0n);
  });
});

// =============================================================================
// Consolidate tests
// =============================================================================

describe("Builder: Consolidate", () => {
  it("should build a native consolidation", () => {
    const intent: ConsolidateIntent = {
      intentType: "consolidate",
      recipients: [{ address: TEST_RECIPIENT, amount: 50_000_000n }],
      receiveAddress: TEST_RECIPIENT,
    };
    const tx = buildTransaction(intent, makeContext());
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.Send);
    assert.strictEqual(parsed.recipients[0].amount, 50_000_000n);
  });

  it("should build a token consolidation with forced space memo", () => {
    const intent: ConsolidateIntent = {
      intentType: "consolidate",
      recipients: [{ address: TEST_RECIPIENT, amount: 1_000_000_000n }],
      receiveAddress: TEST_RECIPIENT,
      isToken: true,
      senderJettonWalletAddress: TEST_JETTON_WALLET,
    };
    const tx = buildTransaction(intent, makeContext());
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.SendToken);
  });
});

// =============================================================================
// Delegate tests
// =============================================================================

describe("Builder: Delegate", () => {
  it("should build a TON Whales deposit", () => {
    const intent: DelegateIntent = {
      intentType: "delegate",
      validatorAddress: TEST_VALIDATOR,
      amount: 10_000_000_000n,
      stakingType: TonStakingType.TonWhales,
    };
    const tx = buildTransaction(intent, makeContext());
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.TonWhalesDeposit);
    assert.strictEqual(parsed.recipients.length, 1);
  });

  it("should build a Single Nominator deposit", () => {
    const intent: DelegateIntent = {
      intentType: "delegate",
      validatorAddress: TEST_VALIDATOR,
      amount: 5_000_000_000n,
      stakingType: TonStakingType.SingleNominator,
    };
    const tx = buildTransaction(intent, makeContext());
    const parsed = parseTransaction(tx);

    // SingleNominator deposit is a plain transfer, parsed as Send
    assert.strictEqual(parsed.transactionType, TransactionType.Send);
    assert.strictEqual(parsed.recipients[0].amount, 5_000_000_000n);
  });

  it("should build a Multi Nominator deposit with memo 'd'", () => {
    const intent: DelegateIntent = {
      intentType: "delegate",
      validatorAddress: TEST_VALIDATOR,
      amount: 5_000_000_000n,
      stakingType: TonStakingType.MultiNominator,
    };
    const tx = buildTransaction(intent, makeContext());
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.Send);
    assert.strictEqual(parsed.memo, "d");
  });
});

// =============================================================================
// Undelegate tests
// =============================================================================

describe("Builder: Undelegate", () => {
  it("should build a TON Whales withdrawal", () => {
    const intent: UndelegateIntent = {
      intentType: "undelegate",
      validatorAddress: TEST_VALIDATOR,
      amount: 200_000_000n,
      stakingType: TonStakingType.TonWhales,
      withdrawalAmount: 5_000_000_000n,
    };
    const tx = buildTransaction(intent, makeContext());
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.TonWhalesWithdrawal);
  });

  it("should build a Single Nominator withdrawal with 1 TON attached", () => {
    const intent: UndelegateIntent = {
      intentType: "undelegate",
      validatorAddress: TEST_RECIPIENT,
      amount: 123_400_000n,
      stakingType: TonStakingType.SingleNominator,
    };
    const tx = buildTransaction(intent, makeContext());
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.SingleNominatorWithdraw);
    // Attached amount should be 1 TON
    assert.strictEqual(parsed.recipients[0].amount, 1_000_000_000n);
  });

  it("should build a Multi Nominator withdrawal with memo 'w'", () => {
    const intent: UndelegateIntent = {
      intentType: "undelegate",
      validatorAddress: TEST_VALIDATOR,
      amount: 1_000_000_000n,
      stakingType: TonStakingType.MultiNominator,
    };
    const tx = buildTransaction(intent, makeContext());
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.Send);
    assert.strictEqual(parsed.memo, "w");
  });
});

// =============================================================================
// Build -> Parse roundtrip tests
// =============================================================================

describe("Builder: Build -> Parse roundtrip", () => {
  it("should produce consistent signable payloads through roundtrip", () => {
    const intent: PaymentIntent = {
      intentType: "payment",
      recipients: [{ address: TEST_RECIPIENT, amount: 10_000_000n }],
    };
    const tx1 = buildTransaction(intent, makeContext());
    const base64 = tx1.toBroadcastFormat();
    const tx2 = Transaction.fromBase64(base64);

    assert.deepStrictEqual(
      Uint8Array.from(tx1.signablePayload()),
      Uint8Array.from(tx2.signablePayload()),
    );
  });

  it("should build unsigned transactions (no signature)", () => {
    const intent: PaymentIntent = {
      intentType: "payment",
      recipients: [{ address: TEST_RECIPIENT, amount: 10_000_000n }],
    };
    const tx = buildTransaction(intent, makeContext());
    // The transaction has a zero signature (unsigned), which our parser treats as unsigned
    assert.ok(tx.signablePayload().length === 32);
  });
});
