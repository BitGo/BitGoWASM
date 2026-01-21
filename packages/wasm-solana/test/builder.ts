import * as assert from "assert";
import {
  buildTransaction,
  parseTransaction,
  type TransactionIntent,
  type BuilderInstruction,
} from "../js/index.js";

describe("buildTransaction", () => {
  // Test addresses from BitGoJS sdk-coin-sol/test/resources/sol.ts
  const AUTH_ACCOUNT = "5hr5fisPi6DXNuuRpm5XUbzpiEnmdyxXuBDTwzwZj5Pe"; // authAccount.pub
  const RECIPIENT = "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH"; // accountWithSeed.publicKey
  const NONCE_ACCOUNT = "8Y7RM6JfcX4ASSNBkrkrmSbRu431YVi9Y3oLFnzC2dCh"; // nonceAccount.pub
  const BLOCKHASH = "5ne7phA48Jrvpn39AtupB8ZkCCAy8gLTfpGihZPuDqen"; // blockHashes.validBlockHashes[0]
  const STAKE_ACCOUNT = "3c5emUWjViFqT72LxQYec8gkU8ZtmfKKXHvGgJNUBdYx"; // stakeAccount.pub

  // Aliases for clarity
  const SENDER = AUTH_ACCOUNT;

  describe("simple transfer", () => {
    it("should build a SOL transfer transaction", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          { type: "transfer", from: SENDER, to: RECIPIENT, lamports: "1000000" },
        ],
      };

      const txBytes = buildTransaction(intent);
      assert.ok(txBytes instanceof Uint8Array);
      assert.ok(txBytes.length > 0);

      // Parse it back to verify structure
      const parsed = parseTransaction(txBytes);
      assert.strictEqual(parsed.feePayer, SENDER);
      assert.strictEqual(parsed.nonce, BLOCKHASH);
      assert.strictEqual(parsed.instructionsData.length, 1);
      assert.strictEqual(parsed.instructionsData[0].type, "Transfer");
    });

    it("should parse the transfer instruction correctly", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "transfer",
            from: SENDER,
            to: RECIPIENT,
            lamports: "1000000",
          },
        ],
      };

      const txBytes = buildTransaction(intent);
      const parsed = parseTransaction(txBytes);

      const transfer = parsed.instructionsData[0];
      assert.strictEqual(transfer.type, "Transfer");
      if (transfer.type === "Transfer") {
        // Parser uses fromAddress/toAddress/amount
        assert.strictEqual(transfer.fromAddress, SENDER);
        assert.strictEqual(transfer.toAddress, RECIPIENT);
        assert.strictEqual(transfer.amount, "1000000");
      }
    });
  });

  describe("transfer with memo", () => {
    it("should build a transfer with memo", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          { type: "transfer", from: SENDER, to: RECIPIENT, lamports: "1000000" },
          { type: "memo", message: "BitGo transfer" },
        ],
      };

      const txBytes = buildTransaction(intent);
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 2);
      assert.strictEqual(parsed.instructionsData[0].type, "Transfer");
      assert.strictEqual(parsed.instructionsData[1].type, "Memo");

      const memo = parsed.instructionsData[1];
      if (memo.type === "Memo") {
        // Parser uses 'memo' field
        assert.strictEqual(memo.memo, "BitGo transfer");
      }
    });
  });

  describe("compute budget", () => {
    it("should build with compute unit limit", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          { type: "computeBudget", unitLimit: 200000 },
          { type: "transfer", from: SENDER, to: RECIPIENT, lamports: "1000000" },
        ],
      };

      const txBytes = buildTransaction(intent);
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 2);
      assert.strictEqual(parsed.instructionsData[0].type, "SetComputeUnitLimit");
      assert.strictEqual(parsed.instructionsData[1].type, "Transfer");

      const computeBudget = parsed.instructionsData[0];
      if (computeBudget.type === "SetComputeUnitLimit") {
        assert.strictEqual(computeBudget.units, 200000);
      }
    });

    it("should build with compute unit price (priority fee)", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          { type: "computeBudget", unitPrice: 5000 },
          { type: "transfer", from: SENDER, to: RECIPIENT, lamports: "1000000" },
        ],
      };

      const txBytes = buildTransaction(intent);
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 2);
      assert.strictEqual(parsed.instructionsData[0].type, "SetPriorityFee");
      assert.strictEqual(parsed.instructionsData[1].type, "Transfer");

      const priorityFee = parsed.instructionsData[0];
      if (priorityFee.type === "SetPriorityFee") {
        // Parser uses 'fee' as a number
        assert.strictEqual(priorityFee.fee, 5000);
      }
    });
  });

  describe("durable nonce", () => {
    it("should prepend nonce advance instruction for durable nonce", () => {
      // Use BitGoJS nonceAccount.pub and a sample nonce value
      const NONCE_AUTHORITY = SENDER;
      // This is the nonce value stored in the nonce account (becomes the blockhash)
      const NONCE_VALUE = "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi";

      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: {
          type: "durable",
          address: NONCE_ACCOUNT,
          authority: NONCE_AUTHORITY,
          value: NONCE_VALUE,
        },
        instructions: [
          { type: "transfer", from: SENDER, to: RECIPIENT, lamports: "1000000" },
        ],
      };

      const txBytes = buildTransaction(intent);
      const parsed = parseTransaction(txBytes);

      // Should have 2 instructions: NonceAdvance + Transfer
      assert.strictEqual(parsed.instructionsData.length, 2);
      assert.strictEqual(parsed.instructionsData[0].type, "NonceAdvance");
      assert.strictEqual(parsed.instructionsData[1].type, "Transfer");

      // Verify nonce advance params
      const nonceAdvance = parsed.instructionsData[0];
      if (nonceAdvance.type === "NonceAdvance") {
        // Parser uses walletNonceAddress/authWalletAddress
        assert.strictEqual(nonceAdvance.walletNonceAddress, NONCE_ACCOUNT);
        assert.strictEqual(nonceAdvance.authWalletAddress, NONCE_AUTHORITY);
      }
    });
  });

  describe("create account", () => {
    it("should build create account instruction", () => {
      // Use BitGoJS stakeAccount.pub as the new account
      const NEW_ACCOUNT = STAKE_ACCOUNT;
      const SYSTEM_PROGRAM = "11111111111111111111111111111111";

      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "createAccount",
            from: SENDER,
            newAccount: NEW_ACCOUNT,
            lamports: "1000000",
            space: 165,
            owner: SYSTEM_PROGRAM,
          },
        ],
      };

      const txBytes = buildTransaction(intent);
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 1);
      assert.strictEqual(parsed.instructionsData[0].type, "CreateAccount");

      const createAccount = parsed.instructionsData[0];
      if (createAccount.type === "CreateAccount") {
        // Parser uses fromAddress/newAddress/amount/space/owner
        assert.strictEqual(createAccount.fromAddress, SENDER);
        assert.strictEqual(createAccount.newAddress, NEW_ACCOUNT);
        assert.strictEqual(createAccount.amount, "1000000");
        assert.strictEqual(createAccount.space, 165);
        assert.strictEqual(createAccount.owner, SYSTEM_PROGRAM);
      }
    });
  });

  describe("error handling", () => {
    it("should reject invalid public key", () => {
      const intent: TransactionIntent = {
        feePayer: "invalid",
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [],
      };

      assert.throws(
        () => buildTransaction(intent),
        /Invalid fee_payer/
      );
    });

    it("should reject invalid blockhash", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: "invalid" },
        instructions: [],
      };

      assert.throws(() => buildTransaction(intent), /Invalid blockhash/);
    });

    it("should reject computeBudget without unitLimit or unitPrice", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [{ type: "computeBudget" } as BuilderInstruction],
      };

      assert.throws(
        () => buildTransaction(intent),
        /ComputeBudget.*unitLimit.*unitPrice/
      );
    });
  });

  describe("roundtrip", () => {
    it("should produce consistent bytes on rebuild", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          { type: "transfer", from: SENDER, to: RECIPIENT, lamports: "1000000" },
          { type: "memo", message: "Test" },
        ],
      };

      const txBytes1 = buildTransaction(intent);
      const txBytes2 = buildTransaction(intent);

      assert.deepStrictEqual(txBytes1, txBytes2);
    });
  });
});
