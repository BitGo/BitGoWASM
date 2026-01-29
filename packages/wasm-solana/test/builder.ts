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
        instructions: [{ type: "transfer", from: SENDER, to: RECIPIENT, lamports: 1000000n }],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
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
            lamports: 1000000n,
          },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      const transfer = parsed.instructionsData[0];
      assert.strictEqual(transfer.type, "Transfer");
      if (transfer.type === "Transfer") {
        // Parser uses fromAddress/toAddress/amount
        assert.strictEqual(transfer.fromAddress, SENDER);
        assert.strictEqual(transfer.toAddress, RECIPIENT);
        assert.strictEqual(transfer.amount, 1000000n);
      }
    });
  });

  describe("transfer with memo", () => {
    it("should build a transfer with memo", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          { type: "transfer", from: SENDER, to: RECIPIENT, lamports: 1000000n },
          { type: "memo", message: "BitGo transfer" },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
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
          { type: "transfer", from: SENDER, to: RECIPIENT, lamports: 1000000n },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
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
          { type: "transfer", from: SENDER, to: RECIPIENT, lamports: 1000000n },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 2);
      assert.strictEqual(parsed.instructionsData[0].type, "SetPriorityFee");
      assert.strictEqual(parsed.instructionsData[1].type, "Transfer");

      const priorityFee = parsed.instructionsData[0];
      if (priorityFee.type === "SetPriorityFee") {
        // Parser uses 'fee' as BigInt
        assert.strictEqual(priorityFee.fee, BigInt(5000));
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
        instructions: [{ type: "transfer", from: SENDER, to: RECIPIENT, lamports: 1000000n }],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
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
            lamports: 1000000n,
            space: 165,
            owner: SYSTEM_PROGRAM,
          },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 1);
      assert.strictEqual(parsed.instructionsData[0].type, "CreateAccount");

      const createAccount = parsed.instructionsData[0];
      if (createAccount.type === "CreateAccount") {
        // Parser uses fromAddress/newAddress/amount/space/owner
        assert.strictEqual(createAccount.fromAddress, SENDER);
        assert.strictEqual(createAccount.newAddress, NEW_ACCOUNT);
        assert.strictEqual(createAccount.amount, 1000000n);
        assert.strictEqual(createAccount.space, 165n);
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

      assert.throws(() => buildTransaction(intent), /Invalid fee_payer/);
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

      assert.throws(() => buildTransaction(intent), /ComputeBudget.*unitLimit.*unitPrice/);
    });
  });

  describe("roundtrip", () => {
    it("should produce consistent bytes on rebuild", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          { type: "transfer", from: SENDER, to: RECIPIENT, lamports: 1000000n },
          { type: "memo", message: "Test" },
        ],
      };

      const tx1 = buildTransaction(intent);
      const tx2 = buildTransaction(intent);

      // Compare serialized bytes since Transaction objects have different wasm pointers
      assert.deepStrictEqual(tx1.toBytes(), tx2.toBytes());
    });
  });

  // ===== Stake Program Tests =====
  describe("stake program", () => {
    // From BitGoJS test/resources/sol.ts
    const VALIDATOR = "CyjoLt3kjqB57K7ewCBHmnHq3UgEj3ak6A7m6EsBsuhA"; // validator.pub

    it("should build stake initialize instruction", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "stakeInitialize",
            stake: STAKE_ACCOUNT,
            staker: SENDER,
            withdrawer: SENDER,
          },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 1);
      assert.strictEqual(parsed.instructionsData[0].type, "StakeInitialize");

      const stakeInit = parsed.instructionsData[0];
      if (stakeInit.type === "StakeInitialize") {
        assert.strictEqual(stakeInit.stakingAddress, STAKE_ACCOUNT);
        assert.strictEqual(stakeInit.staker, SENDER);
        assert.strictEqual(stakeInit.withdrawer, SENDER);
      }
    });

    it("should build stake delegate instruction", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "stakeDelegate",
            stake: STAKE_ACCOUNT,
            vote: VALIDATOR,
            authority: SENDER,
          },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 1);
      assert.strictEqual(parsed.instructionsData[0].type, "StakingDelegate");

      const stakeDelegate = parsed.instructionsData[0];
      if (stakeDelegate.type === "StakingDelegate") {
        assert.strictEqual(stakeDelegate.stakingAddress, STAKE_ACCOUNT);
        assert.strictEqual(stakeDelegate.validator, VALIDATOR);
        assert.strictEqual(stakeDelegate.fromAddress, SENDER);
      }
    });

    it("should build stake deactivate instruction", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "stakeDeactivate",
            stake: STAKE_ACCOUNT,
            authority: SENDER,
          },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 1);
      assert.strictEqual(parsed.instructionsData[0].type, "StakingDeactivate");

      const stakeDeactivate = parsed.instructionsData[0];
      if (stakeDeactivate.type === "StakingDeactivate") {
        assert.strictEqual(stakeDeactivate.stakingAddress, STAKE_ACCOUNT);
        assert.strictEqual(stakeDeactivate.fromAddress, SENDER);
      }
    });

    it("should build stake withdraw instruction", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "stakeWithdraw",
            stake: STAKE_ACCOUNT,
            recipient: RECIPIENT,
            lamports: 300000n,
            authority: SENDER,
          },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 1);
      assert.strictEqual(parsed.instructionsData[0].type, "StakingWithdraw");

      const stakeWithdraw = parsed.instructionsData[0];
      if (stakeWithdraw.type === "StakingWithdraw") {
        assert.strictEqual(stakeWithdraw.stakingAddress, STAKE_ACCOUNT);
        assert.strictEqual(stakeWithdraw.fromAddress, SENDER);
        assert.strictEqual(stakeWithdraw.amount, 300000n);
      }
    });

    it("should build full staking activate flow", () => {
      // Typical staking activate: CreateAccount + StakeInitialize + StakeDelegate
      // The parser combines these into a single StakingActivate instruction
      const STAKE_PROGRAM = "Stake11111111111111111111111111111111111111";

      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "createAccount",
            from: SENDER,
            newAccount: STAKE_ACCOUNT,
            lamports: 300000n,
            space: 200, // Stake account size
            owner: STAKE_PROGRAM,
          },
          {
            type: "stakeInitialize",
            stake: STAKE_ACCOUNT,
            staker: SENDER,
            withdrawer: SENDER,
          },
          {
            type: "stakeDelegate",
            stake: STAKE_ACCOUNT,
            vote: VALIDATOR,
            authority: SENDER,
          },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      // Parser returns individual instructions; combining is done in BitGoJS wasmInstructionCombiner
      assert.strictEqual(parsed.instructionsData.length, 3);
      assert.strictEqual(parsed.instructionsData[0].type, "CreateAccount");
      assert.strictEqual(parsed.instructionsData[1].type, "StakeInitialize");
      assert.strictEqual(parsed.instructionsData[2].type, "StakingDelegate");

      // Verify CreateAccount details
      const createAccount = parsed.instructionsData[0];
      if (createAccount.type === "CreateAccount") {
        assert.strictEqual(createAccount.fromAddress, SENDER);
        assert.strictEqual(createAccount.newAddress, STAKE_ACCOUNT);
        assert.strictEqual(createAccount.amount, 300000n);
      }

      // Verify StakingDelegate details
      const stakeDelegate = parsed.instructionsData[2];
      if (stakeDelegate.type === "StakingDelegate") {
        assert.strictEqual(stakeDelegate.stakingAddress, STAKE_ACCOUNT);
        assert.strictEqual(stakeDelegate.validator, VALIDATOR);
      }
    });
  });

  // ===== SPL Token Tests =====
  describe("spl token", () => {
    // From BitGoJS test/resources/sol.ts
    const MINT_USDC = "F4uLeXJoFz3hw13MposuwaQbMcZbCjqvEGPPeRRB1Byf"; // tokenTransfers.mintUSDC
    const SOURCE_ATA = "2fyhC1YbqaYszkUQw2YGNRVkr2abr69UwFXVCjz4Q5f5"; // tokenTransfers.sourceUSDC
    const DEST_ATA = "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH";

    it("should build token transfer instruction", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "tokenTransfer",
            source: SOURCE_ATA,
            destination: DEST_ATA,
            mint: MINT_USDC,
            amount: 300000n,
            decimals: 9,
            authority: SENDER,
          },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 1);
      assert.strictEqual(parsed.instructionsData[0].type, "TokenTransfer");

      const tokenTransfer = parsed.instructionsData[0];
      if (tokenTransfer.type === "TokenTransfer") {
        assert.strictEqual(tokenTransfer.sourceAddress, SOURCE_ATA);
        assert.strictEqual(tokenTransfer.toAddress, DEST_ATA);
        assert.strictEqual(tokenTransfer.amount, 300000n);
        assert.strictEqual(tokenTransfer.tokenAddress, MINT_USDC);
        assert.strictEqual(tokenTransfer.decimalPlaces, 9);
      }
    });

    it("should build create associated token account instruction", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "createAssociatedTokenAccount",
            payer: SENDER,
            owner: RECIPIENT,
            mint: MINT_USDC,
          },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 1);
      assert.strictEqual(parsed.instructionsData[0].type, "CreateAssociatedTokenAccount");

      const createAta = parsed.instructionsData[0];
      if (createAta.type === "CreateAssociatedTokenAccount") {
        assert.strictEqual(createAta.payerAddress, SENDER);
        assert.strictEqual(createAta.ownerAddress, RECIPIENT);
        assert.strictEqual(createAta.mintAddress, MINT_USDC);
      }
    });

    it("should build close associated token account instruction", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "closeAssociatedTokenAccount",
            account: SOURCE_ATA,
            destination: SENDER,
            authority: SENDER,
          },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 1);
      assert.strictEqual(parsed.instructionsData[0].type, "CloseAssociatedTokenAccount");

      const closeAta = parsed.instructionsData[0];
      if (closeAta.type === "CloseAssociatedTokenAccount") {
        assert.strictEqual(closeAta.accountAddress, SOURCE_ATA);
        assert.strictEqual(closeAta.destinationAddress, SENDER);
        assert.strictEqual(closeAta.authorityAddress, SENDER);
      }
    });

    it("should build token transfer with create ATA", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "createAssociatedTokenAccount",
            payer: SENDER,
            owner: RECIPIENT,
            mint: MINT_USDC,
          },
          {
            type: "tokenTransfer",
            source: SOURCE_ATA,
            destination: DEST_ATA,
            mint: MINT_USDC,
            amount: 300000n,
            decimals: 9,
            authority: SENDER,
          },
          { type: "memo", message: "test memo" },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 3);
      assert.strictEqual(parsed.instructionsData[0].type, "CreateAssociatedTokenAccount");
      assert.strictEqual(parsed.instructionsData[1].type, "TokenTransfer");
      assert.strictEqual(parsed.instructionsData[2].type, "Memo");
    });
  });

  // ===== Jito Stake Pool Tests =====
  describe("jito stake pool", () => {
    // From BitGoJS Jito constants
    const JITO_STAKE_POOL = "Jito4APyf642JPZPx3hGc6WWJ8zPKtRbRs4P815Awbb";
    const JITO_WITHDRAW_AUTHORITY = "6iQKfEyhr3bZMotVkW6beNZz5CPAkiwvgV2CTje9pVSS";
    const JITO_RESERVE_STAKE = "BgKUXdS4Wy6Vdgp1jwT2dz5ZgxPG94aPL77dQscSPGmc";
    const JITO_POOL_MINT = "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn"; // JitoSOL
    const MANAGER_FEE_ACCOUNT = "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN";
    const VALIDATOR_LIST = "3R3nGZpQs2aZo5FDQvd2MUQ5R5E9g7NvHQaxpLPYA8r2";
    const VALIDATOR_STAKE = "BgKUXdS4Wy6Vdgp1jwT2dz5ZgxPG94aPL77dQscSPGmc";
    const DEST_STAKE = "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH";
    const SOURCE_POOL_ACCOUNT = "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN";

    it("should build stake pool deposit sol instruction", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "stakePoolDepositSol",
            stakePool: JITO_STAKE_POOL,
            withdrawAuthority: JITO_WITHDRAW_AUTHORITY,
            reserveStake: JITO_RESERVE_STAKE,
            fundingAccount: SENDER,
            destinationPoolAccount: SOURCE_POOL_ACCOUNT,
            managerFeeAccount: MANAGER_FEE_ACCOUNT,
            referralPoolAccount: MANAGER_FEE_ACCOUNT,
            poolMint: JITO_POOL_MINT,
            lamports: 300000n,
          },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 1);
      assert.strictEqual(parsed.instructionsData[0].type, "StakePoolDepositSol");

      const depositSol = parsed.instructionsData[0];
      if (depositSol.type === "StakePoolDepositSol") {
        assert.strictEqual(depositSol.stakePool, JITO_STAKE_POOL);
        assert.strictEqual(depositSol.fundingAccount, SENDER);
        assert.strictEqual(depositSol.poolMint, JITO_POOL_MINT);
        assert.strictEqual(depositSol.lamports, 300000n);
      }
    });

    it("should build stake pool withdraw stake instruction", () => {
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "stakePoolWithdrawStake",
            stakePool: JITO_STAKE_POOL,
            validatorList: VALIDATOR_LIST,
            withdrawAuthority: JITO_WITHDRAW_AUTHORITY,
            validatorStake: VALIDATOR_STAKE,
            destinationStake: DEST_STAKE,
            destinationStakeAuthority: SENDER,
            sourceTransferAuthority: SENDER,
            sourcePoolAccount: SOURCE_POOL_ACCOUNT,
            managerFeeAccount: MANAGER_FEE_ACCOUNT,
            poolMint: JITO_POOL_MINT,
            poolTokens: 300000n,
          },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 1);
      assert.strictEqual(parsed.instructionsData[0].type, "StakePoolWithdrawStake");

      const withdrawStake = parsed.instructionsData[0];
      if (withdrawStake.type === "StakePoolWithdrawStake") {
        assert.strictEqual(withdrawStake.stakePool, JITO_STAKE_POOL);
        assert.strictEqual(withdrawStake.destinationStake, DEST_STAKE);
        assert.strictEqual(withdrawStake.sourceTransferAuthority, SENDER);
        assert.strictEqual(withdrawStake.poolMint, JITO_POOL_MINT);
        assert.strictEqual(withdrawStake.poolTokens, 300000n);
      }
    });

    it("should build jito deposit with create ATA", () => {
      // Typical Jito deposit flow: Create ATA for JitoSOL + DepositSol
      const intent: TransactionIntent = {
        feePayer: SENDER,
        nonce: { type: "blockhash", value: BLOCKHASH },
        instructions: [
          {
            type: "createAssociatedTokenAccount",
            payer: SENDER,
            owner: SENDER,
            mint: JITO_POOL_MINT,
          },
          {
            type: "stakePoolDepositSol",
            stakePool: JITO_STAKE_POOL,
            withdrawAuthority: JITO_WITHDRAW_AUTHORITY,
            reserveStake: JITO_RESERVE_STAKE,
            fundingAccount: SENDER,
            destinationPoolAccount: SOURCE_POOL_ACCOUNT,
            managerFeeAccount: MANAGER_FEE_ACCOUNT,
            referralPoolAccount: MANAGER_FEE_ACCOUNT,
            poolMint: JITO_POOL_MINT,
            lamports: 1000000000n, // 1 SOL
          },
        ],
      };

      const tx = buildTransaction(intent);
      const txBytes = tx.toBytes();
      const parsed = parseTransaction(txBytes);

      assert.strictEqual(parsed.instructionsData.length, 2);
      assert.strictEqual(parsed.instructionsData[0].type, "CreateAssociatedTokenAccount");
      assert.strictEqual(parsed.instructionsData[1].type, "StakePoolDepositSol");
    });
  });
});
