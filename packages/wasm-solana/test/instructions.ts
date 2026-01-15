import * as assert from "assert";
import {
  decodeSystemInstruction,
  decodeStakeInstruction,
  decodeComputeBudgetInstruction,
  isSystemProgram,
  isStakeProgram,
  isComputeBudgetProgram,
  SYSTEM_PROGRAM_ID,
  STAKE_PROGRAM_ID,
  COMPUTE_BUDGET_PROGRAM_ID,
} from "../js/instructions.js";
import { Transaction } from "../js/transaction.js";

describe("Instruction Decoders", () => {
  describe("Program ID Constants", () => {
    it("should have correct System Program ID", () => {
      assert.strictEqual(SYSTEM_PROGRAM_ID, "11111111111111111111111111111111");
    });

    it("should have correct Stake Program ID", () => {
      assert.strictEqual(
        STAKE_PROGRAM_ID,
        "Stake11111111111111111111111111111111111111"
      );
    });

    it("should have correct ComputeBudget Program ID", () => {
      assert.strictEqual(
        COMPUTE_BUDGET_PROGRAM_ID,
        "ComputeBudget111111111111111111111111111111"
      );
    });
  });

  describe("Program ID Checks", () => {
    it("should identify System Program", () => {
      assert.ok(isSystemProgram(SYSTEM_PROGRAM_ID));
      assert.ok(!isSystemProgram(STAKE_PROGRAM_ID));
      assert.ok(!isSystemProgram(COMPUTE_BUDGET_PROGRAM_ID));
      assert.ok(!isSystemProgram("SomeOtherProgram"));
    });

    it("should identify Stake Program", () => {
      assert.ok(isStakeProgram(STAKE_PROGRAM_ID));
      assert.ok(!isStakeProgram(SYSTEM_PROGRAM_ID));
      assert.ok(!isStakeProgram(COMPUTE_BUDGET_PROGRAM_ID));
    });

    it("should identify ComputeBudget Program", () => {
      assert.ok(isComputeBudgetProgram(COMPUTE_BUDGET_PROGRAM_ID));
      assert.ok(!isComputeBudgetProgram(SYSTEM_PROGRAM_ID));
      assert.ok(!isComputeBudgetProgram(STAKE_PROGRAM_ID));
    });
  });

  describe("System Instruction Decoder", () => {
    it("should decode Transfer instruction", () => {
      // Transfer 100000 lamports
      // discriminator 2 (u32 little-endian) + lamports (u64 little-endian)
      const data = new Uint8Array([
        2, 0, 0, 0, // discriminator = 2 (Transfer)
        160, 134, 1, 0, 0, 0, 0, 0, // lamports = 100000
      ]);

      const instr = decodeSystemInstruction(data);

      assert.strictEqual(instr.type, "Transfer");
      if (instr.type === "Transfer") {
        assert.strictEqual(instr.lamports, BigInt(100000));
      }
    });

    it("should decode AdvanceNonceAccount instruction", () => {
      const data = new Uint8Array([4, 0, 0, 0]); // discriminator = 4

      const instr = decodeSystemInstruction(data);
      assert.strictEqual(instr.type, "AdvanceNonceAccount");
    });

    it("should throw on invalid System instruction data", () => {
      const invalidData = new Uint8Array([255, 255, 255, 255]);
      assert.throws(() => decodeSystemInstruction(invalidData), /Failed to decode/);
    });
  });

  describe("Stake Instruction Decoder", () => {
    it("should decode DelegateStake instruction", () => {
      const data = new Uint8Array([2, 0, 0, 0]); // discriminator = 2

      const instr = decodeStakeInstruction(data);
      assert.strictEqual(instr.type, "DelegateStake");
    });

    it("should decode Deactivate instruction", () => {
      const data = new Uint8Array([5, 0, 0, 0]); // discriminator = 5

      const instr = decodeStakeInstruction(data);
      assert.strictEqual(instr.type, "Deactivate");
    });

    it("should decode Split instruction", () => {
      // Split with 500000 lamports
      const data = new Uint8Array([
        3, 0, 0, 0, // discriminator = 3 (Split)
        32, 161, 7, 0, 0, 0, 0, 0, // lamports = 500000
      ]);

      const instr = decodeStakeInstruction(data);

      assert.strictEqual(instr.type, "Split");
      if (instr.type === "Split") {
        assert.strictEqual(instr.lamports, BigInt(500000));
      }
    });

    it("should decode Withdraw instruction", () => {
      // Withdraw with 200000 lamports
      const data = new Uint8Array([
        4, 0, 0, 0, // discriminator = 4 (Withdraw)
        64, 13, 3, 0, 0, 0, 0, 0, // lamports = 200000
      ]);

      const instr = decodeStakeInstruction(data);

      assert.strictEqual(instr.type, "Withdraw");
      if (instr.type === "Withdraw") {
        assert.strictEqual(instr.lamports, BigInt(200000));
      }
    });

    it("should decode Merge instruction", () => {
      const data = new Uint8Array([7, 0, 0, 0]); // discriminator = 7

      const instr = decodeStakeInstruction(data);
      assert.strictEqual(instr.type, "Merge");
    });

    it("should throw on invalid Stake instruction data", () => {
      const invalidData = new Uint8Array([255, 255, 255, 255]);
      assert.throws(() => decodeStakeInstruction(invalidData), /Failed to decode/);
    });
  });

  describe("ComputeBudget Instruction Decoder", () => {
    it("should decode SetComputeUnitLimit instruction", () => {
      // SetComputeUnitLimit with 1000000 units
      const data = new Uint8Array([
        2, // discriminator = 2
        64, 66, 15, 0, // units = 1000000 (u32)
      ]);

      const instr = decodeComputeBudgetInstruction(data);

      assert.strictEqual(instr.type, "SetComputeUnitLimit");
      if (instr.type === "SetComputeUnitLimit") {
        assert.strictEqual(instr.units, 1000000);
      }
    });

    it("should decode SetComputeUnitPrice instruction", () => {
      // SetComputeUnitPrice with 1000 micro-lamports
      const data = new Uint8Array([
        3, // discriminator = 3
        232, 3, 0, 0, 0, 0, 0, 0, // microLamports = 1000 (u64)
      ]);

      const instr = decodeComputeBudgetInstruction(data);

      assert.strictEqual(instr.type, "SetComputeUnitPrice");
      if (instr.type === "SetComputeUnitPrice") {
        assert.strictEqual(instr.microLamports, BigInt(1000));
      }
    });

    it("should throw on invalid ComputeBudget instruction data", () => {
      const invalidData = new Uint8Array([255, 255, 255, 255]);
      assert.throws(
        () => decodeComputeBudgetInstruction(invalidData),
        /Failed to decode/
      );
    });
  });

  describe("Integration with Transaction", () => {
    it("should decode System Transfer from real transaction", () => {
      // This is a real SOL transfer transaction
      const TEST_TX_BASE64 =
        "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDFVMqpim7tqEi2XL8R6KKkP0DYJvY3eiRXLlL1P9EjYgXKQC+k0FKnqyC4AZGJR7OhJXfpPP3NHOhS8t/6G7bLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/1c7Oaj3RbyLIjU0/ZPpsmVfVUWAzc8g36fK5g6A0JoBAgIAAQwCAAAAoIYBAAAAAAA=";

      const tx = Transaction.fromBase64(TEST_TX_BASE64);
      const instr = tx.instructionAt(0);

      assert.ok(instr);
      assert.strictEqual(instr.programId, SYSTEM_PROGRAM_ID);
      assert.ok(isSystemProgram(instr.programId));

      // Decode the instruction data
      const decoded = decodeSystemInstruction(instr.data);
      assert.strictEqual(decoded.type, "Transfer");
      if (decoded.type === "Transfer") {
        assert.strictEqual(decoded.lamports, BigInt(100000));
      }
    });
  });
});
