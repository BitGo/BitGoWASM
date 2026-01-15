import * as assert from "assert";
import {
  SystemInstruction,
  StakeInstruction,
  ComputeBudgetInstruction,
  Transaction,
} from "../js/index.js";

describe("SystemInstruction", () => {
  describe("program ID", () => {
    it("should have correct program ID", () => {
      assert.strictEqual(SystemInstruction.PROGRAM_ID, "11111111111111111111111111111111");
    });

    it("should identify System program", () => {
      assert.strictEqual(
        SystemInstruction.isSystemProgram("11111111111111111111111111111111"),
        true,
      );
      assert.strictEqual(
        SystemInstruction.isSystemProgram("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
        false,
      );
    });
  });

  describe("decode", () => {
    it("should decode Transfer instruction", () => {
      // Transfer 100000 lamports
      const data = new Uint8Array([
        2,
        0,
        0,
        0, // discriminator = 2 (Transfer)
        160,
        134,
        1,
        0,
        0,
        0,
        0,
        0, // lamports = 100000
      ]);

      const decoded = SystemInstruction.decode(data);
      assert.strictEqual(decoded.type, "Transfer");
      if (decoded.type === "Transfer") {
        assert.strictEqual(decoded.lamports, 100000n);
      }
    });

    it("should decode AdvanceNonceAccount instruction", () => {
      const data = new Uint8Array([4, 0, 0, 0]); // discriminator = 4

      const decoded = SystemInstruction.decode(data);
      assert.strictEqual(decoded.type, "AdvanceNonceAccount");
    });

    it("should decode CreateAccount instruction", () => {
      // CreateAccount with 1 SOL (1000000000 lamports), 165 bytes space
      const owner = new Uint8Array(32).fill(1); // dummy owner
      const data = new Uint8Array([
        0,
        0,
        0,
        0, // discriminator = 0 (CreateAccount)
        0,
        202,
        154,
        59,
        0,
        0,
        0,
        0, // lamports = 1000000000
        165,
        0,
        0,
        0,
        0,
        0,
        0,
        0, // space = 165
        ...owner, // owner pubkey
      ]);

      const decoded = SystemInstruction.decode(data);
      assert.strictEqual(decoded.type, "CreateAccount");
      if (decoded.type === "CreateAccount") {
        assert.strictEqual(decoded.lamports, 1000000000n);
        assert.strictEqual(decoded.space, 165n);
        assert.ok(decoded.owner.length > 0);
      }
    });

    it("should decode Allocate instruction", () => {
      const data = new Uint8Array([
        8,
        0,
        0,
        0, // discriminator = 8 (Allocate)
        0,
        16,
        0,
        0,
        0,
        0,
        0,
        0, // space = 4096
      ]);

      const decoded = SystemInstruction.decode(data);
      assert.strictEqual(decoded.type, "Allocate");
      if (decoded.type === "Allocate") {
        assert.strictEqual(decoded.space, 4096n);
      }
    });

    it("should throw on invalid data", () => {
      const data = new Uint8Array([255, 255, 255, 255]); // invalid discriminator
      assert.throws(() => SystemInstruction.decode(data), /Unknown System instruction/);
    });

    it("should throw on truncated data", () => {
      const data = new Uint8Array([2, 0]); // Transfer but too short
      assert.throws(() => SystemInstruction.decode(data));
    });
  });
});

describe("StakeInstruction", () => {
  describe("program ID", () => {
    it("should have correct program ID", () => {
      assert.strictEqual(
        StakeInstruction.PROGRAM_ID,
        "Stake11111111111111111111111111111111111111",
      );
    });

    it("should identify Stake program", () => {
      assert.strictEqual(
        StakeInstruction.isStakeProgram("Stake11111111111111111111111111111111111111"),
        true,
      );
      assert.strictEqual(
        StakeInstruction.isStakeProgram("11111111111111111111111111111111"),
        false,
      );
    });
  });

  describe("decode", () => {
    it("should decode DelegateStake instruction", () => {
      const data = new Uint8Array([2, 0, 0, 0]); // discriminator = 2

      const decoded = StakeInstruction.decode(data);
      assert.strictEqual(decoded.type, "DelegateStake");
    });

    it("should decode Deactivate instruction", () => {
      const data = new Uint8Array([5, 0, 0, 0]); // discriminator = 5

      const decoded = StakeInstruction.decode(data);
      assert.strictEqual(decoded.type, "Deactivate");
    });

    it("should decode Withdraw instruction", () => {
      const data = new Uint8Array([
        4,
        0,
        0,
        0, // discriminator = 4 (Withdraw)
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0, // lamports = 4294967296
      ]);

      const decoded = StakeInstruction.decode(data);
      assert.strictEqual(decoded.type, "Withdraw");
      if (decoded.type === "Withdraw") {
        assert.strictEqual(decoded.lamports, 4294967296n);
      }
    });

    it("should decode Split instruction", () => {
      const data = new Uint8Array([
        3,
        0,
        0,
        0, // discriminator = 3 (Split)
        128,
        150,
        152,
        0,
        0,
        0,
        0,
        0, // lamports = 10000000
      ]);

      const decoded = StakeInstruction.decode(data);
      assert.strictEqual(decoded.type, "Split");
      if (decoded.type === "Split") {
        assert.strictEqual(decoded.lamports, 10000000n);
      }
    });

    it("should decode Merge instruction", () => {
      const data = new Uint8Array([7, 0, 0, 0]); // discriminator = 7

      const decoded = StakeInstruction.decode(data);
      assert.strictEqual(decoded.type, "Merge");
    });

    it("should decode Authorize instruction", () => {
      const newAuthority = new Uint8Array(32).fill(2);
      const data = new Uint8Array([
        1,
        0,
        0,
        0, // discriminator = 1 (Authorize)
        ...newAuthority, // new authority pubkey
        0,
        0,
        0,
        0, // stake_authorize = 0 (Staker)
      ]);

      const decoded = StakeInstruction.decode(data);
      assert.strictEqual(decoded.type, "Authorize");
      if (decoded.type === "Authorize") {
        assert.strictEqual(decoded.stakeAuthorize, "Staker");
        assert.ok(decoded.newAuthority.length > 0);
      }
    });

    it("should throw on invalid discriminator", () => {
      const data = new Uint8Array([255, 255, 255, 255]);
      assert.throws(() => StakeInstruction.decode(data), /Unknown Stake instruction/);
    });
  });
});

describe("ComputeBudgetInstruction", () => {
  describe("program ID", () => {
    it("should have correct program ID", () => {
      assert.strictEqual(
        ComputeBudgetInstruction.PROGRAM_ID,
        "ComputeBudget111111111111111111111111111111",
      );
    });

    it("should identify ComputeBudget program", () => {
      assert.strictEqual(
        ComputeBudgetInstruction.isComputeBudgetProgram(
          "ComputeBudget111111111111111111111111111111",
        ),
        true,
      );
      assert.strictEqual(
        ComputeBudgetInstruction.isComputeBudgetProgram("11111111111111111111111111111111"),
        false,
      );
    });
  });

  describe("decode", () => {
    it("should decode SetComputeUnitLimit instruction", () => {
      const data = new Uint8Array([
        2, // discriminator = 2 (SetComputeUnitLimit)
        64,
        66,
        15,
        0, // units = 1000000
      ]);

      const decoded = ComputeBudgetInstruction.decode(data);
      assert.strictEqual(decoded.type, "SetComputeUnitLimit");
      if (decoded.type === "SetComputeUnitLimit") {
        assert.strictEqual(decoded.units, 1000000);
      }
    });

    it("should decode SetComputeUnitPrice instruction", () => {
      const data = new Uint8Array([
        3, // discriminator = 3 (SetComputeUnitPrice)
        232,
        3,
        0,
        0,
        0,
        0,
        0,
        0, // micro_lamports = 1000
      ]);

      const decoded = ComputeBudgetInstruction.decode(data);
      assert.strictEqual(decoded.type, "SetComputeUnitPrice");
      if (decoded.type === "SetComputeUnitPrice") {
        assert.strictEqual(decoded.microLamports, 1000n);
      }
    });

    it("should throw on invalid discriminator", () => {
      const data = new Uint8Array([255]);
      assert.throws(
        () => ComputeBudgetInstruction.decode(data),
        /Unknown ComputeBudget instruction/,
      );
    });

    it("should throw on empty data", () => {
      const data = new Uint8Array([]);
      assert.throws(() => ComputeBudgetInstruction.decode(data));
    });
  });
});

describe("Integration: Transaction + Instruction Decoding", () => {
  // Real SOL transfer transaction
  const TEST_TX_BASE64 =
    "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDFVMqpim7tqEi2XL8R6KKkP0DYJvY3eiRXLlL1P9EjYgXKQC+k0FKnqyC4AZGJR7OhJXfpPP3NHOhS8t/6G7bLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/1c7Oaj3RbyLIjU0/ZPpsmVfVUWAzc8g36fK5g6A0JoBAgIAAQwCAAAAoIYBAAAAAAA=";

  it("should decode Transfer instruction from real transaction", () => {
    const tx = Transaction.fromBase64(TEST_TX_BASE64);
    const instr = tx.instructionAt(0);

    assert.ok(instr);
    assert.strictEqual(instr.programId, "11111111111111111111111111111111");
    assert.ok(SystemInstruction.isSystemProgram(instr.programId));

    const decoded = SystemInstruction.decode(instr.data);
    assert.strictEqual(decoded.type, "Transfer");
    if (decoded.type === "Transfer") {
      assert.strictEqual(decoded.lamports, 100000n);
    }
  });

  it("should handle transaction with multiple instruction types", () => {
    const tx = Transaction.fromBase64(TEST_TX_BASE64);

    for (let i = 0; i < tx.numInstructions; i++) {
      const instr = tx.instructionAt(i);
      if (!instr) continue;

      if (SystemInstruction.isSystemProgram(instr.programId)) {
        const decoded = SystemInstruction.decode(instr.data);
        assert.ok(decoded.type);
      } else if (StakeInstruction.isStakeProgram(instr.programId)) {
        const decoded = StakeInstruction.decode(instr.data);
        assert.ok(decoded.type);
      } else if (ComputeBudgetInstruction.isComputeBudgetProgram(instr.programId)) {
        const decoded = ComputeBudgetInstruction.decode(instr.data);
        assert.ok(decoded.type);
      }
    }
  });
});
