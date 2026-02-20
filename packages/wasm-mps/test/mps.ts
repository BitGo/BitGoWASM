import assert from "assert";
import crypto from "crypto";
import * as mps from "../js";
import sodium from "libsodium-wrappers-sumo";

await sodium.ready;

describe("mps", function () {
  const otherIndices = [
    [1, 2],
    [0, 2],
    [0, 1],
  ];
  const keypairs: Array<{ privateKey: Uint8Array; publicKey: Uint8Array }> = [];

  before("generates keypairs", function () {
    for (let i = 0; i < 3; i++) {
      keypairs.push(sodium.crypto_box_keypair());
    }
  });

  it("performs round 0", function () {
    for (let i = 0; i < 3; i++) {
      mps.round0_process(
        i,
        keypairs[i].privateKey,
        otherIndices[i].map((i) => keypairs[i].publicKey),
        crypto.randomBytes(32),
      );
    }
  });

  let results1: Array<mps.MsgState>;

  before("performs round 0", function () {
    results1 = [0, 1, 2].map((i) =>
      mps.round0_process(
        i,
        keypairs[i].privateKey,
        otherIndices[i].map((i) => keypairs[i].publicKey),
        crypto.randomBytes(32),
      ),
    );
  });

  it("performs round 1", function () {
    for (let i = 0; i < 3; i++) {
      mps.round1_process(
        otherIndices[i].map((i) => results1[i].msg),
        results1[i].state,
      );
    }
  });

  let results2: Array<mps.MsgState>;

  before("performs round 1", function () {
    results2 = [0, 1, 2].map((i) =>
      mps.round1_process(
        otherIndices[i].map((i) => results1[i].msg),
        results1[i].state,
      ),
    );
  });

  it("performs round 2", function () {
    const results3 = [0, 1, 2].map((i) =>
      mps.round2_process(
        otherIndices[i].map((i) => results2[i].msg),
        results2[i].state,
      ),
    );
    for (let i = 0; i < 2; i++) {
      assert.ok(results3[i].pk.every((value, index) => value === results3[2].pk[index]));
    }
  });

  describe("input handling", function () {
    function shouldThrow(fn: () => unknown): unknown {
      try {
        fn();
      } catch (e: unknown) {
        return e;
      }
      throw new Error("Expected function to throw an error");
    }

    describe("round0_process", function () {
      it("does not panic on bad party size", function () {
        shouldThrow(() =>
          mps.round0_process(
            "255",
            Buffer.alloc(32),
            [Buffer.alloc(32), Buffer.alloc(32)],
            crypto.randomBytes(32),
          ),
        );
      });

      it("does not panic on bad encryption key", function () {
        shouldThrow(() =>
          mps.round0_process(
            0,
            "encryption key",
            [Buffer.alloc(32), Buffer.alloc(32)],
            crypto.randomBytes(32),
          ),
        );
        shouldThrow(() =>
          mps.round0_process(
            0,
            Buffer.alloc(0),
            [Buffer.alloc(32), Buffer.alloc(32)],
            crypto.randomBytes(32),
          ),
        );
      });

      it("does not panic on bad decryption keys", function () {
        shouldThrow(() =>
          mps.round0_process(0, Buffer.alloc(0), "decryption keys", crypto.randomBytes(32)),
        );
        shouldThrow(() => mps.round0_process(0, Buffer.alloc(0), [], crypto.randomBytes(32)));
        shouldThrow(() =>
          mps.round0_process(0, Buffer.alloc(0), ["decryption key"], crypto.randomBytes(32)),
        );
        shouldThrow(() =>
          mps.round0_process(0, Buffer.alloc(0), [Buffer.alloc(0)], crypto.randomBytes(32)),
        );
        shouldThrow(() =>
          mps.round0_process(
            0,
            Buffer.alloc(0),
            [Buffer.alloc(32), Buffer.alloc(0)],
            crypto.randomBytes(32),
          ),
        );
      });

      it("does not panic on bad seed", function () {
        shouldThrow(() =>
          mps.round0_process(0, Buffer.alloc(0), [Buffer.alloc(32), Buffer.alloc(32)], "seed"),
        );
        shouldThrow(() =>
          mps.round0_process(
            0,
            Buffer.alloc(0),
            [Buffer.alloc(32), Buffer.alloc(32)],
            Buffer.alloc(0),
          ),
        );
      });
    });

    describe("round1_process", function () {
      it("does not panic on bad messages", function () {
        shouldThrow(() => mps.round1_process("messages", Buffer.alloc(1224)));
        shouldThrow(() => mps.round1_process([], Buffer.alloc(1224)));
        shouldThrow(() => mps.round1_process(["message"], Buffer.alloc(1224)));
        shouldThrow(() => mps.round1_process([Buffer.alloc(0), Buffer.alloc(1224)]));
      });

      it("does not panic on bad state", function () {
        shouldThrow(() => mps.round1_process([Buffer.alloc(65), Buffer.alloc(65)], "state"));
        shouldThrow(() =>
          mps.round1_process([Buffer.alloc(65), Buffer.alloc(65)], Buffer.alloc(0)),
        );
      });
    });

    describe("round2_process", function () {
      it("does not panic on bad messages", function () {
        shouldThrow(() => mps.round2_process("messages", Buffer.alloc(1224)));
        shouldThrow(() => mps.round2_process([], Buffer.alloc(1224)));
        shouldThrow(() => mps.round2_process(["message"], Buffer.alloc(1224)));
        shouldThrow(() => mps.round2_process([Buffer.alloc(0), Buffer.alloc(1224)]));
      });

      it("does not panic on bad state", function () {
        shouldThrow(() => mps.round2_process([Buffer.alloc(65), Buffer.alloc(65)], "state"));
        shouldThrow(() =>
          mps.round2_process([Buffer.alloc(65), Buffer.alloc(65)], Buffer.alloc(0)),
        );
      });
    });
  });
});
