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

  describe("dkg", function () {
    it("performs round 0", function () {
      for (let i = 0; i < 3; i++) {
        mps.dkg_round0_process(
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
        mps.dkg_round0_process(
          i,
          keypairs[i].privateKey,
          otherIndices[i].map((i) => keypairs[i].publicKey),
          crypto.randomBytes(32),
        ),
      );
    });

    it("performs round 1", function () {
      for (let i = 0; i < 3; i++) {
        mps.dkg_round1_process(
          otherIndices[i].map((i) => results1[i].msg),
          results1[i].state,
        );
      }
    });

    let results2: Array<mps.MsgState>;

    before("performs round 1", function () {
      results2 = [0, 1, 2].map((i) =>
        mps.dkg_round1_process(
          otherIndices[i].map((i) => results1[i].msg),
          results1[i].state,
        ),
      );
    });

    it("performs round 2", function () {
      const results3 = [0, 1, 2].map((i) =>
        mps.dkg_round2_process(
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
            mps.dkg_round0_process(
              "255",
              Buffer.alloc(32),
              [Buffer.alloc(32), Buffer.alloc(32)],
              crypto.randomBytes(32),
            ),
          );
        });

        it("does not panic on bad encryption key", function () {
          shouldThrow(() =>
            mps.dkg_round0_process(
              0,
              "encryption key",
              [Buffer.alloc(32), Buffer.alloc(32)],
              crypto.randomBytes(32),
            ),
          );
          shouldThrow(() =>
            mps.dkg_round0_process(
              0,
              Buffer.alloc(0),
              [Buffer.alloc(32), Buffer.alloc(32)],
              crypto.randomBytes(32),
            ),
          );
        });

        it("does not panic on bad decryption keys", function () {
          shouldThrow(() =>
            mps.dkg_round0_process(0, Buffer.alloc(0), "decryption keys", crypto.randomBytes(32)),
          );
          shouldThrow(() => mps.dkg_round0_process(0, Buffer.alloc(0), [], crypto.randomBytes(32)));
          shouldThrow(() =>
            mps.dkg_round0_process(0, Buffer.alloc(0), ["decryption key"], crypto.randomBytes(32)),
          );
          shouldThrow(() =>
            mps.dkg_round0_process(0, Buffer.alloc(0), [Buffer.alloc(0)], crypto.randomBytes(32)),
          );
          shouldThrow(() =>
            mps.dkg_round0_process(
              0,
              Buffer.alloc(0),
              [Buffer.alloc(32), Buffer.alloc(0)],
              crypto.randomBytes(32),
            ),
          );
        });

        it("does not panic on bad seed", function () {
          shouldThrow(() =>
            mps.dkg_round0_process(
              0,
              Buffer.alloc(0),
              [Buffer.alloc(32), Buffer.alloc(32)],
              "seed",
            ),
          );
          shouldThrow(() =>
            mps.dkg_round0_process(
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
          shouldThrow(() => mps.dkg_round1_process("messages", Buffer.alloc(1224)));
          shouldThrow(() => mps.dkg_round1_process([], Buffer.alloc(1224)));
          shouldThrow(() => mps.dkg_round1_process(["message"], Buffer.alloc(1224)));
          shouldThrow(() => mps.dkg_round1_process([Buffer.alloc(0), Buffer.alloc(1224)]));
        });

        it("does not panic on bad state", function () {
          shouldThrow(() => mps.dkg_round1_process([Buffer.alloc(65), Buffer.alloc(65)], "state"));
          shouldThrow(() =>
            mps.dkg_round1_process([Buffer.alloc(65), Buffer.alloc(65)], Buffer.alloc(0)),
          );
        });
      });

      describe("round2_process", function () {
        it("does not panic on bad messages", function () {
          shouldThrow(() => mps.dkg_round2_process("messages", Buffer.alloc(1224)));
          shouldThrow(() => mps.dkg_round2_process([], Buffer.alloc(1224)));
          shouldThrow(() => mps.dkg_round2_process(["message"], Buffer.alloc(1224)));
          shouldThrow(() => mps.dkg_round2_process([Buffer.alloc(0), Buffer.alloc(1224)]));
        });

        it("does not panic on bad state", function () {
          shouldThrow(() => mps.dkg_round2_process([Buffer.alloc(65), Buffer.alloc(65)], "state"));
          shouldThrow(() =>
            mps.dkg_round2_process([Buffer.alloc(65), Buffer.alloc(65)], Buffer.alloc(0)),
          );
        });
      });
    });
  });

  describe("dsg", function () {
    const otherIndex = [1, 0];
    let shares: Array<mps.Share>;

    before("performs dkg", function () {
      const results1 = [0, 1, 2].map((i) =>
        mps.dkg_round0_process(
          i,
          keypairs[i].privateKey,
          otherIndices[i].map((i) => keypairs[i].publicKey),
          crypto.randomBytes(32),
        ),
      );
      const results2 = [0, 1, 2].map((i) =>
        mps.dkg_round1_process(
          otherIndices[i].map((i) => results1[i].msg),
          results1[i].state,
        ),
      );
      shares = [0, 1, 2].map((i) =>
        mps.dkg_round2_process(
          otherIndices[i].map((i) => results2[i].msg),
          results2[i].state,
        ),
      );
    });

    const message = Buffer.from(
      "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
    );

    it("performs round 0", function () {
      for (const i of [0, 2]) {
        mps.dsg_round0_process(shares[i].share, "m", message);
      }
    });

    let results1: Array<mps.MsgState>;

    before("performs round 0", function () {
      results1 = [0, 2].map((i) => mps.dsg_round0_process(shares[i].share, "m", message));
    });

    it("performs round 1", function () {
      for (let i = 0; i < 2; i++) {
        mps.dsg_round1_process(results1[otherIndex[i]].msg, results1[i].state);
      }
    });

    let results2: Array<mps.MsgState>;

    before("performs round 1", function () {
      results2 = [0, 1].map((i) =>
        mps.dsg_round1_process(results1[otherIndex[i]].msg, results1[i].state),
      );
    });

    it("performs round 2", function () {
      for (let i = 0; i < 2; i++) {
        mps.dsg_round2_process(results2[otherIndex[i]].msg, results2[i].state);
      }
    });

    let results3: Array<mps.MsgState>;

    before("performs round 2", function () {
      results3 = [0, 1].map((i) =>
        mps.dsg_round2_process(results2[otherIndex[i]].msg, results2[i].state),
      );
    });

    it("performs round 3", function () {
      const signatures = [0, 1].map((i) =>
        mps.dsg_round3_process(results3[otherIndex[i]].msg, results3[i].state),
      );
      assert(sodium.crypto_sign_verify_detached(signatures[0], message, shares[0].pk));
      assert(sodium.crypto_sign_verify_detached(signatures[1], message, shares[2].pk));
    });
  });
});
