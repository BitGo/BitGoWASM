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

  function shouldThrow(fn: () => unknown): unknown {
    try {
      fn();
    } catch (e: unknown) {
      return e;
    }
    throw new Error("Expected function to throw an error");
  }

  before("generates keypairs", function () {
    for (let i = 0; i < 3; i++) {
      keypairs.push(sodium.crypto_box_keypair());
    }
  });

  describe("dkg", function () {
    it("performs round 0", function () {
      const messagePrefix = Buffer.from("mps-ed25519-dkg-round1-message$");
      const statePrefix = Buffer.from("mps-ed25519-dkg-round1-state$");
      for (let i = 0; i < keypairs.length; i++) {
        const result = mps.ed25519_dkg_round0_process(
          i,
          keypairs[i].privateKey,
          otherIndices[i].map((i) => keypairs[i].publicKey),
          crypto.randomBytes(32),
        );
        assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
        assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
      }
    });

    let results1: Array<mps.MsgState>;

    before("performs round 0", function () {
      results1 = [0, 1, 2].map((i) =>
        mps.ed25519_dkg_round0_process(
          i,
          keypairs[i].privateKey,
          otherIndices[i].map((i) => keypairs[i].publicKey),
          crypto.randomBytes(32),
        ),
      );
    });

    it("performs round 1", function () {
      const messagePrefix = Buffer.from("mps-ed25519-dkg-round2-message$");
      const statePrefix = Buffer.from("mps-ed25519-dkg-round2-state$");
      for (let i = 0; i < results1.length; i++) {
        const result = mps.ed25519_dkg_round1_process(
          otherIndices[i].map((i) => results1[i].msg),
          results1[i].state,
        );
        assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
        assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
      }
    });

    it("fails to perform round 1 with invalid message prefix", function () {
      const messagePrefix = Buffer.from("mps-ed25519-dkg-round1-message$");
      for (let i = 0; i < results1.length; i++) {
        shouldThrow(() =>
          mps.ed25519_dkg_round1_process(
            otherIndices[i].map((i) => Buffer.from(results1[i].msg).slice(messagePrefix.length)),
            results1[i].state,
          ),
        );
        shouldThrow(() =>
          mps.ed25519_dkg_round1_process(
            otherIndices[i].map((i) =>
              Buffer.concat([
                Buffer.from("msg-ed25519-dkg-round2-message$"),
                Buffer.from(results1[i].msg).slice(messagePrefix.length),
              ]),
            ),
            results1[i].state,
          ),
        );
      }
    });

    it("fails to perform round 1 with invalid state prefix", function () {
      const statePrefix = Buffer.from("mps-ed25519-dkg-round1-state$");
      for (let i = 0; i < results1.length; i++) {
        shouldThrow(() =>
          mps.ed25519_dkg_round1_process(
            otherIndices[i].map((i) => results1[i].msg),
            Buffer.from(results1[i].state).slice(statePrefix.length),
          ),
        );
        shouldThrow(() =>
          mps.ed25519_dkg_round1_process(
            otherIndices[i].map((i) => results1[i].msg),
            Buffer.concat([
              Buffer.from("mps-ed25519-dkg-round2-state$"),
              Buffer.from(results1[i].state).slice(statePrefix.length),
            ]),
          ),
        );
      }
    });

    let results2: Array<mps.MsgState>;

    before("performs round 1", function () {
      results2 = [0, 1, 2].map((i) =>
        mps.ed25519_dkg_round1_process(
          otherIndices[i].map((i) => results1[i].msg),
          results1[i].state,
        ),
      );
    });

    it("performs round 2", function () {
      const results3 = [0, 1, 2].map((i) =>
        mps.ed25519_dkg_round2_process(
          otherIndices[i].map((i) => results2[i].msg),
          results2[i].state,
        ),
      );
      for (let i = 0; i < 2; i++) {
        assert.ok(results3[i].pk.every((value, index) => value === results3[2].pk[index]));
        assert.ok(
          results3[i].chaincode.every((value, index) => value === results3[2].chaincode[index]),
        );
      }
    });

    describe("input handling", function () {
      describe("round0_process", function () {
        it("does not panic on bad party size", function () {
          shouldThrow(() =>
            mps.ed25519_dkg_round0_process(
              "255",
              Buffer.alloc(32),
              [Buffer.alloc(32), Buffer.alloc(32)],
              crypto.randomBytes(32),
            ),
          );
        });

        it("does not panic on bad encryption key", function () {
          shouldThrow(() =>
            mps.ed25519_dkg_round0_process(
              0,
              "encryption key",
              [Buffer.alloc(32), Buffer.alloc(32)],
              crypto.randomBytes(32),
            ),
          );
          shouldThrow(() =>
            mps.ed25519_dkg_round0_process(
              0,
              Buffer.alloc(0),
              [Buffer.alloc(32), Buffer.alloc(32)],
              crypto.randomBytes(32),
            ),
          );
        });

        it("does not panic on bad decryption keys", function () {
          shouldThrow(() =>
            mps.ed25519_dkg_round0_process(
              0,
              Buffer.alloc(0),
              "decryption keys",
              crypto.randomBytes(32),
            ),
          );
          shouldThrow(() =>
            mps.ed25519_dkg_round0_process(0, Buffer.alloc(0), [], crypto.randomBytes(32)),
          );
          shouldThrow(() =>
            mps.ed25519_dkg_round0_process(
              0,
              Buffer.alloc(0),
              ["decryption key"],
              crypto.randomBytes(32),
            ),
          );
          shouldThrow(() =>
            mps.ed25519_dkg_round0_process(
              0,
              Buffer.alloc(0),
              [Buffer.alloc(0)],
              crypto.randomBytes(32),
            ),
          );
          shouldThrow(() =>
            mps.ed25519_dkg_round0_process(
              0,
              Buffer.alloc(0),
              [Buffer.alloc(32), Buffer.alloc(0)],
              crypto.randomBytes(32),
            ),
          );
        });

        it("does not panic on bad seed", function () {
          shouldThrow(() =>
            mps.ed25519_dkg_round0_process(
              0,
              Buffer.alloc(0),
              [Buffer.alloc(32), Buffer.alloc(32)],
              "seed",
            ),
          );
          shouldThrow(() =>
            mps.ed25519_dkg_round0_process(
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
          shouldThrow(() => mps.ed25519_dkg_round1_process("messages", Buffer.alloc(1224)));
          shouldThrow(() => mps.ed25519_dkg_round1_process([], Buffer.alloc(1224)));
          shouldThrow(() => mps.ed25519_dkg_round1_process(["message"], Buffer.alloc(1224)));
          shouldThrow(() => mps.ed25519_dkg_round1_process([Buffer.alloc(0), Buffer.alloc(1224)]));
        });

        it("does not panic on bad state", function () {
          shouldThrow(() =>
            mps.ed25519_dkg_round1_process([Buffer.alloc(65), Buffer.alloc(65)], "state"),
          );
          shouldThrow(() =>
            mps.ed25519_dkg_round1_process([Buffer.alloc(65), Buffer.alloc(65)], Buffer.alloc(0)),
          );
        });
      });

      describe("round2_process", function () {
        it("does not panic on bad messages", function () {
          shouldThrow(() => mps.ed25519_dkg_round2_process("messages", Buffer.alloc(1224)));
          shouldThrow(() => mps.ed25519_dkg_round2_process([], Buffer.alloc(1224)));
          shouldThrow(() => mps.ed25519_dkg_round2_process(["message"], Buffer.alloc(1224)));
          shouldThrow(() => mps.ed25519_dkg_round2_process([Buffer.alloc(0), Buffer.alloc(1224)]));
        });

        it("does not panic on bad state", function () {
          shouldThrow(() =>
            mps.ed25519_dkg_round2_process([Buffer.alloc(65), Buffer.alloc(65)], "state"),
          );
          shouldThrow(() =>
            mps.ed25519_dkg_round2_process([Buffer.alloc(65), Buffer.alloc(65)], Buffer.alloc(0)),
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
        mps.ed25519_dkg_round0_process(
          i,
          keypairs[i].privateKey,
          otherIndices[i].map((i) => keypairs[i].publicKey),
          crypto.randomBytes(32),
        ),
      );
      const results2 = [0, 1, 2].map((i) =>
        mps.ed25519_dkg_round1_process(
          otherIndices[i].map((i) => results1[i].msg),
          results1[i].state,
        ),
      );
      shares = [0, 1, 2].map((i) =>
        mps.ed25519_dkg_round2_process(
          otherIndices[i].map((i) => results2[i].msg),
          results2[i].state,
        ),
      );
    });

    const message = Buffer.from(
      "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
    );

    it("performs round 0", function () {
      const messagePrefix = Buffer.from("mps-ed25519-dsg-round1-message$");
      const statePrefix = Buffer.from("mps-ed25519-dsg-round1-state$");
      for (const i of [0, 2]) {
        const result = mps.ed25519_dsg_round0_process(shares[i].share, "m", message);
        assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
        assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
      }
    });

    let results1: Array<mps.MsgState>;

    before("performs round 0", function () {
      results1 = [0, 2].map((i) => mps.ed25519_dsg_round0_process(shares[i].share, "m", message));
    });

    it("performs round 1", function () {
      const messagePrefix = Buffer.from("mps-ed25519-dsg-round2-message$");
      const statePrefix = Buffer.from("mps-ed25519-dsg-round2-state$");
      for (let i = 0; i < results1.length; i++) {
        const result = mps.ed25519_dsg_round1_process(
          results1[otherIndex[i]].msg,
          results1[i].state,
        );
        assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
        assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
      }
    });

    it("fails to perform round 1 with invalid message prefix", function () {
      const messagePrefix = Buffer.from("mps-ed25519-dsg-round1-message$");
      for (let i = 0; i < results1.length; i++) {
        shouldThrow(() =>
          mps.ed25519_dsg_round1_process(
            Buffer.from(results1[otherIndex[i]].msg).slice(messagePrefix.length),
            results1[i].state,
          ),
        );
        shouldThrow(() =>
          mps.ed25519_dsg_round1_process(
            Buffer.concat([
              Buffer.from("mps-ed25519-dsg-round2-message$"),
              Buffer.from(results1[otherIndex[i]].msg).slice(messagePrefix.length),
            ]),
            results1[i].state,
          ),
        );
      }
    });

    it("fails to perform round 1 with invalid state prefix", function () {
      const statePrefix = Buffer.from("mps-ed25519-dsg-round1-state$");
      for (let i = 0; i < results1.length; i++) {
        shouldThrow(() =>
          mps.ed25519_dsg_round1_process(
            results1[otherIndex[i]].msg,
            Buffer.from(results1[i].state).slice(statePrefix.length),
          ),
        );
        shouldThrow(() =>
          mps.ed25519_dsg_round1_process(
            results1[otherIndex[i]].msg,
            Buffer.concat([Buffer.from("mps-ed25519-dsg-round2-state$"), results1[i].state]),
          ),
        );
      }
    });

    let results2: Array<mps.MsgState>;

    before("performs round 1", function () {
      results2 = [0, 1].map((i) =>
        mps.ed25519_dsg_round1_process(results1[otherIndex[i]].msg, results1[i].state),
      );
    });

    it("performs round 2", function () {
      for (let i = 0; i < results2.length; i++) {
        mps.ed25519_dsg_round2_process(results2[otherIndex[i]].msg, results2[i].state);
      }
    });

    it("fails to perform round 2 with invalid message prefix", function () {
      const messagePrefix = Buffer.from("mps-ed25519-dsg-round2-message$");
      for (let i = 0; i < results2.length; i++) {
        shouldThrow(() =>
          mps.ed25519_dsg_round2_process(
            Buffer.from(results2[otherIndex[i]].msg).slice(messagePrefix.length),
            results2[i].state,
          ),
        );
        shouldThrow(() =>
          mps.ed25519_dsg_round2_process(
            Buffer.concat([
              Buffer.from("mps-ed25519-dsg-round3-message$"),
              Buffer.from(results2[otherIndex[i]].msg).slice(messagePrefix.length),
            ]),
            results2[i].state,
          ),
        );
      }
    });

    it("fails to perform round 2 with invalid state prefix", function () {
      const statePrefix = Buffer.from("mps-ed25519-dsg-round2-state$");
      for (let i = 0; i < results2.length; i++) {
        shouldThrow(() =>
          mps.ed25519_dsg_round2_process(
            results2[otherIndex[i]].msg,
            Buffer.from(results2[i].state).slice(statePrefix.length),
          ),
        );
        shouldThrow(() =>
          mps.ed25519_dsg_round2_process(
            results2[otherIndex[i]].msg,
            Buffer.concat([Buffer.from("mps-ed25519-dsg-round3-state$"), results2[i].state]),
          ),
        );
      }
    });

    let results3: Array<mps.MsgState>;

    before("performs round 2", function () {
      results3 = [0, 1].map((i) =>
        mps.ed25519_dsg_round2_process(results2[otherIndex[i]].msg, results2[i].state),
      );
    });

    it("performs round 3", function () {
      const signatures = [0, 1].map((i) =>
        mps.ed25519_dsg_round3_process(results3[otherIndex[i]].msg, results3[i].state),
      );
      assert(sodium.crypto_sign_verify_detached(signatures[0], message, shares[0].pk));
      assert(sodium.crypto_sign_verify_detached(signatures[1], message, shares[2].pk));
    });

    it("fails to perform round 3 with invalid message prefix", function () {
      const messagePrefix = Buffer.from("mps-ed25519-dsg-round3-message$");
      for (let i = 0; i < results3.length; i++) {
        shouldThrow(() =>
          mps.ed25519_dsg_round3_process(
            Buffer.from(results3[otherIndex[i]].msg).slice(messagePrefix.length),
            results3[i].state,
          ),
        );
        shouldThrow(() =>
          mps.ed25519_dsg_round3_process(
            Buffer.concat([
              Buffer.from("mps-ed25519-dsg-round4-message$"),
              Buffer.from(results3[otherIndex[i]].msg).slice(messagePrefix.length),
            ]),
            results3[i].state,
          ),
        );
      }
    });

    it("fails to perform round 3 with invalid state prefix", function () {
      const statePrefix = Buffer.from("mps-ed25519-dsg-round3-state$");
      for (let i = 0; i < results3.length; i++) {
        shouldThrow(() =>
          mps.ed25519_dsg_round3_process(
            results3[otherIndex[i]].msg,
            Buffer.from(results3[i].state).slice(statePrefix.length),
          ),
        );
        shouldThrow(() =>
          mps.ed25519_dsg_round3_process(
            results3[otherIndex[i]].msg,
            Buffer.concat([Buffer.from("mps-ed25519-dsg-round4-state$"), results3[i].state]),
          ),
        );
      }
    });
  });
});
