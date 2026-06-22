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

  describe("ed25519", function () {
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
              results1[i].msg,
              Buffer.concat([
                "mps-ed25519-dkg-round2-state$",
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

      it("fails to perform round 2 with invalid message prefix", function () {
        const messagePrefix = Buffer.from("mps-ed25519-dkg-round2-message$");
        for (let i = 0; i < results2.length; i++) {
          shouldThrow(() =>
            mps.ed25519_dkg_round2_process(
              otherIndices[i].map((i) => Buffer.from(results2[i].msg).slice(messagePrefix.length)),
              results2[i].state,
            ),
          );
          shouldThrow(() =>
            mps.ed25519_dkg_round2_process(
              otherIndices[i].map((i) =>
                Buffer.concat([
                  Buffer.from("msg-ed25519-dkg-round3-message$"),
                  Buffer.from(results2[i].msg).slice(messagePrefix.length),
                ]),
              ),
              results2[i].state,
            ),
          );
        }
      });

      it("fails to perform round 2 with invalid state prefix", function () {
        const statePrefix = Buffer.from("mps-ed25519-dkg-round2-state$");
        for (let i = 0; i < results2.length; i++) {
          shouldThrow(() =>
            mps.ed25519_dkg_round2_process(
              otherIndices[i].map((i) => results2[i].msg),
              Buffer.from(results2[i].state).slice(statePrefix.length),
            ),
          );
          shouldThrow(() =>
            mps.ed25519_dkg_round2_process(
              results2[i].msg,
              Buffer.concat([
                "mps-ed25519-dkg-round3-state$",
                Buffer.from(results2[i].state).slice(statePrefix.length),
              ]),
            ),
          );
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
            shouldThrow(() =>
              mps.ed25519_dkg_round1_process([Buffer.alloc(0), Buffer.alloc(1224)]),
            );
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
            shouldThrow(() =>
              mps.ed25519_dkg_round2_process([Buffer.alloc(0), Buffer.alloc(1224)]),
            );
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
        const messagePrefix = Buffer.from("mps-ed25519-dsg-round3-message$");
        const statePrefix = Buffer.from("mps-ed25519-dsg-round3-state$");
        for (let i = 0; i < results2.length; i++) {
          const result = mps.ed25519_dsg_round2_process(
            results2[otherIndex[i]].msg,
            results2[i].state,
          );
          assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
          assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
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

  describe("redpallas", function () {
    describe("dkg", function () {
      it("performs round 0", function () {
        const messagePrefix = Buffer.from("mps-redpallas-dkg-round1-message$");
        const statePrefix = Buffer.from("mps-redpallas-dkg-round1-state$");
        for (let i = 0; i < keypairs.length; i++) {
          const result = mps.redpallas_dkg_round0_process(
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
          mps.redpallas_dkg_round0_process(
            i,
            keypairs[i].privateKey,
            otherIndices[i].map((i) => keypairs[i].publicKey),
            crypto.randomBytes(32),
          ),
        );
      });

      it("performs round 1", function () {
        const messagePrefix = Buffer.from("mps-redpallas-dkg-round2-message$");
        const statePrefix = Buffer.from("mps-redpallas-dkg-round2-state$");
        for (let i = 0; i < results1.length; i++) {
          const result = mps.redpallas_dkg_round1_process(
            otherIndices[i].map((i) => results1[i].msg),
            results1[i].state,
          );
          assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
          assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
        }
      });

      it("fails to perform round 1 with invalid message prefix", function () {
        const messagePrefix = Buffer.from("mps-redpallas-dkg-round1-message$");
        for (let i = 0; i < results1.length; i++) {
          shouldThrow(() =>
            mps.redpallas_dkg_round1_process(
              otherIndices[i].map((i) => Buffer.from(results1[i].msg).slice(messagePrefix.length)),
              results1[i].state,
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dkg_round1_process(
              otherIndices[i].map((i) =>
                Buffer.concat([
                  Buffer.from("msg-redpallas-dkg-round2-message$"),
                  Buffer.from(results1[i].msg).slice(messagePrefix.length),
                ]),
              ),
              results1[i].state,
            ),
          );
        }
      });

      it("fails to perform round 1 with invalid state prefix", function () {
        const statePrefix = Buffer.from("mps-redpallas-dkg-round1-state$");
        for (let i = 0; i < results1.length; i++) {
          shouldThrow(() =>
            mps.redpallas_dkg_round1_process(
              otherIndices[i].map((i) => results1[i].msg),
              Buffer.from(results1[i].state).slice(statePrefix.length),
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dkg_round1_process(
              results1[i].msg,
              Buffer.concat([
                "mps-redpallas-dkg-round2-state$",
                Buffer.from(results1[i].state).slice(statePrefix.length),
              ]),
            ),
          );
        }
      });

      let results2: Array<mps.MsgState>;

      before("performs round 1", function () {
        results2 = [0, 1, 2].map((i) =>
          mps.redpallas_dkg_round1_process(
            otherIndices[i].map((i) => results1[i].msg),
            results1[i].state,
          ),
        );
      });

      it("performs round 2", function () {
        const messagePrefix = Buffer.from("mps-redpallas-dkg-derivation-message$");
        const statePrefix = Buffer.from("mps-redpallas-dkg-derivation-state$");
        for (let i = 0; i < results2.length; i++) {
          const result = mps.redpallas_dkg_round2_process(
            otherIndices[i].map((i) => results2[i].msg),
            results2[i].state,
            crypto.randomBytes(32),
          );
          if (result.drv.length) {
            assert(Buffer.from(result.drv).slice(0, messagePrefix.length).equals(messagePrefix));
          }
          assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
          assert.ok(results3[i].pk.every((value, index) => value === results3[2].pk[index]));
        }
      });

      it("fails to perform round 2 with invalid message prefix", function () {
        const messagePrefix = Buffer.from("mps-redpallas-dkg-round2-message$");
        for (let i = 0; i < results1.length; i++) {
          shouldThrow(() =>
            mps.redpallas_dkg_round2_process(
              otherIndices[i].map((i) => Buffer.from(results2[i].msg).slice(messagePrefix.length)),
              results2[i].state,
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dkg_round2_process(
              otherIndices[i].map((i) =>
                Buffer.concat([
                  Buffer.from("msg-redpallas-dkg-round3-message$"),
                  Buffer.from(results1[i].msg).slice(messagePrefix.length),
                ]),
              ),
              results1[i].state,
            ),
          );
        }
      });

      it("fails to perform round 2 with invalid state prefix", function () {
        const statePrefix = Buffer.from("mps-redpallas-dkg-round2-state$");
        for (let i = 0; i < results1.length; i++) {
          shouldThrow(() =>
            mps.redpallas_dkg_round2_process(
              otherIndices[i].map((i) => results1[i].msg),
              Buffer.from(results1[i].state).slice(statePrefix.length),
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dkg_round2_process(
              results1[i].msg,
              Buffer.concat([
                "mps-redpallas-dkg-round2-state$",
                Buffer.from(results1[i].state).slice(statePrefix.length),
              ]),
            ),
          );
        }
      });

      let results3: Array<mps.MsgDerivationInit>;

      before("performs round 2", function () {
        results3 = [0, 1, 2].map((i) =>
          mps.redpallas_dkg_round2_process(
            otherIndices[i].map((i) => results2[i].msg),
            results2[i].state,
            crypto.randomBytes(32),
          ),
        );
      });

      it("runs derivation to completion", function () {
        this.timeout(30000);
        const messagePrefix = Buffer.from("mps-redpallas-dkg-derivation-message$");
        const statePrefix = Buffer.from("mps-redpallas-dkg-derivation-state$");
        let messages: Array<Uint8Array> = results3.map((d) => d.drv);
        const states = results3.map((d) => d.state);
        const derivedKeys: Map<number, mps.MsgDerivation> = new Map();
        for (let round = 0; round < 500 && Array.from(derivedKeys.keys()).length < 3; round++) {
          for (let party = 0; party < 3; party++) {
            const result = mps.redpallas_derivation_process(messages, states[party]);
            if (result.messages.length) {
              assert(
                Buffer.from(result.messages).slice(0, messagePrefix.length).equals(messagePrefix),
              );
            }
            assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
            messages = [result.messages];
            states[party] = result.state;
            if (result.done) {
              derivedKeys.set(party, result);
            }
          }
        }
        assert.ok(
          Array.from(derivedKeys.keys()).length == 3,
          "derivation did not complete within 500 rounds",
        );
        for (let i = 0; i < 3; i++) {
          const k = derivedKeys.get(i);
          assert.equal(k.ask.length, 32);
          assert.equal(k.nk.length, 32);
          assert.equal(k.rivk.length, 32);
          assert.equal(k.internal_ivk.length, 64);
          assert.equal(k.external_ivk.length, 64);
        }
        const hsmKeys = derivedKeys.get(2);
        for (let i = 0; i < 2; i++) {
          const k = derivedKeys.get(i);
          assert.deepStrictEqual(k.ask, hsmKeys.ask);
          assert.deepStrictEqual(k.nk, hsmKeys.nk);
          assert.deepStrictEqual(k.rivk, hsmKeys.rivk);
          assert.deepStrictEqual(k.internal_ivk, hsmKeys.internal_ivk);
          assert.deepStrictEqual(k.external_ivk, hsmKeys.external_ivk);
        }
        for (let i = 0; i < 3; i++) {
          const k = derivedKeys.get(i);
          assert(!k.ask.every((b) => b === 0));
          assert(!k.nk.every((b) => b === 0));
          assert(!k.rivk.every((b) => b === 0));
          assert(!k.internal_ivk.every((b) => b === 0));
          assert(!k.external_ivk.every((b) => b === 0));
        }
        for (let i = 0; i < 3; i++) {
          const k = derivedKeys.get(i);
          const ivks = mps.redpallas_fvk_to_ivks(k.ask, k.nk, k.rivk);
          assert.deepStrictEqual(ivks.internal_ivk, k.internal_ivk);
          assert.deepStrictEqual(ivks.external_ivk, k.external_ivk);
        }
      });
    });

    describe("dsg", function () {
      const otherIndex = [1, 0];
      let shares: Array<mps.Share>;

      before("performs dkg", function () {
        const results1 = [0, 1, 2].map((i) =>
          mps.redpallas_dkg_round0_process(
            i,
            keypairs[i].privateKey,
            otherIndices[i].map((j) => keypairs[j].publicKey),
            crypto.randomBytes(32),
          ),
        );
        const results2 = [0, 1, 2].map((i) =>
          mps.redpallas_dkg_round1_process(
            otherIndices[i].map((j) => results1[j].msg),
            results1[i].state,
          ),
        );
        shares = [0, 1, 2].map((i) =>
          mps.redpallas_dkg_round2_process(
            otherIndices[i].map((j) => results2[j].msg),
            results2[i].state,
            crypto.randomBytes(32),
          ),
        );
      });

      const message = Buffer.from(
        "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
      );

      it("performs round 0", function () {
        const messagePrefix = Buffer.from("mps-redpallas-dsg-round1-message$");
        const statePrefix = Buffer.from("mps-redpallas-dsg-round1-state$");
        for (const i of [0, 2]) {
          const result = mps.redpallas_dsg_round0_process(shares[i].share, message);
          assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
          assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
        }
      });

      let results1: Array<mps.MsgState>;

      before("performs round 0", function () {
        results1 = [0, 2].map((i) => mps.redpallas_dsg_round0_process(shares[i].share, message));
      });

      it("performs round 1", function () {
        const messagePrefix = Buffer.from("mps-redpallas-dsg-round2-message$");
        const statePrefix = Buffer.from("mps-redpallas-dsg-round2-state$");
        for (let i = 0; i < results1.length; i++) {
          const result = mps.redpallas_dsg_round1_process(
            results1[otherIndex[i]].msg,
            results1[i].state,
          );
          assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
          assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
        }
      });

      it("fails to perform round 1 with invalid message prefix", function () {
        const messagePrefix = Buffer.from("mps-redpallas-dsg-round1-message$");
        for (let i = 0; i < results1.length; i++) {
          shouldThrow(() =>
            mps.redpallas_dsg_round1_process(
              Buffer.from(results1[otherIndex[i]].msg).slice(messagePrefix.length),
              results1[i].state,
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dsg_round1_process(
              Buffer.concat([
                Buffer.from("mps-redpallas-dsg-round2-message$"),
                Buffer.from(results1[otherIndex[i]].msg).slice(messagePrefix.length),
              ]),
              results1[i].state,
            ),
          );
        }
      });

      it("fails to perform round 1 with invalid state prefix", function () {
        const statePrefix = Buffer.from("mps-redpallas-dsg-round1-state$");
        for (let i = 0; i < results1.length; i++) {
          shouldThrow(() =>
            mps.redpallas_dsg_round1_process(
              results1[otherIndex[i]].msg,
              Buffer.from(results1[i].state).slice(statePrefix.length),
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dsg_round1_process(
              results1[otherIndex[i]].msg,
              Buffer.concat([Buffer.from("mps-redpallas-dsg-round2-state$"), results1[i].state]),
            ),
          );
        }
      });

      let results2: Array<mps.MsgState>;

      before("performs round 1", function () {
        results2 = [0, 1].map((i) =>
          mps.redpallas_dsg_round1_process(results1[otherIndex[i]].msg, results1[i].state),
        );
      });

      it("performs round 2", function () {
        const messagePrefix = Buffer.from("mps-redpallas-dsg-round3-message$");
        const statePrefix = Buffer.from("mps-redpallas-dsg-round3-state$");
        for (let i = 0; i < results2.length; i++) {
          const result = mps.redpallas_dsg_round2_process(
            results2[otherIndex[i]].msg,
            results2[i].state,
          );
          assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
          assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
        }
      });

      it("fails to perform round 2 with invalid message prefix", function () {
        const messagePrefix = Buffer.from("mps-redpallas-dsg-round2-message$");
        for (let i = 0; i < results2.length; i++) {
          shouldThrow(() =>
            mps.redpallas_dsg_round2_process(
              Buffer.from(results1[otherIndex[i]].msg).slice(messagePrefix.length),
              results1[i].state,
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dsg_round2_process(
              Buffer.concat([
                Buffer.from("mps-redpallas-dsg-round3-message$"),
                Buffer.from(results1[otherIndex[i]].msg).slice(messagePrefix.length),
              ]),
              results1[i].state,
            ),
          );
        }
      });

      it("fails to perform round 2 with invalid state prefix", function () {
        const statePrefix = Buffer.from("mps-redpallas-dsg-round2-state$");
        for (let i = 0; i < results2.length; i++) {
          shouldThrow(() =>
            mps.redpallas_dsg_round2_process(
              results1[otherIndex[i]].msg,
              Buffer.from(results1[i].state).slice(statePrefix.length),
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dsg_round2_process(
              results1[otherIndex[i]].msg,
              Buffer.concat([Buffer.from("mps-redpallas-dsg-round3-state$"), results1[i].state]),
            ),
          );
        }
      });

      let results3: Array<mps.MsgState>;

      before("performs round 2", function () {
        results3 = [0, 1].map((i) =>
          mps.redpallas_dsg_round2_process(results2[otherIndex[i]].msg, results2[i].state),
        );
      });

      it("performs round 3", function () {
        const results4 = [0, 1].map((i) =>
          mps.redpallas_dsg_round3_process(results3[otherIndex[i]].msg, results3[i].state),
        );
        for (let i = 0; i < 2; i++) {
          assert(mps.redpallas_verify(results4[i].rk, results4[i].signature, message));
        }
        // Both parties produce the same alpha and rk
        assert.deepStrictEqual(results4[0].alpha, results4[1].alpha, "alpha values differ");
        assert.deepStrictEqual(results4[0].rk, results4[1].rk, "rk values differ");
        // Alpha is a random field element — must not be zero
        assert(!results4[0].alpha.every((b) => b === 0), "alpha is zero");
      });

      it("fails to perform round 3 with invalid message prefix", function () {
        const messagePrefix = Buffer.from("mps-redpallas-dsg-round3-message$");
        for (let i = 0; i < results3.length; i++) {
          shouldThrow(() =>
            mps.redpallas_dsg_round3_process(
              Buffer.from(results3[otherIndex[i]].msg).slice(messagePrefix.length),
              results1[i].state,
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dsg_round3_process(
              Buffer.concat([
                Buffer.from("mps-redpallas-dsg-round4-message$"),
                Buffer.from(results3[otherIndex[i]].msg).slice(messagePrefix.length),
              ]),
              results1[i].state,
            ),
          );
        }
      });

      it("fails to perform round 3 with invalid state prefix", function () {
        const statePrefix = Buffer.from("mps-redpallas-dsg-round3-state$");
        for (let i = 0; i < results3.length; i++) {
          shouldThrow(() =>
            mps.redpallas_dsg_round3_process(
              results3[otherIndex[i]].msg,
              Buffer.from(results3[i].state).slice(statePrefix.length),
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dsg_round3_process(
              results3[otherIndex[i]].msg,
              Buffer.concat([Buffer.from("mps-redpallas-dsg-round3-state$"), results3[i].state]),
            ),
          );
        }
      });
    });
  });
});
