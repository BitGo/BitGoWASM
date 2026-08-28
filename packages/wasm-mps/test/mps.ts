import assert from "assert";
import crypto from "crypto";
import * as mps from "../js";
import sodium from "libsodium-wrappers-sumo";
import { makeImportShares, runDsg } from "./utils.js";

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
                  Buffer.from("mps-ed25519-dkg-round2-message$"),
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
              otherIndices[i].map((j) => results1[j].msg),
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
                  Buffer.from("mps-ed25519-dkg-round3-message$"),
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
              otherIndices[i].map((i) => results2[i].msg),
              Buffer.concat([
                Buffer.from("mps-ed25519-dkg-round3-state$"),
                Buffer.from(results2[i].state).slice(statePrefix.length),
              ]),
            ),
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

    describe("dkg_import", function () {
      let importScalars: Buffer[];
      let importExpectedPk: Buffer;
      let importChainCode: Buffer;

      before("generates synthetic MPCv1 shares", function () {
        ({
          scalars: importScalars,
          expectedPk: importExpectedPk,
          chainCode: importChainCode,
        } = makeImportShares());
      });

      it("performs round 0 import", function () {
        const messagePrefix = Buffer.from("mps-ed25519-dkg-round1-message$");
        const statePrefix = Buffer.from("mps-ed25519-dkg-round1-state$");
        for (let i = 0; i < keypairs.length; i++) {
          const result = mps.ed25519_dkg_round0_import(
            i,
            keypairs[i].privateKey,
            otherIndices[i].map((j) => keypairs[j].publicKey),
            importScalars[i],
            importExpectedPk,
            importChainCode,
          );
          assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
          assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
        }
      });

      let r0Results: Array<mps.MsgState>;

      before("performs round 0 import", function () {
        r0Results = [0, 1, 2].map((i) =>
          mps.ed25519_dkg_round0_import(
            i,
            keypairs[i].privateKey,
            otherIndices[i].map((j) => keypairs[j].publicKey),
            importScalars[i],
            importExpectedPk,
            importChainCode,
          ),
        );
      });

      it("performs round 1", function () {
        const messagePrefix = Buffer.from("mps-ed25519-dkg-round2-message$");
        const statePrefix = Buffer.from("mps-ed25519-dkg-round2-state$");
        for (let i = 0; i < r0Results.length; i++) {
          const result = mps.ed25519_dkg_round1_process(
            otherIndices[i].map((j) => r0Results[j].msg),
            r0Results[i].state,
          );
          assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
          assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
        }
      });

      let r1Results: Array<mps.MsgState>;

      before("performs round 1", function () {
        r1Results = [0, 1, 2].map((i) =>
          mps.ed25519_dkg_round1_process(
            otherIndices[i].map((j) => r0Results[j].msg),
            r0Results[i].state,
          ),
        );
      });

      it("performs round 2", function () {
        const shares = [0, 1, 2].map((i) =>
          mps.ed25519_dkg_round2_process(
            otherIndices[i].map((j) => r1Results[j].msg),
            r1Results[i].state,
          ),
        );
        for (let i = 0; i < 2; i++) {
          assert.ok(shares[i].pk.every((value, index) => value === shares[2].pk[index]));
          assert.ok(
            shares[i].chaincode.every((value, index) => value === shares[2].chaincode[index]),
          );
        }
        for (const [i, s] of shares.entries()) {
          assert.ok(
            Buffer.from(s.pk).equals(importExpectedPk),
            `party ${i}: Share.pk !== expected_pk`,
          );
          assert.ok(
            Buffer.from(s.chaincode).equals(importChainCode),
            `party ${i}: Share.chaincode !== chain_code`,
          );
        }
      });

      let importShares: mps.Share[];

      before("performs round 2", function () {
        importShares = [0, 1, 2].map((i) =>
          mps.ed25519_dkg_round2_process(
            otherIndices[i].map((j) => r1Results[j].msg),
            r1Results[i].state,
          ),
        );
      });

      it("signing round-trip at root path verifies against expected_pk", function () {
        const message = Buffer.from("test message for import DKG signing");
        const [sig0, sig2] = runDsg(importShares, "m", message);
        assert.ok(
          sodium.crypto_sign_verify_detached(sig0, message, importExpectedPk),
          "sig0 failed to verify",
        );
        assert.ok(
          sodium.crypto_sign_verify_detached(sig2, message, importExpectedPk),
          "sig2 failed to verify",
        );
        assert.deepStrictEqual(sig0, sig2, "both parties must produce identical signatures");
      });

      // Full derived pubkey verification requires BitGoJS Eddsa.deriveUnhardened, covered separately.
      it("signing round-trip at derived path m/0 produces a valid signature", function () {
        const message = Buffer.from("test message for derived path signing");
        const [sig0, sig2] = runDsg(importShares, "m/0", message);
        assert.strictEqual(sig0.length, 64, "signature must be 64 bytes");
        assert.deepStrictEqual(sig0, sig2, "both parties must produce identical signatures");
      });

      // The wrong pk is a valid Ed25519 point but does not equal G × Σs_i_0, so the
      // mismatch surfaces during the protocol (at round2_process per the MPS library).
      it("rejects mismatched expected_pk — error surfaces during the protocol", function () {
        const wrongPk = Buffer.from(
          sodium.crypto_scalarmult_ed25519_base_noclamp(crypto.randomBytes(32)),
        );
        let threw = false;
        try {
          const r0 = [0, 1, 2].map((i) =>
            mps.ed25519_dkg_round0_import(
              i,
              keypairs[i].privateKey,
              otherIndices[i].map((j) => keypairs[j].publicKey),
              importScalars[i],
              wrongPk,
              importChainCode,
            ),
          );
          const r1 = [0, 1, 2].map((i) =>
            mps.ed25519_dkg_round1_process(
              otherIndices[i].map((j) => r0[j].msg),
              r0[i].state,
            ),
          );
          [0, 1, 2].map((i) =>
            mps.ed25519_dkg_round2_process(
              otherIndices[i].map((j) => r1[j].msg),
              r1[i].state,
            ),
          );
        } catch {
          threw = true;
        }
        assert.ok(threw, "expected protocol to fail when expected_pk does not match Σs_i_0");
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

    describe("vrf_dkg", function () {
      it("performs round 0", function () {
        const messagePrefix = Buffer.from("mps-ed25519-vrf-dkg-round1-message$");
        const statePrefix = Buffer.from("mps-ed25519-vrf-dkg-round1-state$");
        for (let i = 0; i < keypairs.length; i++) {
          const result = mps.ed25519_vrf_dkg_round0_process(i, crypto.randomBytes(32));
          assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
          assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
        }
      });

      let results1: Array<mps.MsgState>;

      before("performs round 0", function () {
        results1 = [0, 1, 2].map((i) =>
          mps.ed25519_vrf_dkg_round0_process(i, crypto.randomBytes(32)),
        );
      });

      it("performs round 1", function () {
        const messagePrefix = Buffer.from("mps-ed25519-vrf-dkg-round2-message$");
        const statePrefix = Buffer.from("mps-ed25519-vrf-dkg-round2-state$");
        for (let i = 0; i < results1.length; i++) {
          const result = mps.ed25519_vrf_dkg_round1_process(
            otherIndices[i].map((i) => results1[i].msg),
            results1[i].state,
          );
          for (const value of Object.values(result.msg as Record<string, Uint8Array>)) {
            assert(Buffer.from(value).slice(0, messagePrefix.length).equals(messagePrefix));
          }
          assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
        }
      });

      it("fails to perform round 1 with invalid message prefix", function () {
        const messagePrefix = Buffer.from("mps-ed25519-vrf-dkg-round1-message$");
        for (let i = 0; i < results1.length; i++) {
          shouldThrow(() =>
            mps.ed25519_vrf_dkg_round1_process(
              otherIndices[i].map((i) => Buffer.from(results1[i].msg).slice(messagePrefix.length)),
              results1[i].state,
            ),
          );
          shouldThrow(() =>
            mps.ed25519_vrf_dkg_round1_process(
              otherIndices[i].map((i) =>
                Buffer.concat([
                  Buffer.from("mps-ed25519-vrf-dkg-round2-message$"),
                  Buffer.from(results1[i].msg).slice(messagePrefix.length),
                ]),
              ),
              results1[i].state,
            ),
          );
        }
      });

      it("fails to perform round 1 with invalid state prefix", function () {
        const statePrefix = Buffer.from("mps-ed25519-vrf-dkg-round1-state$");
        for (let i = 0; i < results1.length; i++) {
          shouldThrow(() =>
            mps.ed25519_vrf_dkg_round1_process(
              otherIndices[i].map((i) => results1[i].msg),
              Buffer.from(results1[i].state).slice(statePrefix.length),
            ),
          );
          shouldThrow(() =>
            mps.ed25519_vrf_dkg_round1_process(
              otherIndices[i].map((j) => results1[j].msg),
              Buffer.concat([
                Buffer.from("mps-ed25519-vrf-dkg-round2-state$"),
                Buffer.from(results1[i].state).slice(statePrefix.length),
              ]),
            ),
          );
        }
      });

      let results2: Array<mps.MsgStateMap>;

      before("performs round 1", function () {
        results2 = [0, 1, 2].map((i) =>
          mps.ed25519_vrf_dkg_round1_process(
            otherIndices[i].map((i) => results1[i].msg),
            results1[i].state,
          ),
        );
      });

      it("performs round 2", function () {
        const shares = [0, 1, 2].map((i) =>
          mps.ed25519_vrf_dkg_round2_process(
            otherIndices[i].map((j) => (results2[j].msg as Record<string, Uint8Array>)[i]),
            results2[i].state,
          ),
        );
        for (const share of shares) {
          assert.ok(share.share.length > 0);
        }
      });

      it("fails to perform round 2 with invalid message prefix", function () {
        const messagePrefix = Buffer.from("mps-ed25519-vrf-dkg-round2-message$");
        for (let i = 0; i < results2.length; i++) {
          shouldThrow(() =>
            mps.ed25519_vrf_dkg_round2_process(
              otherIndices[i].map((j) =>
                Buffer.from((results2[j].msg as Record<string, Uint8Array>)[i]).slice(
                  messagePrefix.length,
                ),
              ),
              results2[i].state,
            ),
          );
          shouldThrow(() =>
            mps.ed25519_vrf_dkg_round2_process(
              otherIndices[i].map((j) =>
                Buffer.concat([
                  Buffer.from("mps-ed25519-vrf-dkg-round3-message$"),
                  Buffer.from((results2[j].msg as Record<string, Uint8Array>)[i]).slice(
                    messagePrefix.length,
                  ),
                ]),
              ),
              results2[i].state,
            ),
          );
        }
      });

      it("fails to perform round 2 with invalid state prefix", function () {
        const statePrefix = Buffer.from("mps-ed25519-vrf-dkg-round2-state$");
        for (let i = 0; i < results2.length; i++) {
          shouldThrow(() =>
            mps.ed25519_vrf_dkg_round2_process(
              otherIndices[i].map((j) => (results2[j].msg as Record<string, Uint8Array>)[i]),
              Buffer.from(results2[i].state).slice(statePrefix.length),
            ),
          );
          shouldThrow(() =>
            mps.ed25519_vrf_dkg_round2_process(
              otherIndices[i].map((j) => (results2[j].msg as Record<string, Uint8Array>)[i]),
              Buffer.concat([
                Buffer.from("mps-ed25519-vrf-dkg-round3-state$"),
                Buffer.from(results2[i].state).slice(statePrefix.length),
              ]),
            ),
          );
        }
      });
    });

    describe("hard_derive", function () {
      const otherIndex = [1, 0];
      let rootShares: Array<mps.Share>;
      let vrfShares: Array<mps.VrfShare>;

      before("performs root dkg", function () {
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
        rootShares = [0, 1, 2].map((i) =>
          mps.ed25519_dkg_round2_process(
            otherIndices[i].map((i) => results2[i].msg),
            results2[i].state,
          ),
        );
      });

      before("performs vrf dkg", function () {
        const results1 = [0, 1, 2].map((i) =>
          mps.ed25519_vrf_dkg_round0_process(i, crypto.randomBytes(32)),
        );
        const results2 = [0, 1, 2].map((i) =>
          mps.ed25519_vrf_dkg_round1_process(
            otherIndices[i].map((i) => results1[i].msg),
            results1[i].state,
          ),
        );
        vrfShares = [0, 1, 2].map((i) =>
          mps.ed25519_vrf_dkg_round2_process(
            otherIndices[i].map((j) => (results2[j].msg as Record<string, Uint8Array>)[i]),
            results2[i].state,
          ),
        );
      });

      const path = "m/44'/0'/0'";

      it("performs round 0", function () {
        const messagePrefix = Buffer.from("mps-ed25519-hard-derive-round1-message$");
        const statePrefix = Buffer.from("mps-ed25519-hard-derive-round1-state$");
        for (const i of [0, 2]) {
          const result = mps.ed25519_hard_derive_round0_process(
            vrfShares[i].share,
            rootShares[i].share,
            path,
          );
          assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
          assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
        }
      });

      let results0: Array<mps.MsgState>;

      before("performs round 0", function () {
        results0 = [0, 2].map((i) =>
          mps.ed25519_hard_derive_round0_process(vrfShares[i].share, rootShares[i].share, path),
        );
      });

      it("performs round 1", function () {
        const messagePrefix = Buffer.from("mps-ed25519-hard-derive-round2-message$");
        const statePrefix = Buffer.from("mps-ed25519-hard-derive-round2-state$");
        for (let i = 0; i < results0.length; i++) {
          const result = mps.ed25519_hard_derive_round1_process(
            results0[otherIndex[i]].msg,
            results0[i].state,
          );
          assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
          assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
        }
      });

      it("fails to perform round 1 with invalid message prefix", function () {
        const messagePrefix = Buffer.from("mps-ed25519-hard-derive-round1-message$");
        for (let i = 0; i < results0.length; i++) {
          shouldThrow(() =>
            mps.ed25519_hard_derive_round1_process(
              Buffer.from(results0[otherIndex[i]].msg).slice(messagePrefix.length),
              results0[i].state,
            ),
          );
          shouldThrow(() =>
            mps.ed25519_hard_derive_round1_process(
              Buffer.concat([
                Buffer.from("mps-ed25519-hard-derive-round2-message$"),
                Buffer.from(results0[otherIndex[i]].msg).slice(messagePrefix.length),
              ]),
              results0[i].state,
            ),
          );
        }
      });

      it("fails to perform round 1 with invalid state prefix", function () {
        const statePrefix = Buffer.from("mps-ed25519-hard-derive-round1-state$");
        for (let i = 0; i < results0.length; i++) {
          shouldThrow(() =>
            mps.ed25519_hard_derive_round1_process(
              results0[otherIndex[i]].msg,
              Buffer.from(results0[i].state).slice(statePrefix.length),
            ),
          );
          shouldThrow(() =>
            mps.ed25519_hard_derive_round1_process(
              results0[otherIndex[i]].msg,
              Buffer.concat([
                Buffer.from("mps-ed25519-hard-derive-round2-state$"),
                results0[i].state,
              ]),
            ),
          );
        }
      });

      let results1: Array<mps.MsgState>;

      before("performs round 1", function () {
        results1 = [0, 1].map((i) =>
          mps.ed25519_hard_derive_round1_process(results0[otherIndex[i]].msg, results0[i].state),
        );
      });

      it("performs round 2", function () {
        const shares = [0, 1].map((i) =>
          mps.ed25519_hard_derive_round2_process(results1[otherIndex[i]].msg, results1[i].state),
        );
        assert.deepStrictEqual(shares[0].pk, shares[1].pk, "derived pubkeys differ");
        assert.deepStrictEqual(
          shares[0].chaincode,
          shares[1].chaincode,
          "derived chain codes differ",
        );
        assert.notDeepStrictEqual(
          shares[0].pk,
          rootShares[0].pk,
          "derived pubkey must differ from the root pubkey",
        );
      });

      it("fails to perform round 2 with invalid message prefix", function () {
        const messagePrefix = Buffer.from("mps-ed25519-hard-derive-round2-message$");
        for (let i = 0; i < results1.length; i++) {
          shouldThrow(() =>
            mps.ed25519_hard_derive_round2_process(
              Buffer.from(results1[otherIndex[i]].msg).slice(messagePrefix.length),
              results1[i].state,
            ),
          );
          shouldThrow(() =>
            mps.ed25519_hard_derive_round2_process(
              Buffer.concat([
                Buffer.from("mps-ed25519-hard-derive-round3-message$"),
                Buffer.from(results1[otherIndex[i]].msg).slice(messagePrefix.length),
              ]),
              results1[i].state,
            ),
          );
        }
      });

      it("fails to perform round 2 with invalid state prefix", function () {
        const statePrefix = Buffer.from("mps-ed25519-hard-derive-round2-state$");
        for (let i = 0; i < results1.length; i++) {
          shouldThrow(() =>
            mps.ed25519_hard_derive_round2_process(
              results1[otherIndex[i]].msg,
              Buffer.from(results1[i].state).slice(statePrefix.length),
            ),
          );
          shouldThrow(() =>
            mps.ed25519_hard_derive_round2_process(
              results1[otherIndex[i]].msg,
              Buffer.concat([
                Buffer.from("mps-ed25519-hard-derive-round3-state$"),
                Buffer.from(results1[i].state).slice(statePrefix.length),
              ]),
            ),
          );
        }
      });

      const derivedShares: Array<mps.Share> = [];

      before("performs round 2", function () {
        const shares = [0, 1].map((i) =>
          mps.ed25519_hard_derive_round2_process(results1[otherIndex[i]].msg, results1[i].state),
        );
        derivedShares[0] = shares[0];
        derivedShares[2] = shares[1];
      });

      it("signs with the derived share and verifies against the derived pubkey", function () {
        const message = Buffer.from("hard-derived signing test");
        const [sig0, sig2] = runDsg(derivedShares, "m", message);
        assert.deepStrictEqual(sig0, sig2);
        assert.ok(sodium.crypto_sign_verify_detached(sig0, message, derivedShares[0].pk));
      });

      it("composes soft derivation on top of a hard-derived share", function () {
        const message = Buffer.from("soft-on-hard signing test");
        const [sig0, sig2] = runDsg(derivedShares, "m/0/1", message);
        assert.deepStrictEqual(sig0, sig2);
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
                  Buffer.from("mps-redpallas-dkg-round2-message$"),
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
              otherIndices[i].map((j) => results1[j].msg),
              Buffer.concat([
                Buffer.from("mps-redpallas-dkg-round2-state$"),
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
        const results3 = [0, 1, 2].map((i) =>
          mps.redpallas_dkg_round2_process(
            otherIndices[i].map((i) => results2[i].msg),
            results2[i].state,
          ),
        );
        for (let i = 0; i < 2; i++) {
          assert.ok(results3[i].pk.every((value, index) => value === results3[2].pk[index]));
        }
      });

      it("fails to perform round 2 with invalid message prefix", function () {
        const messagePrefix = Buffer.from("mps-redpallas-dkg-round2-message$");
        for (let i = 0; i < results2.length; i++) {
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
                  Buffer.from("mps-redpallas-dkg-round3-message$"),
                  Buffer.from(results2[i].msg).slice(messagePrefix.length),
                ]),
              ),
              results2[i].state,
            ),
          );
        }
      });

      it("fails to perform round 2 with invalid state prefix", function () {
        const statePrefix = Buffer.from("mps-redpallas-dkg-round2-state$");
        for (let i = 0; i < results2.length; i++) {
          shouldThrow(() =>
            mps.redpallas_dkg_round2_process(
              otherIndices[i].map((i) => results2[i].msg),
              Buffer.from(results2[i].state).slice(statePrefix.length),
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dkg_round2_process(
              otherIndices[i].map((i) => results2[i].msg),
              Buffer.concat([
                Buffer.from("mps-redpallas-dkg-round3-state$"),
                Buffer.from(results2[i].state).slice(statePrefix.length),
              ]),
            ),
          );
        }
      });
    });

    describe("dsg", function () {
      const otherIndex = [1, 0];
      let shares: Array<mps.RedPallasShare>;

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
              Buffer.from(results2[otherIndex[i]].msg).slice(messagePrefix.length),
              results2[i].state,
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dsg_round2_process(
              Buffer.concat([
                Buffer.from("mps-redpallas-dsg-round3-message$"),
                Buffer.from(results2[otherIndex[i]].msg).slice(messagePrefix.length),
              ]),
              results2[i].state,
            ),
          );
        }
      });

      it("fails to perform round 2 with invalid state prefix", function () {
        const statePrefix = Buffer.from("mps-redpallas-dsg-round2-state$");
        for (let i = 0; i < results2.length; i++) {
          shouldThrow(() =>
            mps.redpallas_dsg_round2_process(
              results2[otherIndex[i]].msg,
              Buffer.from(results2[i].state).slice(statePrefix.length),
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dsg_round2_process(
              results2[otherIndex[i]].msg,
              Buffer.concat([Buffer.from("mps-redpallas-dsg-round3-state$"), results2[i].state]),
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
              results3[i].state,
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dsg_round3_process(
              Buffer.concat([
                Buffer.from("mps-redpallas-dsg-round4-message$"),
                Buffer.from(results3[otherIndex[i]].msg).slice(messagePrefix.length),
              ]),
              results3[i].state,
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
              Buffer.concat([
                Buffer.from("mps-redpallas-dsg-round4-state$"),
                Buffer.from(results3[i].state).slice(statePrefix.length),
              ]),
            ),
          );
        }
      });
    });
  });
});
