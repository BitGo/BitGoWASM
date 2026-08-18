import assert from "assert";
import crypto from "crypto";
import * as mps from "../js";
import sodium from "libsodium-wrappers-sumo";
import { makeImportShares, runDkgRound0, runDsg, runHardDerive, runRootDkg } from "./utils.js";

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
            false,
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
            false,
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

      it("with_vrf=false is byte-identical across runs with the same seeds", function () {
        const seeds: [Buffer, Buffer, Buffer] = [
          Buffer.alloc(32, 1),
          Buffer.alloc(32, 2),
          Buffer.alloc(32, 3),
        ];
        const a = runDkgRound0(keypairs, seeds, false);
        const b = runDkgRound0(keypairs, seeds, false);
        for (let i = 0; i < 3; i++) {
          assert(Buffer.from(a[i].msg).equals(Buffer.from(b[i].msg)));
          assert(Buffer.from(a[i].state).equals(Buffer.from(b[i].state)));
        }
        const sharesA = runRootDkg(keypairs, false, seeds);
        const sharesB = runRootDkg(keypairs, false, seeds);
        for (let i = 0; i < 3; i++) {
          assert(Buffer.from(sharesA[i].share).equals(Buffer.from(sharesB[i].share)));
          assert.equal(sharesA[i].vrf_pk.length, 0);
        }
      });

      it("with_vrf=true produces a combined root and agreeing VRF public keys", function () {
        const shares = runRootDkg(keypairs, true);
        for (let i = 0; i < 2; i++) {
          assert(Buffer.from(shares[i].pk).equals(Buffer.from(shares[2].pk)));
          assert(Buffer.from(shares[i].chaincode).equals(Buffer.from(shares[2].chaincode)));
          assert(Buffer.from(shares[i].vrf_pk).equals(Buffer.from(shares[2].vrf_pk)));
          assert(Buffer.from(shares[i].vrf_chaincode).equals(Buffer.from(shares[2].vrf_chaincode)));
        }
        assert(shares[0].vrf_pk.length === 32);
        shouldThrow(() => mps.ed25519_dsg_round0_process(shares[0].share, "m", Buffer.from("x")));
      });

      it("rejects mixed VRF and non-VRF round1 messages", function () {
        const seeds: [Buffer, Buffer, Buffer] = [
          Buffer.alloc(32, 4),
          Buffer.alloc(32, 5),
          Buffer.alloc(32, 6),
        ];
        const plain = runDkgRound0(keypairs, seeds, false);
        const vrf = runDkgRound0(keypairs, seeds, true);
        shouldThrow(() => mps.ed25519_dkg_round1_process([vrf[1].msg, vrf[2].msg], plain[0].state));
        shouldThrow(() => mps.ed25519_dkg_round1_process([plain[1].msg, vrf[2].msg], vrf[0].state));
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
                false,
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
                false,
              ),
            );
            shouldThrow(() =>
              mps.ed25519_dkg_round0_process(
                0,
                Buffer.alloc(0),
                [Buffer.alloc(32), Buffer.alloc(32)],
                crypto.randomBytes(32),
                false,
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
                false,
              ),
            );
            shouldThrow(() =>
              mps.ed25519_dkg_round0_process(0, Buffer.alloc(0), [], crypto.randomBytes(32), false),
            );
            shouldThrow(() =>
              mps.ed25519_dkg_round0_process(
                0,
                Buffer.alloc(0),
                ["decryption key"],
                crypto.randomBytes(32),
                false,
              ),
            );
            shouldThrow(() =>
              mps.ed25519_dkg_round0_process(
                0,
                Buffer.alloc(0),
                [Buffer.alloc(0)],
                crypto.randomBytes(32),
                false,
              ),
            );
            shouldThrow(() =>
              mps.ed25519_dkg_round0_process(
                0,
                Buffer.alloc(0),
                [Buffer.alloc(32), Buffer.alloc(0)],
                crypto.randomBytes(32),
                false,
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
                false,
              ),
            );
            shouldThrow(() =>
              mps.ed25519_dkg_round0_process(
                0,
                Buffer.alloc(0),
                [Buffer.alloc(32), Buffer.alloc(32)],
                Buffer.alloc(0),
                false,
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
            false,
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
        const messagePrefix = Buffer.from("mps-redpallas-dkg-derivation-message$");
        const statePrefix = Buffer.from("mps-redpallas-dkg-derivation-state$");
        const results3 = [0, 1, 2].map((i) =>
          mps.redpallas_dkg_round2_process(
            otherIndices[i].map((i) => results2[i].msg),
            results2[i].state,
            crypto.randomBytes(32),
          ),
        );
        for (let i = 0; i < results3.length; i++) {
          if (results3[i].msg.length) {
            assert(
              Buffer.from(results3[i].msg).slice(0, messagePrefix.length).equals(messagePrefix),
            );
          }
          assert(Buffer.from(results3[i].state).slice(0, statePrefix.length).equals(statePrefix));
        }
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
              crypto.randomBytes(32),
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
              crypto.randomBytes(32),
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
              crypto.randomBytes(32),
            ),
          );
          shouldThrow(() =>
            mps.redpallas_dkg_round2_process(
              otherIndices[i].map((i) => results2[i].msg),
              Buffer.concat([
                Buffer.from("mps-redpallas-dkg-round3-state$"),
                Buffer.from(results2[i].state).slice(statePrefix.length),
              ]),
              crypto.randomBytes(32),
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
        let message = Buffer.concat(results3.map((d) => Buffer.from(d.msg)));
        const states = results3.map((d) => d.state);
        const derivedKeys: Map<number, mps.MsgDerivation> = new Map();
        for (let round = 0; round < 500 && Array.from(derivedKeys.keys()).length < 3; round++) {
          for (let party = 0; party < 3; party++) {
            const result = mps.redpallas_derivation_process(message, states[party]);
            if (result.msg.length) {
              assert(Buffer.from(result.msg).slice(0, messagePrefix.length).equals(messagePrefix));
            }
            assert(Buffer.from(result.state).slice(0, statePrefix.length).equals(statePrefix));
            message = result.msg;
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
        const hsmKeys = derivedKeys.get(2); // HSM is always part 2.
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
      let shares: Array<mps.MsgDerivationInit>;

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

  describe("hard derivation (interleaved VRF DKG + hard derive)", function () {
    function fromHex(s: string): Uint8Array {
      return new Uint8Array(Buffer.from(s, "hex"));
    }

    function signChild(a: mps.Share, b: mps.Share, message: Buffer): Uint8Array {
      const dsg0 = [a, b].map((s) => mps.ed25519_dsg_round0_process(s.share, "m", message));
      const dsg1 = [0, 1].map((i) =>
        mps.ed25519_dsg_round1_process(dsg0[i ^ 1].msg, dsg0[i].state),
      );
      const dsg2 = [0, 1].map((i) =>
        mps.ed25519_dsg_round2_process(dsg1[i ^ 1].msg, dsg1[i].state),
      );
      const [sig0, sig1] = [0, 1].map((i) =>
        mps.ed25519_dsg_round3_process(dsg2[i ^ 1].msg, dsg2[i].state),
      );
      assert(Buffer.from(sig0).equals(Buffer.from(sig1)));
      return sig0;
    }

    describe("full chain: interleaved DKG -> hard derive -> sign", function () {
      it("derives a consistent child from every 2-of-3 quorum", function () {
        const rootShares = runRootDkg(keypairs, true);
        const path = "m/999999'/0'";
        const extraPath = "m/44'/0'/0'";
        const hdSeeds: [Buffer, Buffer] = [Buffer.alloc(32, 10), Buffer.alloc(32, 11)];
        const quorums: Array<[number, number]> = [
          [0, 1],
          [0, 2],
          [1, 2],
        ];

        const derivedByQuorum = quorums.map((q) => runHardDerive(rootShares, path, hdSeeds, q));
        for (const [d0, d1] of derivedByQuorum) {
          assert(Buffer.from(d0.pk).equals(Buffer.from(d1.pk)));
          assert(Buffer.from(d0.chaincode).equals(Buffer.from(d1.chaincode)));
          assert(!Buffer.from(d0.pk).equals(Buffer.from(rootShares[0].pk)));
        }
        assert(Buffer.from(derivedByQuorum[0][0].pk).equals(Buffer.from(derivedByQuorum[1][0].pk)));
        assert(Buffer.from(derivedByQuorum[1][0].pk).equals(Buffer.from(derivedByQuorum[2][0].pk)));

        const extra = runHardDerive(rootShares, extraPath, hdSeeds, [0, 2]);
        assert(!Buffer.from(extra[0].pk).equals(Buffer.from(derivedByQuorum[0][0].pk)));

        const message = Buffer.from("hard-derive harness test message");
        const [derived0, derived2] = derivedByQuorum[1];
        const sig = signChild(derived0, derived2, message);
        assert(
          sodium.crypto_sign_verify_detached(Buffer.from(sig), message, Buffer.from(derived0.pk)),
        );
      });
    });

    describe("golden vector (cross-implementation agreement with sl-mps)", function () {
      it("matches the derived pk/chaincode produced by the Rust (sl-mps) implementation", function () {
        // Fixture bytes captured from one run of sl-mps's
        // `vrf_dkg_hard_derive_and_sign_ed25519` test (root + VRF Keyshares
        // for parties 0/1, bincode-encoded) and duplicated verbatim in
        // hsm-firmware's `src/sl-mps/src/lib.rs` (`hard_derive_matches_golden_vector`).
        const root0 = fromHex(
          "020300510ba2d9807d478162c122ee6bd93fbf01c162554461bef21b57e94d7bc02903fed89f7b5f76a1f9956d12f1dca812b13cef803e7d75e3f70c1a12e65b26e7b2602fef6c18da4b231dab4f3aa1bb8548285f2de1f6ef1919840988504c60a21979795dc2091feed51e7a4fe3a23f7efb45c7565310180f5f5a05b6b72f960c729442307047067dfd9252c2c6696463253189b8052e393d67f1a49d92682da4f63e11b9aedf8726986b38496701900889d1f6390a6e2ce3d9f5ff109f5ae08f89b500c81e70b32e37854ef128d34706f53768bd106c2166b50b5f86ae1dc366a354f1ba9b44929c3b69660732137fc02757d6bc86e4356865a22324995ea65590fe8b",
        );
        const root1 = fromHex(
          "02030179256ee54665afb0cac79b0cc71c55997be50b6ee51e08a20b1f7d3e26d05a0afed89f7b5f76a1f9956d12f1dca812b13cef803e7d75e3f70c1a12e65b26e7b2602fef6c18da4b231dab4f3aa1bb8548285f2de1f6ef1919840988504c60a21979795dc2091feed51e7a4fe3a23f7efb45c7565310180f5f5a05b6b72f960c729442307047067dfd9252c2c6696463253189b8052e393d67f1a49d92682da4f63e11b9aedf8726986b38496701900889d1f6390a6e2ce3d9f5ff109f5ae08f89b500c81e70b32e37854ef128d34706f53768bd106c2166b50b5f86ae1dc366a354f1ba9b44929c3b69660732137fc02757d6bc86e4356865a22324995ea65590fe8b",
        );
        const vrf0 = fromHex(
          "0203007e9d1f3c4cab22497d43d2b42db7e6dbd8e5e5832fbc4591c1c660194ca00d07703059881be18310acf8d3c4245745bf920cc1d2a4366000e6574b04ecd7f119601cceadb743fc50a88c3cbd60449f2c76cf4a72f15835d87a9c447ad58523f95824b902529eee1abb183e328a2d79473b3216649c6cd28c6d5e67f0cb74db8828fcbed41bf2cd2f83ef58bf05218e70da4dbdfeb3f45bb801c981f95e1688083a5b7db6feeb887fb76524245d34fac53acb5d0be01159faaa1e56de48fd68af3500c43dd8d30860e7468984f03fe5722ec702e34ebc4bc449195f999cb26949eb4ffd52fd5af3fa730c78706c7943cf409e526b46adf46914e0188948acf934eea0",
        );
        const vrf1 = fromHex(
          "020301e50d4d81352589c35ca45cc2605f20ba51e089aa0fc2210e0ae29dc98124e406703059881be18310acf8d3c4245745bf920cc1d2a4366000e6574b04ecd7f119601cceadb743fc50a88c3cbd60449f2c76cf4a72f15835d87a9c447ad58523f95824b902529eee1abb183e328a2d79473b3216649c6cd28c6d5e67f0cb74db8828fcbed41bf2cd2f83ef58bf05218e70da4dbdfeb3f45bb801c981f95e1688083a5b7db6feeb887fb76524245d34fac53acb5d0be01159faaa1e56de48fd68af3500c43dd8d30860e7468984f03fe5722ec702e34ebc4bc449195f999cb26949eb4ffd52fd5af3fa730c78706c7943cf409e526b46adf46914e0188948acf934eea0",
        );

        const expectedPk = fromHex(
          "c11014176342e28c839709e764f57df045332e518e9fef163466be19b0df8892",
        );
        const expectedChaincode = fromHex(
          "709028c8a5d46c58a8c42a527201c5d6c4964002a21003620c8efffebb9ac7bc",
        );

        const path = Buffer.from("m/999999'/0'");
        const seed0 = Buffer.alloc(32, 20);
        const seed1 = Buffer.alloc(32, 21);
        const participatingIds = new Uint8Array([0, 1]);
        const doc0 = mps.ed25519_encode_root_document(root0, vrf0);
        const doc1 = mps.ed25519_encode_root_document(root1, vrf1);

        const r0 = [
          mps.ed25519_hard_derive_round0_process(doc0, path, seed0),
          mps.ed25519_hard_derive_round0_process(doc1, path, seed1),
        ];
        const r1 = [0, 1].map((i) =>
          mps.ed25519_hard_derive_round1_process(r0[i ^ 1].msg, r0[i].state),
        );
        const derived0 = mps.ed25519_hard_derive_round2_process(
          r1[1].msg,
          r1[0].state,
          participatingIds,
        );

        assert(
          Buffer.from(derived0.pk).equals(Buffer.from(expectedPk)),
          "derived pk must match the golden vector produced by sl-mps",
        );
        assert(
          Buffer.from(derived0.chaincode).equals(Buffer.from(expectedChaincode)),
          "derived chaincode must match the golden vector produced by sl-mps",
        );
      });
    });
  });
});
