import assert from "assert";
import crypto from "crypto";
import * as sl from "@silencelaboratories/dkls-wasm-ll-node";
import { HardDeriveSession } from "../js";
import { hardDerive, seed, slDkg, slSign, verifySignature, vrfDkg } from "./utils.js";

const PATH = Buffer.from("m/0'", "ascii");

describe("HardDeriveSession", function () {
  // key generation on both sides is not cheap
  this.timeout(120_000);

  let rootShares: Uint8Array[];
  let vrfShares: Uint8Array[];

  before(function () {
    rootShares = slDkg(3, 2);
    vrfShares = vrfDkg(3, 2);
  });

  it("derives a key share every signer agrees on", function () {
    const derived = hardDerive(rootShares, vrfShares, [0, 1], PATH);
    assert.strictEqual(derived.length, 2);
    assert.strictEqual(derived[0].publicKey.length, 33);
    assert.strictEqual(derived[0].rootChainCode.length, 32);
    assert.deepStrictEqual(derived[1].publicKey, derived[0].publicKey);
    assert.deepStrictEqual(derived[1].rootChainCode, derived[0].rootChainCode);

    const root = sl.Keyshare.fromBytes(rootShares[0]);
    assert.notDeepStrictEqual(derived[0].publicKey, root.publicKey);
    assert.notDeepStrictEqual(derived[0].rootChainCode, root.publicKey);
  });

  it("derives a different key for a different path", function () {
    const a = hardDerive(rootShares, vrfShares, [0, 1], PATH);
    const b = hardDerive(rootShares, vrfShares, [0, 1], Buffer.from("m/1'", "ascii"));
    assert.notDeepStrictEqual(b[0].publicKey, a[0].publicKey);
  });

  // This is the check that keeps the two wasm builds compatible: a key share generated
  // by Silence Labs' published package goes into our hard derivation, and the derived
  // share goes back into their package and signs. Re-run it on every dependency bump -
  // key share format drift breaks at runtime, not at compile time.
  it("signs with Silence Labs' wasm using a key share we derived", function () {
    const derived = hardDerive(rootShares, vrfShares, [0, 1], PATH);

    const shares = derived.map((d) => sl.Keyshare.fromBytes(d.keyshare));
    assert.deepStrictEqual(
      shares.map((s) => s.partyId),
      [0, 1],
    );
    for (const share of shares) {
      assert.strictEqual(share.threshold, 2);
      assert.strictEqual(share.participants, 3);
      assert.deepStrictEqual(share.publicKey, derived[0].publicKey);
    }

    const message = Buffer.from("bitgo wasm-dkls-vrf hard derivation");
    const messageHash = crypto.createHash("sha256").update(message).digest();
    const signature = slSign(
      derived.map((d) => d.keyshare),
      "m",
      messageHash,
    );

    assert.ok(verifySignature(derived[0].publicKey, message, signature));
  });

  it("works for any quorum of size threshold", function () {
    const derived = hardDerive(rootShares, vrfShares, [1, 2], PATH);
    const message = Buffer.from("quorum 1,2");
    const messageHash = crypto.createHash("sha256").update(message).digest();
    const signature = slSign(
      derived.map((d) => d.keyshare),
      "m",
      messageHash,
    );
    assert.ok(verifySignature(derived[0].publicKey, message, signature));
  });

  it("round-trips sessions between rounds", function () {
    const restore = (s: HardDeriveSession) => HardDeriveSession.fromBytes(s.toBytes());
    const quorum = [0, 1];

    let sessions = quorum.map((i) =>
      restore(new HardDeriveSession(rootShares[i], vrfShares[i], PATH, seed(i, 3))),
    );
    assert.deepStrictEqual(
      sessions.map((s) => s.round),
      [0, 0],
    );

    const msg0 = sessions.map((s) => s.createFirstMessage());
    sessions = sessions.map(restore);

    const msg1 = sessions.map((s, idx) => s.handleRound1Messages(msg0, seed(quorum[idx], 4)));
    assert.deepStrictEqual(
      sessions.map((s) => s.round),
      [1, 1],
    );
    sessions = sessions.map(restore);

    const derived = sessions.map((s) => s.handleRound2Messages(msg1));
    assert.deepStrictEqual(derived[1].publicKey, derived[0].publicKey);
  });

  it("rejects key shares that do not belong together", function () {
    assert.throws(
      () => new HardDeriveSession(rootShares[0], vrfShares[1], PATH, seed(0, 3)),
      /disagree on party id/,
    );
    assert.throws(
      () => new HardDeriveSession(new Uint8Array([1, 2, 3]), vrfShares[0], PATH, seed(0, 3)),
      /deserialization failed/,
    );
    assert.throws(
      () => new HardDeriveSession(rootShares[0], vrfShares[0], PATH, new Uint8Array(8)),
      /seed must be exactly 32 bytes/,
    );
  });

  it("rejects round 0 message sets that are not exactly the quorum", function () {
    const sessions = [0, 1, 2].map(
      (i) => new HardDeriveSession(rootShares[i], vrfShares[i], PATH, seed(i, 3)),
    );
    const msg0 = sessions.map((s) => s.createFirstMessage());

    assert.throws(
      () => sessions[0].handleRound1Messages(msg0, seed(0, 4)),
      /expected 2 round 0 messages, got 3/,
    );
    assert.throws(
      () => sessions[0].handleRound1Messages(msg0.slice(1), seed(0, 4)),
      /missing our own party id 0/,
    );
    assert.throws(
      () => sessions[0].handleRound1Messages(msg0.slice(0, 2), seed(0, 4), Uint8Array.from([0, 2])),
      /.*/,
    );
    assert.doesNotThrow(() => sessions[0].handleRound1Messages(msg0.slice(0, 2), seed(0, 4)));
  });
});
