import assert from "assert";
import { VrfDkgSession, VrfKeyshare } from "../js";
import { range, seed, vrfDkg } from "./utils.js";

describe("VrfDkgSession", function () {
  it("runs a 2-of-3 DKG that agrees on the VRF public key", function () {
    const shares = vrfDkg(3, 2).map((bytes) => VrfKeyshare.fromBytes(bytes));
    assert.strictEqual(shares.length, 3);

    for (const [i, share] of shares.entries()) {
      assert.strictEqual(share.partyId, i);
      assert.strictEqual(share.threshold, 2);
      assert.strictEqual(share.participants, 3);
      assert.strictEqual(share.publicKey.length, 32);
      assert.strictEqual(share.keyId.length, 32);
      assert.strictEqual(share.rootChainCode.length, 32);
      assert.deepStrictEqual(share.publicKey, shares[0].publicKey);
      assert.deepStrictEqual(share.keyId, shares[0].keyId);
      assert.deepStrictEqual(share.rootChainCode, shares[0].rootChainCode);
    }
  });

  it("runs a 3-of-3 DKG", function () {
    const shares = vrfDkg(3, 3).map((bytes) => VrfKeyshare.fromBytes(bytes));
    assert.deepStrictEqual(shares[2].publicKey, shares[0].publicKey);
  });

  it("round-trips key shares", function () {
    const bytes = vrfDkg(3, 2)[1];
    const share = VrfKeyshare.fromBytes(bytes);
    assert.deepStrictEqual(share.toBytes(), bytes);
    assert.strictEqual(share.partyId, 1);
  });

  it("round-trips sessions between rounds", function () {
    const restore = (s: VrfDkgSession) => VrfDkgSession.fromBytes(s.toBytes());

    let sessions = range(3).map((i) => restore(new VrfDkgSession(3, 2, i, seed(i, 0))));
    assert.deepStrictEqual(
      sessions.map((s) => s.round),
      [1, 1, 1],
    );

    const msg1 = sessions.map((s, i) => s.createFirstMessage(seed(i, 1)));
    sessions = sessions.map(restore);

    const msg2 = sessions.map((s, i) => s.handleRound1Messages(msg1, seed(i, 2)));
    assert.deepStrictEqual(
      sessions.map((s) => s.round),
      [2, 2, 2],
    );
    sessions = sessions.map(restore);

    const shares = sessions.map((s) => s.handleRound2Messages(msg2));
    assert.deepStrictEqual(shares[1].publicKey, shares[0].publicKey);
  });

  it("is deterministic for fixed seeds", function () {
    const a = VrfKeyshare.fromBytes(vrfDkg(3, 2)[0]);
    const b = VrfKeyshare.fromBytes(vrfDkg(3, 2)[0]);
    assert.deepStrictEqual(a.publicKey, b.publicKey);
  });

  it("rejects bad parameters", function () {
    assert.throws(() => new VrfDkgSession(3, 1, 0, seed(0, 0)), /threshold must be at least 2/);
    assert.throws(() => new VrfDkgSession(3, 4, 0, seed(0, 0)), /exceeds participants/);
    assert.throws(() => new VrfDkgSession(3, 2, 3, seed(0, 0)), /party id 3 is not in 0\.\.3/);
    assert.throws(
      () => new VrfDkgSession(3, 2, 0, new Uint8Array(16)),
      /seed must be exactly 32 bytes/,
    );
  });

  it("rejects wrong message counts, duplicate senders and round skipping", function () {
    const sessions = range(3).map((i) => new VrfDkgSession(3, 2, i, seed(i, 0)));

    assert.throws(() => sessions[0].handleRound2Messages([]), /expected round 2/);

    const msg1 = sessions.map((s, i) => s.createFirstMessage(seed(i, 1)));
    assert.throws(
      () => sessions[0].handleRound1Messages(msg1.slice(0, 2), seed(0, 2)),
      /expected 2 round 1 messages from peers, got 1/,
    );
    assert.throws(
      () => sessions[0].handleRound1Messages([msg1[0], msg1[1], msg1[1]], seed(0, 2)),
      /duplicate message from party 1/,
    );

    const msg2 = sessions.map((s, i) => s.handleRound1Messages(msg1, seed(i, 2)));
    assert.throws(
      () => sessions[0].handleRound2Messages(msg2.slice(0, 2)),
      /expected 3 round 2 messages, got 2/,
    );
    assert.doesNotThrow(() => sessions[0].handleRound2Messages(msg2));
  });

  it("rejects state bytes without the matching domain prefix", function () {
    const session = new VrfDkgSession(3, 2, 0, seed(0, 0));
    const bytes = session.toBytes();
    assert.throws(
      () => VrfDkgSession.fromBytes(bytes.slice(1)),
      /do not carry the expected domain prefix/,
    );
  });
});
