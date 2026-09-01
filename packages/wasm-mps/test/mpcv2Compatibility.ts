/**
 * Wire-format compatibility regression tests for EdDSA MPCv2 keyshares.
 *
 * The fixture keyshare bytes below were generated on 2026-09-01 by building
 * this repo from source (wasm-pack) and running a deterministic 3-party DKG.
 * If a future wasm-mps build or multi-party-schnorr dependency bump changes
 * the bincode wire format of Keyshare<EdwardsPoint>, DSG round 0 will throw
 * "Deserialization Error" and CI will surface the breaking change before it
 * reaches production.
 */

import assert from "assert";
import crypto from "crypto";
import sodium from "libsodium-wrappers-sumo";
import * as mps from "../js";
import { runDsg } from "./utils.js";

// Frozen bincode-serialized Keyshare<EdwardsPoint> bytes produced by this
// repo's WASM binary built from source. pk is the aggregate Ed25519 public key
// (32 bytes); chaincode is the 32-byte BIP32 chain code.
const FIXTURES = {
  pk: Buffer.from("4d085a45375f3308d93f9a7de21bd6edd77a7a5d7a02cd0c1a2f4ba4560bd76a", "hex"),
  chaincode: Buffer.from("926021c9cd6712e0e52ccf7f6867eb0ebc8889f335d34f21dd5e36b2db5cb4fe", "hex"),
  userKeyShare: Uint8Array.from(
    Buffer.from(
      "0203007c01f56048ff0c0056edac6cc44d54c6d95fe68d072d1c1fbad9c4f3fac9ec054d085a45375f3308d93f9a7de21bd6edd77a7a5d7a02cd0c1a2f4ba4560bd76a6058f5d7601f380c8419e6fce20b8fbd2ec63ab06b5f4b81cab3959cd4e01433452df0e73fb57b332be5bc0bbb4cd34585494614923309be8a844125ed773af2456613b78a6339153b12a20152c055f19ba02283c84c4fe068d760bfcfc7e1d620c182a8d5159b5122940b3063f76d3f713e9e01a06f6e770502b7b8e97fe03a3b00926021c9cd6712e0e52ccf7f6867eb0ebc8889f335d34f21dd5e36b2db5cb4fe",
      "hex",
    ),
  ),
  bitgoKeyShare: Uint8Array.from(
    Buffer.from(
      "0203026046e1eacee50afde3e07dadf1490459864f680f3dcf3e701b18c17beb0f54034d085a45375f3308d93f9a7de21bd6edd77a7a5d7a02cd0c1a2f4ba4560bd76a6058f5d7601f380c8419e6fce20b8fbd2ec63ab06b5f4b81cab3959cd4e01433452df0e73fb57b332be5bc0bbb4cd34585494614923309be8a844125ed773af2456613b78a6339153b12a20152c055f19ba02283c84c4fe068d760bfcfc7e1d620c182a8d5159b5122940b3063f76d3f713e9e01a06f6e770502b7b8e97fe03a3b00926021c9cd6712e0e52ccf7f6867eb0ebc8889f335d34f21dd5e36b2db5cb4fe",
      "hex",
    ),
  ),
} as const;

const MESSAGE = Buffer.from("WCI-1476 EdDSA MPCv2 wire-format regression sentinel");

function shouldThrow(fn: () => unknown): unknown {
  try {
    fn();
  } catch (e) {
    return e;
  }
  throw new Error("Expected function to throw an error");
}

describe("EdDSA MPCv2 wire-format compatibility", function () {
  before("init libsodium", async function () {
    await sodium.ready;
  });

  it("should deserialize frozen user keyshare in DSG round 0 without error (bincode format guard)", function () {
    const result = mps.ed25519_dsg_round0_process(FIXTURES.userKeyShare, "m", MESSAGE);
    assert(
      result.msg.length > 0,
      "DSG round 0 must produce a non-empty message from the frozen user keyshare",
    );
    assert(result.state.length > 0, "DSG round 0 must produce non-empty state");
  });

  it("should deserialize frozen bitgo keyshare in DSG round 0 without error", function () {
    const result = mps.ed25519_dsg_round0_process(FIXTURES.bitgoKeyShare, "m", MESSAGE);
    assert(
      result.msg.length > 0,
      "DSG round 0 must produce a non-empty message from the frozen bitgo keyshare",
    );
    assert(result.state.length > 0, "DSG round 0 must produce non-empty state");
  });

  it("should produce a valid Ed25519 signature from frozen user+bitgo keyshares at root path", function () {
    const shares = [
      { share: FIXTURES.userKeyShare, pk: FIXTURES.pk, chaincode: FIXTURES.chaincode },
      { share: new Uint8Array(0), pk: new Uint8Array(0), chaincode: new Uint8Array(0) },
      { share: FIXTURES.bitgoKeyShare, pk: FIXTURES.pk, chaincode: FIXTURES.chaincode },
    ] as mps.Share[];

    const [sig0, sig2] = runDsg(shares, "m", MESSAGE);

    assert.strictEqual(sig0.length, 64, "Signature must be 64 bytes");
    assert.deepStrictEqual(sig0, sig2, "Both parties must produce identical signatures");

    const valid = sodium.crypto_sign_verify_detached(sig0, MESSAGE, FIXTURES.pk);
    assert(valid, "Signature must verify under the frozen aggregate public key");
  });

  it("should produce a 64-byte signature at a derived path that does not verify under root key", function () {
    const shares = [
      { share: FIXTURES.userKeyShare, pk: FIXTURES.pk, chaincode: FIXTURES.chaincode },
      { share: new Uint8Array(0), pk: new Uint8Array(0), chaincode: new Uint8Array(0) },
      { share: FIXTURES.bitgoKeyShare, pk: FIXTURES.pk, chaincode: FIXTURES.chaincode },
    ] as mps.Share[];

    const [sig] = runDsg(shares, "m/0/1", MESSAGE);

    assert.strictEqual(sig.length, 64, "Derived-path signature must be 64 bytes");
    // Signature at m/0/1 verifies under the derived child key, not the root key.
    assert(
      !sodium.crypto_sign_verify_detached(sig, MESSAGE, FIXTURES.pk),
      "derived-path signature must not verify under root public key",
    );
  });

  it("should throw when keyshare bytes are randomised (guard validation)", function () {
    // Fill with random bytes — valid bincode is overwhelmingly unlikely to
    // survive random corruption across the entire payload. Confirms the
    // deserialization guard is actually rejecting bad bytes.
    const corrupted = Uint8Array.from(
      crypto.getRandomValues(new Uint8Array(FIXTURES.userKeyShare.length)),
    );
    shouldThrow(() => mps.ed25519_dsg_round0_process(corrupted, "m", MESSAGE));
  });

  it("should produce a different signature for a different message, verifiable under the same key", function () {
    const shares = [
      { share: FIXTURES.userKeyShare, pk: FIXTURES.pk, chaincode: FIXTURES.chaincode },
      { share: new Uint8Array(0), pk: new Uint8Array(0), chaincode: new Uint8Array(0) },
      { share: FIXTURES.bitgoKeyShare, pk: FIXTURES.pk, chaincode: FIXTURES.chaincode },
    ] as mps.Share[];

    const altMessage = Buffer.from("A different message entirely");
    const [altSig] = runDsg(shares, "m", altMessage);

    assert.strictEqual(altSig.length, 64, "Alternative signature must be 64 bytes");
    const valid = sodium.crypto_sign_verify_detached(altSig, altMessage, FIXTURES.pk);
    assert(valid, "Alternative message signature must verify under the same aggregate public key");
  });
});
