import assert from "node:assert";
import { describe, it } from "mocha";

import {
  ZcashIronwoodBitGoPsbt,
  zip302NoMemo,
} from "../../js/fixedScriptWallet/ZcashIronwoodBitGoPsbt.js";
import {
  IRONWOOD_VERSION_GROUP_ID,
  ZcashBitGoPsbt,
} from "../../js/fixedScriptWallet/ZcashBitGoPsbt.js";
import { getWalletKeysForSeed } from "../../js/testutils/index.js";

// NU6.3 (Ironwood) testnet activation height.
const NU6_3_TESTNET_HEIGHT = 4134000;

// A valid raw Orchard/Ironwood receiver (43 bytes), derived in Rust from
// SpendingKey([7u8; 32]) → FullViewingKey → address_at(0, External).
const RECIPIENT = Buffer.from(
  "4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d",
  "hex",
);

const SCRIPT_ID = { chain: 0, index: 0 } as const;

describe("ZcashIronwoodBitGoPsbt v6 (Ironwood)", function () {
  const walletKeys = getWalletKeysForSeed("ironwood-ts");

  function buildShieldPsbt(): ZcashIronwoodBitGoPsbt {
    const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
      blockHeight: NU6_3_TESTNET_HEIGHT,
    });
    // One 2-of-3 P2SH transparent input (2 ZEC) and a transparent change output.
    psbt.addWalletInput({ txid: "11".repeat(32), vout: 0, value: 200_000_000n }, walletKeys, {
      scriptId: SCRIPT_ID,
      signPath: { signer: "user", cosigner: "bitgo" },
    });
    psbt.addWalletOutput(walletKeys, { chain: 1, index: 0, value: 99_900_000n });
    // Shielded Ironwood output (1 ZEC). Any valid Pallas base element is a usable build-time
    // anchor (validity against a real tree is a prover concern), so all-zeros works.
    psbt.addShieldedOutput(RECIPIENT, 100_000_000n, { anchor: new Uint8Array(32) });
    return psbt;
  }

  /** The user pubkey in the input's 2-of-3 redeem script (derivation prefix `m/0/0`, then chain/index). */
  function userPubkeyForInput(): Uint8Array {
    return walletKeys.userKey().derivePath(`0/0/${SCRIPT_ID.chain}/${SCRIPT_ID.index}`).publicKey;
  }

  it("creates an Ironwood PSBT with the Ironwood version group id", function () {
    const psbt = buildShieldPsbt();
    assert.strictEqual(psbt.versionGroupId, IRONWOOD_VERSION_GROUP_ID);
  });

  it("computes a canonical v6 txid and 32-byte per-input sighash that survive a serialize round-trip", function () {
    const psbt = buildShieldPsbt();
    const txid = psbt.getId();
    assert.match(txid, /^[0-9a-f]{64}$/, "canonical (display-order) hex txid");
    const sighash = psbt.transparentSighash(0);
    assert.strictEqual(sighash.length, 32);

    // serialize → fromBytes preserves the v6 state (transparent skeleton + PCZT + params).
    const bytes = psbt.serialize();
    const round = ZcashIronwoodBitGoPsbt.fromBytes(bytes, "zcashTest");
    assert.strictEqual(round.versionGroupId, IRONWOOD_VERSION_GROUP_ID);
    assert.strictEqual(round.getId(), txid);
    assert.deepStrictEqual(round.transparentSighash(0), sighash);
  });

  it("rejects a well-formed signature that does not verify against the v6 sighash", function () {
    const psbt = buildShieldPsbt();
    // A pubkey the redeem script actually contains, so the failure comes from verification against
    // the v6 sighash rather than from the pubkey checks below.
    // Minimal well-formed DER encoding of (r, s) = (1, 1) plus the SIGHASH_ALL byte: parses as a
    // signature, cannot verify against any message.
    const sig = Buffer.from("3006020101020101" + "01", "hex");
    assert.throws(
      () => psbt.addTransparentSignature(0, userPubkeyForInput(), sig),
      /does not verify/i,
    );
  });

  it("rejects a signature whose sighash type is not SIGHASH_ALL", function () {
    const psbt = buildShieldPsbt();
    // Same DER body, SIGHASH_NONE (0x02) type byte.
    const sig = Buffer.from("3006020101020101" + "02", "hex");
    assert.throws(
      () => psbt.addTransparentSignature(0, userPubkeyForInput(), sig),
      /must be SIGHASH_ALL/,
    );
  });

  it("rejects a malformed pubkey", function () {
    const psbt = buildShieldPsbt();
    // All-zeros is not a valid secp256k1 point, so this fails before any sighash comparison.
    assert.throws(
      () => psbt.addTransparentSignature(0, new Uint8Array(33), new Uint8Array(72)),
      /invalid pubkey/,
    );
  });

  it("rejects a valid pubkey that is not in the input's redeem script", function () {
    const psbt = buildShieldPsbt();
    const stranger = getWalletKeysForSeed("not-this-wallet").userKey().publicKey;
    assert.throws(
      () => psbt.addTransparentSignature(0, stranger, new Uint8Array(72)),
      /not one of the redeem script's keys/,
    );
  });

  it("rejects an out-of-range transparent input index", function () {
    const psbt = buildShieldPsbt();
    assert.throws(() => psbt.transparentSighash(5), /out of range/);
  });

  describe("addShieldedOutput byte-length validation", function () {
    // Each field is validated at the wasm boundary, before the orchard builder is touched.
    const anchor = new Uint8Array(32);
    const cases: Array<[string, () => void, RegExp]> = [
      [
        "recipient",
        () => buildShieldPsbt().addShieldedOutput(new Uint8Array(10), 1n, { anchor }),
        /recipient must be 43 bytes/,
      ],
      [
        "anchor",
        () => buildShieldPsbt().addShieldedOutput(RECIPIENT, 1n, { anchor: new Uint8Array(31) }),
        /anchor must be 32 bytes/,
      ],
      [
        "memo",
        () =>
          buildShieldPsbt().addShieldedOutput(RECIPIENT, 1n, { anchor, memo: new Uint8Array(511) }),
        /memo must be 512 bytes/,
      ],
      [
        "ovk",
        () =>
          buildShieldPsbt().addShieldedOutput(RECIPIENT, 1n, { anchor, ovk: new Uint8Array(31) }),
        /ovk must be 32 bytes/,
      ],
    ];
    for (const [field, run, expected] of cases) {
      it(`rejects a ${field} of the wrong length`, function () {
        assert.throws(run, expected);
      });
    }
  });

  it("rejects a second Ironwood output", function () {
    const psbt = buildShieldPsbt();
    assert.throws(
      () => psbt.addShieldedOutput(RECIPIENT, 1n, { anchor: new Uint8Array(32) }),
      /already present/,
    );
  });

  describe("combineProof", function () {
    // The Rust `combine_ironwood_proof` consumes `self`, so the wasm binding clones and only calls
    // `mark_ironwood_extracted()` after the clone has actually produced a transaction. That ordering
    // is a property of the binding, not of the Rust function it wraps (a consuming call has no
    // "after failure" state to be in), so it is only observable — and only pinned — from here.

    it("leaves the PSBT usable when it fails, so the call is retryable", function () {
      const psbt = buildShieldPsbt();
      const txid = psbt.getId();

      // The transparent input is unsigned, so finalization fails before the proof is ever used.
      assert.throws(() => psbt.combineProof(new Uint8Array(192)));

      // Nothing was dropped: the PCZT is still in the proprietary map, so every v6 read still works
      // and returns what it did before. A transient prover failure must not brick the PSBT.
      assert.strictEqual(psbt.getId(), txid);
      assert.strictEqual(psbt.transparentSighash(0).length, 32);

      // ...and it survives a round-trip, which `deserialize_v6` would reject if the PCZT were gone.
      const round = ZcashIronwoodBitGoPsbt.fromBytes(psbt.serialize(), "zcashTest");
      assert.strictEqual(round.getId(), txid);
    });

    it("reports the missing transparent signatures rather than a proof error", function () {
      // Finalization runs before the (expensive) shielded combine, so an under-signed PSBT fails
      // fast and the message points at the signatures, not at the placeholder proof bytes.
      assert.throws(() => buildShieldPsbt().combineProof(new Uint8Array(192)), /signature/i);
    });
  });

  it("the default memo is the ZIP-302 no-memo encoding, not all zeros", function () {
    // `addShieldedOutput` defaults `memo` to this. Asserted on the encoding rather than by comparing
    // txids across two builds: `construct_shield_pczt` draws a random rseed, so two separately-built
    // PSBTs have different note ciphertexts (hence different txids) whatever their memos.
    const memo = zip302NoMemo();
    assert.strictEqual(memo.length, 512);
    assert.strictEqual(memo[0], 0xf6, "ZIP-302 no-memo marker byte");
    assert.ok(
      memo.slice(1).every((b: number) => b === 0),
      "remaining bytes are zero padding",
    );
  });

  it("zip302NoMemo returns a fresh array, so a caller cannot poison the default", function () {
    const mine = zip302NoMemo();
    mine[0] = 0x00;
    assert.strictEqual(zip302NoMemo()[0], 0xf6);
  });

  describe("createEmptyWithConsensusBranchId", function () {
    // Only the *version group id* is fixed by the v6 format; the consensus branch id tracks the
    // active network upgrade, so it stays caller-supplied exactly as it is for v4.
    const NU6_3_TESTNET_BRANCH_ID = ZcashBitGoPsbt.branchIdForHeight(
      "zcashTest",
      NU6_3_TESTNET_HEIGHT,
    );
    assert.ok(NU6_3_TESTNET_BRANCH_ID !== undefined, "NU6.3 testnet branch id is known");

    it("builds a v6 PSBT equivalent to the block-height factory", function () {
      const explicit = ZcashIronwoodBitGoPsbt.createEmptyWithConsensusBranchId(
        "zcashTest",
        walletKeys,
        { consensusBranchId: NU6_3_TESTNET_BRANCH_ID },
      );
      const byHeight = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
        blockHeight: NU6_3_TESTNET_HEIGHT,
      });
      assert.strictEqual(explicit.versionGroupId, IRONWOOD_VERSION_GROUP_ID);
      assert.strictEqual(explicit.consensusBranchId, byHeight.consensusBranchId);
      assert.strictEqual(explicit.versionGroupId, byHeight.versionGroupId);
    });

    it("returns the Ironwood subclass, not a v4-shaped base instance", function () {
      const psbt = ZcashIronwoodBitGoPsbt.createEmptyWithConsensusBranchId(
        "zcashTest",
        walletKeys,
        { consensusBranchId: NU6_3_TESTNET_BRANCH_ID },
      );
      assert.ok(psbt instanceof ZcashIronwoodBitGoPsbt);
      // The v6-only surface is reachable, which it would not be on a base `ZcashBitGoPsbt`.
      psbt.addShieldedOutput(RECIPIENT, 100_000_000n, { anchor: new Uint8Array(32) });
      assert.strictEqual(psbt.transparentSighash.length, 1);
    });

    it("accepts an arbitrary branch id, unlike the height factory", function () {
      // The escape hatch does no activation check — that is the point of it.
      const psbt = ZcashIronwoodBitGoPsbt.createEmptyWithConsensusBranchId(
        "zcashTest",
        walletKeys,
        { consensusBranchId: 0x12345678, expiryHeight: 99 },
      );
      assert.strictEqual(psbt.consensusBranchId, 0x12345678);
      assert.strictEqual(psbt.expiryHeight, 99);
      assert.strictEqual(psbt.versionGroupId, IRONWOOD_VERSION_GROUP_ID);
    });
  });

  describe("factories that v6 cannot implement are fenced off", function () {
    // Inherited because JS statics are inherited; each would hand back a v4-shaped
    // `ZcashBitGoPsbt` (they construct the base class directly), so each must refuse instead.
    // Unlike `createEmptyWithConsensusBranchId`, these two are not merely unwired — a broadcast v6
    // transaction cannot yield the PCZT witness data every v6 operation needs.
    const cases: Array<[string, () => void]> = [
      ["fromNetworkFormat", () => ZcashIronwoodBitGoPsbt.fromNetworkFormat()],
      [
        "fromHalfSignedLegacyTransaction",
        () => ZcashIronwoodBitGoPsbt.fromHalfSignedLegacyTransaction(),
      ],
    ];
    for (const [name, run] of cases) {
      it(`${name} throws`, function () {
        assert.throws(run, /not supported for v6/);
      });
    }
  });

  it("ZcashBitGoPsbt.fromBytes rejects a v6 (Ironwood) PSBT", function () {
    const bytes = buildShieldPsbt().serialize();
    assert.throws(() => ZcashBitGoPsbt.fromBytes(bytes, "zcashTest"), /Ironwood/);
  });

  it("ZcashIronwoodBitGoPsbt.fromBytes rejects a non-v6 (v4/Sapling) PSBT", function () {
    const v4Psbt = ZcashBitGoPsbt.createEmpty("zcashTest", walletKeys, {
      blockHeight: NU6_3_TESTNET_HEIGHT,
    });
    v4Psbt.addWalletInput({ txid: "11".repeat(32), vout: 0, value: 200_000_000n }, walletKeys, {
      scriptId: SCRIPT_ID,
      signPath: { signer: "user", cosigner: "bitgo" },
    });
    v4Psbt.addWalletOutput(walletKeys, { chain: 1, index: 0, value: 199_900_000n });
    const bytes = v4Psbt.serialize();
    assert.throws(() => ZcashIronwoodBitGoPsbt.fromBytes(bytes, "zcashTest"), /not a v6/);
  });
});
