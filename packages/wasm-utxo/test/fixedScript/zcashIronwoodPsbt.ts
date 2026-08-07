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
import { getKeyTriple, getWalletKeysForSeed } from "../../js/testutils/index.js";
import { ZcashUnifiedAddress } from "../../js/fixedScriptWallet/ZcashUnifiedAddress.js";

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

  it("unsignedTxId (the generic PsbtAccess accessor) agrees with getId() for a v6 PSBT", function () {
    // Regression test: unsignedTxId used to fall through to the v4/Sapling txid path for every
    // Zcash PSBT, which builds an invalid transaction for v6 (wrong wire format) and panicked
    // (wasm `unreachable` trap) instead of returning a usable value.
    const psbt = buildShieldPsbt();
    assert.strictEqual(psbt.unsignedTxId(), psbt.getId());
  });

  it("unsignedTxId works before a shielded output has been added", function () {
    const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
      blockHeight: NU6_3_TESTNET_HEIGHT,
    });
    psbt.addWalletInput({ txid: "11".repeat(32), vout: 0, value: 200_000_000n }, walletKeys, {
      scriptId: SCRIPT_ID,
      signPath: { signer: "user", cosigner: "bitgo" },
    });
    psbt.addWalletOutput(walletKeys, { chain: 1, index: 0, value: 199_900_000n });
    assert.match(psbt.unsignedTxId(), /^[0-9a-f]{64}$/);
  });

  // The extraction-accounting regression (unsignedTxId/parseTransactionWithWalletKeys must throw,
  // not silently go transparent-only, once the PCZT has been dropped by combineProof) is covered
  // at the Rust level — `unsigned_v6_txid_and_shielded_output_info_error_after_extraction` in
  // zcash_psbt.rs — since reaching a real extracted PSBT from this package's current JS surface
  // needs a full ECDSA signing flow this test file has no utility for.

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

  describe("parseTransactionWithWalletKeys", function () {
    // The shielded output has no `unsigned_tx` entry of its own (it lives in the PSBT's
    // proprietary-map PCZT), so it is invisible to plain transparent-output parsing unless
    // surfaced explicitly via `isShielded`.
    it("surfaces the shielded output as isShielded and folds its value into fee/spend accounting", function () {
      const psbt = buildShieldPsbt();
      const parsed = psbt.parseTransactionWithWalletKeys(walletKeys, {
        replayProtection: { publicKeys: [] },
      });

      assert.strictEqual(parsed.outputs.length, 2);
      const shielded = parsed.outputs.filter((o) => o.isShielded);
      assert.strictEqual(shielded.length, 1);
      assert.strictEqual(shielded[0].value, 100_000_000n, "the shielded note's value");
      // `address` is a real, usable single-receiver unified address encoding the raw receiver
      // (read from the PCZT's plaintext recipient field, not from decrypting anything); `script`
      // carries the same 43 raw bytes.
      assert.deepStrictEqual(Buffer.from(shielded[0].script), RECIPIENT);
      const ua = ZcashUnifiedAddress.parse(shielded[0].address ?? "", "zcashTest");
      assert.deepStrictEqual(Buffer.from(ua.orchardReceiver ?? []), RECIPIENT);
      assert.strictEqual(shielded[0].derivationPath, null);

      const change = parsed.outputs.find((o) => !o.isShielded);
      assert.strictEqual(change?.derivationPath, "0/0/1/0");

      // 200_000_000 in - (99_900_000 transparent change + 100_000_000 shielded) = 100_000 fee.
      assert.strictEqual(parsed.minerFee, 100_000n);
      // The shielded note counts as an external spend, same as any other non-wallet output.
      assert.strictEqual(parsed.spendAmount, 100_000_000n);
    });

    it("omits the shielded entry for a v6 PSBT with no shielded output yet", function () {
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
        blockHeight: NU6_3_TESTNET_HEIGHT,
      });
      psbt.addWalletInput({ txid: "11".repeat(32), vout: 0, value: 200_000_000n }, walletKeys, {
        scriptId: SCRIPT_ID,
        signPath: { signer: "user", cosigner: "bitgo" },
      });
      psbt.addWalletOutput(walletKeys, { chain: 1, index: 0, value: 199_900_000n });

      const parsed = psbt.parseTransactionWithWalletKeys(walletKeys, {
        replayProtection: { publicKeys: [] },
      });
      assert.strictEqual(parsed.outputs.length, 1);
      assert.strictEqual(parsed.outputs[0].isShielded, false);
      assert.strictEqual(parsed.minerFee, 100_000n);
      assert.strictEqual(parsed.spendAmount, 0n);
    });
  });

  describe("parseOutputsWithWalletKeys", function () {
    // This method skips input validation but shares the same output-parsing path, so the shielded
    // output must be surfaced here too — otherwise a caller using it (e.g. to identify outputs
    // belonging to a different wallet than the inputs) would silently miss the shielded note.
    it("surfaces the shielded output alongside the transparent change output", function () {
      const psbt = buildShieldPsbt();
      const outputs = psbt.parseOutputsWithWalletKeys(walletKeys);

      assert.strictEqual(outputs.length, 2);
      const shielded = outputs.filter((o) => o.isShielded);
      assert.strictEqual(shielded.length, 1);
      assert.strictEqual(shielded[0].value, 100_000_000n);
      assert.deepStrictEqual(Buffer.from(shielded[0].script), RECIPIENT);
      const ua = ZcashUnifiedAddress.parse(shielded[0].address ?? "", "zcashTest");
      assert.deepStrictEqual(Buffer.from(ua.orchardReceiver ?? []), RECIPIENT);
      assert.strictEqual(shielded[0].derivationPath, null);

      const change = outputs.find((o) => !o.isShielded);
      assert.strictEqual(change?.derivationPath, "0/0/1/0");
    });

    it("omits the shielded entry for a v6 PSBT with no shielded output yet", function () {
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
        blockHeight: NU6_3_TESTNET_HEIGHT,
      });
      psbt.addWalletInput({ txid: "11".repeat(32), vout: 0, value: 200_000_000n }, walletKeys, {
        scriptId: SCRIPT_ID,
        signPath: { signer: "user", cosigner: "bitgo" },
      });
      psbt.addWalletOutput(walletKeys, { chain: 1, index: 0, value: 199_900_000n });

      const outputs = psbt.parseOutputsWithWalletKeys(walletKeys);
      assert.strictEqual(outputs.length, 1);
      assert.strictEqual(outputs[0].isShielded, false);
    });
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

  describe("setShieldedOutCiphertext (client-managed ovk)", function () {
    // The ovk is the ECDH agreement of the two *root* wallet keys — bitgoKey()'s pubkey and the user
    // xpriv — so the server, holding the other side of that pair, can re-derive it to validate
    // out_ciphertext without ever seeing the user key or the ovk itself.
    const [USER_KEY] = getKeyTriple("ironwood-ts");

    it("re-encrypts out_ciphertext, changing the sighash and txid, without touching anything else", function () {
      // Server: build the keyless PSBT (`addShieldedOutput` with no `ovk`) and hand off the bytes,
      // matching the microservice build/serve flow — round-tripping through bytes rather than
      // reusing the in-memory object, so this exercises exactly what a real client receives.
      const server = buildShieldPsbt();
      const txidBefore = server.getId();
      const sighashBefore = server.transparentSighash(0);
      const serverBytes = server.serialize();

      // Client: deserialize, then re-encrypt out_ciphertext under its ECDH-derived ovk.
      const client = ZcashIronwoodBitGoPsbt.fromBytes(serverBytes, "zcashTest");
      client.setShieldedOutCiphertext(0, USER_KEY, walletKeys);

      // out_ciphertext is committed by the ZIP-244 sighash (and hence the txid), so both change.
      assert.notStrictEqual(client.getId(), txidBefore);
      assert.notDeepStrictEqual(client.transparentSighash(0), sighashBefore);

      // The patch survives a further serialize round-trip.
      const round = ZcashIronwoodBitGoPsbt.fromBytes(client.serialize(), "zcashTest");
      assert.strictEqual(round.getId(), client.getId());
      assert.deepStrictEqual(round.transparentSighash(0), client.transparentSighash(0));
    });

    it("is deterministic in its two key inputs (same keys -> same sighash)", function () {
      const bytes = buildShieldPsbt().serialize();

      const a = ZcashIronwoodBitGoPsbt.fromBytes(bytes, "zcashTest");
      a.setShieldedOutCiphertext(0, USER_KEY, walletKeys);

      const b = ZcashIronwoodBitGoPsbt.fromBytes(bytes, "zcashTest");
      b.setShieldedOutCiphertext(0, USER_KEY, walletKeys);

      assert.deepStrictEqual(a.transparentSighash(0), b.transparentSighash(0));
    });

    it("a different wallet's keys derive a different ovk, producing a different sighash", function () {
      const bytes = buildShieldPsbt().serialize();

      const a = ZcashIronwoodBitGoPsbt.fromBytes(bytes, "zcashTest");
      a.setShieldedOutCiphertext(0, USER_KEY, walletKeys);

      // Same PSBT, but the ovk pair comes from a different wallet's user/bitgo keys.
      const otherWalletKeys = getWalletKeysForSeed("ironwood-ts-other");
      const [otherUserKey] = getKeyTriple("ironwood-ts-other");
      const b = ZcashIronwoodBitGoPsbt.fromBytes(bytes, "zcashTest");
      b.setShieldedOutCiphertext(0, otherUserKey, otherWalletKeys);

      assert.notDeepStrictEqual(a.transparentSighash(0), b.transparentSighash(0));
    });

    it("rejects an out-of-range action index", function () {
      const psbt = buildShieldPsbt();
      assert.throws(
        () => psbt.setShieldedOutCiphertext(1, USER_KEY, walletKeys),
        /out of range|ActionIndexOutOfRange/i,
      );
    });

    it("rejects a key that is not the wallet's user root key", function () {
      // The backup and bitgo keys would each derive an ovk neither the user nor the server can
      // reproduce, leaving the shielded output permanently unrecoverable — so they are rejected
      // rather than silently accepted.
      const [, backupKey, bitgoKey] = getKeyTriple("ironwood-ts");
      for (const key of [backupKey, bitgoKey, getKeyTriple("some-other-wallet")[0]]) {
        assert.throws(
          () => buildShieldPsbt().setShieldedOutCiphertext(0, key, walletKeys),
          /user root key/i,
        );
      }
    });

    it("rejects a public-only key, which cannot complete the ECDH", function () {
      assert.throws(
        () => buildShieldPsbt().setShieldedOutCiphertext(0, USER_KEY.neutered(), walletKeys),
        /xpriv from public key/i,
      );
    });
  });

  describe("sign() — full client-managed-ovk signing flow", function () {
    // A separate seed/PSBT-builder for this block: `sign()` needs the actual private keys (not just
    // the pubkey-only `walletKeys` used elsewhere in this file), so build from `getKeyTriple`
    // directly.
    const seed = "ironwood-sign-flow";
    const signFlowWalletKeys = getWalletKeysForSeed(seed);
    const [userKey, , bitgoKey] = getKeyTriple(seed);

    function buildSignFlowPsbt(): ZcashIronwoodBitGoPsbt {
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", signFlowWalletKeys, {
        blockHeight: NU6_3_TESTNET_HEIGHT,
      });
      psbt.addWalletInput(
        { txid: "22".repeat(32), vout: 0, value: 200_000_000n },
        signFlowWalletKeys,
        { scriptId: SCRIPT_ID, signPath: { signer: "user", cosigner: "bitgo" } },
      );
      psbt.addWalletOutput(signFlowWalletKeys, { chain: 1, index: 0, value: 99_900_000n });
      psbt.addShieldedOutput(RECIPIENT, 100_000_000n, { anchor: new Uint8Array(32) });
      return psbt;
    }

    it("user signs first (deriving ovk via ECDH), then bitgo signs, producing a combinable tx", function () {
      const psbt = buildSignFlowPsbt();
      const txidBefore = psbt.getId();
      const sighashBefore = psbt.transparentSighash(0);

      const signedByUser = psbt.sign(userKey, signFlowWalletKeys);
      assert.deepStrictEqual(signedByUser, [0], "signed the one transparent input");
      assert.notStrictEqual(
        psbt.getId(),
        txidBefore,
        "user's call derived the ovk via ECDH and finalized out_ciphertext",
      );
      assert.notDeepStrictEqual(psbt.transparentSighash(0), sighashBefore);

      const sighashAfterUser = psbt.transparentSighash(0);
      const signedByBitgo = psbt.sign(bitgoKey, signFlowWalletKeys);
      assert.deepStrictEqual(signedByBitgo, [0]);
      assert.deepStrictEqual(
        psbt.transparentSighash(0),
        sighashAfterUser,
        "bitgo's call did not touch out_ciphertext a second time",
      );

      // A placeholder proof of the real (4992-byte, single-action) size stands in for the external
      // prover; the transparent side is what this test actually exercises.
      const tx = psbt.combineProof(new Uint8Array(4992));
      assert.ok(tx.length > 0, "produced a broadcast-ready v6 transaction");
    });

    it("accepts any WalletKeysArg form, not just a RootWalletKeys instance", function () {
      // BitGoJS passes whatever `RootWalletKeys` it holds — potentially utxo-lib's, or this class
      // resolved from a second copy of the package. Normalizing via `RootWalletKeys.from` (as
      // `createEmpty` and `setShieldedOutCiphertext` do) keeps signing insensitive to class
      // identity, so an xpub triple must derive the same ovk and produce the same signed sighash.
      const xpubs = getKeyTriple(seed).map((k) => k.neutered().toBase58()) as [
        string,
        string,
        string,
      ];

      // One shared PSBT: `addShieldedOutput` builds a fresh random note per call, so only the same
      // serialized bytes make the two sighashes comparable.
      const bytes = buildSignFlowPsbt().serialize();

      const viaInstance = ZcashIronwoodBitGoPsbt.fromBytes(bytes, "zcashTest");
      assert.deepStrictEqual(viaInstance.sign(userKey, signFlowWalletKeys), [0]);

      const viaXpubs = ZcashIronwoodBitGoPsbt.fromBytes(bytes, "zcashTest");
      assert.deepStrictEqual(viaXpubs.sign(userKey, xpubs), [0]);

      assert.deepStrictEqual(
        viaXpubs.transparentSighash(0),
        viaInstance.transparentSighash(0),
        "same wallet keys in a different form derive the same ovk",
      );
    });

    it("throws if rootWalletKeys is omitted, rather than silently signing without the ovk step", function () {
      const psbt = buildSignFlowPsbt();
      assert.throws(() => psbt.sign(userKey), /rootWalletKeys is required/);
    });

    it("signing with an unrelated key signs nothing", function () {
      // An xpriv from a different wallet: it matches no input's bip32_derivation, so nothing is
      // signed — and the ovk step never runs either, since it only runs for a round that signs.
      const psbt = buildSignFlowPsbt();
      const txidBefore = psbt.getId();
      const [stranger] = getKeyTriple("not-this-wallet-either");
      assert.deepStrictEqual(psbt.sign(stranger, signFlowWalletKeys), []);
      assert.strictEqual(psbt.getId(), txidBefore, "out_ciphertext untouched");
    });

    it("rejects a public-only key, which cannot sign or complete the ovk ECDH", function () {
      const psbt = buildSignFlowPsbt();
      assert.throws(
        () => psbt.sign(userKey.neutered(), signFlowWalletKeys),
        /xpriv from public key/i,
      );
    });

    it("rejects the deprecated single-input overload", function () {
      const psbt = buildSignFlowPsbt();
      assert.throws(() => psbt.sign(0, userKey), /no ZIP-244 equivalent/);
    });

    it("rejects a raw privkey (ECPairArg), which has no bip32_derivation path", function () {
      const psbt = buildSignFlowPsbt();
      assert.throws(() => psbt.sign(new Uint8Array(32).fill(0x01)), /bip32_derivation/);
    });

    it("the ordering guard rejects setShieldedOutCiphertext once a real signature exists", function () {
      const psbt = buildSignFlowPsbt();
      // A real signature now exists (this call also finalizes out_ciphertext via its own ovk step).
      psbt.sign(userKey, signFlowWalletKeys);
      assert.throws(
        () => psbt.setShieldedOutCiphertext(0, userKey, signFlowWalletKeys),
        /after a transparent signature has been collected/,
      );
    });

    it("rejects a first signing round opened by bitgo, rather than deriving an unusable ovk", function () {
      // Only the user key can open the round, because that round is what fixes out_ciphertext under
      // the wallet's ovk. If bitgo could sign first, its key would be used as the user's, producing
      // an ovk neither side can reproduce — and the user's later round could not correct it, since a
      // signature would already exist. The tx would still broadcast; the shielded output would simply
      // never be recoverable. So this fails loudly instead.
      const psbt = buildSignFlowPsbt();
      const txidBefore = psbt.getId();
      assert.throws(() => psbt.sign(bitgoKey, signFlowWalletKeys), /user root key/i);
      assert.strictEqual(psbt.getId(), txidBefore, "out_ciphertext untouched");

      // In the correct order it works: user first, then bitgo.
      assert.deepStrictEqual(psbt.sign(userKey, signFlowWalletKeys), [0]);
      assert.deepStrictEqual(psbt.sign(bitgoKey, signFlowWalletKeys), [0]);
    });
  });
});
