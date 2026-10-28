import assert from "node:assert";
import { describe, it } from "mocha";

import {
  ZcashIronwoodBitGoPsbt,
  type CreateEmptyIronwoodOptions,
} from "../../js/fixedScriptWallet/ZcashIronwoodBitGoPsbt.js";
import { ZcashIronwoodWitness } from "../../js/fixedScriptWallet/ZcashIronwoodWitness.js";
import { ZcashV6Transaction } from "../../js/fixedScriptWallet/ZcashV6Transaction.js";
import { getWalletKeysForSeed } from "../../js/testutils/index.js";
import type {
  IronwoodShieldedStatus,
  ZcashShieldedOutputRequest,
  ZcashShieldedSpendRequest,
} from "../../js/fixedScriptWallet/ZcashIronwoodTypes.js";
import {
  assertErrorCode,
  freshPsbt,
  hex,
  loadFixture,
  type IronwoodSpendFixture,
} from "./zcashIronwoodSpend.util.js";

/** The fixture's spend request, with witnesses rebuilt (and re-validated) from the raw path. */
function spendRequests(fixture: IronwoodSpendFixture): ZcashShieldedSpendRequest[] {
  return fixture.request.spends.map((spend) => ({
    recipient: hex(spend.recipient),
    value: BigInt(spend.value),
    rho: hex(spend.rho),
    rseed: hex(spend.rseed),
    cmx: hex(spend.cmx),
    witness: ZcashIronwoodWitness.build(
      hex(spend.cmx),
      spend.witness.position,
      spend.witness.authPath.map(hex),
      hex(fixture.request.anchor),
    ),
    nullifier: hex(spend.nullifier),
  }));
}

function outputRequests(fixture: IronwoodSpendFixture): ZcashShieldedOutputRequest[] {
  return fixture.request.outputs.map((output) => ({
    recipient: hex(output.recipient),
    amount: BigInt(output.amount),
    memo: hex(output.memo),
    ...(output.unifiedAddress ? { unifiedAddress: output.unifiedAddress } : {}),
  }));
}

/** `serialize` → `fromBytes`: the wire round-trip every lifecycle step must survive. */
function roundtrip(psbt: ZcashIronwoodBitGoPsbt): ZcashIronwoodBitGoPsbt {
  return ZcashIronwoodBitGoPsbt.fromBytes(psbt.serialize(), "zcashTest");
}

/** Whether `needle`'s byte sequence appears anywhere in `haystack`. */
function containsSequence(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let start = 0; start + needle.length <= haystack.length; start++) {
    for (let offset = 0; offset < needle.length; offset++) {
      if (haystack[start + offset] !== needle[offset]) {
        continue outer;
      }
    }
    return true;
  }
  return false;
}

/** Status view with index lists sorted, for order-independent comparison. */
function normalizedStatus(status: IronwoodShieldedStatus): IronwoodShieldedStatus {
  const sort = (indices: number[]) => indices.slice().sort((a, b) => a - b);
  return {
    ...status,
    pendingOutCiphertexts: sort(status.pendingOutCiphertexts),
    pendingRandomizers: sort(status.pendingRandomizers),
    pendingSpendSignatures: sort(status.pendingSpendSignatures),
  };
}

/** The expected pre-work status of the fixture's post-construction PSBT. */
function expectedPending(fixture: IronwoodSpendFixture): {
  inputKind: "shielded";
  pendingOutCiphertexts: number[];
  pendingRandomizers: number[];
  pendingSpendSignatures: number[];
  readyForProof: boolean;
} {
  const spendIndices = fixture.spendActionIndices.slice().sort((a, b) => a - b);
  const outputIndices = fixture.outputActionIndices.slice().sort((a, b) => a - b);
  return {
    inputKind: "shielded",
    pendingOutCiphertexts: outputIndices,
    pendingRandomizers: spendIndices,
    pendingSpendSignatures: spendIndices,
    readyForProof: false,
  };
}

describe("ZcashIronwoodBitGoPsbt shielded spends", function () {
  const walletKeys = getWalletKeysForSeed("ironwood-ts");
  const createOptions = (blockHeight: number): CreateEmptyIronwoodOptions => ({ blockHeight });
  const scriptId = { chain: 0, index: 0 } as const;
  const signPath = { signer: "user", cosigner: "bitgo" } as const;

  describe("keyless construction (addShieldedSpends)", function () {
    it("constructs a spend bundle from the fixture request and maps the actions", function () {
      for (const fixture of [loadFixture("deshield"), loadFixture("transfer")]) {
        const psbt = ZcashIronwoodBitGoPsbt.createEmpty(
          fixture.network,
          walletKeys,
          createOptions(fixture.blockHeight),
        );
        if (fixture.request.transparentOutput) {
          psbt.addTransparentOutput(
            hex(fixture.request.transparentOutput.script),
            BigInt(fixture.request.transparentOutput.value),
          );
        }
        const map = psbt.addShieldedSpends(spendRequests(fixture), outputRequests(fixture), {
          anchor: hex(fixture.request.anchor),
        });

        // Every request landed at an action, all distinct, and the bundle has exactly
        // max(spends, outputs) actions (deshield: 1 spend + a fabricated dummy output).
        assert.strictEqual(map.spendActionIndices.length, fixture.request.spends.length);
        assert.strictEqual(map.outputActionIndices.length, fixture.request.outputs.length);
        const actions = new Set([...map.spendActionIndices, ...map.outputActionIndices]);
        assert.strictEqual(
          actions.size,
          Math.max(fixture.request.spends.length, fixture.request.outputs.length),
        );

        // Freshly constructed: everything pending, nothing signed, not ready for proof.
        assert.deepStrictEqual(normalizedStatus(psbt.shieldedStatus()), expectedPending(fixture));

        // The ZIP-317 fee matches the seeded fixture value recorded at the same stage.
        assert.strictEqual(psbt.zip317ConventionalFee(), BigInt(fixture.zip317ConventionalFee));

        // One input kind: no transparent input may join a spend bundle.
        assert.throws(
          () =>
            psbt.addWalletInput({ txid: "11".repeat(32), vout: 0, value: 100_000n }, walletKeys, {
              scriptId,
              signPath,
            }),
          /one input kind per transaction/,
        );
      }
    });

    it("rejects shielded spends on a PSBT that already carries transparent inputs", function () {
      const fixture = loadFixture("deshield");
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty(
        fixture.network,
        walletKeys,
        createOptions(fixture.blockHeight),
      );
      psbt.addWalletInput({ txid: "11".repeat(32), vout: 0, value: 200_000_000n }, walletKeys, {
        scriptId,
        signPath,
      });
      assertErrorCode(
        () =>
          psbt.addShieldedSpends(spendRequests(fixture), outputRequests(fixture), {
            anchor: hex(fixture.request.anchor),
          }),
        "IronwoodPsbtError.MixedInputKinds",
      );
    });

    it("leaves the caller's witnesses usable, so a failed build can be retried", function () {
      const fixture = loadFixture("transfer");
      const spends = spendRequests(fixture);
      const outputs = outputRequests(fixture);
      const options = { anchor: hex(fixture.request.anchor) };
      const rejected = ZcashIronwoodBitGoPsbt.createEmpty(
        fixture.network,
        walletKeys,
        createOptions(fixture.blockHeight),
      );
      rejected.addWalletInput({ txid: "11".repeat(32), vout: 0, value: 100_000n }, walletKeys, {
        scriptId,
        signPath,
      });
      assertErrorCode(
        () => rejected.addShieldedSpends(spends, outputs, options),
        "IronwoodPsbtError.MixedInputKinds",
      );

      const psbt = ZcashIronwoodBitGoPsbt.createEmpty(
        fixture.network,
        walletKeys,
        createOptions(fixture.blockHeight),
      );
      psbt.addShieldedSpends(spends, outputs, options);
      for (const [i, spend] of spends.entries()) {
        assert.strictEqual(spend.witness.position, fixture.request.spends[i].witness.position);
      }
    });

    it("rejects wrongly sized byte fields with a typed code", function () {
      const fixture = loadFixture("deshield");
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty(
        fixture.network,
        walletKeys,
        createOptions(fixture.blockHeight),
      );
      const [spend] = spendRequests(fixture);
      assertErrorCode(
        () =>
          psbt.addShieldedSpends([{ ...spend, rho: spend.rho.slice(1) }], [], {
            anchor: hex(fixture.request.anchor),
          }),
        "IronwoodPsbtError.BadLength",
      );
      assertErrorCode(
        () => psbt.addShieldedSpends([spend], [], { anchor: new Uint8Array(31) }),
        "IronwoodPsbtError.BadLength",
      );

      const built = freshPsbt(fixture);
      const [randomizer] = fixture.randomizers;
      assertErrorCode(
        () =>
          built.addSpendRandomizers([
            {
              actionIndex: randomizer.actionIndex,
              alpha: new Uint8Array(31),
              rk: hex(randomizer.rk),
            },
          ]),
        "IronwoodPsbtError.BadLength",
      );
      assertErrorCode(
        () => built.addSpendSignature(randomizer.actionIndex, new Uint8Array(63)),
        "IronwoodPsbtError.BadLength",
      );
    });
  });

  describe("shielded change (addShieldedSpends options.change)", function () {
    it("routes change to the chosen spend's own address and verifies as isChange", function () {
      const fixture = loadFixture("transfer");
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty(
        fixture.network,
        walletKeys,
        createOptions(fixture.blockHeight),
      );
      const spends = spendRequests(fixture);
      // One external output alongside the change: 180M spent − (89.995M + 80M) = 10.005M fee.
      const [external] = outputRequests(fixture);
      const { spendActionIndices, outputActionIndices, changeActionIndex } = psbt.addShieldedSpends(
        spends,
        [external],
        {
          anchor: hex(fixture.request.anchor),
          change: { amount: 80_000_000n, spendIndex: 1 },
        },
      );
      assert.strictEqual(spendActionIndices.length, spends.length);
      assert.notStrictEqual(changeActionIndex, null);
      // The change output is the extra, last entry of outputActionIndices.
      assert.strictEqual(outputActionIndices.length, 2);
      assert.strictEqual(outputActionIndices[1], changeActionIndex);

      const report = psbt.verifyShieldedBundle();
      assert.strictEqual(report.outputs.length, 2);
      const change = report.outputs.find((output) => output.actionIndex === changeActionIndex);
      assert.ok(change);
      assert.strictEqual(change.isChange, true);
      assert.strictEqual(change.value, 80_000_000n);
      assert.strictEqual(change.memo.length, 512);
      const spentFrom = report.spends.find((spend) => spend.actionIndex === spendActionIndices[1]);
      assert.ok(spentFrom);
      assert.deepStrictEqual(Buffer.from(change.recipient), Buffer.from(spentFrom.recipient));
      // The requested output pays an address no spend comes from: it stays external.
      const sent = report.outputs.find((output) => output.actionIndex === outputActionIndices[0]);
      assert.ok(sent);
      assert.strictEqual(sent.isChange, false);
      assert.strictEqual(sent.value, external.amount);
      assert.deepStrictEqual(
        Buffer.from(sent.memo),
        Buffer.from(hex(fixture.request.outputs[0].memo)),
      );

      // The parse keeps the change out of spendAmount but still counts it as output value.
      const parsed = psbt.parseTransactionWithWalletKeys(walletKeys, {
        replayProtection: { publicKeys: [] },
      });
      assert.strictEqual(parsed.spendAmount, external.amount);
      assert.strictEqual(parsed.minerFee, 180_000_000n - external.amount - 80_000_000n);
      assert.deepStrictEqual(
        parsed.outputs.map((output) => [output.actionIndex, output.isChange]),
        report.outputs.map((output) => [output.actionIndex, output.isChange]),
      );
    });

    it("rejects change naming a spend index outside the request", function () {
      const fixture = loadFixture("deshield");
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty(
        fixture.network,
        walletKeys,
        createOptions(fixture.blockHeight),
      );
      assertErrorCode(
        () =>
          psbt.addShieldedSpends(spendRequests(fixture), [], {
            anchor: hex(fixture.request.anchor),
            change: { amount: 1n, spendIndex: 7 },
          }),
        "IronwoodPsbtError.BadChangeSpend",
      );
    });
  });

  for (const name of ["deshield", "transfer"]) {
    describe(`lifecycle: ${name}`, function () {
      const fixture = loadFixture(name);
      const spendIndices = fixture.spendActionIndices.slice().sort((a, b) => a - b);
      const ciphertextEntries = fixture.outCiphertexts.map((entry) => ({
        actionIndex: entry.actionIndex,
        outCiphertext: hex(entry.outCiphertext),
      }));
      const randomizerEntries = fixture.randomizers.map((entry) => ({
        actionIndex: entry.actionIndex,
        alpha: hex(entry.alpha),
        rk: hex(entry.rk),
      }));
      const signatureEntries = fixture.signatures.map((entry) => ({
        actionIndex: entry.actionIndex,
        signature: hex(entry.signature),
      }));
      const alphaEntries = fixture.randomizers.map((entry) => ({
        actionIndex: entry.actionIndex,
        alpha: hex(entry.alpha),
      }));
      const ak = hex(fixture.ak);
      /** The anchor refresh: one re-witnessed entry per real spend under the refreshed root. */
      const refreshEntries = fixture.refresh.witnesses.map((entry) => ({
        actionIndex: entry.actionIndex,
        witness: ZcashIronwoodWitness.build(
          hex(entry.cmx),
          entry.position,
          entry.authPath.map(hex),
          hex(fixture.refresh.anchor),
        ),
      }));
      function refreshAnchor(psbt: ZcashIronwoodBitGoPsbt): void {
        psbt.updateAnchorAndWitnesses(hex(fixture.refresh.anchor), refreshEntries);
      }

      /** Drives a fresh PSBT to the signed state (ciphertexts → refresh → randomizers →
       * signatures), with the anchor refresh before any signature. */
      function psbtReadyForProof(): ZcashIronwoodBitGoPsbt {
        const psbt = freshPsbt(fixture);
        if (ciphertextEntries.length > 0) {
          psbt.addOutCiphertexts(ciphertextEntries);
        }
        refreshAnchor(psbt);
        psbt.addSpendRandomizers(randomizerEntries, { spendValidatingKey: ak });
        psbt.addSpendSignatures(signatureEntries);
        return psbt;
      }

      it("runs the full build → ciphertexts → sign → prove flow with wire round-trips", function () {
        let psbt = freshPsbt(fixture);

        // Ciphertexts first: randomizers are rejected while any out_ciphertext is pending.
        if (ciphertextEntries.length > 0) {
          assertErrorCode(
            () => psbt.addSpendRandomizers(randomizerEntries),
            "IronwoodPsbtError.OutCiphertextPending",
          );

          // The request names exactly the pending real outputs.
          const request = psbt.getOutCiphertextRequest();
          assert.deepStrictEqual(
            request.actionIndices.slice().sort((a, b) => a - b),
            ciphertextEntries.map((entry) => entry.actionIndex).sort((a, b) => a - b),
          );
          assert.ok(request.pczt instanceof Uint8Array && request.pczt.length > 0);

          psbt.addOutCiphertexts(ciphertextEntries);
          assert.deepStrictEqual(psbt.shieldedStatus().pendingOutCiphertexts, []);
          psbt = roundtrip(psbt);
        } else {
          // A pure deshield has no shielded outputs, so there is nothing to request.
          assertErrorCode(() => psbt.getOutCiphertextRequest(), "IronwoodPsbtError.NothingPending");
        }

        // The anchor refresh lands before the signing rounds: the build's approval is
        // assumed to have sat long enough that the anchor moved.
        refreshAnchor(psbt);

        // Randomizers next: no sighash while any real spend still carries the placeholder rk.
        assertErrorCode(() => psbt.spendSighash(), "IronwoodPsbtError.RandomizerPending");
        assertErrorCode(
          () => psbt.getProofRequest(alphaEntries),
          "IronwoodPsbtError.RandomizerPending",
        );
        psbt.addSpendRandomizers(randomizerEntries, { spendValidatingKey: ak });
        psbt = roundtrip(psbt);

        // The randomized rks changed the digest: it matches the fixture's, computed over the
        // same ciphertexts and rks.
        assert.strictEqual(Buffer.from(psbt.spendSighash()).toString("hex"), fixture.sighash);
        assert.deepStrictEqual(psbt.shieldedStatus().pendingRandomizers, []);
        assert.strictEqual(psbt.getId(), fixture.expectedTxid);

        // Signed before proven: the proof is requested only once the wallet has signed.
        assertErrorCode(
          () => psbt.getProofRequest(alphaEntries),
          "IronwoodPsbtError.SpendSignaturePending",
        );
        psbt.addSpendSignatures(signatureEntries);
        psbt = roundtrip(psbt);

        const signedStatus = psbt.shieldedStatus();
        assert.deepStrictEqual(signedStatus.pendingSpendSignatures, []);
        assert.strictEqual(signedStatus.readyForProof, true);

        // The gated proof request returns exactly the bytes the prover proved over — alphas patched
        // in, never stored.
        assert.strictEqual(
          Buffer.from(psbt.getProofRequest(alphaEntries)).toString("hex"),
          fixture.proofRequest,
        );
      });

      it("refreshes the anchor and every spend's witness, and the lifecycle proceeds over it", function () {
        const psbt = freshPsbt(fixture);
        if (ciphertextEntries.length > 0) {
          psbt.addOutCiphertexts(ciphertextEntries);
        }
        assert.strictEqual(
          Buffer.from(psbt.verifyShieldedBundle().anchor).toString("hex"),
          fixture.request.anchor,
          "the bundle anchors to the build-time root before the refresh",
        );

        // The refresh re-anchors the bundle; the key-free verifier accepts it, since every
        // fresh witness recomputes to the new root over its spend's own cmx. The refresh
        // survives the wire round-trip.
        refreshAnchor(psbt);
        assert.strictEqual(
          Buffer.from(psbt.verifyShieldedBundle().anchor).toString("hex"),
          fixture.refresh.anchor,
        );
        const round = roundtrip(psbt);
        assert.strictEqual(
          Buffer.from(round.verifyShieldedBundle().anchor).toString("hex"),
          fixture.refresh.anchor,
        );

        // The refreshed bundle carries the same digest as the fixture's post-refresh run.
        round.addSpendRandomizers(randomizerEntries, { spendValidatingKey: ak });
        assert.strictEqual(Buffer.from(round.spendSighash()).toString("hex"), fixture.sighash);
      });

      it("rejects a stale witness (still anchoring the old root) and stores nothing", function () {
        const psbt = freshPsbt(fixture);
        if (ciphertextEntries.length > 0) {
          psbt.addOutCiphertexts(ciphertextEntries);
        }
        const before = psbt.getPczt();
        // The build-time witnesses — validated against the old anchor — no longer recompute
        // to the refreshed root, and one bad entry stores nothing.
        const stale = fixture.request.spends.map((spend, i) => ({
          actionIndex: fixture.refresh.witnesses[i].actionIndex,
          witness: ZcashIronwoodWitness.build(
            hex(spend.cmx),
            spend.witness.position,
            spend.witness.authPath.map(hex),
            hex(fixture.request.anchor),
          ),
        }));
        assertErrorCode(
          () => psbt.updateAnchorAndWitnesses(hex(fixture.refresh.anchor), stale),
          "IronwoodBuildError.WitnessAnchorMismatch",
        );
        assert.deepStrictEqual(Buffer.from(psbt.getPczt()), Buffer.from(before));
      });

      it("rejects bad batches: empty, duplicate, partial coverage, unknown action", function () {
        const psbt = freshPsbt(fixture);
        if (ciphertextEntries.length > 0) {
          psbt.addOutCiphertexts(ciphertextEntries);
        }
        const anchor = hex(fixture.refresh.anchor);
        assertErrorCode(
          () => psbt.updateAnchorAndWitnesses(anchor, []),
          "IronwoodPsbtError.NothingPending",
        );
        assertErrorCode(
          () => psbt.updateAnchorAndWitnesses(anchor, [refreshEntries[0], refreshEntries[0]]),
          "IronwoodPsbtError.DuplicateAction",
        );
        if (refreshEntries.length > 1) {
          // A batch covering only one of the two real spends: the anchor is bundle-level,
          // so the uncovered spend would be left anchoring the old root.
          assertErrorCode(
            () => psbt.updateAnchorAndWitnesses(anchor, [refreshEntries[0]]),
            "IronwoodPsbtError.WitnessMissing",
          );
        }
        // Every real spend covered, plus one out-of-range index.
        assertErrorCode(
          () =>
            psbt.updateAnchorAndWitnesses(anchor, [
              ...refreshEntries,
              { actionIndex: 99, witness: refreshEntries[0].witness },
            ]),
          "IronwoodPsbtError.UnknownAction",
        );
      });

      it("refreshes the anchor after signing, keeping the signatures valid", function () {
        // Signed over the build-time anchor: the v6 sighash does not commit the anchor, so the
        // fixture's signatures (made over the refreshed bundle) are valid here too.
        let psbt = freshPsbt(fixture);
        if (ciphertextEntries.length > 0) {
          psbt.addOutCiphertexts(ciphertextEntries);
        }
        psbt.addSpendRandomizers(randomizerEntries, { spendValidatingKey: ak });
        assert.strictEqual(Buffer.from(psbt.spendSighash()).toString("hex"), fixture.sighash);
        psbt.addSpendSignatures(signatureEntries);
        assert.strictEqual(
          Buffer.from(psbt.verifyShieldedBundle().anchor).toString("hex"),
          fixture.request.anchor,
        );

        // The refresh after signing lands the same bundle the refresh-then-sign order builds:
        // the proof request matches the fixture's byte for byte, and the fixture's proof
        // combines over it.
        refreshAnchor(psbt);
        psbt = roundtrip(psbt);
        assert.strictEqual(Buffer.from(psbt.spendSighash()).toString("hex"), fixture.sighash);
        assert.strictEqual(
          Buffer.from(psbt.getProofRequest(alphaEntries)).toString("hex"),
          fixture.proofRequest,
        );
        const tx = ZcashV6Transaction.fromBytes(psbt.combineProof(hex(fixture.proof)));
        assert.ok(tx.ironwoodAnchor);
        assert.strictEqual(Buffer.from(tx.ironwoodAnchor).toString("hex"), fixture.refresh.anchor);
      });

      it("keeps the alphas out of the PSBT", function () {
        const psbt = psbtReadyForProof();
        psbt.getProofRequest(alphaEntries);
        const bytes = psbt.serialize();
        for (const entry of fixture.randomizers) {
          assert.ok(
            !containsSequence(bytes, hex(entry.alpha)),
            "the proof request must never write an alpha back into the PSBT",
          );
        }
        assert.ok(!containsSequence(bytes, ak), "the wallet ak must never appear in the PSBT");
      });

      it("rejects ciphertexts for unknown and dummy actions, and conflicting bytes", function () {
        if (ciphertextEntries.length === 0) {
          // The deshield's single action pairs the real spend with a fabricated dummy
          // output: an out_ciphertext for it is rejected as a dummy, not stored.
          const psbt = freshPsbt(fixture);
          assertErrorCode(
            () => psbt.addOutCiphertext(0, new Uint8Array(80)),
            "IronwoodPsbtError.DummyAction",
          );
          return;
        }
        const psbt = freshPsbt(fixture);
        assertErrorCode(
          () => psbt.addOutCiphertexts([{ actionIndex: 99, outCiphertext: new Uint8Array(80) }]),
          "IronwoodPsbtError.UnknownAction",
        );
        // Re-delivering identical bytes is fine; different bytes for a set index are not.
        psbt.addOutCiphertexts(ciphertextEntries);
        psbt.addOutCiphertexts(ciphertextEntries);
        const [first, ...rest] = ciphertextEntries;
        const conflict = Uint8Array.from(first.outCiphertext);
        conflict[0] ^= 0xff;
        assertErrorCode(
          () =>
            psbt.addOutCiphertexts([
              { actionIndex: first.actionIndex, outCiphertext: conflict },
              ...rest,
            ]),
          "IronwoodPsbtError.OutCiphertextConflict",
        );
      });

      it("rejects a randomizer pair that does not match the spend-validating key", function () {
        const psbt = freshPsbt(fixture);
        if (ciphertextEntries.length > 0) {
          // Ciphertexts first: the randomizer gate runs before the pair check.
          psbt.addOutCiphertexts(ciphertextEntries);
        }
        // A perturbed rk no longer satisfies rk == ak.randomize(alpha).
        const broken = randomizerEntries.map((entry, i) =>
          i === 0 ? { ...entry, rk: entry.rk.map((b, j) => (j === 0 ? b ^ 1 : b)) } : entry,
        );
        assertErrorCode(
          () => psbt.addSpendRandomizers(broken, { spendValidatingKey: ak }),
          "IronwoodBuildError.RandomizerMismatch",
        );
        // A perturbed alpha is rejected the same way: ak no longer randomizes under it to the
        // recorded rk.
        const brokenAlpha = randomizerEntries.map((entry, i) =>
          i === 0 ? { ...entry, alpha: entry.alpha.map((b, j) => (j === 0 ? b ^ 1 : b)) } : entry,
        );
        assertErrorCode(
          () => psbt.addSpendRandomizers(brokenAlpha, { spendValidatingKey: ak }),
          "IronwoodBuildError.RandomizerMismatch",
        );
        // A non-canonical spend-validating key is rejected before any pair check.
        const malformedAk = ak.map((b, i) => (i === 0 ? b ^ 1 : b));
        assertErrorCode(
          () => psbt.addSpendRandomizers(randomizerEntries, { spendValidatingKey: malformedAk }),
          "IronwoodBuildError.BadSpendValidatingKey",
        );
        // Without a spend-validating key the (unchecked) pair is accepted — the client
        // verifier and the keyed prover re-check it later.
        const unchecked = freshPsbt(fixture);
        if (ciphertextEntries.length > 0) {
          unchecked.addOutCiphertexts(ciphertextEntries);
        }
        unchecked.addSpendRandomizers(randomizerEntries);
        assert.deepStrictEqual(unchecked.shieldedStatus().pendingRandomizers, []);
      });

      it("rejects a signature that does not verify against the spend's rk", function () {
        const psbt = freshPsbt(fixture);
        if (ciphertextEntries.length > 0) {
          psbt.addOutCiphertexts(ciphertextEntries);
        }
        psbt.addSpendRandomizers(randomizerEntries, { spendValidatingKey: ak });
        // A signature with flipped bytes fails verification, and the batch stores nothing.
        const tampered = signatureEntries.map((entry, i) =>
          i === 0
            ? { ...entry, signature: entry.signature.map((b, j) => (j === 0 ? b ^ 1 : b)) }
            : entry,
        );
        assertErrorCode(
          () => psbt.addSpendSignatures(tampered),
          "IronwoodBuildError.InvalidExternalSignature",
        );
        assert.deepStrictEqual(psbt.shieldedStatus().pendingSpendSignatures, spendIndices);
      });
      it("freezes ciphertexts and randomizers once signed", function () {
        const psbt = psbtReadyForProof();
        assertErrorCode(
          () => psbt.addSpendRandomizers(randomizerEntries),
          "IronwoodPsbtError.AlreadySigned",
        );
        if (ciphertextEntries.length > 0) {
          assertErrorCode(
            () => psbt.addOutCiphertexts(ciphertextEntries),
            "IronwoodPsbtError.AlreadySigned",
          );
        }
      });

      it("gates the proof request on one alpha per real spend", function () {
        const psbt = freshPsbt(fixture);
        if (ciphertextEntries.length > 0) {
          psbt.addOutCiphertexts(ciphertextEntries);
        }
        psbt.addSpendRandomizers(randomizerEntries, { spendValidatingKey: ak });

        // Signed before proven: the signature gate runs before the alpha checks.
        assertErrorCode(() => psbt.getProofRequest([]), "IronwoodPsbtError.SpendSignaturePending");
        psbt.addSpendSignatures(signatureEntries);

        // No alphas at all: every real spend is missing one.
        assertErrorCode(() => psbt.getProofRequest([]), "IronwoodPsbtError.RandomizerMissing");
        // One alpha twice: the batch names an action more than once.
        const [first] = alphaEntries;
        assertErrorCode(
          () => psbt.getProofRequest([first, ...alphaEntries.slice(0, 1)]),
          "IronwoodPsbtError.DuplicateAction",
        );
      });

      it("combines the external proof into a broadcast-ready v6 transaction", function () {
        const psbt = psbtReadyForProof();
        const proof = hex(fixture.proof);

        // The proof must be sized for the bundle's action count.
        assertErrorCode(
          () => psbt.combineProof(proof.slice(0, proof.length - 1)),
          "IronwoodPsbtError.ProofLength",
        );
        assertErrorCode(
          () => psbt.combineProof(new Uint8Array(proof.length + 1)),
          "IronwoodPsbtError.ProofLength",
        );

        const rawTx = psbt.combineProof(proof);
        const tx = ZcashV6Transaction.fromBytes(rawTx);
        assert.strictEqual(
          tx.ironwoodActionCount,
          Math.max(fixture.request.spends.length, fixture.request.outputs.length),
        );
        assert.strictEqual(
          tx.ironwoodValueBalance,
          fixture.request.spends.reduce((sum, spend) => sum + BigInt(spend.value), 0n) -
            fixture.request.outputs.reduce((sum, output) => sum + BigInt(output.amount), 0n),
        );
        // Terminal: the PCZT is gone, including from the serialized bytes.
        assert.strictEqual(psbt.getPczt(), undefined);
        assert.throws(() => psbt.combineProof(proof), /no Ironwood PCZT stored/);
      });
    });
  }
});
