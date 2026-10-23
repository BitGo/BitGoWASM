import assert from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
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

/**
 * One `test/fixtures/zcash/ironwood_spend_*.json` fixture, generated in Rust by the
 * `#[ignore]`d `generate_ts_spend_fixtures` test (under `orchard-proving`):
 *
 * - `request` is what the builder replays through `addShieldedSpends`;
 * - `psbt` is the seeded post-construction PSBT the lifecycle drives;
 * - `outCiphertexts` / `proof` are the viewing-key holder's and prover's responses (they need
 *   the FVK / Halo2, which the TS
 *   side does not hold);
 * - `randomizers` / `signatures` are the FROST stand-in round, keyed to the same run's
 *   ciphertexts (the sighash chain depends on them);
 * - `proofRequest` is the exact alpha-patched PCZT `getProofRequest` must return.
 */
type IronwoodSpendFixture = {
  name: string;
  network: "zcashTest";
  blockHeight: number;
  request: {
    anchor: string;
    spends: Array<{
      recipient: string;
      value: string;
      rho: string;
      rseed: string;
      cmx: string;
      witness: { position: number; authPath: string[] };
      nullifier: string;
    }>;
    outputs: Array<{
      recipient: string;
      amount: string;
      memo: string;
      unifiedAddress: string | null;
    }>;
    transparentOutput: { script: string; value: string } | null;
  };
  psbt: string;
  spendActionIndices: number[];
  outputActionIndices: number[];
  ak: string;
  outCiphertexts: Array<{ actionIndex: number; outCiphertext: string }>;
  randomizers: Array<{ actionIndex: number; alpha: string; rk: string }>;
  sighash: string;
  signatures: Array<{ actionIndex: number; signature: string }>;
  proofRequest: string;
  proof: string;
  expectedTxid: string;
  zip317ConventionalFee: string;
};

const hex = (value: string): Uint8Array => Buffer.from(value, "hex");
const base64 = (value: string): Uint8Array => Buffer.from(value, "base64");

const fixtureDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../fixtures/zcash");

function loadFixture(name: string): IronwoodSpendFixture {
  return JSON.parse(
    fs.readFileSync(path.join(fixtureDir, `ironwood_spend_${name}.json`), "utf8"),
  ) as IronwoodSpendFixture;
}

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

/** A fresh PSBT at the fixture's post-construction state (the deterministic seeded build). */
function freshPsbt(fixture: IronwoodSpendFixture): ZcashIronwoodBitGoPsbt {
  return ZcashIronwoodBitGoPsbt.fromBytes(base64(fixture.psbt), "zcashTest");
}

/** `serialize` → `fromBytes`: the wire round-trip every lifecycle step must survive. */
function roundtrip(psbt: ZcashIronwoodBitGoPsbt): ZcashIronwoodBitGoPsbt {
  return ZcashIronwoodBitGoPsbt.fromBytes(psbt.serialize(), "zcashTest");
}

/** Asserts `call` throws with the given typed error code. */
function assertErrorCode(call: () => unknown, expectedCode: string): void {
  try {
    call();
  } catch (err) {
    assert.strictEqual((err as Error & { code?: string }).code, expectedCode);
    return;
  }
  assert.fail(`expected ${expectedCode}, but the call succeeded`);
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

      /** Drives a fresh PSBT to the signed state (ciphertexts → randomizers → signatures). */
      function psbtReadyForProof(): ZcashIronwoodBitGoPsbt {
        const psbt = freshPsbt(fixture);
        if (ciphertextEntries.length > 0) {
          psbt.addOutCiphertexts(ciphertextEntries);
        }
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
