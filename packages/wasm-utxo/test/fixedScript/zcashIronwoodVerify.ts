import assert from "node:assert";
import { describe, it } from "mocha";

import { ZcashIronwoodBitGoPsbt } from "../../js/fixedScriptWallet/ZcashIronwoodBitGoPsbt.js";
import { getWalletKeysForSeed } from "../../js/testutils/index.js";
import type {
  IronwoodVerificationReport,
  ZcashShieldedSpend,
} from "../../js/fixedScriptWallet/ZcashIronwoodTypes.js";
import {
  assertErrorCode,
  base64,
  freshPsbt,
  hex,
  loadFixture,
  type IronwoodSpendFixture,
} from "./zcashIronwoodSpend.util.js";

const hexOf = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

/** The signer's randomizers, as the client received them. */
function randomizerOptions(fixture: IronwoodSpendFixture): {
  spendValidatingKey: Uint8Array;
  randomizers: Array<{ actionIndex: number; alpha: Uint8Array; rk: Uint8Array }>;
} {
  return {
    spendValidatingKey: hex(fixture.ak),
    randomizers: fixture.randomizers.map((entry) => ({
      actionIndex: entry.actionIndex,
      alpha: hex(entry.alpha),
      rk: hex(entry.rk),
    })),
  };
}

/** Installs the ciphertexts (when the shape has shielded outputs), randomizers and signatures. */
function psbtSigned(fixture: IronwoodSpendFixture): ZcashIronwoodBitGoPsbt {
  const psbt = freshPsbt(fixture);
  if (fixture.outCiphertexts.length > 0) {
    psbt.addOutCiphertexts(
      fixture.outCiphertexts.map((entry) => ({
        actionIndex: entry.actionIndex,
        outCiphertext: hex(entry.outCiphertext),
      })),
    );
  }
  const { spendValidatingKey, randomizers } = randomizerOptions(fixture);
  psbt.addSpendRandomizers(randomizers, { spendValidatingKey });
  psbt.addSpendSignatures(
    fixture.signatures.map((entry) => ({
      actionIndex: entry.actionIndex,
      signature: hex(entry.signature),
    })),
  );
  return psbt;
}

/** The report's spend list keyed by action index. */
function spendByAction(report: IronwoodVerificationReport): Map<number, ZcashShieldedSpend> {
  return new Map(report.spends.map((spend) => [spend.actionIndex, spend]));
}

describe("ZcashIronwoodBitGoPsbt.verifyShieldedBundle", function () {
  const walletKeys = getWalletKeysForSeed("ironwood-ts");

  for (const name of ["deshield", "transfer"]) {
    describe(`${name}: report matches the build-side state`, function () {
      const fixture = loadFixture(name);

      it("verifies the freshly constructed bundle with nothing installed yet", function () {
        const report = freshPsbt(fixture).verifyShieldedBundle();

        // Every real spend, still on its placeholder key and unsigned.
        assert.strictEqual(report.spends.length, fixture.request.spends.length);
        for (const spend of report.spends) {
          assert.strictEqual(spend.randomizer, "placeholder");
          assert.strictEqual(spend.signed, false);
        }
        // The verified plaintext matches the request: values, nullifiers, anchor.
        assert.deepStrictEqual(
          report.spends.map((spend) => spend.value.toString()).sort(),
          fixture.request.spends.map((spend) => spend.value).sort(),
        );
        assert.deepStrictEqual(
          report.spends.map((spend) => hexOf(spend.nullifier)).sort(),
          fixture.request.spends.map((spend) => spend.nullifier).sort(),
        );
        assert.strictEqual(hexOf(report.anchor), fixture.request.anchor);

        // Real outputs: exactly the requested ones. The action order is shuffled and both
        // outputs can share a value, so the pairing is by (value, recipient) multiset.
        assert.strictEqual(report.outputs.length, fixture.request.outputs.length);
        assert.deepStrictEqual(
          report.outputs.map((output) => `${output.value}:${hexOf(output.recipient)}`).sort(),
          fixture.request.outputs.map((output) => `${output.amount}:${output.recipient}`).sort(),
        );
        // The bundle's value balance is the deshield's payout (or the transfer's zero).
        const spent = fixture.request.spends.reduce((sum, spend) => sum + BigInt(spend.value), 0n);
        const paid = fixture.request.outputs.reduce(
          (sum, output) => sum + BigInt(output.amount),
          0n,
        );
        assert.strictEqual(report.valueBalance, spent - paid);
      });

      it("verifies the signed bundle and reports each spend's state", function () {
        const psbt = psbtSigned(fixture);
        const { spendValidatingKey, randomizers } = randomizerOptions(fixture);

        const report = psbt.verifyShieldedBundle({ spendValidatingKey, randomizers });
        const byAction = spendByAction(report);
        for (const entry of fixture.randomizers) {
          const spend = byAction.get(entry.actionIndex);
          assert.ok(spend, `no verified spend at action ${entry.actionIndex}`);
          assert.strictEqual(spend.randomizer, "installed");
          assert.strictEqual(spend.signed, true);
        }
        // Signatures are checked over the internally computed sighash: the same digest the
        // signer signed.
        assert.strictEqual(hexOf(psbt.spendSighash()), fixture.sighash);
      });

      it("rejects a foreign spend-validating key and mismatched randomizers", function () {
        const psbt = psbtSigned(fixture);
        const { spendValidatingKey, randomizers } = randomizerOptions(fixture);

        // A foreign key: its randomize(α) is not the installed rk.
        const foreignKey = new Uint8Array(spendValidatingKey);
        foreignKey[0] ^= 1;
        assertErrorCode(
          () => psbt.verifyShieldedBundle({ spendValidatingKey: foreignKey, randomizers }),
          "IronwoodVerifyError.Rk",
        );

        // A randomizer whose rk does not match the installed one.
        const [first, ...rest] = randomizers;
        const broken = new Uint8Array(first.rk);
        broken[0] ^= 1;
        assertErrorCode(
          () =>
            psbt.verifyShieldedBundle({
              spendValidatingKey,
              randomizers: [{ ...first, rk: broken }, ...rest],
            }),
          "IronwoodVerifyError.Rk",
        );

        // A randomizer aimed at an action without a real spend.
        assertErrorCode(
          () =>
            psbt.verifyShieldedBundle({
              spendValidatingKey,
              randomizers: [...randomizers, { actionIndex: 99, alpha: first.alpha, rk: first.rk }],
            }),
          "IronwoodVerifyError.Rk",
        );
      });

      it("rejects randomizer expectations while the spends are still placeholders", function () {
        // Nothing installed yet: expectations aimed at placeholder spends are mismatches.
        const { spendValidatingKey, randomizers } = randomizerOptions(fixture);
        assertErrorCode(
          () => freshPsbt(fixture).verifyShieldedBundle({ spendValidatingKey, randomizers }),
          "IronwoodVerifyError.Rk",
        );
      });
    });
  }

  it("rejects a tampered PSBT in verifyShieldedBundle and in the parse", function () {
    const fixture = loadFixture("transfer");
    // Flip a byte in the bundle's anchor — located by value, so the tamper is deterministic
    // and lands in a field the verifier checks (the spends' witnesses no longer recompute to
    // it), while the PCZT's own framing stays intact.
    const bytes = Buffer.from(base64(fixture.psbt));
    const anchorAt = bytes.indexOf(hex(fixture.request.anchor));
    assert.ok(anchorAt >= 0, "the anchor must appear in the PSBT bytes");
    bytes[anchorAt] ^= 0x01;

    const psbt = ZcashIronwoodBitGoPsbt.fromBytes(bytes, "zcashTest");
    assertErrorCode(() => psbt.verifyShieldedBundle(), "IronwoodVerifyError.SpendWitness");
    assertErrorCode(
      () =>
        psbt.parseTransactionWithWalletKeys(walletKeys, { replayProtection: { publicKeys: [] } }),
      "IronwoodVerifyError.SpendWitness",
    );
  });

  it("rejects a transparent signature check on a PSBT without transparent inputs", function () {
    // A spend PSBT has no transparent inputs: an action index passed by mistake is out of range.
    const fixture = loadFixture("deshield");
    assertErrorCode(
      () =>
        psbtSigned(fixture).verifySignature(fixture.spendActionIndices[0], walletKeys.userKey()),
      "VerifyV6SignatureError.InputIndexOutOfRange",
    );
  });

  it("errors on a PSBT without a shielded bundle, and verifies a shielding bundle's outputs", function () {
    // No PCZT at all: nothing to verify.
    const empty = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
      blockHeight: 4134000,
    });
    assertErrorCode(() => empty.verifyShieldedBundle(), "IronwoodPsbtError.NotSpendBundle");

    // A shielding bundle (dummy spends only) verifies with no spends and its shielded
    // output in the report.
    const shield = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
      blockHeight: 4134000,
    });
    const recipient = hex(loadFixture("deshield").request.spends[0].recipient);
    shield.addShieldedOutput(recipient, 100_000_000n, { anchor: new Uint8Array(32) });
    const report = shield.verifyShieldedBundle();
    assert.deepStrictEqual(report.spends, []);
    assert.strictEqual(report.outputs.length, 1);
    assert.strictEqual(report.outputs[0].value, 100_000_000n);
    assert.strictEqual(hexOf(report.outputs[0].recipient), hexOf(recipient));
    assert.strictEqual(report.valueBalance, -100_000_000n);
  });
});
