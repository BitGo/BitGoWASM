import * as utxolib from "@bitgo/utxo-lib";
import * as assert from "node:assert";
import { getPsbtFixtures, PsbtStage } from "./psbtFixedScriptCompatFixtures.js";
import { Descriptor, Psbt } from "../js/index.js";

import { getDescriptorForScriptType } from "./descriptorUtil.js";
import {
  assertEqualPsbt,
  toUtxoPsbt,
  toWrappedPsbt,
  updateInputWithDescriptor,
} from "./psbt.util.js";
import { getKey } from "@bitgo/utxo-lib/dist/src/testutil";

const rootWalletKeys = new utxolib.bitgo.RootWalletKeys(utxolib.testutil.getKeyTriple("wasm"));

function assertEqualBuffer(a: Buffer | Uint8Array, b: Buffer | Uint8Array, message?: string) {
  assert.strictEqual(Buffer.from(a).toString("hex"), Buffer.from(b).toString("hex"), message);
}

const fixtures = getPsbtFixtures(rootWalletKeys);

function describeUpdateInputWithDescriptor(
  psbt: utxolib.bitgo.UtxoPsbt,
  scriptType: utxolib.bitgo.outputScripts.ScriptType2Of3,
) {
  function getFixtureAtStage(stage: PsbtStage) {
    const f = fixtures.find((f) => f.scriptType === scriptType && f.stage === stage);
    if (!f) {
      throw new Error(`Could not find fixture for scriptType ${scriptType} and stage ${stage}`);
    }
    return f;
  }

  const descriptorStr = getDescriptorForScriptType(rootWalletKeys, scriptType, "internal");
  const index = 0;
  const descriptor = Descriptor.fromString(descriptorStr, "derivable");

  function getWrappedPsbt() {
    return toWrappedPsbt(psbt);
  }

  function getWrappedPsbtWithDescriptorInfo(): Psbt {
    const wrappedPsbt = getWrappedPsbt();
    const descriptorAtDerivation = descriptor.atDerivationIndex(index);
    wrappedPsbt.updateInputWithDescriptor(0, descriptorAtDerivation);
    wrappedPsbt.updateOutputWithDescriptor(0, descriptorAtDerivation);
    return wrappedPsbt;
  }

  describe("Wrapped PSBT updateInputWithDescriptor", function () {
    it("should update the input with the descriptor", function () {
      const wrappedPsbt = getWrappedPsbtWithDescriptorInfo();
      const updatedPsbt = toUtxoPsbt(wrappedPsbt);
      assertEqualPsbt(updatedPsbt, getFixtureAtStage("unsigned").psbt);
      updatedPsbt.signAllInputsHD(rootWalletKeys.triple[0]);
      updatedPsbt.signAllInputsHD(rootWalletKeys.triple[2]);
      const wrappedSignedPsbt = toWrappedPsbt(updatedPsbt);
      updatedPsbt.finalizeAllInputs();
      wrappedSignedPsbt.finalize();

      assertEqualBuffer(updatedPsbt.toBuffer(), wrappedSignedPsbt.serialize());

      assertEqualBuffer(
        getFixtureAtStage("fullsigned")
          .psbt.clone()
          .finalizeAllInputs()
          .extractTransaction()
          .toBuffer(),
        updatedPsbt.extractTransaction().toBuffer(),
      );
    });
  });

  describe("updateInputWithDescriptor util", function () {
    it("should update the input with the descriptor", function () {
      const cloned = psbt.clone();
      updateInputWithDescriptor(cloned, 0, descriptor.atDerivationIndex(index));
      cloned.signAllInputsHD(rootWalletKeys.triple[0]);
      cloned.signAllInputsHD(rootWalletKeys.triple[2]);
      cloned.finalizeAllInputs();

      assertEqualBuffer(
        getFixtureAtStage("fullsigned")
          .psbt.clone()
          .finalizeAllInputs()
          .extractTransaction()
          .toBuffer(),
        cloned.extractTransaction().toBuffer(),
      );
    });
  });

  describe("psbt signWithXprv", function () {
    type KeyName = utxolib.bitgo.KeyName | "unrelated";
    function signWithKey(keys: KeyName[], { checkFinalized = false } = {}) {
      it(`signs the input with keys ${keys.join(", ")}`, function () {
        const psbt = getWrappedPsbtWithDescriptorInfo();
        keys.forEach((keyName) => {
          const key = keyName === "unrelated" ? getKey(keyName) : rootWalletKeys[keyName];
          const derivationPaths = toUtxoPsbt(psbt).data.inputs[0].bip32Derivation.map(
            (d) => d.path,
          );
          assert.ok(derivationPaths.every((p) => p === derivationPaths[0]));
          const derived = key.derivePath(derivationPaths[0]);
          assert.deepStrictEqual(psbt.signWithXprv(key.toBase58()), {
            // map: input index -> pubkey array
            0: { Ecdsa: keyName === "unrelated" ? [] : [derived.publicKey.toString("hex")] },
          });
        });

        if (checkFinalized) {
          psbt.finalize();
          assertEqualBuffer(
            toUtxoPsbt(psbt).extractTransaction().toBuffer(),
            getFixtureAtStage("fullsigned")
              .psbt.finalizeAllInputs()
              .extractTransaction()
              .toBuffer(),
          );
        }
      });
    }

    signWithKey(["user"]);
    signWithKey(["backup"]);
    signWithKey(["bitgo"]);
    signWithKey(["unrelated"]);
    signWithKey(["user", "bitgo"], { checkFinalized: true });
  });
}

describe("PSBT fixture", function () {
  fixtures.forEach(({ psbt, scriptType, stage }) => {
    describe(`PSBT fixture ${scriptType} ${stage}`, function () {
      let buf: Buffer;
      let wrappedPsbt: Psbt;

      before(function () {
        buf = psbt.toBuffer();
        wrappedPsbt = toWrappedPsbt(buf);
      });

      it("should map to same hex", function () {
        assertEqualBuffer(buf, wrappedPsbt.serialize());
      });

      it("should round-trip utxolib -> ms -> utxolib", function () {
        assertEqualBuffer(buf, toUtxoPsbt(wrappedPsbt).toBuffer());
      });

      if (stage === "bare") {
        describeUpdateInputWithDescriptor(psbt, scriptType);
      }
    });
  });
});
