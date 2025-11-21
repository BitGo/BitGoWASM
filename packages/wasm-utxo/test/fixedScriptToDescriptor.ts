import * as assert from "assert";
import * as utxolib from "@bitgo/utxo-lib";
import { Descriptor } from "../js/index.js";
import { getDescriptorForScriptType } from "./descriptorUtil.js";

const rootWalletKeys = new utxolib.bitgo.RootWalletKeys(utxolib.testutil.getKeyTriple("wasm"));
const scriptTypes = ["p2sh", "p2shP2wsh", "p2wsh"] as const;
const scope = ["external", "internal"] as const;
const index = [0, 1, 2];

/** Get the expected max weight to satisfy the descriptor */
function getExpectedMaxWeightToSatisfy(scriptType: utxolib.bitgo.outputScripts.ScriptType2Of3) {
  switch (scriptType) {
    case "p2sh":
      return 256;
    case "p2shP2wsh":
      return 99;
    case "p2wsh":
      return 64;
    default:
      throw new Error("unexpected script type");
  }
}

/** Compute the total size of the input, including overhead */
function getTotalInputSize(vSize: number) {
  const sizeOpPushData1 = 1;
  const sizeOpPushData2 = 2;
  return (
    32 /* txid */ +
    4 /* vout */ +
    4 /* nSequence */ +
    (vSize < 255 ? sizeOpPushData1 : sizeOpPushData2) +
    vSize
  );
}

/** Get the full expected vSize of the input including overhead */
function getExpectedVSize(scriptType: utxolib.bitgo.outputScripts.ScriptType2Of3) {
  // https://github.com/BitGo/BitGoJS/blob/master/modules/unspents/docs/input-costs.md
  switch (scriptType) {
    case "p2sh":
      return 298;
    case "p2shP2wsh":
      return 140;
    case "p2wsh":
      return 105;
    default:
      throw new Error("unexpected script type");
  }
}

function runTest(
  scriptType: utxolib.bitgo.outputScripts.ScriptType2Of3,
  index: number,
  scope: "internal" | "external",
) {
  describe(`scriptType=${scriptType}, index=${index}, scope=${scope}`, function () {
    const chainCode =
      scope === "external"
        ? utxolib.bitgo.getExternalChainCode(scriptType)
        : utxolib.bitgo.getInternalChainCode(scriptType);
    const derivedKeys = rootWalletKeys.deriveForChainAndIndex(chainCode, index);
    const scriptUtxolib = utxolib.bitgo.outputScripts.createOutputScript2of3(
      derivedKeys.publicKeys,
      scriptType,
    ).scriptPubKey;

    let descriptor: Descriptor;

    before(function () {
      descriptor = Descriptor.fromString(
        getDescriptorForScriptType(rootWalletKeys, scriptType, scope),
        "derivable",
      );
    });

    it("descriptor should have expected format", function () {
      const [x1, x2, x3] = rootWalletKeys.triple.map((xpub) => xpub.neutered().toBase58());
      if (scriptType === "p2sh" && scope === "external") {
        // spot check
        assert.ok(
          descriptor
            .toString()
            .startsWith(`sh(multi(2,${x1}/0/0/0/*,${x2}/0/0/0/*,${x3}/0/0/0/*))`),
        );
      }
      if (scriptType === "p2shP2wsh" && scope === "internal") {
        // spot check
        assert.ok(
          descriptor
            .toString()
            .startsWith(`sh(wsh(multi(2,${x1}/0/0/11/*,${x2}/0/0/11/*,${x3}/0/0/11/*)))`),
        );
      }
    });

    it("address should match descriptor", function () {
      const scriptFromDescriptor = Buffer.from(descriptor.atDerivationIndex(index).scriptPubkey());
      assert.deepStrictEqual(scriptUtxolib.toString("hex"), scriptFromDescriptor.toString("hex"));
    });

    it("should have expected weights", function () {
      assert.ok(Number.isInteger(descriptor.maxWeightToSatisfy()));
      const vSize = Math.ceil(descriptor.maxWeightToSatisfy() / 4);
      console.log(
        scriptType,
        "scriptLength",
        descriptor.atDerivationIndex(0).encode().length,
        "vSize",
        vSize,
      );
      assert.equal(vSize, getExpectedMaxWeightToSatisfy(scriptType));
      assert.equal(getTotalInputSize(vSize), getExpectedVSize(scriptType));
    });
  });
}

describe("fixedScript to descriptor", function () {
  scriptTypes.forEach((scriptType) => {
    index.forEach((index) => {
      scope.forEach((scope) => {
        runTest(scriptType, index, scope);
      });
    });
  });
});
