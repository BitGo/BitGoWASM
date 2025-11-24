import * as utxolib from "@bitgo/utxo-lib";
import { RootWalletKeys } from "@bitgo/utxo-lib/dist/src/bitgo";

export type PsbtStage = "bare" | "unsigned" | "halfsigned" | "fullsigned";

export function toPsbtWithPrevOutOnly(psbt: utxolib.bitgo.UtxoPsbt) {
  const psbtCopy = utxolib.bitgo.UtxoPsbt.createPsbt({
    network: utxolib.networks.bitcoin,
  });
  psbtCopy.setVersion(psbt.version);
  psbtCopy.setLocktime(psbt.locktime);
  psbt.txInputs.forEach((input, vin) => {
    const { witnessUtxo, nonWitnessUtxo } = psbt.data.inputs[vin];
    psbtCopy.addInput({
      hash: input.hash,
      index: input.index,
      sequence: input.sequence,
      ...(witnessUtxo ? { witnessUtxo } : { nonWitnessUtxo }),
    });
  });
  psbt.txOutputs.forEach((output) => {
    psbtCopy.addOutput(output);
  });
  return psbtCopy;
}

function getPsbtWithScriptTypeAndStage(
  keys: RootWalletKeys,
  scriptType: utxolib.bitgo.outputScripts.ScriptType2Of3,
  stage: PsbtStage,
) {
  if (stage === "bare") {
    const psbt = getPsbtWithScriptTypeAndStage(keys, scriptType, "unsigned");
    return toPsbtWithPrevOutOnly(psbt);
  }
  return utxolib.testutil.constructPsbt(
    [
      {
        scriptType,
        value: BigInt(1e8),
      },
    ],
    [
      {
        value: BigInt(1e8 - 1000),
        scriptType,
        isInternalAddress: true,
      },
    ],
    utxolib.networks.bitcoin,
    keys,
    stage,
  );
}

export type PsbtFixture = {
  psbt: utxolib.bitgo.UtxoPsbt;
  scriptType: utxolib.bitgo.outputScripts.ScriptType2Of3;
  stage: PsbtStage;
};

export function getPsbtFixtures(keys: RootWalletKeys): PsbtFixture[] {
  const testMatrixScriptTypes = ["p2sh", "p2shP2wsh", "p2wsh"] as const;
  const testMatrixStages = ["bare", "unsigned", "halfsigned", "fullsigned"] as const;

  return testMatrixStages.flatMap((stage) => {
    return testMatrixScriptTypes.map((scriptType) => {
      return {
        psbt: getPsbtWithScriptTypeAndStage(keys, scriptType, stage),
        name: `${scriptType}-${stage}`,
        scriptType,
        stage,
      };
    });
  });
}
