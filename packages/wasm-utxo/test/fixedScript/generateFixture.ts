import { AcidTest, type TxFormat } from "../../js/testutils/AcidTest.js";
import { getKeyTriple, getWalletKeysForSeed } from "../../js/testutils/keys.js";
import { ECPair } from "../../js/ecpair.js";
import { BitGoPsbt, type InputScriptType } from "../../js/fixedScriptWallet/index.js";
import type { CoinName } from "../../js/coinName.js";
import { RootWalletKeys } from "../../js/fixedScriptWallet/RootWalletKeys.js";
import type {
  Fixture,
  PsbtInput,
  PsbtOutput,
  Output,
  SignatureState,
  Bip32Derivation,
} from "./fixtureUtil.js";

export function createOtherWalletKeys(): RootWalletKeys {
  return getWalletKeysForSeed("too many secrets");
}

function toFixtureType(scriptType: InputScriptType): string {
  switch (scriptType) {
    case "p2sh":
    case "p2shP2wsh":
    case "p2wsh":
    case "p2shP2pk":
      return scriptType;
    case "p2trLegacy":
      return "p2tr";
    case "p2trMusig2ScriptPath":
      return "p2trMusig2";
    case "p2trMusig2KeyPath":
      return "taprootKeyPathSpend";
    default:
      throw new Error(`Unknown script type: ${String(scriptType)}`);
  }
}

function reverseHex(hex: string): string {
  return Buffer.from(hex, "hex").reverse().toString("hex");
}

function toBip32Derivation(d: { pubkey: Uint8Array; path: string }): Bip32Derivation {
  return {
    pubkey: Buffer.from(d.pubkey).toString("hex"),
    path: d.path,
  };
}

function snapshotFixture(acid: AcidTest, psbt: BitGoPsbt): Fixture {
  const xprivs = getKeyTriple("default");
  const rpBip32 = acid.getReplayProtectionKey();
  const rpKey = ECPair.fromPublicKey(rpBip32.publicKey);

  const parsed = psbt.parseTransactionWithWalletKeys(acid.rootWalletKeys, {
    replayProtection: { publicKeys: [rpKey] },
  });

  const psbtInputData = psbt.getInputs();
  const psbtOutputData = psbt.getOutputs();

  const inputs = parsed.inputs.map((input) => ({
    hash: reverseHex(input.previousOutput.txid),
    index: input.previousOutput.vout,
    sequence: input.sequence,
  }));

  const psbtInputs: PsbtInput[] = parsed.inputs.map((input, i) => {
    const data = psbtInputData[i];
    const result: PsbtInput = {
      type: toFixtureType(input.scriptType),
      sighashType: input.scriptType.startsWith("p2tr") ? 0 : 1,
    };
    if (data.witnessUtxo) {
      result.witnessUtxo = {
        value: data.witnessUtxo.value.toString(),
        script: Buffer.from(data.witnessUtxo.script).toString("hex"),
      };
    }
    if (data.bip32Derivation.length > 0) {
      result.bip32Derivation = data.bip32Derivation.map(toBip32Derivation);
    }
    if (data.tapBip32Derivation.length > 0) {
      result.tapBip32Derivation = data.tapBip32Derivation.map(toBip32Derivation);
    }
    return result;
  });

  const outputs: Output[] = psbtOutputData.map((out) => ({
    script: Buffer.from(out.script).toString("hex"),
    value: out.value.toString(),
  }));

  const psbtOutputs: PsbtOutput[] = psbtOutputData.map((out) => {
    const result: PsbtOutput = {};
    if (out.bip32Derivation.length > 0) {
      result.bip32Derivation = out.bip32Derivation.map(toBip32Derivation);
    }
    if (out.tapBip32Derivation.length > 0) {
      result.tapBip32Derivation = out.tapBip32Derivation.map(toBip32Derivation);
    }
    return result;
  });

  return {
    walletKeys: xprivs.map((k) => k.toBase58()) as [string, string, string],
    psbtBase64: Buffer.from(psbt.serialize()).toString("base64"),
    psbtBase64Finalized: null,
    inputs,
    psbtInputs,
    psbtInputsFinalized: null,
    outputs,
    psbtOutputs,
    extractedTransaction: null,
  };
}

export function generateAllStates(
  network: CoinName,
  txFormat: TxFormat = "psbt-lite",
): Record<SignatureState, Fixture> {
  const unsignedAcid = AcidTest.withConfig(network, "unsigned", txFormat);
  const halfsignedAcid = AcidTest.withConfig(network, "halfsigned", txFormat);
  const fullsignedAcid = AcidTest.withConfig(network, "fullsigned", txFormat);

  const unsignedPsbt = unsignedAcid.createPsbt();
  const halfsignedPsbt = halfsignedAcid.createPsbt();
  const fullsignedPsbt = fullsignedAcid.createPsbt();

  const unsigned = snapshotFixture(unsignedAcid, unsignedPsbt);
  const halfsigned = snapshotFixture(halfsignedAcid, halfsignedPsbt);
  const fullsigned = snapshotFixture(fullsignedAcid, fullsignedPsbt);

  // Finalize the fullsigned PSBT and capture finalized data
  fullsignedPsbt.finalizeAllInputs();
  fullsigned.psbtBase64Finalized = Buffer.from(fullsignedPsbt.serialize()).toString("base64");
  const tx = fullsignedPsbt.extractTransaction();
  fullsigned.extractedTransaction = Buffer.from(tx.toBytes()).toString("hex");

  return { unsigned, halfsigned, fullsigned };
}
