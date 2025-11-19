import * as assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";
import { Descriptor, Psbt } from "../js/index.js";

function toAddress(descriptor: Descriptor, network: utxolib.Network) {
  utxolib.address.fromOutputScript(Buffer.from(descriptor.scriptPubkey()), network);
}

export function toWrappedPsbt(psbt: utxolib.bitgo.UtxoPsbt | utxolib.Psbt | Buffer | Uint8Array) {
  if (psbt instanceof utxolib.bitgo.UtxoPsbt || psbt instanceof utxolib.Psbt) {
    psbt = psbt.toBuffer();
  }
  if (psbt instanceof Buffer || psbt instanceof Uint8Array) {
    return Psbt.deserialize(psbt);
  }
  throw new Error("Invalid input");
}

export function toUtxoPsbt(psbt: Psbt | Buffer | Uint8Array) {
  if (psbt instanceof Psbt) {
    psbt = psbt.serialize();
  }
  if (psbt instanceof Buffer || psbt instanceof Uint8Array) {
    return utxolib.bitgo.UtxoPsbt.fromBuffer(Buffer.from(psbt), {
      network: utxolib.networks.bitcoin,
    });
  }
  throw new Error("Invalid input");
}

export function updateInputWithDescriptor(
  psbt: utxolib.Psbt,
  inputIndex: number,
  descriptor: Descriptor,
) {
  const wrappedPsbt = toWrappedPsbt(psbt);
  wrappedPsbt.updateInputWithDescriptor(inputIndex, descriptor);
  psbt.data.inputs[inputIndex] = toUtxoPsbt(wrappedPsbt).data.inputs[inputIndex];
}

export function updateOutputWithDescriptor(
  psbt: utxolib.Psbt,
  outputIndex: number,
  descriptor: Descriptor,
) {
  const wrappedPsbt = toWrappedPsbt(psbt);
  wrappedPsbt.updateOutputWithDescriptor(outputIndex, descriptor);
  psbt.data.outputs[outputIndex] = toUtxoPsbt(wrappedPsbt).data.outputs[outputIndex];
}

export function finalizePsbt(psbt: utxolib.Psbt) {
  const wrappedPsbt = toWrappedPsbt(psbt);
  wrappedPsbt.finalize();
  const unwrappedPsbt = toUtxoPsbt(wrappedPsbt);
  for (let i = 0; i < psbt.data.inputs.length; i++) {
    psbt.data.inputs[i] = unwrappedPsbt.data.inputs[i];
  }
}

function toEntries(k: string, v: unknown, path: (string | number)[]): [] | [[string, unknown]] {
  if (matchPath(path, ["data", "inputs", any, "sighashType"])) {
    return [];
  }
  if (matchPath(path.slice(-1), ["unknownKeyVals"])) {
    if (Array.isArray(v) && v.length === 0) {
      return [];
    }
  }
  return [[k, toPlainObject(v, path)]];
}

const any = Symbol("any");

function matchPath(path: (string | number)[], pattern: (string | number | symbol)[]) {
  if (path.length !== pattern.length) {
    return false;
  }
  for (let i = 0; i < path.length; i++) {
    if (pattern[i] !== any && path[i] !== pattern[i]) {
      return false;
    }
  }
  return true;
}

function normalizeBip32Derivation(v: unknown) {
  if (!Array.isArray(v)) {
    throw new Error("Expected bip32Derivation to be an array");
  }
  return (
    [...v] as {
      masterFingerprint: Buffer;
      path: string;
    }[]
  )
    .map((e) => {
      let { path } = e;
      if (path.startsWith("m/")) {
        path = path.slice(2);
      }
      return {
        ...e,
        path,
      };
    })
    .sort((a, b) => a.masterFingerprint.toString().localeCompare(b.masterFingerprint.toString()));
}

function toPlainObject(v: unknown, path: (string | number)[]) {
  // psbts have fun getters and other types of irregular properties that we mash into shape here
  if (v === null || v === undefined) {
    return v;
  }
  if (
    matchPath(path, ["data", "inputs", any, "bip32Derivation"]) ||
    matchPath(path, ["data", "outputs", any, "bip32Derivation"])
  ) {
    v = normalizeBip32Derivation(v);
  }
  switch (typeof v) {
    case "number":
    case "bigint":
    case "string":
    case "boolean":
      return v;
    case "object":
      if (v instanceof Buffer || v instanceof Uint8Array) {
        return v.toString("hex");
      }
      if (Array.isArray(v)) {
        return v.map((v, i) => toPlainObject(v, [...path, i]));
      }
      return Object.fromEntries(
        Object.entries(v)
          .flatMap(([k, v]) => toEntries(k, v, [...path, k]))
          .sort(([a], [b]) => a.localeCompare(b)),
      );
    default:
      throw new Error(`Unsupported type: ${typeof v}`);
  }
}

export function assertEqualPsbt(a: utxolib.Psbt, b: utxolib.Psbt) {
  assert.deepStrictEqual(toPlainObject(a, []), toPlainObject(b, []));
}
