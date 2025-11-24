import * as utxolib from "@bitgo/utxo-lib";
import { toUtxoPsbt, toWrappedPsbt } from "./psbt.util.js";
import { Descriptor } from "../js/index.js";

export function createScriptPubKeyFromDescriptor(descriptor: Descriptor, index?: number): Buffer {
  if (index === undefined) {
    return Buffer.from(descriptor.scriptPubkey());
  }
  return createScriptPubKeyFromDescriptor(descriptor.atDerivationIndex(index));
}

export type Output = {
  script: Buffer;
  value: bigint;
};

export type WithDescriptor<T> = T & {
  descriptor: Descriptor;
};

export type PrevOutput = {
  hash: string;
  index: number;
  witnessUtxo: Output;
};

export type DescriptorWalletOutput = PrevOutput & {
  descriptorName: string;
  descriptorIndex: number;
};

export type DerivedDescriptorWalletOutput = WithDescriptor<PrevOutput>;

export function toDerivedDescriptorWalletOutput(
  output: DescriptorWalletOutput,
  descriptor: Descriptor,
): DerivedDescriptorWalletOutput {
  const derivedDescriptor = descriptor.atDerivationIndex(output.descriptorIndex);
  const script = createScriptPubKeyFromDescriptor(derivedDescriptor);
  if (!script.equals(output.witnessUtxo.script)) {
    throw new Error(
      `Script mismatch: descriptor ${output.descriptorName} ${descriptor.toString()} script=${script.toString("hex")}`,
    );
  }
  return {
    hash: output.hash,
    index: output.index,
    witnessUtxo: output.witnessUtxo,
    descriptor: descriptor.atDerivationIndex(output.descriptorIndex),
  };
}

/**
 * Non-Final (Replaceable)
 * Reference: https://github.com/bitcoin/bitcoin/blob/v25.1/src/rpc/rawtransaction_util.cpp#L49
 * */
export const MAX_BIP125_RBF_SEQUENCE = 0xffffffff - 2;

function updateInputsWithDescriptors(psbt: utxolib.bitgo.UtxoPsbt, descriptors: Descriptor[]) {
  if (psbt.txInputs.length !== descriptors.length) {
    throw new Error(
      `Input count mismatch (psbt=${psbt.txInputs.length}, descriptors=${descriptors.length})`,
    );
  }
  const wrappedPsbt = toWrappedPsbt(psbt);
  for (const [inputIndex, descriptor] of descriptors.entries()) {
    wrappedPsbt.updateInputWithDescriptor(inputIndex, descriptor);
  }
  const unwrappedPsbt = toUtxoPsbt(wrappedPsbt);
  for (let inputIndex = 0; inputIndex < psbt.txInputs.length; inputIndex++) {
    psbt.data.inputs[inputIndex] = unwrappedPsbt.data.inputs[inputIndex];
  }
}

function updateOutputsWithDescriptors(
  psbt: utxolib.bitgo.UtxoPsbt,
  descriptors: WithOptDescriptor<Output>[],
) {
  const wrappedPsbt = toWrappedPsbt(psbt);
  for (const [outputIndex, { descriptor }] of descriptors.entries()) {
    if (descriptor) {
      wrappedPsbt.updateOutputWithDescriptor(outputIndex, descriptor);
    }
  }
  const unwrappedPsbt = toUtxoPsbt(wrappedPsbt);
  for (let outputIndex = 0; outputIndex < psbt.txOutputs.length; outputIndex++) {
    psbt.data.outputs[outputIndex] = unwrappedPsbt.data.outputs[outputIndex];
  }
}

type WithOptDescriptor<T> = T & { descriptor?: Descriptor };

export function createPsbt(
  params: PsbtParams,
  inputs: DerivedDescriptorWalletOutput[],
  outputs: WithOptDescriptor<Output>[],
): utxolib.bitgo.UtxoPsbt {
  const psbt = utxolib.bitgo.UtxoPsbt.createPsbt({ network: params.network });
  psbt.setVersion(params.version ?? 2);
  psbt.setLocktime(params.locktime ?? 0);
  psbt.addInputs(
    inputs.map((i) => ({ ...i, sequence: params.sequence ?? MAX_BIP125_RBF_SEQUENCE })),
  );
  psbt.addOutputs(outputs);
  updateInputsWithDescriptors(
    psbt,
    inputs.map((i) => i.descriptor),
  );
  updateOutputsWithDescriptors(psbt, outputs);
  return psbt;
}

type MockOutputIdParams = { hash?: string; vout?: number };

type BaseMockDescriptorOutputParams = {
  id?: MockOutputIdParams;
  index?: number;
  value?: bigint;
};

function mockOutputId(id?: MockOutputIdParams): {
  hash: string;
  vout: number;
} {
  const hash = id?.hash ?? Buffer.alloc(32, 1).toString("hex");
  const vout = id?.vout ?? 0;
  return { hash, vout };
}

export function mockDerivedDescriptorWalletOutput(
  descriptor: Descriptor,
  outputParams: BaseMockDescriptorOutputParams = {},
): DerivedDescriptorWalletOutput {
  const { value = BigInt(1e6) } = outputParams;
  const { hash, vout } = mockOutputId(outputParams.id);
  return {
    hash,
    index: vout,
    witnessUtxo: {
      script: createScriptPubKeyFromDescriptor(descriptor),
      value,
    },
    descriptor,
  };
}

type MockInput = BaseMockDescriptorOutputParams & {
  index: number;
  descriptor: Descriptor;
};

type MockOutput = {
  descriptor: Descriptor;
  index: number;
  value: bigint;
  external?: boolean;
};

function deriveIfWildcard(descriptor: Descriptor, index: number): Descriptor {
  return descriptor.hasWildcard() ? descriptor.atDerivationIndex(index) : descriptor;
}

export function mockPsbt(
  inputs: MockInput[],
  outputs: MockOutput[],
  params: Partial<PsbtParams> = {},
): utxolib.bitgo.UtxoPsbt {
  return createPsbt(
    { ...params, network: params.network ?? utxolib.networks.bitcoin },
    inputs.map((i) =>
      mockDerivedDescriptorWalletOutput(deriveIfWildcard(i.descriptor, i.index), i),
    ),
    outputs.map((o) => {
      const derivedDescriptor = deriveIfWildcard(o.descriptor, o.index);
      return {
        script: createScriptPubKeyFromDescriptor(derivedDescriptor),
        value: o.value,
        descriptor: o.external ? undefined : derivedDescriptor,
      };
    }),
  );
}

export type PsbtParams = {
  network: utxolib.Network;
  version?: number;
  locktime?: number;
  sequence?: number;
};

export function mockPsbtDefault({
  descriptorSelf,
  descriptorOther,
  params = {},
}: {
  descriptorSelf: Descriptor;
  descriptorOther: Descriptor;
  params?: Partial<PsbtParams>;
}): utxolib.bitgo.UtxoPsbt {
  return mockPsbt(
    [
      { descriptor: descriptorSelf, index: 0 },
      { descriptor: descriptorSelf, index: 1, id: { vout: 1 } },
    ],
    [
      { descriptor: descriptorOther, index: 0, value: BigInt(4e5), external: true },
      { descriptor: descriptorSelf, index: 0, value: BigInt(4e5) },
    ],
    params,
  );
}
