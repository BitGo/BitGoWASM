import assert from "node:assert";
import { BIP32Interface, ECPair, ECPairInterface } from "@bitgo/utxo-lib";
import { getKey } from "@bitgo/utxo-lib/dist/src/testutil";

import { DescriptorNode, formatNode } from "../js/ast/index.js";
import { mockPsbtDefault } from "./psbtFromDescriptor.util.js";
import { Descriptor } from "../js/index.js";
import { toWrappedPsbt } from "./psbt.util.js";

function toKeyWithPath(k: BIP32Interface, path = "*"): string {
  return k.neutered().toBase58() + "/" + path;
}

function toECPair(k: BIP32Interface): ECPairInterface {
  assert(k.privateKey);
  return ECPair.fromPrivateKey(k.privateKey);
}

function toKeyPlainXOnly(k: Buffer): string {
  return k.subarray(1).toString("hex");
}

const external = getKey("external");
const a = getKey("a");
const b = getKey("b");
const c = getKey("c");
const keys = { external, a, b, c };
function getKeyName(k: BIP32Interface | ECPairInterface) {
  const objKeys = Object.keys(keys) as (keyof typeof keys)[];
  return objKeys.find(
    (key) => keys[key] === k || toECPair(keys[key]).publicKey.equals(k.publicKey),
  );
}

function describeSignDescriptor(
  name: string,
  descriptor: Descriptor,
  {
    signBip32 = [],
    signECPair = [],
  }: {
    signBip32?: BIP32Interface[][];
    signECPair?: ECPairInterface[][];
  },
) {
  describe(`psbt with descriptor ${name}`, function () {
    const isTaproot = Object.keys(descriptor.node())[0] === "Tr";
    const psbt = mockPsbtDefault({
      descriptorSelf: descriptor,
      descriptorOther: Descriptor.fromString(
        formatNode({ wpkh: toKeyWithPath(external) }),
        "derivable",
      ),
    });

    function getSigResult(keys: (BIP32Interface | ECPairInterface)[]) {
      return {
        [isTaproot ? "Schnorr" : "Ecdsa"]: keys.map((key) =>
          key.publicKey.subarray(isTaproot ? 1 : 0).toString("hex"),
        ),
      };
    }

    signBip32.forEach((signSeq) => {
      it(`should sign ${signSeq.map((k) => getKeyName(k)).join(", ")} xprv`, function () {
        const wrappedPsbt = toWrappedPsbt(psbt);
        signSeq.forEach((key) => {
          assert.deepStrictEqual(wrappedPsbt.signWithXprv(key.toBase58()), {
            0: getSigResult([key.derive(0)]),
            1: getSigResult([key.derive(1)]),
          });
        });
        wrappedPsbt.finalize();
      });

      it(`should sign ${signSeq.map((k) => getKeyName(k)).join(", ")} prv buffer`, function () {
        const wrappedPsbt = toWrappedPsbt(psbt);
        signSeq.forEach((key) => {
          assert.deepStrictEqual(wrappedPsbt.signWithPrv(key.derive(0).privateKey), {
            // NOTE: signing with a plain derived key does not work for taproot
            // see SingleKeySigner implementation in psbt.rs for details
            0: getSigResult(isTaproot ? [] : [key.derive(0)]),
            1: getSigResult([]),
          });
        });
      });
    });

    signECPair.forEach((signSeq) => {
      it(`should sign ${signSeq.map((k) => getKeyName(k)).join(", ")} ec pair`, function () {
        const wrappedPsbt = toWrappedPsbt(psbt);
        signSeq.forEach((key) => {
          assert(key.privateKey);
          assert.deepStrictEqual(wrappedPsbt.signWithPrv(key.privateKey), {
            0: getSigResult([key]),
            1: getSigResult([key]),
          });
        });
        wrappedPsbt.finalize();
      });
    });
  });
}

function fromNodes(node: DescriptorNode, type: "definite" | "derivable") {
  return Descriptor.fromString(formatNode(node), type);
}

describeSignDescriptor(
  "Wsh2Of3",
  fromNodes(
    {
      wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] },
    },
    "derivable",
  ),
  {
    signBip32: [
      [a, b],
      [b, a],
    ],
  },
);

describeSignDescriptor(
  "Tr1Of3",
  fromNodes(
    {
      tr: [toKeyWithPath(a), [{ pk: toKeyWithPath(b) }, { pk: toKeyWithPath(c) }]],
    },
    "derivable",
  ),
  { signBip32: [[a], [b], [c]] },
);

describeSignDescriptor(
  "TrWithExternalPlain",
  fromNodes(
    {
      tr: [
        toKeyPlainXOnly(external.publicKey),
        [
          { pk: toKeyPlainXOnly(external.publicKey) },
          {
            or_b: [
              { pk: toKeyPlainXOnly(external.publicKey) },
              { "s:pk": toKeyPlainXOnly(a.publicKey) },
            ],
          },
        ],
      ],
    },
    "definite",
  ),
  { signECPair: [[toECPair(a)]] },
);
