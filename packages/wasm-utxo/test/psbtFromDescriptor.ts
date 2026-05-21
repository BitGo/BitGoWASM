import assert from "node:assert";
import { BIP32Interface, ECPair, ECPairInterface } from "@bitgo/utxo-lib";
import { getKey } from "@bitgo/utxo-lib/dist/src/testutil";

import { DescriptorNode, formatNode } from "../js/ast/index.js";
import { mockPsbtDefault, PsbtParams } from "./psbtFromDescriptor.util.js";
import { Descriptor, Transaction } from "../js/index.js";
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
    psbtParams,
  }: {
    signBip32?: BIP32Interface[][];
    signECPair?: ECPairInterface[][];
    psbtParams?: Partial<PsbtParams>;
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
      params: psbtParams,
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

// sBTC taproot: NUMS internal key + deposit leaf (payload_drop + protocol signers key)
// and reclaim leaf (2-of-3 multi_a behind r:older(1)). Reclaim path is the one signable
// by user keys; sequence=1 satisfies older(1).
const SBTC_UNSPENDABLE = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const SBTC_SIGNERS_KEY = "c9c2312ca406dcb8eed50b829b5292f5fb3e846db0a556af61cc53834ce75421";
const SBTC_PAYLOAD_HEX = "0000000000013880051ad206838b7981a116c334e8cb1b950afb73eb54a5";
const sbtcDescriptorNode: DescriptorNode = {
  tr: [
    SBTC_UNSPENDABLE,
    [
      { and_v: [{ payload_drop: SBTC_PAYLOAD_HEX }, { pk: SBTC_SIGNERS_KEY }] },
      {
        and_v: [
          { "r:older": 1 },
          { multi_a: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] },
        ],
      },
    ],
  ],
};

describeSignDescriptor("P2trSBTC", fromNodes(sbtcDescriptorNode, "derivable"), {
  signBip32: [
    [a, b],
    [b, a],
  ],
  psbtParams: { sequence: 1 },
});

describe("WrapPsbt extractTransaction", function () {
  function signFinalizeExtract(
    descriptor: Descriptor,
    signKeys: BIP32Interface[],
    psbtParams?: Partial<PsbtParams>,
  ) {
    const psbt = mockPsbtDefault({
      descriptorSelf: descriptor,
      descriptorOther: Descriptor.fromString(
        formatNode({ wpkh: toKeyWithPath(external) }),
        "derivable",
      ),
      params: psbtParams,
    });
    const wrappedPsbt = toWrappedPsbt(psbt);
    for (const key of signKeys) {
      wrappedPsbt.signWithXprv(key.toBase58());
    }
    wrappedPsbt.finalize();
    return wrappedPsbt.extractTransaction();
  }

  it("should extract transaction from finalized Wsh2Of3 PSBT", function () {
    const tx = signFinalizeExtract(
      fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      ),
      [a, b],
    );

    assert.strictEqual(typeof tx.getId(), "string");
    assert.strictEqual(tx.getId().length, 64);
    assert.ok(tx.getVSize() > 0);
    assert.ok(tx.toBytes().length > 0);
  });

  it("should extract transaction from finalized Tr PSBT", function () {
    const tx = signFinalizeExtract(
      fromNodes(
        { tr: [toKeyWithPath(a), [{ pk: toKeyWithPath(b) }, { pk: toKeyWithPath(c) }]] },
        "derivable",
      ),
      [a],
    );

    assert.strictEqual(typeof tx.getId(), "string");
    assert.strictEqual(tx.getId().length, 64);
    assert.ok(tx.getVSize() > 0);
    assert.ok(tx.toBytes().length > 0);
  });

  it("should extract transaction from finalized P2trSBTC PSBT", function () {
    const tx = signFinalizeExtract(fromNodes(sbtcDescriptorNode, "derivable"), [a, b], {
      sequence: 1,
    });

    assert.strictEqual(typeof tx.getId(), "string");
    assert.strictEqual(tx.getId().length, 64);
    assert.ok(tx.getVSize() > 0);
    assert.ok(tx.toBytes().length > 0);
  });

  it("should produce consistent txid across repeated calls", function () {
    const tx = signFinalizeExtract(
      fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      ),
      [a, b],
    );

    assert.strictEqual(tx.getId(), tx.getId());
  });

  it("should produce a transaction whose bytes round-trip to the same txid", function () {
    const tx = signFinalizeExtract(
      fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      ),
      [a, b],
    );

    const txBytes = tx.toBytes();
    const tx2 = Transaction.fromBytes(txBytes);
    assert.strictEqual(tx2.getId(), tx.getId());
  });
});
