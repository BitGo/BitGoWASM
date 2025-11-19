import * as assert from "assert";
import * as utxolib from "@bitgo/utxo-lib";
import { Descriptor } from "../js/index.js";
import { finalizePsbt, updateInputWithDescriptor } from "./psbt.util.js";
import { getFixture } from "./fixtures.js";

const rootWalletKeys = new utxolib.bitgo.RootWalletKeys(utxolib.testutil.getKeyTriple("wasm"));

function getDescriptorOpDropP2ms(locktime: number, keys: utxolib.BIP32Interface[]) {
  const xpubs = keys.map((key) => key.toBase58() + "/*");
  // the `r:` prefix is a custom BitGo modification of miniscript to allow OP_DROP
  return `wsh(and_v(r:after(${locktime}),multi(2,${xpubs.join(",")})))`;
}

describe("CLV with OP_DROP", function () {
  const locktime = 1024;
  const descriptor = Descriptor.fromString(
    getDescriptorOpDropP2ms(locktime, rootWalletKeys.triple),
    "derivable",
  );
  it("has expected AST", () => {
    assert.deepStrictEqual(descriptor.node(), {
      Wsh: {
        Ms: {
          AndV: [
            {
              Drop: {
                After: {
                  absLockTime: 1024,
                },
              },
            },
            {
              Multi: [
                2,
                {
                  XPub: "xpub661MyMwAqRbcFNusVUbSN3nbanHMtJjLgZGrs1wxH6f77kKQd6Vq4HfkZQNPC1vSbN6RTiBWJJV6FwJtCfBon2SgaT2J3MSkydukstKjwbJ/*",
                },
                {
                  XPub: "xpub661MyMwAqRbcFo3t7PUqvbgvAcEuuoeVib5aapsg52inrG6KGF5aNtR5ey1FNCt1zJpMQiNec5XpofQmLNRhHvQRbhkc8UsWwwMwsXW6ogU/*",
                },
                {
                  XPub: "xpub661MyMwAqRbcGg7f22Kcg2gy1F4jBjWR3xQTECVeJPHmxvhg5gUAZC6EYFtnyi6aMDQir1kV8HzCqC2FzTowGgEZqRh7rinqUCDeNDdmYzH/*",
                },
              ],
            },
          ],
        },
      },
    });
  });

  it("has expected asm", () => {
    assert.deepStrictEqual(descriptor.atDerivationIndex(0).toAsmString().split(" "), [
      "OP_PUSHBYTES_2",
      "0004",
      "OP_CLTV",
      "OP_DROP",
      "OP_PUSHNUM_2",
      "OP_PUSHBYTES_33",
      "02ae7c3c0ebc315a33151a1985ebb1fdcae72b3b91c38e3193c40ebabfffe9c343",
      "OP_PUSHBYTES_33",
      "0260ba2407f7c75d525db9f171e9b2f3cf5ba3f0d7fc6067b20d4b91585432f974",
      "OP_PUSHBYTES_33",
      "03eadd6e4300dac62f1d4cf1131a06c5e140911f04245c64934c27510e93dbe843",
      "OP_PUSHNUM_3",
      "OP_CHECKMULTISIG",
    ]);
  });

  it("can be signed", async function () {
    const psbt = Object.assign(new utxolib.Psbt({ network: utxolib.networks.bitcoin }), {
      locktime,
    });
    const signers = rootWalletKeys.triple.slice(0, 2);
    const descriptorAt0 = descriptor.atDerivationIndex(0);
    const script = Buffer.from(descriptorAt0.scriptPubkey());
    psbt.addInput({
      hash: Buffer.alloc(32),
      index: 0,
      sequence: 0xfffffffe,
      witnessUtxo: { script, value: BigInt(1e8) },
    });
    psbt.addOutput({ script, value: BigInt(1e8) });
    updateInputWithDescriptor(psbt, 0, descriptorAt0);
    for (const signer of signers) {
      psbt.signAllInputsHD(signer);
    }
    finalizePsbt(psbt);
    const signedTx = psbt.extractTransaction().toBuffer();
    assert.strictEqual(
      signedTx.toString("hex"),
      await getFixture("test/fixtures/opdrop.json", signedTx.toString("hex")),
    );
  });
});
