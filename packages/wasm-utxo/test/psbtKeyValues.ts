import * as assert from "assert";
import * as crypto from "crypto";

import { fixedScriptWallet, Psbt } from "../js/index.js";

const KEY_TYPE_SHA256 = "PSBT_IN_SHA256";
const UNKNOWN_KEY_TYPE = 0x50n;
const EXTENDED_UNKNOWN_KEY_TYPE = 0x1234n;
const EXTENDED_KEY_TYPE_SUFFIX = new Uint8Array([0x34, 0x12, 0xaa]);

function createPsbt(): Psbt {
  const psbt = Psbt.create(2, 0);
  psbt.addInput("01".repeat(32), 0, 100_000n, new Uint8Array(34));
  psbt.addOutput(new Uint8Array([0x6a]), 0n);
  return psbt;
}

function assertInputKeyValues(
  keyValues: ReturnType<Psbt["getInputKeyValues"]>,
  preimage: Uint8Array,
): void {
  const sha256Preimage = keyValues.find(
    (keyValue) =>
      keyValue.type === "known" &&
      keyValue.key === KEY_TYPE_SHA256 &&
      Buffer.from(keyValue.keyData).equals(crypto.createHash("sha256").update(preimage).digest()),
  );
  assert.ok(sha256Preimage, "PSBT input must expose the SHA256 preimage record");
  assert.deepStrictEqual(sha256Preimage.value, preimage);

  const unknownKeyValue = keyValues.find(
    (keyValue) => keyValue.type === "unknown" && keyValue.keyType === UNKNOWN_KEY_TYPE,
  );
  assert.ok(unknownKeyValue, "PSBT input must expose unknown key-value records");
  assert.deepStrictEqual(unknownKeyValue.keyData, new Uint8Array([0x01, 0x02]));
  assert.deepStrictEqual(unknownKeyValue.value, new Uint8Array([0x03, 0x04]));

  const extendedUnknownKeyValue = keyValues.find(
    (keyValue) => keyValue.type === "unknown" && keyValue.keyType === EXTENDED_UNKNOWN_KEY_TYPE,
  );
  assert.ok(extendedUnknownKeyValue, "PSBT input must preserve CompactSize key types");
  assert.deepStrictEqual(extendedUnknownKeyValue.keyData, new Uint8Array([0xaa]));
  assert.deepStrictEqual(extendedUnknownKeyValue.value, new Uint8Array([0x05, 0x06]));
}

describe("PSBT input key values", function () {
  it("classifies known and unknown records after deserialization", function () {
    const preimage = new Uint8Array(32).fill(0x42);
    const psbt = createPsbt();
    psbt.addSha256Preimage(0, preimage);
    psbt.setInputKV(
      0,
      { type: "unknown", keyType: Number(UNKNOWN_KEY_TYPE), data: new Uint8Array([0x01, 0x02]) },
      new Uint8Array([0x03, 0x04]),
    );
    psbt.setInputKV(
      0,
      { type: "unknown", keyType: 0xfd, data: EXTENDED_KEY_TYPE_SUFFIX },
      new Uint8Array([0x05, 0x06]),
    );

    const serialized = psbt.serialize();
    assertInputKeyValues(Psbt.deserialize(serialized).getInputKeyValues(0), preimage);
    assertInputKeyValues(
      fixedScriptWallet.BitGoPsbt.fromBytes(serialized, "bitcoin").getInputKeyValues(0),
      preimage,
    );
  });
});
