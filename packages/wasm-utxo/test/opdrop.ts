import * as assert from "assert";
import { Descriptor, Miniscript } from "../js/index.js";

const ECDSA_KEY = "02ae7c3c0ebc315a33151a1985ebb1fdcae72b3b91c38e3193c40ebabfffe9c343";
const DROP_CONTEXT_ERROR = /Drop fragments are only supported in taproot/;

function payloadDropMiniscript(payloadSize: number): string {
  return `and_v(payload_drop(${Buffer.alloc(payloadSize).toString("hex")}),pk(${ECDSA_KEY}))`;
}

function encodedPayloadDropScript(payloadSize: number): Buffer {
  return Buffer.concat([
    Buffer.from([0x4d, payloadSize & 0xff, payloadSize >> 8]),
    Buffer.alloc(payloadSize),
    Buffer.from([0x75, 0x21]),
    Buffer.from(ECDSA_KEY, "hex"),
    Buffer.from([0xac]),
  ]);
}

describe("OP_DROP context restrictions", function () {
  it("rejects 520- and 521-byte payloads in segwitv0 miniscript", () => {
    for (const payloadSize of [520, 521]) {
      assert.throws(
        () =>
          Miniscript.fromStringExt(payloadDropMiniscript(payloadSize), "segwitv0", {
            drop: true,
          }),
        DROP_CONTEXT_ERROR,
      );
    }
  });

  it("rejects payload_drop when decoding a segwitv0 script", () => {
    assert.throws(
      () =>
        Miniscript.fromBitcoinScriptExt(encodedPayloadDropScript(521), "segwitv0", {
          drop: true,
        }),
      DROP_CONTEXT_ERROR,
    );
  });

  it("rejects Drop and PayloadDrop fragments in legacy miniscript", () => {
    assert.throws(() =>
      Miniscript.fromStringExt(
        `and_v(r:after(1024),pk(${ECDSA_KEY}))`,
        "legacy",
        { drop: true },
      ),
    );
    assert.throws(
      () => Miniscript.fromStringExt(payloadDropMiniscript(1), "legacy", { drop: true }),
      DROP_CONTEXT_ERROR,
    );
  });

  it("rejects payload_drop in non-taproot descriptors, including Ext parsing", () => {
    const descriptor = `wsh(${payloadDropMiniscript(520)})`;
    assert.throws(() => Descriptor.fromString(descriptor, "definite"), DROP_CONTEXT_ERROR);
    assert.throws(
      () => Descriptor.fromString(`sh(${payloadDropMiniscript(1)})`, "definite"),
      DROP_CONTEXT_ERROR,
    );
    assert.throws(
      () => Descriptor.fromStringExt(descriptor, "definite", { drop: true }),
      DROP_CONTEXT_ERROR,
    );
  });

  it("rejects the r: wrapper in P2WSH and P2SH descriptors", () => {
    const fragment = `and_v(r:after(1024),pk(${ECDSA_KEY}))`;
    assert.throws(() => Descriptor.fromString(`wsh(${fragment})`, "definite"));
    assert.throws(() => Descriptor.fromString(`sh(${fragment})`, "definite"));
  });
});
