import assert from "node:assert";
import { fixedScriptWallet } from "../../js/index.js";

// Compressed public key for private key 0x01 * 32
const PUBKEY = Buffer.from(
  "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
  "hex",
);

describe("p2shP2pkOutputScript", function () {
  it("should produce expected P2SH output script", function () {
    const script = fixedScriptWallet.p2shP2pkOutputScript(PUBKEY);

    // P2SH output scripts are always 23 bytes: OP_HASH160 <20-byte-hash> OP_EQUAL
    assert.strictEqual(script.length, 23);
    assert.strictEqual(script[0], 0xa9);
    assert.strictEqual(script[1], 0x14);
    assert.strictEqual(script[22], 0x87);

    assert.strictEqual(
      Buffer.from(script).toString("hex"),
      "a9140c79ca26388c7130abaa079b1968288911d3677387",
    );
  });

  it("should produce different scripts for different keys", function () {
    const otherPubkey = Buffer.from(
      "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
      "hex",
    );
    const script1 = fixedScriptWallet.p2shP2pkOutputScript(PUBKEY);
    const script2 = fixedScriptWallet.p2shP2pkOutputScript(otherPubkey);
    assert.notDeepStrictEqual(script1, script2);
  });

  it("should reject an invalid public key", function () {
    assert.throws(() => fixedScriptWallet.p2shP2pkOutputScript(new Uint8Array(32)));
  });
});
