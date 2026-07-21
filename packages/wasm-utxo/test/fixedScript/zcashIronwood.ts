import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { ZcashBitGoPsbt } from "../../js/fixedScriptWallet/ZcashBitGoPsbt.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const srcZcash = path.resolve(__dirname, "../../src/zcash");

// ZIP-316 unified-address test vector (mainnet), Orchard + P2PKH receivers.
const UA =
  "u1pg2aaph7jp8rpf6yhsza25722sg5fcn3vaca6ze27hqjw7jvvhhuxkpcg0ge9xh6drsgdkda8qjq5chpehkcpxf87rnjryjqwymdheptpvnljqqrjqzjwkc2ma6hcq666kgwfytxwac8eyex6ndgr6ezte66706e3vaqrd25dzvzkc69kw0jgywtd0cmq52q5lkw6uh7hyvzjse8ksx";
const UA_ORCHARD =
  "cecbe5e689a453a3fe10ccf7617e6c1fb382819d7fc9200a1f42092ac84a30378f8c1fb90dff71a6d5042d";
const UA_P2PKH_HASH = "cad268758c5e71493066446b98e71df9d1d6a5ca";

function hex(u: Uint8Array): string {
  return Buffer.from(u).toString("hex");
}

describe("ZcashBitGoPsbt Ironwood (v6) helpers", function () {
  describe("parseUnifiedAddress", function () {
    it("extracts the Orchard/Ironwood receiver", function () {
      const out = ZcashBitGoPsbt.parseUnifiedAddress(UA, "zec", true);
      assert.strictEqual(hex(out), UA_ORCHARD);
      assert.strictEqual(out.length, 43);
    });

    it("extracts the transparent receiver as a P2PKH scriptPubKey", function () {
      const out = ZcashBitGoPsbt.parseUnifiedAddress(UA, "zec", false);
      assert.strictEqual(hex(out), `76a914${UA_P2PKH_HASH}88ac`);
    });

    it("rejects an address on the wrong network", function () {
      assert.throws(() => ZcashBitGoPsbt.parseUnifiedAddress(UA, "tzec", true));
    });
  });

  describe("computeV6Txid", function () {
    it("matches the golden shielding transaction txid", function () {
      const rawHex = fs
        .readFileSync(path.join(srcZcash, "testdata_v6_shield_rawtx.hex"), "utf8")
        .trim();
      const expectedTxid = fs
        .readFileSync(path.join(srcZcash, "testdata_v6_shield_txid.hex"), "utf8")
        .trim();
      const internal = ZcashBitGoPsbt.computeV6Txid(Buffer.from(rawHex, "hex"));
      // Internal byte order; reverse for the canonical display txid.
      const display = Buffer.from(internal).reverse();
      assert.strictEqual(display.toString("hex"), expectedTxid);
    });

    it("throws on non-v6 bytes", function () {
      assert.throws(() => ZcashBitGoPsbt.computeV6Txid(Buffer.from("00010203", "hex")));
    });
  });
});
