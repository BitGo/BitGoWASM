import * as assert from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { zcashAddress } from "../../js/index.js";
import { ZcashUnifiedAddress } from "../../js/fixedScriptWallet/ZcashUnifiedAddress.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesZcash = path.resolve(__dirname, "../fixtures/zcash");

type UaVector = {
  network: "zec" | "tzec";
  unified: string;
  transparentAddress?: string;
  orchardReceiverHex?: string;
  ironwoodReceiverHex?: string;
  transparentPubkeyHashHex: string;
};

const uaFixtures = JSON.parse(
  fs.readFileSync(path.join(fixturesZcash, "unified_address.json"), "utf8"),
) as {
  zip316Mainnet: UaVector;
  testnetWallet: UaVector;
};
const MAINNET = uaFixtures.zip316Mainnet;
const WALLET = uaFixtures.testnetWallet;

const ZEC = "zec";
const TZEC = "tzec";

// An Orchard-only unified address (no transparent receiver), derived from the mainnet fixture's
// Orchard receiver.
const ORCHARD_ONLY_UA = ZcashUnifiedAddress.encodeOrchardReceiver(
  Buffer.from(MAINNET.orchardReceiverHex, "hex"),
  ZEC,
);

describe("zcashAddress.hasOrchardReceiver", function () {
  it("is true for a unified address with an Orchard/Ironwood receiver", function () {
    assert.strictEqual(zcashAddress.hasOrchardReceiver(MAINNET.unified, ZEC), true);
    assert.strictEqual(zcashAddress.hasOrchardReceiver(WALLET.unified, TZEC), true);
  });

  it("is true for an Orchard-only unified address", function () {
    assert.strictEqual(zcashAddress.hasOrchardReceiver(ORCHARD_ONLY_UA, ZEC), true);
  });

  it("is false for an ordinary (non-UA) transparent address", function () {
    assert.strictEqual(zcashAddress.hasOrchardReceiver(WALLET.transparentAddress, TZEC), false);
  });

  it("is false for a wrong-network unified address", function () {
    assert.strictEqual(zcashAddress.hasOrchardReceiver(MAINNET.unified, TZEC), false);
  });

  it("is false for garbage input, and never throws", function () {
    assert.strictEqual(zcashAddress.hasOrchardReceiver("not an address", ZEC), false);
    assert.strictEqual(zcashAddress.hasOrchardReceiver("", ZEC), false);
  });
});

describe("zcashAddress.hasTransparentReceiver", function () {
  it("is true for a unified address with a transparent receiver", function () {
    assert.strictEqual(zcashAddress.hasTransparentReceiver(MAINNET.unified, ZEC), true);
    assert.strictEqual(zcashAddress.hasTransparentReceiver(WALLET.unified, TZEC), true);
  });

  it("is false for an Orchard-only unified address", function () {
    assert.strictEqual(zcashAddress.hasTransparentReceiver(ORCHARD_ONLY_UA, ZEC), false);
  });

  it("is true for an ordinary transparent address that decodes for the coin", function () {
    assert.strictEqual(zcashAddress.hasTransparentReceiver(WALLET.transparentAddress, TZEC), true);
    assert.strictEqual(
      zcashAddress.hasTransparentReceiver("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc"),
      true,
    );
  });

  it("is false for a wrong-network unified address", function () {
    assert.strictEqual(zcashAddress.hasTransparentReceiver(MAINNET.unified, TZEC), false);
  });

  it("is false for garbage input, and never throws", function () {
    assert.strictEqual(zcashAddress.hasTransparentReceiver("not an address", ZEC), false);
    assert.strictEqual(zcashAddress.hasTransparentReceiver("", ZEC), false);
  });
});
