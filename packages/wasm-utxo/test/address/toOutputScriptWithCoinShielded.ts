import * as assert from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { address as addressNs, zcashAddress } from "../../js/index.js";

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

// This coin-name mapping mirrors `Network::from_coin_name`: "zec"/"tzec" both resolve, but the
// rest of this test suite (and BitGoJS) spells them "zec"/"tzec" too.
const ZEC = "zec";
const TZEC = "tzec";

describe("zcashAddress.toShieldedReceiverWithCoin", function () {
  it("returns the raw Orchard/Ironwood receiver for a unified address (mainnet)", function () {
    const script = zcashAddress.toShieldedReceiverWithCoin(MAINNET.unified, ZEC);
    assert.strictEqual(Buffer.from(script).toString("hex"), MAINNET.orchardReceiverHex);
    assert.strictEqual(script.length, 43);
  });

  it("returns the raw Orchard/Ironwood receiver for a unified address (testnet)", function () {
    const script = zcashAddress.toShieldedReceiverWithCoin(WALLET.unified, TZEC);
    assert.strictEqual(Buffer.from(script).toString("hex"), WALLET.ironwoodReceiverHex);
  });

  it("throws for a wrong-network unified address rather than silently succeeding", function () {
    // MAINNET.unified has the "u" HRP; asking for "tzec" (expects "utest") means the HRP sniff
    // itself returns false, so this never reaches the UA parser's own (separately tested)
    // network check — it falls through to the transparent path, which fails for an unrelated
    // reason (a UA string never decodes as a transparent address). Assert on that specific
    // failure rather than a bare `throws()`, so this pins down which path actually rejected it —
    // a bare `throws()` would still pass even if the network check were silently removed.
    assert.throws(
      () => zcashAddress.toShieldedReceiverWithCoin(MAINNET.unified, TZEC),
      /Could not decode address/,
    );
  });
});

describe("zcashAddress.toTransparentReceiverWithCoin", function () {
  it("returns the unified address's transparent receiver", function () {
    // A unified address is always attempted as one; the transparent receiver is always the
    // authoritative one for this function -- never the shielded receiver. See
    // `zcashAddress.toShieldedReceiverWithCoin` for resolving the shielded receiver instead.
    const expected = `76a914${MAINNET.transparentPubkeyHashHex}88ac`;
    assert.strictEqual(
      Buffer.from(zcashAddress.toTransparentReceiverWithCoin(MAINNET.unified, ZEC)).toString("hex"),
      expected,
    );
  });

  it("falls through to the transparent path for an ordinary (non-UA) address", function () {
    const script = zcashAddress.toTransparentReceiverWithCoin(
      WALLET.transparentAddress ?? "",
      TZEC,
    );
    assert.strictEqual(
      Buffer.from(script).toString("hex"),
      `76a914${WALLET.transparentPubkeyHashHex}88ac`,
    );
  });
});

describe("address.toOutputScriptWithCoin", function () {
  it("does not resolve a unified address -- it is not a valid transparent address", function () {
    // The general-purpose function never attempts unified-address resolution; a UA string is
    // just as invalid to it as any other malformed address. See
    // `zcashAddress.toTransparentReceiverWithCoin` for resolving a UA's transparent receiver.
    assert.throws(
      () => addressNs.toOutputScriptWithCoin(MAINNET.unified, ZEC),
      /Could not decode address/,
    );
  });

  it("decodes an ordinary (non-UA) transparent address", function () {
    const script = addressNs.toOutputScriptWithCoin(WALLET.transparentAddress ?? "", TZEC);
    assert.strictEqual(
      Buffer.from(script).toString("hex"),
      `76a914${WALLET.transparentPubkeyHashHex}88ac`,
    );
  });
});
