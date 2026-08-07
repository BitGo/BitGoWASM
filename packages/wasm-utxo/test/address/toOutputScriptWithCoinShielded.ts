import * as assert from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { address as addressNs } from "../../js/index.js";

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

describe("toOutputScriptWithCoin canBeShieldedOutput", function () {
  it("returns the raw Orchard/Ironwood receiver for a unified address, when set (mainnet)", function () {
    const script = addressNs.toOutputScriptWithCoin(MAINNET.unified, ZEC, true);
    assert.strictEqual(Buffer.from(script).toString("hex"), MAINNET.orchardReceiverHex);
    assert.strictEqual(script.length, 43);
  });

  it("returns the raw Orchard/Ironwood receiver for a unified address, when set (testnet)", function () {
    const script = addressNs.toOutputScriptWithCoin(WALLET.unified, TZEC, true);
    assert.strictEqual(Buffer.from(script).toString("hex"), WALLET.ironwoodReceiverHex);
  });

  it("still resolves a unified address's transparent script when canBeShieldedOutput is unset", function () {
    // Without the flag, a UA is never even attempted as one — it falls through to the same
    // transparent-only path as before this feature existed. A UA string is never itself a valid
    // transparent address, so this must fail exactly like it always did.
    assert.throws(() => addressNs.toOutputScriptWithCoin(MAINNET.unified, ZEC));
    assert.throws(() => addressNs.toOutputScriptWithCoin(MAINNET.unified, ZEC, false));
  });

  it("falls through to the transparent path for an ordinary (non-UA) address, even when set", function () {
    const script = addressNs.toOutputScriptWithCoin(WALLET.transparentAddress, TZEC, true);
    assert.strictEqual(
      Buffer.from(script).toString("hex"),
      `76a914${WALLET.transparentPubkeyHashHex}88ac`,
    );
  });

  it("throws for a wrong-network unified address rather than silently succeeding", function () {
    // MAINNET.unified has the "u" HRP; asking for "tzec" (expects "utest") means the HRP sniff
    // itself returns false, so this never reaches the UA parser's own (separately tested)
    // network check — it falls through to the transparent path, which fails for an unrelated
    // reason (a UA string never decodes as a transparent address). Assert on that specific
    // failure rather than a bare `throws()`, so this pins down which path actually rejected it —
    // a bare `throws()` would still pass even if the network check were silently removed.
    assert.throws(
      () => addressNs.toOutputScriptWithCoin(MAINNET.unified, TZEC, true),
      /Could not decode address/,
    );
  });
});
