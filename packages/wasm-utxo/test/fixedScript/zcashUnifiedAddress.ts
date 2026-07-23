import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { ZcashUnifiedAddress } from "../../js/fixedScriptWallet/ZcashUnifiedAddress.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesZcash = path.resolve(__dirname, "../fixtures/zcash");

function readFixture(name: string): string {
  return fs.readFileSync(path.join(fixturesZcash, name), "utf8").trim();
}

type UaVector = {
  network: "zec" | "tzec";
  unified: string;
  transparentAddress?: string;
  orchardReceiverHex?: string;
  ironwoodReceiverHex?: string;
  transparentPubkeyHashHex: string;
};

const uaFixtures = JSON.parse(readFixture("unified_address.json")) as {
  zip316Mainnet: UaVector;
  testnetWallet: UaVector;
};
const MAINNET = uaFixtures.zip316Mainnet;
const WALLET = uaFixtures.testnetWallet;

function hex(u: Uint8Array | undefined): string | undefined {
  return u === undefined ? undefined : Buffer.from(u).toString("hex");
}

describe("ZcashUnifiedAddress", function () {
  describe("parse + component accessors", function () {
    it("exposes the Orchard/Ironwood and transparent components (mainnet vector)", function () {
      const ua = ZcashUnifiedAddress.parse(MAINNET.unified, MAINNET.network);
      assert.strictEqual(hex(ua.orchardReceiver), MAINNET.orchardReceiverHex);
      assert.strictEqual(ua.orchardReceiver?.length, 43);
      assert.strictEqual(
        hex(ua.transparentScript),
        `76a914${MAINNET.transparentPubkeyHashHex}88ac`,
      );
    });

    it("resolves the wallet vector's components (testnet)", function () {
      const ua = ZcashUnifiedAddress.parse(WALLET.unified, WALLET.network);
      assert.strictEqual(hex(ua.orchardReceiver), WALLET.ironwoodReceiverHex);
      assert.strictEqual(hex(ua.transparentScript), `76a914${WALLET.transparentPubkeyHashHex}88ac`);
    });

    it("rejects an address on the wrong network", function () {
      assert.throws(() => ZcashUnifiedAddress.parse(MAINNET.unified, "tzec"));
    });

    it("throws a marked Error carrying a typed .code", function () {
      // The wasm layer routes through WasmUtxoError, so JS receives a real Error
      // with a typed .code — not a bare string.
      assert.throws(
        () => ZcashUnifiedAddress.parse(MAINNET.unified, "tzec"),
        (err: unknown) => {
          assert.ok(err instanceof Error, "should be a real Error");
          assert.strictEqual(
            (err as Error & { code?: string }).code,
            "UnifiedAddressError.WrongHrp",
          );
          return true;
        },
      );
    });
  });

  describe("contains", function () {
    it("recognizes the transparent address as a component", function () {
      const ua = ZcashUnifiedAddress.parse(WALLET.unified, WALLET.network);
      assert.strictEqual(ua.contains(WALLET.transparentAddress), true);
    });

    it("recognizes the unified address as a component of itself", function () {
      const ua = ZcashUnifiedAddress.parse(WALLET.unified, WALLET.network);
      assert.strictEqual(ua.contains(WALLET.unified), true);
    });

    it("throws on a cross-network candidate", function () {
      const ua = ZcashUnifiedAddress.parse(WALLET.unified, WALLET.network);
      // Mainnet UA candidate is neither a testnet UA nor a valid tzec transparent address.
      assert.throws(() => ua.contains(MAINNET.unified));
    });

    it("throws on a malformed candidate address", function () {
      const ua = ZcashUnifiedAddress.parse(WALLET.unified, WALLET.network);
      assert.throws(() => ua.contains("not-an-address"));
    });
  });
});
