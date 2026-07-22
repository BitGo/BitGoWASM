import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { ZcashBitGoPsbt } from "../../js/fixedScriptWallet/ZcashBitGoPsbt.js";

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

function hex(u: Uint8Array): string {
  return Buffer.from(u).toString("hex");
}

describe("ZcashBitGoPsbt Ironwood (v6) helpers", function () {
  describe("parseUnifiedAddress", function () {
    it("extracts the Orchard/Ironwood receiver", function () {
      const out = ZcashBitGoPsbt.parseUnifiedAddress(MAINNET.unified, MAINNET.network, true);
      assert.strictEqual(hex(out), MAINNET.orchardReceiverHex);
      assert.strictEqual(out.length, 43);
    });

    it("extracts the transparent receiver as a P2PKH scriptPubKey", function () {
      const out = ZcashBitGoPsbt.parseUnifiedAddress(MAINNET.unified, MAINNET.network, false);
      assert.strictEqual(hex(out), `76a914${MAINNET.transparentPubkeyHashHex}88ac`);
    });

    it("rejects an address on the wrong network", function () {
      assert.throws(() => ZcashBitGoPsbt.parseUnifiedAddress(MAINNET.unified, "tzec", true));
    });
  });

  describe("resolveUnifiedAddressComponent", function () {
    it("resolves the shielded (Ironwood) component", function () {
      const out = ZcashBitGoPsbt.resolveUnifiedAddressComponent(
        WALLET.unified,
        WALLET.network,
        true,
      );
      assert.strictEqual(hex(out), WALLET.ironwoodReceiverHex);
    });

    it("resolves the transparent component as a scriptPubKey", function () {
      const out = ZcashBitGoPsbt.resolveUnifiedAddressComponent(
        WALLET.unified,
        WALLET.network,
        false,
      );
      assert.strictEqual(hex(out), `76a914${WALLET.transparentPubkeyHashHex}88ac`);
    });
  });

  describe("isAddressComponentOf", function () {
    it("recognizes the transparent address as a component", function () {
      assert.strictEqual(
        ZcashBitGoPsbt.isAddressComponentOf(
          WALLET.unified,
          WALLET.transparentAddress,
          WALLET.network,
        ),
        true,
      );
    });

    it("recognizes the unified address as a component of itself", function () {
      assert.strictEqual(
        ZcashBitGoPsbt.isAddressComponentOf(WALLET.unified, WALLET.unified, WALLET.network),
        true,
      );
    });

    it("throws when the addresses are on the wrong network", function () {
      // Mainnet UA container queried on testnet.
      assert.throws(() =>
        ZcashBitGoPsbt.isAddressComponentOf(
          MAINNET.unified,
          WALLET.transparentAddress,
          "tzec",
        ),
      );
    });

    it("throws on a malformed candidate address", function () {
      assert.throws(() =>
        ZcashBitGoPsbt.isAddressComponentOf(WALLET.unified, "not-an-address", WALLET.network),
      );
    });
  });

  describe("computeV6Txid", function () {
    // Golden testnet transactions captured from the Ironwood reference.
    for (const name of ["shield", "selfsend", "shield1zec"]) {
      it(`matches the golden ${name} transaction txid`, function () {
        const rawHex = readFixture(`v6_${name}_rawtx.hex`);
        const expectedTxid = readFixture(`v6_${name}_txid.hex`);
        const internal = ZcashBitGoPsbt.computeV6Txid(Buffer.from(rawHex, "hex"));
        // Internal byte order; reverse for the canonical display txid.
        const display = Buffer.from(internal).reverse();
        assert.strictEqual(display.toString("hex"), expectedTxid);
      });
    }

    it("throws on non-v6 bytes", function () {
      assert.throws(() => ZcashBitGoPsbt.computeV6Txid(Buffer.from("00010203", "hex")));
    });
  });
});
