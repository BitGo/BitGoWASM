import * as path from "node:path";
import * as fs from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

import * as utxolib from "@bitgo/utxo-lib";
import assert from "node:assert";
import {
  utxolibCompat,
  address as addressNs,
  type CoinName,
  AddressFormat,
} from "../../js/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

type Fixture = [type: string, script: string, address: string];

function getCoinNameForNetwork(name: string): CoinName {
  switch (name) {
    case "bitcoin":
      return "btc";
    case "testnet":
      return "tbtc";
    case "bitcoinTestnet4":
      return "tbtc4";
    case "bitcoinPublicSignet":
      return "tbtcsig";
    case "bitcoinBitGoSignet":
      return "tbtcbgsig";
    case "bitcoincash":
      return "bch";
    case "bitcoincashTestnet":
      return "tbch";
    case "ecash":
      return "bcha";
    case "ecashTest":
      return "tbcha";
    case "bitcoingold":
      return "btg";
    case "bitcoingoldTestnet":
      return "tbtg";
    case "bitcoinsv":
      return "bsv";
    case "bitcoinsvTestnet":
      return "tbsv";
    case "dash":
      return "dash";
    case "dashTest":
      return "tdash";
    case "dogecoin":
      return "doge";
    case "dogecoinTest":
      return "tdoge";
    case "litecoin":
      return "ltc";
    case "litecoinTest":
      return "tltc";
    case "zcash":
      return "zec";
    case "zcashTest":
      return "tzec";
    default:
      throw new Error(`Unknown network: ${name}`);
  }
}

async function getFixtures(name: string, addressFormat?: AddressFormat): Promise<Fixture[]> {
  if (name === "bitcoinBitGoSignet") {
    name = "bitcoinPublicSignet";
  }
  const filename = addressFormat ? `${name}-${addressFormat}` : name;
  const fixturePath = path.join(__dirname, "..", "fixtures", "address", `${filename}.json`);
  const fixtures = await fs.readFile(fixturePath, "utf8");
  return JSON.parse(fixtures);
}

function runTest(network: utxolib.Network, addressFormat?: AddressFormat) {
  const name = utxolib.getNetworkName(network);

  describe(`utxolibCompat ${name} ${addressFormat ?? "default"}`, function () {
    let fixtures: Fixture[];
    before(async function () {
      fixtures = await getFixtures(name, addressFormat);
    });

    it("should convert to utxolib compatible network", async function () {
      for (const fixture of fixtures) {
        const [_type, script, addressRef] = fixture;
        const scriptBuf = Buffer.from(script, "hex");
        const address = utxolibCompat.fromOutputScript(scriptBuf, network, addressFormat);
        assert.strictEqual(address, addressRef);
        const scriptFromAddress = utxolibCompat.toOutputScript(address, network, addressFormat);
        assert.deepStrictEqual(Buffer.from(scriptFromAddress), scriptBuf);
      }
    });

    it("should convert using coin name", async function () {
      const coinName = getCoinNameForNetwork(name);

      for (const fixture of fixtures) {
        const [_type, script, addressRef] = fixture;
        const scriptBuf = Buffer.from(script, "hex");

        // Test encoding (script -> address)
        const address = addressNs.fromOutputScriptWithCoin(scriptBuf, coinName, addressFormat);
        assert.strictEqual(address, addressRef);

        // Test decoding (address -> script)
        const scriptFromAddress = addressNs.toOutputScriptWithCoin(addressRef, coinName);
        assert.deepStrictEqual(Buffer.from(scriptFromAddress), scriptBuf);
      }
    });
  });
}

describe("utxolib compatible address encoding/decoding", function () {
  utxolib.getNetworkList().forEach((network) => {
    runTest(network);
    const mainnet = utxolib.getMainnet(network);
    if (mainnet === utxolib.networks.bitcoincash || mainnet === utxolib.networks.ecash) {
      runTest(network, "cashaddr");
    }
  });
});
