import assert from "node:assert";
import { address as addressNs } from "../../js/index.js";
import { coinNames, type CoinName } from "../../js/coinName.js";

/**
 * For a given script, encode as an address for every coin.
 * Returns groups of coins that produce the same address, sorted.
 */
function getCompatibilityGroups(scriptHex: string): CoinName[][] {
  const script = Buffer.from(scriptHex, "hex");
  const addressToCoins = new Map<string, CoinName[]>();

  for (const coin of coinNames) {
    try {
      const addr = addressNs.fromOutputScriptWithCoin(script, coin);
      const group = addressToCoins.get(addr);
      if (group) {
        group.push(coin);
      } else {
        addressToCoins.set(addr, [coin]);
      }
    } catch {
      // coin does not support this script type
    }
  }

  return Array.from(addressToCoins.values())
    .map((g) => g.sort())
    .sort((a, b) => a[0].localeCompare(b[0]));
}

// Representative scripts from test/fixtures/address/bitcoin.json
const scripts = {
  p2sh: "a91411510d2560794b3ed7bf734bc0e030e70e4db42d87",
  p2shP2wsh: "a9140c4e25aa3282fa35888f5e1eedb876265328312587",
  p2wsh: "00208bb2ef4181b60abe68b4c9cdc44c92e73bbb17fa2611e7e5b60d794794a1c94d",
  p2tr: "5120c4beea12923f95c32976d3d1ca7d5490aa3ea28f96d5feacc8ecc28819925eb5",
  p2trMusig2: "51205f98a79a3f750b250bee5bbdca0705db0ec8621f1bda91a083536a8a8bd6b6ed",
};

// p2sh and p2shP2wsh are both a914...87 scripts; the encoding cannot distinguish them,
// so they produce the same compatibility groups.
const legacyGroups: CoinName[][] = [
  ["bch", "bcha", "bsv", "btc"],
  ["btg"],
  ["dash"],
  ["doge"],
  ["ltc"],
  ["tbch", "tbcha", "tbsv", "tbtc", "tbtc4", "tbtcbgsig", "tbtcsig", "tbtg", "tdoge"],
  ["tdash"],
  ["tltc"],
  ["tzec"],
  ["zec"],
];

const segwitGroups: CoinName[][] = [
  ["btc"],
  ["btg"],
  ["ltc"],
  ["tbtc", "tbtc4", "tbtcbgsig", "tbtcsig"],
  ["tbtg"],
  ["tltc"],
];

const taprootGroups: CoinName[][] = [["btc"], ["tbtc", "tbtc4", "tbtcbgsig", "tbtcsig"]];

describe("address compatibility", function () {
  it("p2sh: btc/bch/bcha/bsv share mainnet format, most testnets share testnet format", function () {
    assert.deepStrictEqual(getCompatibilityGroups(scripts.p2sh), legacyGroups);
  });

  it("p2shP2wsh: same groups as p2sh (indistinguishable script structure)", function () {
    assert.deepStrictEqual(getCompatibilityGroups(scripts.p2shP2wsh), legacyGroups);
  });

  it("p2wsh: btc/btg/ltc each have unique bech32 HRP, testnets likewise", function () {
    assert.deepStrictEqual(getCompatibilityGroups(scripts.p2wsh), segwitGroups);
  });

  it("p2tr: only btc family supports taproot", function () {
    assert.deepStrictEqual(getCompatibilityGroups(scripts.p2tr), taprootGroups);
  });

  it("p2trMusig2: same groups as p2tr (same bech32m encoding)", function () {
    assert.deepStrictEqual(getCompatibilityGroups(scripts.p2trMusig2), taprootGroups);
  });
});
