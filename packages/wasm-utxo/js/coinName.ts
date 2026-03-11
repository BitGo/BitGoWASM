// BitGo coin names (from Network::from_coin_name in src/networks.rs)
export const coinNames = [
  "btc",
  "tbtc",
  "tbtc4",
  "tbtcsig",
  "tbtcbgsig",
  "bch",
  "tbch",
  "bcha",
  "tbcha",
  "btg",
  "tbtg",
  "bsv",
  "tbsv",
  "dash",
  "tdash",
  "doge",
  "tdoge",
  "ltc",
  "tltc",
  "zec",
  "tzec",
] as const;

export type CoinName = (typeof coinNames)[number];

export function getMainnet(name: CoinName): CoinName {
  switch (name) {
    case "tbtc":
    case "tbtc4":
    case "tbtcsig":
    case "tbtcbgsig":
      return "btc";
    case "tbch":
      return "bch";
    case "tbcha":
      return "bcha";
    case "tbtg":
      return "btg";
    case "tbsv":
      return "bsv";
    case "tdash":
      return "dash";
    case "tdoge":
      return "doge";
    case "tltc":
      return "ltc";
    case "tzec":
      return "zec";
    default:
      return name;
  }
}

export function isMainnet(name: CoinName): boolean {
  return getMainnet(name) === name;
}

export function isTestnet(name: CoinName): boolean {
  return getMainnet(name) !== name;
}

export function isCoinName(v: string): v is CoinName {
  return (coinNames as readonly string[]).includes(v);
}

import type { UtxolibName } from "./utxolibCompat.js";

/** Convert a CoinName or UtxolibName to CoinName */
export function toCoinName(name: CoinName | UtxolibName): CoinName {
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
      // CoinName values pass through (including "dash" which is both CoinName and UtxolibName)
      return name;
  }
}
