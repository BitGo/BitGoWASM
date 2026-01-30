import type { CoinName } from "../js/coinName.js";
import * as utxolib from "@bitgo/utxo-lib";

/**
 * Mainnet coin names for third-party fixtures.
 *
 * We keep this in `test/` because it's only used by the fixture harness.
 */
export const mainnetCoinNames = [
  "btc",
  "bch",
  "bcha",
  "btg",
  "bsv",
  "dash",
  "doge",
  "ltc",
  "zec",
] as const satisfies readonly CoinName[];

export type MainnetCoinName = (typeof mainnetCoinNames)[number];

export function getNetworkList(): MainnetCoinName[] {
  return [...mainnetCoinNames];
}

export function getNetworkName(coin: MainnetCoinName): string {
  return coin;
}

export function isZcash(coin: MainnetCoinName): boolean {
  return coin === "zec";
}

/** Convert utxolib network to CoinName */
export function getCoinNameForNetwork(network: utxolib.Network): CoinName {
  const name = utxolib.getNetworkName(network);
  switch (name) {
    case "bitcoin":
      return "btc";
    case "testnet":
      return "tbtc";
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
  }
}
