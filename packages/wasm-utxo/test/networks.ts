import type { CoinName } from "../js/coinName.js";

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
