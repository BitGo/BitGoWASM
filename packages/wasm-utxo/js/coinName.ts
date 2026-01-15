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
