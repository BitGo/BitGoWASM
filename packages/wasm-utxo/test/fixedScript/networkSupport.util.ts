import { coinNames, isMainnet, type CoinName } from "../../js/coinName.js";

export const mainnetCoinNames = coinNames.filter((c): c is CoinName => isMainnet(c) && c !== "bsv");
