import assert from "node:assert";

import { requiresPrevTxForP2sh, type CoinName } from "../../js/index.js";

describe("prevTx policy", function () {
  describe("requiresPrevTxForP2sh", function () {
    // Callers gate on script type (p2sh) and tx format themselves; this
    // predicate only answers the coin-level question for a p2sh input.
    const cases: { coin: CoinName; expected: boolean; note: string }[] = [
      // Value-committing coins: skip prevTx (sighash commits the amount)
      {
        coin: "zec",
        expected: false,
        note: "zec p2sh — skip prevTx (ZIP-243, the fix)",
      },
      {
        coin: "tzec",
        expected: false,
        note: "tzec p2sh — skip prevTx (ZIP-243, the fix)",
      },
      {
        coin: "bch",
        expected: false,
        note: "bch p2sh — skip prevTx (FORKID commits value)",
      },
      {
        coin: "tbch",
        expected: false,
        note: "tbch p2sh — skip prevTx (FORKID commits value)",
      },
      {
        coin: "bcha",
        expected: false,
        note: "bcha (eCash) p2sh — skip prevTx (FORKID commits value)",
      },
      {
        coin: "bsv",
        expected: false,
        note: "bsv p2sh — skip prevTx (FORKID commits value)",
      },
      {
        coin: "btg",
        expected: false,
        note: "btg p2sh — skip prevTx (FORKID commits value)",
      },
      // Non-value-committing coins: prevTx still required (unchanged)
      {
        coin: "btc",
        expected: true,
        note: "btc p2sh — unchanged (needs prevTx)",
      },
      {
        coin: "tbtc",
        expected: true,
        note: "tbtc p2sh — unchanged (needs prevTx)",
      },
      {
        coin: "ltc",
        expected: true,
        note: "ltc p2sh — unchanged (needs prevTx)",
      },
      {
        coin: "doge",
        expected: true,
        note: "doge p2sh — unchanged (needs prevTx)",
      },
      {
        coin: "dash",
        expected: true,
        note: "dash p2sh — unchanged (needs prevTx)",
      },
    ];

    for (const c of cases) {
      it(`returns ${c.expected} for ${c.note}`, function () {
        assert.strictEqual(requiresPrevTxForP2sh(c.coin), c.expected);
      });
    }
  });
});
