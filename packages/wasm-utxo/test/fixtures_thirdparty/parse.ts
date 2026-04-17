import * as assert from "assert/strict";
import { describe } from "mocha";
import { getNetworkList, getNetworkName } from "../networks.js";
import { testFixtureArray, txValidTestFile, TxValidVector } from "./fixtures.js";
import { Transaction } from "../../js/index.js";
import { toCoinName } from "../../js/coinName.js";

describe("Third-Party Fixtures", function () {
  getNetworkList().forEach((network) => {
    describe(`parse ${getNetworkName(network)}`, function () {
      testFixtureArray(this, network, txValidTestFile, function (vectors: TxValidVector[]) {
        vectors.forEach((v: TxValidVector, i) => {
          const [, /* inputs , */ txHex] = v;
          const buffer = Buffer.from(txHex, "hex");

          // Parse transaction using factory dispatch
          const coin = toCoinName(getNetworkName(network));
          const tx = Transaction.fromBytes(buffer, coin);

          // Round-trip to verify serialization
          const serialized = Buffer.from(tx.toBytes());
          assert.deepEqual(
            serialized,
            buffer,
            `Transaction round-trip failed for ${coin} vector ${i}`,
          );
        });
      });
    });
  });
});
