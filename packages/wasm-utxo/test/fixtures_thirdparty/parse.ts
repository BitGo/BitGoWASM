import * as assert from "assert/strict";
import { describe } from "mocha";
import { getNetworkList, getNetworkName, isZcash } from "../networks.js";
import { testFixtureArray, txValidTestFile, TxValidVector } from "./fixtures.js";

import { Transaction, ZcashTransaction } from "../../js/index.js";

describe("Third-Party Fixtures", function () {
  getNetworkList().forEach((network) => {
    describe(`parse ${getNetworkName(network)}`, function () {
      testFixtureArray(this, network, txValidTestFile, function (vectors: TxValidVector[]) {
        vectors.forEach((v: TxValidVector, i) => {
          const [, /* inputs , */ txHex] = v;
          const buffer = Buffer.from(txHex, "hex");

          // Parse transaction to verify it's valid
          if (isZcash(network)) {
            const tx = ZcashTransaction.fromBytes(buffer);
            // Round-trip to verify serialization
            const serialized = Buffer.from(tx.toBytes());
            assert.deepEqual(serialized, buffer, `Zcash transaction ${i} failed round-trip`);
          } else {
            const tx = Transaction.fromBytes(buffer);
            // Round-trip to verify serialization
            const serialized = Buffer.from(tx.toBytes());
            assert.deepEqual(serialized, buffer, `Transaction ${i} failed round-trip`);
          }
        });
      });
    });
  });
});
